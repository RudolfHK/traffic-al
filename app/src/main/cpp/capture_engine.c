/*
 * Traffic AL - on-device traffic audit for Android
 * Copyright (C) 2026 RudolfHK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "capture_engine.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#define PACKET_BUFSIZE 65535
#define BATCH_BUFSIZE (512 * 1024)
#define FLUSH_INTERVAL_US 250000
#define PURGE_INTERVAL_US 3000000
#define SELECT_TIMEOUT_US 250000

#define TCP_FLAGS_OFFSET 13
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

#define DNS_PORT 53
#define PRIVATE_DNS_PORT 853

typedef struct dns_config {
  zdtun_ip_t virtual_ip;
  uint8_t virtual_ipver; /* 0 = not configured */
  zdtun_ip_t upstream_ip;
  uint8_t upstream_ipver; /* 0 = not configured */
  int block_private_dns;
} dns_config_t;

struct capture_engine {
  int wakeup_pipe[2];

  pthread_mutex_t lock;
  dns_config_t dns; /* guarded by lock */

  /* Owned by the thread in capture_engine_run(). */
  int started;
  zdtun_t *tun;
  int tun_fd;
  const capture_callbacks_t *callbacks;
  void *userdata;
  uint8_t *batch;
  size_t batch_len;
  uint64_t last_flush_us;

  /* Set by on_connection_open() when it rejects a connection. */
  int last_blocked;
  int last_blocked_uid;
};

typedef struct conn_data {
  int uid;
} conn_data_t;

/* ******************************************************* */

static uint64_t now_us(void) {
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);
  return ((uint64_t) ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
}

/* ******************************************************* */

static void flush_batch(capture_engine_t *engine) {
  if(engine->batch_len > 0 && engine->callbacks->on_packets)
    engine->callbacks->on_packets(engine->userdata, engine->batch, engine->batch_len);

  engine->batch_len = 0;
  engine->last_flush_us = now_us();
}

/* ******************************************************* */

static void record_packet(capture_engine_t *engine, const char *pkt, int len,
                          int uid, uint8_t direction, uint8_t flags) {
  capture_record_t hdr;
  size_t needed = sizeof(hdr) + (size_t) len;

  if(!engine->callbacks->on_packets || len <= 0 || needed > BATCH_BUFSIZE)
    return;

  if(engine->batch_len + needed > BATCH_BUFSIZE)
    flush_batch(engine);

  hdr.timestamp_us = now_us();
  hdr.uid = uid;
  hdr.length = (uint16_t) len;
  hdr.direction = direction;
  hdr.flags = flags;

  memcpy(engine->batch + engine->batch_len, &hdr, sizeof(hdr));
  memcpy(engine->batch + engine->batch_len + sizeof(hdr), pkt, len);
  engine->batch_len += needed;
}

/* ******************************************************* */

static int conn_uid(const zdtun_conn_t *conn) {
  const conn_data_t *data = (const conn_data_t*) zdtun_conn_get_userdata(conn);

  return data ? data->uid : CAPTURE_UID_UNKNOWN;
}

/* ******************************************************* */

static int is_same_ip(uint8_t ipver, const zdtun_ip_t *a, const zdtun_ip_t *b) {
  if(ipver == 4)
    return a->ip4 == b->ip4;
  return memcmp(&a->ip6, &b->ip6, sizeof(a->ip6)) == 0;
}

/* ******************************************************* */

/* zdtun callback: a packet must be delivered to the apps. */
static int send_client(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn) {
  capture_engine_t *engine = (capture_engine_t*) zdtun_userdata(tun);
  ssize_t written;

  do {
    written = write(engine->tun_fd, pkt->buf, pkt->len);
  } while(written < 0 && errno == EINTR);

  if(written != pkt->len) {
    error("write(tun) failed: %zd/%u bytes, errno %d", written, pkt->len, errno);
    return -1;
  }

  record_packet(engine, pkt->buf, pkt->len, conn_uid(conn), CAPTURE_DIR_IN, 0);
  return 0;
}

/* ******************************************************* */

static void on_socket_open(zdtun_t *tun, socket_t sock) {
  capture_engine_t *engine = (capture_engine_t*) zdtun_userdata(tun);

  if(engine->callbacks->protect_socket)
    engine->callbacks->protect_socket(engine->userdata, sock);
}

/* ******************************************************* */

/* zdtun callback: decide whether and where a new connection is forwarded. */
static int on_connection_open(zdtun_t *tun, zdtun_conn_t *conn) {
  capture_engine_t *engine = (capture_engine_t*) zdtun_userdata(tun);
  const zdtun_5tuple_t *tuple = zdtun_conn_get_5tuple(conn);
  uint16_t dst_port = ntohs(tuple->dst_port);
  int is_tcp_or_udp = (tuple->ipproto == IPPROTO_TCP) || (tuple->ipproto == IPPROTO_UDP);
  int block = 0;
  dns_config_t dns;
  conn_data_t *data;
  zdtun_ip_t dst_ip;
  int uid = CAPTURE_UID_UNKNOWN;

  /* The tuple is packed: copy the address instead of pointing into it. */
  memcpy(&dst_ip, &tuple->dst_ip, sizeof(dst_ip));

  if(engine->callbacks->resolve_uid)
    uid = engine->callbacks->resolve_uid(engine->userdata, tuple);

  pthread_mutex_lock(&engine->lock);
  dns = engine->dns;
  pthread_mutex_unlock(&engine->lock);

  if(dns.virtual_ipver == tuple->ipver && is_same_ip(tuple->ipver, &dst_ip, &dns.virtual_ip)) {
    /* The virtual DNS server only exists inside the VPN: redirect plain DNS to
     * the real resolver and reject anything else (e.g. DoT probes on 853). */
    if(is_tcp_or_udp && dst_port == DNS_PORT && dns.upstream_ipver != 0)
      zdtun_conn_dnat(conn, &dns.upstream_ip, htons(DNS_PORT), dns.upstream_ipver);
    else
      block = 1;
  } else if(dns.block_private_dns && is_tcp_or_udp && dst_port == PRIVATE_DNS_PORT)
    block = 1;

  if(block) {
    engine->last_blocked = 1;
    engine->last_blocked_uid = uid;
    return 1;
  }

  data = (conn_data_t*) calloc(1, sizeof(conn_data_t));
  if(!data) {
    error("calloc failed");
    return 1;
  }
  data->uid = uid;
  zdtun_conn_set_userdata(conn, data);
  return 0;
}

/* ******************************************************* */

static void on_connection_close(zdtun_t *tun, const zdtun_conn_t *conn) {
  free(zdtun_conn_get_userdata(conn));
  zdtun_conn_set_userdata((zdtun_conn_t*) conn, NULL);
}

/* ******************************************************* */

/* A packet sent by an app: record it and forward it to the network. */
static void handle_tun_packet(capture_engine_t *engine, char *buf, int len) {
  zdtun_pkt_t pkt;
  zdtun_conn_t *conn;
  int tcp_established;

  if(zdtun_parse_pkt(engine->tun, buf, (uint16_t) len, &pkt) != 0 || (pkt.flags & ZDTUN_PKT_IS_FRAGMENT)) {
    /* Not forwardable (e.g. IP fragments), but still part of the capture. */
    record_packet(engine, buf, len, CAPTURE_UID_UNKNOWN, CAPTURE_DIR_OUT, 0);
    return;
  }

  tcp_established = (pkt.tuple.ipproto == IPPROTO_TCP) &&
    (!(pkt.l4[TCP_FLAGS_OFFSET] & TCP_FLAG_SYN) || (pkt.l4[TCP_FLAGS_OFFSET] & TCP_FLAG_ACK));

  engine->last_blocked = 0;
  engine->last_blocked_uid = CAPTURE_UID_UNKNOWN;
  conn = zdtun_lookup(engine->tun, &pkt.tuple, !tcp_established);

  if(!conn) {
    record_packet(engine, buf, len, engine->last_blocked_uid, CAPTURE_DIR_OUT,
                  engine->last_blocked ? CAPTURE_FLAG_BLOCKED : 0);
    return;
  }

  record_packet(engine, buf, len, conn_uid(conn), CAPTURE_DIR_OUT, 0);

  if(zdtun_forward(engine->tun, &pkt, conn) != 0)
    zdtun_conn_close(engine->tun, conn, CONN_STATUS_ERROR);
}

/* ******************************************************* */

capture_engine_t *capture_engine_new(void) {
  capture_engine_t *engine = (capture_engine_t*) calloc(1, sizeof(capture_engine_t));

  if(!engine)
    return NULL;

  if(pipe(engine->wakeup_pipe) != 0) {
    free(engine);
    return NULL;
  }

  pthread_mutex_init(&engine->lock, NULL);
  engine->tun_fd = -1;
  return engine;
}

/* ******************************************************* */

void capture_engine_free(capture_engine_t *engine) {
  if(!engine)
    return;

  close(engine->wakeup_pipe[0]);
  close(engine->wakeup_pipe[1]);
  pthread_mutex_destroy(&engine->lock);
  free(engine);
}

/* ******************************************************* */

int capture_engine_set_dns(capture_engine_t *engine, const char *virtual_dns, const char *upstream_dns) {
  zdtun_ip_t virtual_ip, upstream_ip;
  int virtual_ipver = zdtun_parse_ip(virtual_dns, &virtual_ip);
  int upstream_ipver = zdtun_parse_ip(upstream_dns, &upstream_ip);

  if(virtual_ipver < 0 || upstream_ipver < 0)
    return -1;

  pthread_mutex_lock(&engine->lock);
  engine->dns.virtual_ip = virtual_ip;
  engine->dns.virtual_ipver = (uint8_t) virtual_ipver;
  engine->dns.upstream_ip = upstream_ip;
  engine->dns.upstream_ipver = (uint8_t) upstream_ipver;
  pthread_mutex_unlock(&engine->lock);
  return 0;
}

/* ******************************************************* */

void capture_engine_set_block_private_dns(capture_engine_t *engine, int block) {
  pthread_mutex_lock(&engine->lock);
  engine->dns.block_private_dns = block;
  pthread_mutex_unlock(&engine->lock);
}

/* ******************************************************* */

void capture_engine_stop(capture_engine_t *engine) {
  char c = 0;

  while(write(engine->wakeup_pipe[1], &c, 1) < 0 && errno == EINTR)
    ;
}

/* ******************************************************* */

int capture_engine_run(capture_engine_t *engine, int tun_fd, int mtu,
                       const capture_callbacks_t *callbacks, void *userdata) {
  zdtun_callbacks_t zdtun_callbacks = {
    .send_client = send_client,
    .on_socket_open = on_socket_open,
    .on_connection_open = on_connection_open,
    .on_connection_close = on_connection_close,
  };
  char *pkt_buf = NULL;
  uint64_t last_purge_us;
  int flags, rv = 0;

  if(engine->started) {
    error("capture_engine_run called twice");
    return -1;
  }

  engine->started = 1;
  engine->tun_fd = tun_fd;
  engine->callbacks = callbacks;
  engine->userdata = userdata;

  /* Writes must not fail with EAGAIN: zdtun never retransmits to the client. */
  flags = fcntl(tun_fd, F_GETFL);
  if(flags >= 0 && (flags & O_NONBLOCK))
    fcntl(tun_fd, F_SETFL, flags & ~O_NONBLOCK);

  pkt_buf = (char*) malloc(PACKET_BUFSIZE);
  engine->batch = (uint8_t*) malloc(BATCH_BUFSIZE);
  engine->tun = zdtun_init(&zdtun_callbacks, engine);

  if(!pkt_buf || !engine->batch || !engine->tun) {
    error("capture engine initialization failed");
    rv = -1;
    goto cleanup;
  }

  zdtun_set_mtu(engine->tun, mtu);
  engine->last_flush_us = last_purge_us = now_us();

  while(1) {
    fd_set rd_fds, wr_fds;
    int max_fd = 0, ready;
    struct timeval timeout = {0, SELECT_TIMEOUT_US};
    uint64_t now;

    zdtun_fds(engine->tun, &max_fd, &rd_fds, &wr_fds);
    FD_SET(tun_fd, &rd_fds);
    FD_SET(engine->wakeup_pipe[0], &rd_fds);
    max_fd = max(max_fd, max(tun_fd, engine->wakeup_pipe[0]));

    ready = select(max_fd + 1, &rd_fds, &wr_fds, NULL, &timeout);

    if(ready < 0) {
      if(errno == EINTR)
        continue;
      error("select failed: %d", errno);
      rv = -1;
      break;
    }

    if(FD_ISSET(engine->wakeup_pipe[0], &rd_fds))
      break; /* stop requested */

    if(ready > 0) {
      if(FD_ISSET(tun_fd, &rd_fds)) {
        ssize_t len = read(tun_fd, pkt_buf, PACKET_BUFSIZE);

        if(len > 0)
          handle_tun_packet(engine, pkt_buf, (int) len);
        else if(len == 0 || (errno != EINTR && errno != EAGAIN)) {
          error("read(tun) failed: %zd, errno %d", len, errno);
          rv = -1;
          break;
        }
      } else {
        /* Only when the TUN was not handled: a socket closed while handling a
         * TUN packet may have its fd reused by a new connection in this round. */
        zdtun_handle_fd(engine->tun, &rd_fds, &wr_fds);
      }
    }

    now = now_us();
    if(now - last_purge_us >= PURGE_INTERVAL_US) {
      zdtun_purge_expired(engine->tun);
      last_purge_us = now;
    }
    if(now - engine->last_flush_us >= FLUSH_INTERVAL_US)
      flush_batch(engine);
  }

cleanup:
  if(engine->tun) {
    /* Closes all connections (sending TCP RSTs to the apps) and frees conn data. */
    zdtun_finalize(engine->tun);
    engine->tun = NULL;
  }
  if(engine->batch)
    flush_batch(engine);

  free(engine->batch);
  engine->batch = NULL;
  free(pkt_buf);
  return rv;
}
