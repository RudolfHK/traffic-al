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

#include "ndpi_api.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#define PACKET_BUFSIZE 65535
#define BATCH_BUFSIZE (512 * 1024)
#define FLUSH_INTERVAL_US 250000
#define PURGE_INTERVAL_US 3000000
#define WAIT_TIMEOUT_MS 250
#define RETRANSMIT_CHECK_INTERVAL_US 50000
#define MAX_EVENTS 64

#define TCP_FLAGS_OFFSET 13
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

#define DNS_PORT 53
#define PRIVATE_DNS_PORT 853

/* Like PCAPdroid: enough for TLS/QUIC/HTTP/DNS metadata, bounded per-connection cost. */
#define MAX_DPI_PACKETS 12

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
  struct ndpi_detection_module_struct *ndpi; /* NULL if nDPI failed to initialize */
  int tun_fd;
  const capture_callbacks_t *callbacks;
  void *userdata;
  uint8_t *batch;
  size_t batch_len;
  uint64_t last_flush_us;

  /* The sockets of zdtun that the epoll set watches, for reading and for writing. */
  int epoll_fd;
  fd_set watched_rd, watched_wr;

  /* Set by on_connection_open() when it rejects a connection. */
  int last_blocked;
  int last_blocked_uid;
};

typedef struct conn_data {
  int uid;
  struct ndpi_flow_struct *ndpi_flow; /* NULL once the detection is finished */
  uint16_t dpi_packets;
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

static void put_string(uint8_t *buf, size_t *pos, const char *str) {
  size_t len = str ? strlen(str) : 0;

  if(len > 255)
    len = 255;
  buf[(*pos)++] = (uint8_t) len;
  memcpy(buf + *pos, str, len);
  *pos += len;
}

/* Reports the nDPI result of a connection and releases its nDPI state. */
static void finish_dpi(capture_engine_t *engine, const zdtun_conn_t *conn, conn_data_t *data, int giveup,
                       ndpi_protocol proto) {
  const zdtun_5tuple_t *tuple = zdtun_conn_get_5tuple(conn);
  uint8_t buf[sizeof(capture_flow_info_t) + 4 * 256];
  capture_flow_info_t info = {0};
  char proto_name[64];
  size_t pos = sizeof(info);

  if(giveup)
    proto = ndpi_detection_giveup(engine->ndpi, data->ndpi_flow);

  info.ipver = tuple->ipver;
  info.ipproto = tuple->ipproto;
  info.src_port = ntohs(tuple->src_port);
  info.dst_port = ntohs(tuple->dst_port);
  memcpy(info.src_ip, &tuple->src_ip, (tuple->ipver == 4) ? 4 : 16);
  memcpy(info.dst_ip, &tuple->dst_ip, (tuple->ipver == 4) ? 4 : 16);
  info.master_protocol = proto.proto.master_protocol;
  info.app_protocol = proto.proto.app_protocol;
  info.category = (uint16_t) proto.category;
  memcpy(buf, &info, sizeof(info));

  put_string(buf, &pos, ndpi_protocol2name(engine->ndpi, proto.proto, proto_name, sizeof(proto_name)));
  put_string(buf, &pos, ndpi_category_get_name(engine->ndpi, proto.category));
  put_string(buf, &pos, (const char*) data->ndpi_flow->host_server_name);
  put_string(buf, &pos, ndpi_get_proto_breed_name(proto.breed));

  record_packet(engine, (const char*) buf, (int) pos, data->uid, CAPTURE_DIR_INFO, 0);

  ndpi_free_flow(data->ndpi_flow);
  data->ndpi_flow = NULL;
}

/* Feeds a packet of the connection to nDPI until it is classified. */
static void process_dpi(capture_engine_t *engine, const zdtun_conn_t *conn, const char *pkt, int len) {
  conn_data_t *data = (conn_data_t*) zdtun_conn_get_userdata(conn);
  ndpi_protocol proto;

  if(!data || !data->ndpi_flow)
    return;

  proto = ndpi_detection_process_packet(engine->ndpi, data->ndpi_flow, (const unsigned char*) pkt,
                                        (unsigned short) len, now_us() / 1000, NULL);
  data->dpi_packets++;

  if((proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN || proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (proto.state >= NDPI_STATE_MONITORING))
    finish_dpi(engine, conn, data, 0, proto);
  else if(data->dpi_packets >= MAX_DPI_PACKETS)
    finish_dpi(engine, conn, data, 1, proto);
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
  process_dpi(engine, conn, pkt->buf, pkt->len);
  return 0;
}

/* ******************************************************* */

/*
 * zdtun tracks the sockets it wants to read and write in fd_sets, made for select().
 * select() checks every socket on each call, which made every packet cost time
 * proportional to the number of open connections; epoll only reports the ready ones.
 * The epoll set follows zdtun's fd_sets: only the words that changed are compared.
 */

static void watch(capture_engine_t *engine, int fd, int readable, int writable) {
  /* Bionic's FD_ISSET returns the bit, not 1. */
  int was_readable = FD_ISSET(fd, &engine->watched_rd) != 0, was_writable = FD_ISSET(fd, &engine->watched_wr) != 0;
  struct epoll_event event = {0};
  int op;

  if((readable == was_readable) && (writable == was_writable))
    return;

  event.events = (readable ? EPOLLIN : 0) | (writable ? EPOLLOUT : 0);
  event.data.fd = fd;
  if(!was_readable && !was_writable)
    op = EPOLL_CTL_ADD;
  else if(!readable && !writable)
    op = EPOLL_CTL_DEL;
  else
    op = EPOLL_CTL_MOD;

  if(epoll_ctl(engine->epoll_fd, op, fd, &event) != 0)
    error("epoll_ctl(%d, fd %d) failed: %d", op, fd, errno);

  if(readable) FD_SET(fd, &engine->watched_rd); else FD_CLR(fd, &engine->watched_rd);
  if(writable) FD_SET(fd, &engine->watched_wr); else FD_CLR(fd, &engine->watched_wr);
}

/* For the TUN device and the wake-up pipe, which are always watched for reading. */
static int add_to_epoll(capture_engine_t *engine, int fd) {
  struct epoll_event event = {0};

  event.events = EPOLLIN;
  event.data.fd = fd;
  return epoll_ctl(engine->epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

static void sync_watched(capture_engine_t *engine) {
  fd_set rd, wr;
  int max_fd = 0;
  const unsigned long *rd_words = (const unsigned long*) &rd, *wr_words = (const unsigned long*) &wr;
  const unsigned long *watched_rd = (const unsigned long*) &engine->watched_rd;
  const unsigned long *watched_wr = (const unsigned long*) &engine->watched_wr;
  const int bits = 8 * sizeof(unsigned long);

  zdtun_fds(engine->tun, &max_fd, &rd, &wr);

  for(size_t w = 0; w < sizeof(fd_set) / sizeof(unsigned long); w++) {
    if((rd_words[w] == watched_rd[w]) && (wr_words[w] == watched_wr[w]))
      continue;

    for(int fd = (int) w * bits; fd < (int) (w + 1) * bits; fd++)
      watch(engine, fd, FD_ISSET(fd, &rd) != 0, FD_ISSET(fd, &wr) != 0);
  }
}

/* ******************************************************* */

static void on_socket_open(zdtun_t *tun, socket_t sock) {
  capture_engine_t *engine = (capture_engine_t*) zdtun_userdata(tun);

  if(engine->callbacks->protect_socket)
    engine->callbacks->protect_socket(engine->userdata, sock);
}

/* zdtun callback before it closes a socket: the fd number may be reused right away. */
static void on_socket_close(zdtun_t *tun, socket_t sock) {
  watch((capture_engine_t*) zdtun_userdata(tun), sock, 0, 0);
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
  if(engine->ndpi) {
    data->ndpi_flow = (struct ndpi_flow_struct*) ndpi_calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
    if(!data->ndpi_flow)
      error("cannot allocate the nDPI flow");
  }
  zdtun_conn_set_userdata(conn, data);
  return 0;
}

/* ******************************************************* */

static void on_connection_close(zdtun_t *tun, const zdtun_conn_t *conn) {
  capture_engine_t *engine = (capture_engine_t*) zdtun_userdata(tun);
  conn_data_t *data = (conn_data_t*) zdtun_conn_get_userdata(conn);

  /* Report what nDPI found so far for connections it did not classify yet. */
  if(data && data->ndpi_flow) {
    ndpi_protocol unknown = {0};
    finish_dpi(engine, conn, data, 1, unknown);
  }

  free(data);
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
  process_dpi(engine, conn, buf, len);

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
  engine->epoll_fd = -1;
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
    .on_socket_close = on_socket_close,
    .on_connection_open = on_connection_open,
    .on_connection_close = on_connection_close,
  };
  char *pkt_buf = NULL;
  uint64_t last_purge_us, last_retransmit_us;
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
  engine->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  FD_ZERO(&engine->watched_rd);
  FD_ZERO(&engine->watched_wr);
  engine->tun = zdtun_init(&zdtun_callbacks, engine);

  if(!pkt_buf || !engine->batch || (engine->epoll_fd < 0) || !engine->tun
     || (add_to_epoll(engine, tun_fd) != 0) || (add_to_epoll(engine, engine->wakeup_pipe[0]) != 0)) {
    error("capture engine initialization failed");
    rv = -1;
    goto cleanup;
  }

  zdtun_set_mtu(engine->tun, mtu);

  /* Protocol detection is optional: without it connections are still forwarded. */
  engine->ndpi = ndpi_init_detection_module(NULL);
  if(engine->ndpi && ndpi_finalize_initialization(engine->ndpi) != 0) {
    error("nDPI initialization failed");
    ndpi_exit_detection_module(engine->ndpi);
    engine->ndpi = NULL;
  }
  engine->last_flush_us = last_purge_us = last_retransmit_us = now_us();

  while(1) {
    struct epoll_event events[MAX_EVENTS];
    fd_set rd_fds, wr_fds;
    int ready, stop = 0, tun_ready = 0, sockets_ready = 0;
    uint64_t now;

    sync_watched(engine);
    ready = epoll_wait(engine->epoll_fd, events, MAX_EVENTS, WAIT_TIMEOUT_MS);

    if(ready < 0) {
      if(errno == EINTR)
        continue;
      error("epoll_wait failed: %d", errno);
      rv = -1;
      break;
    }

    FD_ZERO(&rd_fds);
    FD_ZERO(&wr_fds);
    for(int i = 0; i < ready; i++) {
      int fd = events[i].data.fd;
      uint32_t ev = events[i].events;

      if(fd == engine->wakeup_pipe[0])
        stop = 1;
      else if(fd == tun_fd)
        tun_ready = 1;
      else {
        /* Like select(): an error or hang-up makes a socket readable and writable. */
        if((ev & (EPOLLIN | EPOLLERR | EPOLLHUP)) && FD_ISSET(fd, &engine->watched_rd)) {
          FD_SET(fd, &rd_fds);
          sockets_ready = 1;
        }
        if((ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)) && FD_ISSET(fd, &engine->watched_wr)) {
          FD_SET(fd, &wr_fds);
          sockets_ready = 1;
        }
      }
    }

    if(stop)
      break; /* stop requested */

    if(tun_ready) {
      ssize_t len = read(tun_fd, pkt_buf, PACKET_BUFSIZE);

      if(len > 0)
        handle_tun_packet(engine, pkt_buf, (int) len);
      else if(len == 0 || (errno != EINTR && errno != EAGAIN)) {
        error("read(tun) failed: %zd, errno %d", len, errno);
        rv = -1;
        break;
      }
    } else if(sockets_ready) {
      /* Only when the TUN was not handled: a socket closed while handling a
       * TUN packet may have its fd reused by a new connection in this round. */
      zdtun_handle_fd(engine->tun, &rd_fds, &wr_fds);
    }

    now = now_us();

    /* Resend data an app has not acknowledged in time (it may have been dropped). This
     * visits every connection, so not for every packet: timeouts are 200 ms or more. */
    if(now - last_retransmit_us >= RETRANSMIT_CHECK_INTERVAL_US) {
      zdtun_tcp_retransmit_timeouts(engine->tun);
      last_retransmit_us = now;
    }

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
  if(engine->epoll_fd >= 0) {
    close(engine->epoll_fd);
    engine->epoll_fd = -1;
  }
  if(engine->ndpi) {
    ndpi_exit_detection_module(engine->ndpi);
    engine->ndpi = NULL;
  }
  if(engine->batch)
    flush_batch(engine);

  free(engine->batch);
  engine->batch = NULL;
  free(pkt_buf);
  return rv;
}
