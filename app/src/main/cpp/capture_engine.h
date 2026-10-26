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

/*
 * Platform-independent capture engine: reads IP packets from a TUN fd, forwards
 * them through zdtun (a user-space TCP/UDP/ICMP proxy) and reports every packet
 * that crosses the TUN interface in batches. No JNI here, so it can be tested on
 * a Linux host with a real TUN device (see test/).
 */

#ifndef TRAFFICAL_CAPTURE_ENGINE_H
#define TRAFFICAL_CAPTURE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "zdtun.h"

#define CAPTURE_UID_UNKNOWN (-1)

/* Packet came from the TUN interface (app -> network). */
#define CAPTURE_DIR_OUT 1
/* Packet was written to the TUN interface (network -> app). */
#define CAPTURE_DIR_IN 0

/* Not a packet: a capture_flow_info_t with the protocol detection result of a connection. */
#define CAPTURE_DIR_INFO 2

/* The connection was blocked by the engine and never forwarded. */
#define CAPTURE_FLAG_BLOCKED 0x01

/*
 * One record in a packet batch, in host byte order, immediately followed by
 * `length` bytes of the raw IP packet. Records are not padded.
 */
typedef struct __attribute__((packed)) capture_record {
  uint64_t timestamp_us; /* microseconds since the Unix epoch */
  int32_t uid;           /* owning app uid or CAPTURE_UID_UNKNOWN */
  uint16_t length;
  uint8_t direction;     /* CAPTURE_DIR_* */
  uint8_t flags;         /* CAPTURE_FLAG_* */
} capture_record_t;

/*
 * Payload of a CAPTURE_DIR_INFO record, sent once per connection when nDPI has
 * classified it (or given up). Multi-byte fields in host byte order. It is followed by
 * four strings, each a u8 length and UTF-8 bytes: the protocol name (e.g.
 * "TLS.YouTube"), the category name, the server name (TLS/QUIC SNI, HTTP Host or DNS
 * query, may be empty) and nDPI's rating of the protocol ("Safe", "Tracker_Ads",
 * "Dangerous", ...).
 */
typedef struct __attribute__((packed)) capture_flow_info {
  uint8_t ipver;
  uint8_t ipproto;
  uint16_t src_port;        /* the app's side */
  uint16_t dst_port;
  uint8_t src_ip[16];       /* IPv4 addresses use the first 4 bytes */
  uint8_t dst_ip[16];
  uint16_t master_protocol; /* nDPI protocol ids, e.g. TLS */
  uint16_t app_protocol;    /* e.g. YouTube */
  uint16_t category;        /* nDPI category id */
} capture_flow_info_t;

typedef struct capture_callbacks {
  /* Returns the uid that owns the connection, or CAPTURE_UID_UNKNOWN. */
  int (*resolve_uid)(void *userdata, const zdtun_5tuple_t *tuple);

  /* Receives a batch of capture_record_t records; only valid during the call. */
  void (*on_packets)(void *userdata, const uint8_t *batch, size_t length);

  /* Optional: called for every socket zdtun opens (e.g. VpnService.protect). */
  void (*protect_socket)(void *userdata, int sock);
} capture_callbacks_t;

typedef struct capture_engine capture_engine_t;

capture_engine_t *capture_engine_new(void);
void capture_engine_free(capture_engine_t *engine);

/*
 * Sets the virtual DNS server announced to the apps and the real resolver its
 * queries (UDP and TCP port 53) are redirected to. Thread-safe; applies to new
 * connections. Returns 0 on success, -1 if an address cannot be parsed.
 */
int capture_engine_set_dns(capture_engine_t *engine, const char *virtual_dns, const char *upstream_dns);

/*
 * When enabled, DNS-over-TLS / DNS-over-QUIC (port 853) is blocked so that
 * Android's "automatic" Private DNS falls back to plain, observable DNS.
 * Thread-safe.
 */
void capture_engine_set_block_private_dns(capture_engine_t *engine, int block);

/*
 * Runs the forwarding loop on the calling thread until capture_engine_stop() is
 * called or a fatal error occurs. Returns 0 after a requested stop, -1 on error.
 * Does not close tun_fd. An engine can only be run once.
 */
int capture_engine_run(capture_engine_t *engine, int tun_fd, int mtu,
                       const capture_callbacks_t *callbacks, void *userdata);

/* Makes capture_engine_run() return. Thread-safe, may be called before run. */
void capture_engine_stop(capture_engine_t *engine);

#endif
