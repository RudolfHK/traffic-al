/*
 * Traffic AL - on-device traffic audit for Android
 * Copyright (C) 2026 RudolfHK
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Runs the capture engine on a Linux TUN device so it can be tested without a
 * phone. Routing is set up by run.sh. Packet batches are appended to a file.
 *
 * Usage: host_capture <tun-name> <mtu> <virtual-dns> <upstream-dns> <batch-file>
 */

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "capture_engine.h"

#define TEST_UID 4242
#define PROTECT_MARK 0x77

static capture_engine_t *engine;
static FILE *batch_file;
static unsigned long num_batches, num_bytes, num_protected;

static int resolve_uid(void *userdata, const zdtun_5tuple_t *tuple) {
  return TEST_UID;
}

static void on_packets(void *userdata, const uint8_t *batch, size_t length) {
  fwrite(batch, 1, length, batch_file);
  num_batches++;
  num_bytes += length;
}

/* Marked sockets bypass the TUN (like VpnService.protect on Android). */
static void protect_socket(void *userdata, int sock) {
  uint32_t mark = PROTECT_MARK;

  if(setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    perror("SO_MARK");
  num_protected++;
}

static void on_signal(int sig) {
  capture_engine_stop(engine);
}

int main(int argc, char **argv) {
  struct ifreq ifr = {0};
  struct sigaction action = {0};
  capture_callbacks_t callbacks = {
    .resolve_uid = resolve_uid,
    .on_packets = on_packets,
    .protect_socket = protect_socket,
  };
  int tun_fd, rv;

  if(argc != 6) {
    fprintf(stderr, "Usage: %s <tun-name> <mtu> <virtual-dns> <upstream-dns> <batch-file>\n", argv[0]);
    return 2;
  }

  signal(SIGPIPE, SIG_IGN); /* like ART on Android */
  action.sa_handler = on_signal;
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGTERM, &action, NULL);

  tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
  if(tun_fd < 0 || ioctl(tun_fd, TUNSETIFF, &ifr) != 0) {
    perror("TUN setup");
    return 1;
  }

  engine = capture_engine_new();
  if(!engine || capture_engine_set_dns(engine, argv[3], argv[4]) != 0) {
    fprintf(stderr, "engine setup failed\n");
    return 1;
  }
  capture_engine_set_block_private_dns(engine, 1);
  batch_file = fopen(argv[5], "wb");

  printf("ready\n");
  fflush(stdout);

  rv = capture_engine_run(engine, tun_fd, atoi(argv[2]), &callbacks, NULL);

  fclose(batch_file);
  capture_engine_free(engine);
  printf("run=%d batches=%lu bytes=%lu protected_sockets=%lu\n", rv, num_batches, num_bytes, num_protected);
  return rv == 0 ? 0 : 1;
}
