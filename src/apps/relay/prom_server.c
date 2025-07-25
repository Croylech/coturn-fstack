/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2020 Miquel Ortega
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "prom_server.h"
#include "mainrelay.h"
#include "ns_turn_utils.h"
#include "wrappers.h"
#if !defined(WINDOWS)
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if !defined(TURN_NO_PROMETHEUS)

prom_counter_t *stun_binding_request;
prom_counter_t *stun_binding_response;
prom_counter_t *stun_binding_error;

prom_counter_t *turn_traffic_rcvp;
prom_counter_t *turn_traffic_rcvb;
prom_counter_t *turn_traffic_sentp;
prom_counter_t *turn_traffic_sentb;

prom_counter_t *turn_traffic_peer_rcvp;
prom_counter_t *turn_traffic_peer_rcvb;
prom_counter_t *turn_traffic_peer_sentp;
prom_counter_t *turn_traffic_peer_sentb;

prom_counter_t *turn_total_traffic_rcvp;
prom_counter_t *turn_total_traffic_rcvb;
prom_counter_t *turn_total_traffic_sentp;
prom_counter_t *turn_total_traffic_sentb;

prom_counter_t *turn_total_traffic_peer_rcvp;
prom_counter_t *turn_total_traffic_peer_rcvb;
prom_counter_t *turn_total_traffic_peer_sentp;
prom_counter_t *turn_total_traffic_peer_sentb;

prom_gauge_t *turn_total_allocations;

#if MHD_VERSION >= 0x00097002
#define MHD_RESULT enum MHD_Result
#else
#define MHD_RESULT int
#endif

MHD_RESULT promhttp_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                            const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
  MHD_RESULT ret;

  char *body = "not found";
  enum MHD_ResponseMemoryMode mode = MHD_RESPMEM_PERSISTENT;
  unsigned int status = MHD_HTTP_NOT_FOUND;

  if (strcmp(method, "GET") != 0) {
    status = MHD_HTTP_METHOD_NOT_ALLOWED;
    body = "method not allowed";
  } else if (strcmp(url, turn_params.prometheus_path) == 0) {
    body = prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
    mode = MHD_RESPMEM_MUST_FREE;
    status = MHD_HTTP_OK;
  } else if (strcmp(url, "/") == 0) {
    // Return 200 OK for root path as a health check
    body = "ok";
    mode = MHD_RESPMEM_PERSISTENT;
    status = MHD_HTTP_OK;
  }

  struct MHD_Response *response = MHD_create_response_from_buffer(strlen(body), body, mode);
  if (response == NULL) {
    if (mode == MHD_RESPMEM_MUST_FREE) {
      free(body);
    }
    ret = MHD_NO;
  } else {
    MHD_add_response_header(response, "Content-Type", "text/plain");
    ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
  }
  return ret;
}

void start_prometheus_server(void) {
  if (turn_params.prometheus == 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus collector disabled, not started\n");
    return;
  }
  prom_collector_registry_default_init();

  const char *label[] = {"realm", NULL};
  size_t nlabels = 1;

  if (turn_params.prometheus_username_labels) {
    label[1] = "user";
    nlabels++;
  }

  // Create STUN counters
  stun_binding_request = prom_collector_registry_must_register_metric(
      prom_counter_new("stun_binding_request", "Incoming STUN Binding requests", 0, NULL));
  stun_binding_response = prom_collector_registry_must_register_metric(
      prom_counter_new("stun_binding_response", "Outgoing STUN Binding responses", 0, NULL));
  stun_binding_error = prom_collector_registry_must_register_metric(
      prom_counter_new("stun_binding_error", "STUN Binding errors", 0, NULL));

  // Create TURN traffic counter metrics
  turn_traffic_rcvp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_rcvp", "Represents finished sessions received packets", nlabels, label));
  turn_traffic_rcvb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_rcvb", "Represents finished sessions received bytes", nlabels, label));
  turn_traffic_sentp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_sentp", "Represents finished sessions sent packets", nlabels, label));
  turn_traffic_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_sentb", "Represents finished sessions sent bytes", nlabels, label));

  // Create finished sessions traffic for peers counter metrics
  turn_traffic_peer_rcvp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_rcvp", "Represents finished sessions peer received packets", nlabels, label));
  turn_traffic_peer_rcvb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_rcvb", "Represents finished sessions peer received bytes", nlabels, label));
  turn_traffic_peer_sentp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_sentp", "Represents finished sessions peer sent packets", nlabels, label));
  turn_traffic_peer_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_sentb", "Represents finished sessions peer sent bytes", nlabels, label));

  // Create total finished traffic counter metrics
  turn_total_traffic_rcvp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_rcvp", "Represents total finished sessions received packets", 0, NULL));
  turn_total_traffic_rcvb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_rcvb", "Represents total finished sessions received bytes", 0, NULL));
  turn_total_traffic_sentp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_sentp", "Represents total finished sessions sent packets", 0, NULL));
  turn_total_traffic_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_sentb", "Represents total finished sessions sent bytes", 0, NULL));

  // Create total finished sessions traffic for peers counter metrics
  turn_total_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new(
      "turn_total_traffic_peer_rcvp", "Represents total finished sessions peer received packets", 0, NULL));
  turn_total_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new(
      "turn_total_traffic_peer_rcvb", "Represents total finished sessions peer received bytes", 0, NULL));
  turn_total_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new(
      "turn_total_traffic_peer_sentp", "Represents total finished sessions peer sent packets", 0, NULL));
  turn_total_traffic_peer_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_peer_sentb", "Represents total finished sessions peer sent bytes", 0, NULL));

  // Create total allocations number gauge metric
  const char *typeLabel[] = {"type"};
  turn_total_allocations = prom_collector_registry_must_register_metric(
      prom_gauge_new("turn_total_allocations", "Represents current allocations number", 1, typeLabel));

  // some flags appeared first in microhttpd v0.9.53
  unsigned int flags = 0;
#if MHD_VERSION >= 0x00095300
  flags |= MHD_USE_ERROR_LOG;
#endif
  if (MHD_is_feature_supported(MHD_FEATURE_EPOLL)) {
#if MHD_VERSION >= 0x00095300
    flags |= MHD_USE_EPOLL_INTERNAL_THREAD;
#else
    flags |= MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY; // old versions of microhttpd
#endif
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus exporter server will start using EPOLL\n");
  } else {
    flags |= MHD_USE_SELECT_INTERNALLY;
    // Select() will not work if all 1024 first file-descriptors are used.
    // In this case the prometheus server will be unreachable
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "prometheus exporter server will start using SELECT. "
                                          "The exporter might be unreachable on highly used servers\n");
  }

  ioa_addr server_addr;
  addr_set_any(&server_addr);
  if (turn_params.prometheus_address[0]) {
    if (make_ioa_addr((const uint8_t *)turn_params.prometheus_address, turn_params.prometheus_port, &server_addr) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "could not parse prometheus collector's server address\n");
      return;
    }

    if (is_ipv6_enabled() && server_addr.ss.sa_family == AF_INET6) {
      flags |= MHD_USE_IPv6;
    }
  } else {
    if (MHD_is_feature_supported(MHD_FEATURE_IPv6) && is_ipv6_enabled()) {
      flags |= MHD_USE_DUAL_STACK;
      server_addr.ss.sa_family = AF_INET6;
      server_addr.s6.sin6_port = htons((uint16_t)turn_params.prometheus_port);
    } else {
      server_addr.ss.sa_family = AF_INET;
      server_addr.s4.sin_port = htons((uint16_t)turn_params.prometheus_port);
    }
  }

  uint8_t addr[MAX_IOA_ADDR_STRING];
  addr_to_string(&server_addr, addr);
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus exporter server will listen on %s\n", addr);

  struct MHD_Daemon *daemon =
      MHD_start_daemon(flags, 0, NULL, NULL, &promhttp_handler, NULL, MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
                       MHD_OPTION_SOCK_ADDR, &server_addr, MHD_OPTION_END);
  if (daemon == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "could not start prometheus collector\n");
    return;
  }

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus collector started successfully\n");
}

void prom_set_finished_traffic(const char *realm, const char *user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer) {
  if (turn_params.prometheus == 1) {

    const char *label[] = {realm, NULL};
    if (turn_params.prometheus_username_labels) {
      label[1] = user;
    }

    if (peer) {
      prom_counter_add(turn_traffic_peer_rcvp, rsvp, label);
      prom_counter_add(turn_traffic_peer_rcvb, rsvb, label);
      prom_counter_add(turn_traffic_peer_sentp, sentp, label);
      prom_counter_add(turn_traffic_peer_sentb, sentb, label);

      prom_counter_add(turn_total_traffic_peer_rcvp, rsvp, NULL);
      prom_counter_add(turn_total_traffic_peer_rcvb, rsvb, NULL);
      prom_counter_add(turn_total_traffic_peer_sentp, sentp, NULL);
      prom_counter_add(turn_total_traffic_peer_sentb, sentb, NULL);
    } else {
      prom_counter_add(turn_traffic_rcvp, rsvp, label);
      prom_counter_add(turn_traffic_rcvb, rsvb, label);
      prom_counter_add(turn_traffic_sentp, sentp, label);
      prom_counter_add(turn_traffic_sentb, sentb, label);

      prom_counter_add(turn_total_traffic_rcvp, rsvp, NULL);
      prom_counter_add(turn_total_traffic_rcvb, rsvb, NULL);
      prom_counter_add(turn_total_traffic_sentp, sentp, NULL);
      prom_counter_add(turn_total_traffic_sentb, sentb, NULL);
    }
  }
}

void prom_inc_allocation(SOCKET_TYPE type) {
  if (turn_params.prometheus == 1) {
    const char *label[] = {socket_type_name(type)};
    prom_gauge_inc(turn_total_allocations, label);
  }
}

void prom_dec_allocation(SOCKET_TYPE type) {
  if (turn_params.prometheus == 1) {
    const char *label[] = {socket_type_name(type)};
    prom_gauge_dec(turn_total_allocations, label);
  }
}

void prom_inc_stun_binding_request(void) {
  if (turn_params.prometheus == 1) {
    prom_counter_add(stun_binding_request, 1, NULL);
  }
}

void prom_inc_stun_binding_response(void) {
  if (turn_params.prometheus == 1) {
    prom_counter_add(stun_binding_response, 1, NULL);
  }
}

void prom_inc_stun_binding_error(void) {
  if (turn_params.prometheus == 1) {
    prom_counter_add(stun_binding_error, 1, NULL);
  }
}

int is_ipv6_enabled(void) {
  int ret = 0;

#ifdef AF_INET6
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "About to call myscoket in prom_server.c - 309");
  int fd = my_socket(AF_INET6, SOCK_STREAM, 0);
  if (fd == -1) {
    ret = errno != EAFNOSUPPORT;
  } else {
    ret = 1;
    my_close(fd);
  }
#endif /* AF_INET6 */

  return ret;
}

#else

void start_prometheus_server(void) {
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "turnserver compiled without prometheus support\n");
  return;
}

void prom_set_finished_traffic(const char *realm, const char *user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer) {
  UNUSED_ARG(realm);
  UNUSED_ARG(user);
  UNUSED_ARG(rsvp);
  UNUSED_ARG(rsvb);
  UNUSED_ARG(sentp);
  UNUSED_ARG(sentb);
  UNUSED_ARG(peer);
}

void prom_inc_allocation(SOCKET_TYPE type) { UNUSED_ARG(type); }

void prom_dec_allocation(SOCKET_TYPE type) { UNUSED_ARG(type); }

#endif /* TURN_NO_PROMETHEUS */
