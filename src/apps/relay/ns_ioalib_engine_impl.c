/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
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

#include "ns_turn_khash.h"
#include "ns_turn_server.h"
#include "ns_turn_session.h"
#include "ns_turn_utils.h"

#include "apputils.h"
#include "stun_buffer.h"

#include "ns_ioalib_impl.h"

#include "prom_server.h"

//includes jose
#include <sys/timerfd.h>
#include <fcntl.h>
#include "wrappers.h"

#if TLS_SUPPORTED
#include <event2/bufferevent_ssl.h>
#endif

#include <event2/listener.h>

#include "ns_turn_openssl.h"

#if !defined(TURN_NO_HIREDIS)
#include "hiredis_libevent2.h"
#endif

#if !defined(TURN_NO_SCTP) && defined(TURN_SCTP_INCLUDE)
#include TURN_SCTP_INCLUDE
#endif

/* Compilation test:
#if defined(IP_RECVTTL)
#undef IP_RECVTTL
#endif
#if defined(IPV6_RECVHOPLIMIT)
#undef IPV6_RECVHOPLIMIT
#endif
#if defined(IP_RECVTOS)
#undef IP_RECVTOS
#endif
#if defined(IPV6_RECVTCLASS)
#undef IPV6_RECVTCLASS
#endif
*/

#define MAX_ERRORS_IN_UDP_BATCH (1024)

struct turn_sock_extended_err {
  uint32_t ee_errno; /* error number */
  uint8_t ee_origin; /* where the error originated */
  uint8_t ee_type;   /* type */
  uint8_t ee_code;   /* code */
  uint8_t ee_pad;    /* padding */
  uint32_t ee_info;  /* additional information */
  uint32_t ee_data;  /* other data */
  /* More data may follow */
};

#define TRIAL_EFFORTS_TO_SEND (2)

#define SSL_MAX_RENEG_NUMBER (3)

const int predef_timer_intervals[PREDEF_TIMERS_NUM] = {30,  60,  90,  120, 240, 300,  360,
                                                       540, 600, 700, 800, 900, 1800, 3600};

/************** Forward function declarations ******/

static int socket_readerr(evutil_socket_t fd, ioa_addr *orig_addr);

static void socket_input_handler(evutil_socket_t fd, short what, void *arg);
static void socket_output_handler_bev(struct bufferevent *bev, void *arg);
static void socket_input_handler_bev(struct bufferevent *bev, void *arg);
static void eventcb_bev(struct bufferevent *bev, short events, void *arg);
void my_combined_handler(int fd, short what, void *arg);
void socket_output_handler_fstack(int fd, void *arg);
void socket_input_handler_fstack(int fd, void *arg);

static int send_ssl_backlog_buffers(ioa_socket_handle s);

static int set_accept_cb(ioa_socket_handle s, accept_cb acb, void *arg);

static void close_socket_net_data(ioa_socket_handle s);

/************** Utils **************************/

static const int tcp_congestion_control = 1;

static int bufferevent_enabled(struct bufferevent *bufev, short flags) {
  return (bufferevent_get_enabled(bufev) & flags);
}

static int is_socket_writeable(ioa_socket_handle s, size_t sz, const char *msg, int option) {
  UNUSED_ARG(sz);
  UNUSED_ARG(msg);
  UNUSED_ARG(option);

  if (!s) {
    return 0;
  }

  if (!(s->done) && !(s->broken) && !(s->tobeclosed)) {

    switch (s->st) {

    case SCTP_SOCKET:
    case TLS_SCTP_SOCKET:

    case TCP_SOCKET:
    case TLS_SOCKET:

      if (s->bev) {

        struct evbuffer *evb = bufferevent_get_output(s->bev);

        if (evb) {
          size_t bufsz = evbuffer_get_length(evb);
          size_t newsz = bufsz + sz;

          switch (s->sat) {
          case TCP_CLIENT_DATA_SOCKET:
          case TCP_RELAY_DATA_SOCKET:

            switch (option) {
            case 0:
            case 1:
              if (newsz >= BUFFEREVENT_MAX_TCP_TO_TCP_WRITE) {
                return 0;
              }
              break;
            case 3:
            case 4:
              if (newsz >= BUFFEREVENT_MAX_TCP_TO_TCP_WRITE) {
                return 0;
              }
              break;
            default:
              return 1;
            };
            break;
          default:
            if (option == 2) {
              if (newsz >= BUFFEREVENT_MAX_UDP_TO_TCP_WRITE) {
                return 0;
              }
            }
          };
        }
      }
      break;
    default:;
    };
  }

  return 1;
}

static void log_socket_event(ioa_socket_handle s, const char *msg, int error) {
  if (s && (error || (s->e && s->e->verbose))) {
    if (!msg) {
      msg = "General socket event";
    }
    turnsession_id id = 0;
    {
      ts_ur_super_session *ss = s->session;
      if (ss) {
        id = ss->id;
      } else {
        return;
      }
    }

    TURN_LOG_LEVEL ll = TURN_LOG_LEVEL_INFO;
    if (error) {
      ll = TURN_LOG_LEVEL_ERROR;
    }

    UNUSED_ARG(ll);

    {
      char sraddr[129] = "\0";
      char sladdr[129] = "\0";
      addr_to_string(&(s->remote_addr), (uint8_t *)sraddr);
      addr_to_string(&(s->local_addr), (uint8_t *)sladdr);

      if (EVUTIL_SOCKET_ERROR()) {
        TURN_LOG_FUNC(ll, "session %018llu: %s: %s (local %s, remote %s)\n", (unsigned long long)id, msg,
                      evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()), sladdr, sraddr);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: %s (local %s, remote %s)\n", (unsigned long long)id, msg,
                      sladdr, sraddr);
      }
    }
  }
}

int set_df_on_ioa_socket(ioa_socket_handle s, int value) {
  if (!s) {
    return 0;
  }

  if (s->parent_s) {
    return 0;
  }

  if (s->do_not_use_df) {
    value = 0;
  }

  if (s->current_df_relay_flag != value) {
    s->current_df_relay_flag = value;
    return set_socket_df(s->fd, s->family, value);
  }

  return 0;
}

void set_do_not_use_df(ioa_socket_handle s) {
  if (s->parent_s) {
    return;
  }

  s->do_not_use_df = 1;
  s->current_df_relay_flag = 1;
  set_socket_df(s->fd, s->family, 0);
}

/************** Buffer List ********************/

static int buffer_list_empty(stun_buffer_list *bufs) {
  if (bufs && bufs->head && bufs->tsz) {
    return 0;
  }
  return 1;
}

static stun_buffer_list_elem *get_elem_from_buffer_list(stun_buffer_list *bufs) {
  stun_buffer_list_elem *ret = NULL;

  if (bufs && bufs->head && bufs->tsz) {

    ret = bufs->head;
    bufs->head = ret->next;
    --bufs->tsz;
    if (bufs->tsz == 0) {
      bufs->tail = NULL;
    }

    ret->next = NULL;
    ret->buf.len = 0;
    ret->buf.offset = 0;
    ret->buf.coffset = 0;
  }

  return ret;
}

static void pop_elem_from_buffer_list(stun_buffer_list *bufs) {
  if (bufs && bufs->head && bufs->tsz) {

    stun_buffer_list_elem *ret = bufs->head;
    bufs->head = ret->next;
    --bufs->tsz;
    if (bufs->tsz == 0) {
      bufs->tail = NULL;
    }
    free(ret);
  }
}

static stun_buffer_list_elem *new_blist_elem(ioa_engine_handle e) {
  stun_buffer_list_elem *ret = get_elem_from_buffer_list(&(e->bufs));

  if (!ret) {
    ret = (stun_buffer_list_elem *)malloc(sizeof(stun_buffer_list_elem));
  }

  if (ret) {
    ret->buf.len = 0;
    ret->buf.offset = 0;
    ret->buf.coffset = 0;
    ret->next = NULL;
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot allocate memory for STUN buffer!\n", __FUNCTION__);
  }

  return ret;
}

static inline void add_elem_to_buffer_list(stun_buffer_list *bufs, stun_buffer_list_elem *buf_elem) {
  // We want a queue, so add to tail
  if (bufs->tail) {
    bufs->tail->next = buf_elem;
  } else {
    bufs->head = buf_elem;
  }
  buf_elem->next = NULL;
  bufs->tail = buf_elem;
  bufs->tsz += 1;
}

static void add_buffer_to_buffer_list(stun_buffer_list *bufs, char *buf, size_t len) {
  if (bufs && buf && (bufs->tsz < MAX_SOCKET_BUFFER_BACKLOG)) {
    stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)malloc(sizeof(stun_buffer_list_elem));
    memcpy(buf_elem->buf.buf, buf, len);
    buf_elem->buf.len = len;
    buf_elem->buf.offset = 0;
    buf_elem->buf.coffset = 0;
    add_elem_to_buffer_list(bufs, buf_elem);
  }
}

static void free_blist_elem(ioa_engine_handle e, stun_buffer_list_elem *buf_elem) {
  if (buf_elem) {
    if (e && (e->bufs.tsz < MAX_BUFFER_QUEUE_SIZE_PER_ENGINE)) {
      add_elem_to_buffer_list(&(e->bufs), buf_elem);
    } else {
      free(buf_elem);
    }
  }
}

/************** ENGINE *************************/

static void timer_handler(ioa_engine_handle e, void *arg) {

  UNUSED_ARG(arg);

  _log_time_value = turn_time();
  _log_time_value_set = 1;

  e->jiffie = _log_time_value;
}

ioa_engine_handle create_ioa_engine(super_memory_t *sm
#ifndef USE_FSTACK
                                  , struct event_base *eb
#else     
                                  , struct MyEventBase *eb
#endif
                                  , turnipports *tp,
                                    const char *relay_ifname, size_t relays_number, char **relay_addrs,
                                    int default_relays, int verbose
#if !defined(TURN_NO_HIREDIS)
                                    ,
                                    redis_stats_db_t *redis_stats_db
#endif
){
  static int capabilities_checked = 0;

  if (!capabilities_checked) {
    capabilities_checked = 1;
#if !defined(CMSG_SPACE)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "On this platform, I am using alternative behavior of TTL/TOS according to RFC 5766.\n");
#endif
#if !defined(IP_RECVTTL) || !defined(IP_TTL)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "IPv4: On this platform, I am using alternative behavior of TTL according to RFC 5766.\n");
#endif
#if !defined(IPV6_RECVHOPLIMIT) || !defined(IPV6_HOPLIMIT)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "IPv6: On this platform, I am using alternative behavior of TTL (HOPLIMIT) according to RFC 6156.\n");
#endif
#if !defined(IP_RECVTOS) || !defined(IP_TOS)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "IPv4: On this platform, I am using alternative behavior of TOS according to RFC 5766.\n");
#endif
#if !defined(IPV6_RECVTCLASS) || !defined(IPV6_TCLASS)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "IPv6: On this platform, I am using alternative behavior of TRAFFIC CLASS according to RFC 6156.\n");
#endif
  }

  if (!relays_number || !relay_addrs || !tp) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot create TURN engine\n", __FUNCTION__);
    return NULL;
  } else {
    ioa_engine_handle e = (ioa_engine_handle)allocate_super_memory_region(sm, sizeof(ioa_engine));

    e->sm = sm;
    e->default_relays = default_relays;
    e->verbose = verbose;
    e->tp = tp;
    if (eb) {
      e->event_base = eb;
      e->deallocate_eb = 0;
    } else {
      #ifndef USE_FSTACK
      e->event_base = turn_event_base_new();
      #else
      e->event_base = my_event_base_new();
      #endif
      e->deallocate_eb = 1;
    }

#if !defined(TURN_NO_HIREDIS)
    e->rch = get_redis_async_connection(e->event_base, redis_stats_db, 0);
#endif

    {
      int t;
      #ifndef USE_FSTACK
        for (int t = 0; t < PREDEF_TIMERS_NUM; ++t) {
          struct timeval duration;
          duration.tv_sec = predef_timer_intervals[t];
          duration.tv_usec = 0;
          const struct timeval *ptv = event_base_init_common_timeout(e->event_base, &duration);
          if (!ptv) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "FATAL: cannot create timeval for %d secs (%d)\n",
                          predef_timer_intervals[t], t);
            exit(-1);
          } else {
            memcpy(&(e->predef_timers[t]), ptv, sizeof(struct timeval));
            e->predef_timer_intervals[t] = predef_timer_intervals[t];
          }
        }
      #endif
    }

    if (relay_ifname) {
      STRCPY(e->relay_ifname, relay_ifname);
    }
    {
      size_t i = 0;
      e->relay_addrs = (ioa_addr *)allocate_super_memory_region(sm, relays_number * sizeof(ioa_addr) + 8);
      for (i = 0; i < relays_number; i++) {
        if (make_ioa_addr((uint8_t *)relay_addrs[i], 0, &(e->relay_addrs[i])) < 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot add a relay address: %s\n", relay_addrs[i]);
        }
      }
      e->relays_number = relays_number;
    }
    e->relay_addr_counter = (unsigned short)turn_random();
    timer_handler(e, e);
    e->timer_ev = set_ioa_timer(e, 1, 0, timer_handler, e, 1, "timer_handler");
    return e;
  }
}

void ioa_engine_set_rtcp_map(ioa_engine_handle e, rtcp_map *rtcpmap) {
  if (e) {
    e->map_rtcp = rtcpmap;
  }
}

static const ioa_addr *ioa_engine_get_relay_addr(ioa_engine_handle e, ioa_socket_handle client_s, int address_family,
                                                 int *err_code) {
  if (e) {

    int family = AF_INET;
    if (address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
      family = AF_INET6;
    }

    if (e->default_relays) {

      // No relay addrs defined - just return the client address if appropriate:

      ioa_addr *client_addr = get_local_addr_from_ioa_socket(client_s);
      if (client_addr) {
        switch (address_family) {
        case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
          if (client_addr->ss.sa_family == AF_INET) {
            return client_addr;
          }
          break;
        case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
          if (client_addr->ss.sa_family == AF_INET6) {
            return client_addr;
          }
          break;
        default:
          return client_addr;
        };
      }
    }

    if (e->relays_number > 0) {

      size_t i = 0;

      // Default recommended behavior:

      for (i = 0; i < e->relays_number; i++) {

        if (e->relay_addr_counter >= e->relays_number) {
          e->relay_addr_counter = 0;
        }
        ioa_addr *relay_addr = &(e->relay_addrs[e->relay_addr_counter++]);

        if (addr_any_no_port(relay_addr)) {
          get_a_local_relay(family, relay_addr);
        }

        switch (address_family) {
        case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT:
        case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
          if (relay_addr->ss.sa_family == AF_INET) {
            return relay_addr;
          }
          break;
        case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
          if (relay_addr->ss.sa_family == AF_INET6) {
            return relay_addr;
          }
          break;
        default:;
        };
      }

      if (address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT) {

        // Fallback to "find whatever is available":

        if (e->relay_addr_counter >= e->relays_number) {
          e->relay_addr_counter = 0;
        }
        const ioa_addr *relay_addr = &(e->relay_addrs[e->relay_addr_counter++]);
        return relay_addr;
      }

      *err_code = 440;
    }
  }
  return NULL;
}

/******************** Timers ****************************/

static void timer_event_handler(evutil_socket_t fd, short what, void *arg) {
  timer_event *te = (timer_event *)arg;

  if (!te) {
    return;
  }

  UNUSED_ARG(fd);

  if (!(what & EV_TIMEOUT)) {
    return;
  }

  if (te->e && eve(te->e->verbose)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: timeout %p: %s\n", __FUNCTION__, te, te->txt);
  }

  ioa_timer_event_handler cb = te->cb;
  ioa_engine_handle e = te->e;
  void *ctx = te->ctx;

  cb(e, ctx);
}

static void dpdk_timer_adapter_cb(struct rte_timer *tim, void *arg) { //jose
  timer_event *te = (timer_event *)arg;
  if (te && te->cb) {
    te->cb(te->e, te->ctx);
  }
}

ioa_timer_handle set_ioa_timer(ioa_engine_handle e, int secs, int ms, ioa_timer_event_handler cb, void *ctx,
                               int persist, const char *txt) {
  ioa_timer_handle ret = NULL;

#if defined(USE_FSTACK)
  if (e && cb && secs > 0 && ms == 0) {
    // Usar DPDK timer (no hay soporte de microsegundos con rte_timer)
    timer_event *te = (timer_event *)malloc(sizeof(timer_event));
    if (!te) return NULL;

    te->ctx = ctx;
    te->e = e;
    te->cb = cb;
    te->txt = strdup(txt);

    rte_timer_init(&te->dpdk_timer);  

    uint64_t hz = rte_get_timer_hz();
    uint64_t ticks = secs * hz;

    int result = rte_timer_reset(
      &te->dpdk_timer,
      ticks,
      persist ? PERIODICAL : SINGLE,
      rte_lcore_id(),
      dpdk_timer_adapter_cb,  // <- Wrapper que adapta los parámetros
      te                      // <- Pasas el struct entero
    );

    if (result != 0) {
      free(te);
      return NULL;
    }

    ret = te;
  }

#else
  if (e && cb && secs > 0) {
    timer_event *te = (timer_event *)malloc(sizeof(timer_event));
    int flags = EV_TIMEOUT;
    if (persist) {
      flags |= EV_PERSIST;
    }

    struct event *ev = event_new(e->event_base, -1, flags, timer_event_handler, te);
    struct timeval tv;
    tv.tv_sec = secs;

    te->ctx = ctx;
    te->e = e;
    te->ev = ev;
    te->cb = cb;
    te->txt = strdup(txt);

    if (!ms) {
      tv.tv_usec = 0;
      int found = 0;
      for (int t = 0; t < PREDEF_TIMERS_NUM; ++t) {
        if (e->predef_timer_intervals[t] == secs) {
          evtimer_add(ev, &(e->predef_timers[t]));
          found = 1;
          break;
        }
      }
      if (!found) {
        evtimer_add(ev, &tv);
      }
    } else {
      tv.tv_usec = ms * 1000;
      evtimer_add(ev, &tv);
    }

    ret = te;
  }
#endif

  return ret;
}

void stop_ioa_timer(ioa_timer_handle th) {
  if (th) {
    timer_event *te = (timer_event *)th;
#ifdef USE_FSTACK
    rte_timer_stop(&te->dpdk_timer);
#else
    EVENT_DEL(te->ev);
#endif
  }
}

void delete_ioa_timer(ioa_timer_handle th) {
  if (th) {
    stop_ioa_timer(th);
    timer_event *te = (timer_event *)th;
    if (te->txt) {
      free(te->txt);
      te->txt = NULL;
    }
    free(th);
  }
}

/************** SOCKETS HELPERS ***********************/

int ioa_socket_check_bandwidth(ioa_socket_handle s, ioa_network_buffer_handle nbh, int read) {
  if (s && (s->e) && nbh && ((s->sat == CLIENT_SOCKET) || (s->sat == RELAY_SOCKET) || (s->sat == RELAY_RTCP_SOCKET)) &&
      (s->session)) {

    size_t sz = ioa_network_buffer_get_size(nbh);

    band_limit_t max_bps = s->session->bps;

    if (max_bps < 1) {
      return 1;
    }

    struct traffic_bytes *traffic = &(s->data_traffic);

    if (s->sat == CLIENT_SOCKET) {
      uint8_t *buf = ioa_network_buffer_data(nbh);
      if (stun_is_command_message_str(buf, sz)) {
        uint16_t method = stun_get_method_str(buf, sz);
        if ((method != STUN_METHOD_SEND) && (method != STUN_METHOD_DATA)) {
          traffic = &(s->control_traffic);
        }
      }
    }

    band_limit_t bsz = (band_limit_t)sz;

    if (s->jiffie != s->e->jiffie) {

      s->jiffie = s->e->jiffie;
      traffic->jiffie_bytes_read = 0;
      traffic->jiffie_bytes_write = 0;

      if (bsz > max_bps) {
        return 0;
      } else {
        if (read) {
          traffic->jiffie_bytes_read = bsz;
        } else {
          traffic->jiffie_bytes_write = bsz;
        }
        return 1;
      }
    } else {
      band_limit_t nsz;
      if (read) {
        nsz = traffic->jiffie_bytes_read + bsz;
      } else {
        nsz = traffic->jiffie_bytes_write + bsz;
      }
      if (nsz > max_bps) {
        return 0;
      } else {
        if (read) {
          traffic->jiffie_bytes_read = nsz;
        } else {
          traffic->jiffie_bytes_write = nsz;
        }
        return 1;
      }
    }
  }

  return 1;
}

int get_ioa_socket_from_reservation(ioa_engine_handle e, uint64_t in_reservation_token, ioa_socket_handle *s) {
  if (e && in_reservation_token && s) {
    *s = rtcp_map_get(e->map_rtcp, in_reservation_token);
    if (*s) {
      return 0;
    }
  }
  return -1;
}

/* Socket options helpers ==>> */

static int set_socket_ttl(ioa_socket_handle s, int ttl) {
  if (s->default_ttl < 0) { // Unsupported
    return -1;
  }

  if (ttl < 0) {
    ttl = s->default_ttl;
  }

  CORRECT_RAW_TTL(ttl);

  if (ttl > s->default_ttl) {
    ttl = s->default_ttl;
  }

  if (s->current_ttl != ttl) {
    int ret = set_raw_socket_ttl(s->fd, s->family, ttl);
    s->current_ttl = ttl;
    return ret;
  }

  return 0;
}

static int set_socket_tos(ioa_socket_handle s, int tos) {
  if (s->default_tos < 0) { // Unsupported
    return -1;
  }

  if (tos < 0) {
    tos = s->default_tos;
  }

  CORRECT_RAW_TOS(tos);

  if (s->current_tos != tos) {
    int ret = set_raw_socket_tos(s->fd, s->family, tos);
    s->current_tos = tos;
    return ret;
  }

  return 0;
}

int set_raw_socket_ttl_options(evutil_socket_t fd, int family) {
  if (family == AF_INET6) {
#if !defined(IPV6_RECVHOPLIMIT)
    UNUSED_ARG(fd);
#else
    int recv_ttl_on = 1;
    if (my_setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, (const void *)&recv_ttl_on, sizeof(recv_ttl_on)) < 0) {
      perror("cannot set recvhoplimit\n");
    }
#endif
  } else {
#if !defined(IP_RECVTTL)
    UNUSED_ARG(fd);
#else
    int recv_ttl_on = 1;
    if (my_setsockopt(fd, IPPROTO_IP, IP_RECVTTL, (const void *)&recv_ttl_on, sizeof(recv_ttl_on)) < 0) {
      perror("cannot set recvttl\n");
    }
#endif
  }

  return 0;
}

int set_raw_socket_tos_options(evutil_socket_t fd, int family) {
  if (family == AF_INET6) {
#if !defined(IPV6_RECVTCLASS)
    UNUSED_ARG(fd);
#else
    int recv_tos_on = 1;
    if (my_setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, (const void *)&recv_tos_on, sizeof(recv_tos_on)) < 0) {
      perror("cannot set recvtclass\n");
    }
#endif
  } else {
#if !defined(IP_RECVTOS)
    UNUSED_ARG(fd);
#else
    int recv_tos_on = 1;
    if (my_setsockopt(fd, IPPROTO_IP, IP_RECVTOS, (const void *)&recv_tos_on, sizeof(recv_tos_on)) < 0) {
      perror("cannot set recvtos\n");
    }
#endif
  }

  return 0;
}

int set_socket_options_fd(evutil_socket_t fd, SOCKET_TYPE st, int family) {
  if (fd < 0) {
    return 0;
  }

  set_sock_buf_size(fd, UR_CLIENT_SOCK_BUF_SIZE);

  if (is_tcp_socket(st)) { /* <<== FREEBSD fix */
    struct linger so_linger;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;
    if (my_setsockopt(fd, SOL_SOCKET, SO_LINGER, (const void *)&so_linger, sizeof(so_linger)) < 1) {
      // perror("setsolinger")
      ;
    }
  }

  socket_set_nonblocking(fd);

  if (!is_stream_socket(st)) {
    set_raw_socket_ttl_options(fd, family);
    set_raw_socket_tos_options(fd, family);

#ifdef IP_RECVERR
    if (family != AF_INET6) {
      int on = 0;
#ifdef TURN_IP_RECVERR
      on = 1;
#endif
      if (my_setsockopt(fd, IPPROTO_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
        perror("IP_RECVERR");
      }
    }
#endif

#ifdef IPV6_RECVERR
    if (family == AF_INET6) {
      int on = 0;
#ifdef TURN_IP_RECVERR
      on = 1;
#endif
      if (my_setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, (const void *)&on, sizeof(on)) < 0) {
        perror("IPV6_RECVERR");
      }
    }
#endif

  } else {

    int flag = 1;

    if (is_tcp_socket(st)) {
      my_setsockopt(fd,                  /* socket affected */
                 IPPROTO_TCP,         /* set option at TCP level */
                 TCP_NODELAY,         /* name of option */
                 (const void *)&flag, /* value */
                 sizeof(int));        /* length of option value */
    } else {
#if defined(SCTP_NODELAY)
      my_setsockopt(fd,                  /* socket affected */
                 IPPROTO_SCTP,        /* set option at SCTP level */
                 SCTP_NODELAY,        /* name of option */
                 (const void *)&flag, /* value */
                 sizeof(int));        /* length of option value */
#endif
    }

    socket_tcp_set_keepalive(fd, st);
  }

  return 0;
}

int set_socket_options(ioa_socket_handle s) {
  if (!s || (s->parent_s)) {
    return 0;
  }

#ifndef USE_FSTACK
  set_socket_options_fd(s->fd, s->st, s->family);

  s->default_ttl = get_raw_socket_ttl(s->fd, s->family);
  s->current_ttl = s->default_ttl;

  s->default_tos = get_raw_socket_tos(s->fd, s->family);
  s->current_tos = s->default_tos;
#else
  set_socket_options_fd(s->fd, s->st, s->family);  // solo lo permitido
  s->default_ttl = 64;  // valor estándar razonable
  s->current_ttl = 64;
  s->default_tos = 0;
  s->current_tos = 0;
#endif

  return 0;
}

/* <<== Socket options helpers */

ioa_socket_handle create_unbound_relay_ioa_socket(ioa_engine_handle e, int family, SOCKET_TYPE st,
                                                  SOCKET_APP_TYPE sat) {
  evutil_socket_t fd = -1;
  ioa_socket_handle ret = NULL;

  switch (st) {
  case UDP_SOCKET:
    
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "About to call myscoket in ns_iolib_engine_impl.c - 907");
    fd = my_socket(family, RELAY_DGRAM_SOCKET_TYPE, RELAY_DGRAM_SOCKET_PROTOCOL);
    if (fd < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create UDP socket\n");
      perror("UDP socket");
      return NULL;
    }
    set_sock_buf_size(fd, UR_CLIENT_SOCK_BUF_SIZE);
    break;
  case TCP_SOCKET:

    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "About to call myscoket in ns_iolib_engine_impl.c - 917");
    fd = my_socket(family, RELAY_STREAM_SOCKET_TYPE, RELAY_STREAM_SOCKET_PROTOCOL);
    if (fd < 0) {
      perror("TCP socket");
      return NULL;
    }
    set_sock_buf_size(fd, UR_CLIENT_SOCK_BUF_SIZE);
    break;
  default:
    /* we do not support other sockets in the relay position */
    return NULL;
  }

  ret = (ioa_socket *)calloc(sizeof(ioa_socket), 1);

  ret->magic = SOCKET_MAGIC;

  ret->fd = fd;
  ret->family = family;
  ret->st = st;
  ret->sat = sat;
  ret->e = e;

  set_socket_options(ret);

  return ret;
}

static int bind_ioa_socket(ioa_socket_handle s, const ioa_addr *local_addr, int reusable) {
  if (!s || (s->parent_s)) {
    return 0;
  }

  if (s && s->fd >= 0 && s->e && local_addr) {

    int res = addr_bind(s->fd, local_addr, reusable, 1, s->st);
    if (res >= 0) {
      s->bound = 1;
      addr_cpy(&(s->local_addr), local_addr);
      if (addr_get_port(local_addr) < 1) {
        ioa_addr tmpaddr;
        addr_get_from_sock(s->fd, &tmpaddr);
        if (addr_any(&(s->local_addr))) {
          addr_cpy(&(s->local_addr), &tmpaddr);
        } else {
          addr_set_port(&(s->local_addr), addr_get_port(&tmpaddr));
        }
      }
      s->local_addr_known = 1;
      return 0;
    }
  }
  return -1;
}

int create_relay_ioa_sockets(ioa_engine_handle e, ioa_socket_handle client_s, int address_family, uint8_t transport,
                             int even_port, ioa_socket_handle *rtp_s, ioa_socket_handle *rtcp_s,
                             uint64_t *out_reservation_token, int *err_code, const uint8_t **reason, accept_cb acb,
                             void *acbarg) {

  *rtp_s = NULL;
  if (rtcp_s) {
    *rtcp_s = NULL;
  }

  turnipports *tp = e->tp;

  size_t iip = 0;

  for (iip = 0; iip < e->relays_number; ++iip) {

    ioa_addr relay_addr;
    const ioa_addr *ra = ioa_engine_get_relay_addr(e, client_s, address_family, err_code);
    if (ra) {
      addr_cpy(&relay_addr, ra);
    }

    if (*err_code) {
      if (*err_code == 440) {
        *reason = (const uint8_t *)"Unsupported address family";
      }
      return -1;
    }

    int rtcp_port = -1;

    IOA_CLOSE_SOCKET(*rtp_s);
    if (rtcp_s) {
      IOA_CLOSE_SOCKET(*rtcp_s);
    }

    ioa_addr rtcp_local_addr;
    addr_cpy(&rtcp_local_addr, &relay_addr);

    int i = 0;
    int port = 0;
    ioa_addr local_addr;
    addr_cpy(&local_addr, &relay_addr);
    for (i = 0; i < 0xFFFF; i++) {
      port = 0;
      rtcp_port = -1;
      if (even_port < 0) {
        port = turnipports_allocate(tp, transport, &relay_addr);
      } else {

        port = turnipports_allocate_even(tp, &relay_addr, even_port, out_reservation_token);
        if (port >= 0 && even_port > 0) {

          IOA_CLOSE_SOCKET(*rtcp_s);
          *rtcp_s = create_unbound_relay_ioa_socket(e, relay_addr.ss.sa_family, UDP_SOCKET, RELAY_RTCP_SOCKET);
          if (*rtcp_s == NULL) {
            perror("socket");
            IOA_CLOSE_SOCKET(*rtp_s);
            addr_set_port(&local_addr, port);
            turnipports_release(tp, transport, &local_addr);
            rtcp_port = port + 1;
            addr_set_port(&rtcp_local_addr, rtcp_port);
            turnipports_release(tp, transport, &rtcp_local_addr);
            return -1;
          }else{ //DEBUG
             TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "INFO: IPv4. Local relay addr: %s:%d fd=%d\n",
    inet_ntoa(((struct sockaddr_in *)&((*rtp_s)->local_addr))->sin_addr),
    ntohs(((struct sockaddr_in *)&((*rtp_s)->local_addr))->sin_port),
    (*rtp_s)->fd);
          }
          sock_bind_to_device((*rtcp_s)->fd, (unsigned char *)e->relay_ifname);

          rtcp_port = port + 1;
          addr_set_port(&rtcp_local_addr, rtcp_port);
          if (bind_ioa_socket(*rtcp_s, &rtcp_local_addr, (transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)) < 0) {
            addr_set_port(&local_addr, port);
            turnipports_release(tp, transport, &local_addr);
            turnipports_release(tp, transport, &rtcp_local_addr);
            rtcp_port = -1;
            IOA_CLOSE_SOCKET(*rtcp_s);
            continue;
          }
        }
      }
      if (port < 0) {
        IOA_CLOSE_SOCKET(*rtp_s);
        if (rtcp_s) {
          IOA_CLOSE_SOCKET(*rtcp_s);
        }
        rtcp_port = -1;
        break;
      } else {

        IOA_CLOSE_SOCKET(*rtp_s);

        *rtp_s = create_unbound_relay_ioa_socket(
            e, relay_addr.ss.sa_family, (transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) ? TCP_SOCKET : UDP_SOCKET,
            RELAY_SOCKET);
        if (*rtp_s == NULL) {
          int rtcp_bound = 0;
          if (rtcp_s && *rtcp_s) {
            rtcp_bound = (*rtcp_s)->bound;
            IOA_CLOSE_SOCKET(*rtcp_s);
          }
          addr_set_port(&local_addr, port);
          turnipports_release(tp, transport, &local_addr);
          if (rtcp_port >= 0 && !rtcp_bound) {
            addr_set_port(&rtcp_local_addr, rtcp_port);
            turnipports_release(tp, transport, &rtcp_local_addr);
          }
          perror("socket");
          return -1;
        }

        sock_bind_to_device((*rtp_s)->fd, (unsigned char *)e->relay_ifname);

        addr_set_port(&local_addr, port);
        if (bind_ioa_socket(*rtp_s, &local_addr, (transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)) >= 0) {
          break;
        } else {
          IOA_CLOSE_SOCKET(*rtp_s);
          int rtcp_bound = 0;
          if (rtcp_s && *rtcp_s) {
            rtcp_bound = (*rtcp_s)->bound;
            IOA_CLOSE_SOCKET(*rtcp_s);
          }
          addr_set_port(&local_addr, port);
          turnipports_release(tp, transport, &local_addr);
          if (rtcp_port >= 0 && !rtcp_bound) {
            addr_set_port(&rtcp_local_addr, rtcp_port);
            turnipports_release(tp, transport, &rtcp_local_addr);
          }
          rtcp_port = -1;
        }
      }
    }

    if (i >= 0xFFFF) {
      IOA_CLOSE_SOCKET(*rtp_s);
      if (rtcp_s) {
        IOA_CLOSE_SOCKET(*rtcp_s);
      }
    }

    if (*rtp_s) {
      addr_set_port(&local_addr, port);
      addr_debug_print(e->verbose, &local_addr, "Local relay addr");
      if (rtcp_s && *rtcp_s) {
        addr_set_port(&local_addr, port + 1);
        addr_debug_print(e->verbose, &local_addr, "Local reserved relay addr");
      }
      break;
    }
  }

  if (!(*rtp_s)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: no available ports 3\n", __FUNCTION__);
    IOA_CLOSE_SOCKET(*rtp_s);
    if (rtcp_s) {
      IOA_CLOSE_SOCKET(*rtcp_s);
    }
    return -1;
  }

  set_accept_cb(*rtp_s, acb, acbarg);

  if (rtcp_s && *rtcp_s && out_reservation_token && *out_reservation_token) {
    if (!rtcp_map_put(e->map_rtcp, *out_reservation_token, *rtcp_s)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot update RTCP map\n", __FUNCTION__);
      IOA_CLOSE_SOCKET(*rtp_s);
      if (rtcp_s) {
        IOA_CLOSE_SOCKET(*rtcp_s);
      }
      return -1;
    }
  }

  return 0;
}

/* RFC 6062 ==>> */

static void tcp_listener_input_handler(
  #ifndef USE_FSTACK
  struct evconnlistener *l,
  #else
  struct MyEvConnListener *l,
  #endif
   evutil_socket_t fd, struct sockaddr *sa, int socklen,
                                       void *arg) {
  UNUSED_ARG(l);

  ioa_socket_handle list_s = (ioa_socket_handle)arg;

  ioa_addr client_addr;
  memcpy(&client_addr, sa, socklen);

  addr_debug_print(((list_s->e) && list_s->e->verbose), &client_addr, "tcp accepted from");

  ioa_socket_handle s = create_ioa_socket_from_fd(list_s->e, fd, NULL, TCP_SOCKET, TCP_RELAY_DATA_SOCKET, &client_addr,
                                                  &(list_s->local_addr));

  if (s) {
    if (list_s->acb) {
      list_s->acb(s, list_s->acbarg);
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Do not know what to do with accepted TCP socket\n");
      close_ioa_socket(s);
    }
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from FD\n");
    socket_closesocket(fd);
  }
}

static int set_accept_cb(ioa_socket_handle s, accept_cb acb, void *arg) {
  if (!s || s->parent_s) {
    return -1;
  }

  if (s->st == TCP_SOCKET) {
    #ifndef USE_FSTACK
    s->list_ev = evconnlistener_new(s->e->event_base, tcp_listener_input_handler, s, LEV_OPT_REUSEABLE, 1024, s->fd);
    #else
    s->list_ev = my_evconnlistener_new(s->e->event_base, tcp_listener_input_handler, s, LEV_OPT_REUSEABLE, 1024, s->fd);
    #endif
    if (!(s->list_ev)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot start TCP listener\n", __FUNCTION__);
      return -1;
    }
    s->acb = acb;
    s->acbarg = arg;
  }
  return 0;
}

static void connect_eventcb(
#ifndef USE_FSTACK
  struct bufferevent *bev,
  short events,
#else
  int fd,
  short events,
#endif
  void *ptr)
{
  ioa_socket_handle ret = (ioa_socket_handle)ptr;

  if (!ret)
    return;

  connect_cb cb = ret->conn_cb;
  void *arg = ret->conn_arg;

#ifndef USE_FSTACK
  UNUSED_ARG(bev);

  if (events & BEV_EVENT_CONNECTED) {
    ret->connected = 1;
    BUFFEREVENT_FREE(ret->conn_bev);
    ret->conn_cb = NULL;
    ret->conn_arg = NULL;
    if (cb) {
      cb(1, arg);
    }

  } else if (events & BEV_EVENT_ERROR) {
    BUFFEREVENT_FREE(ret->conn_bev);
    ret->conn_cb = NULL;
    ret->conn_arg = NULL;
    if (cb) {
      cb(0, arg);
    }
  }

#else
  UNUSED_ARG(fd);

  int err = 0;
  socklen_t len = sizeof(err);
  if (my_getsockopt(ret->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
    err = errno;
  }
  printf("Se debería desregistrar el evento de conexión, fd=%d, err=%d\n", ret->fd, err);
  if (events & EV_WRITE) {
    my_event_del(ret->conn_bev);  // desregistrar el evento
    printf("Evento de conexión desregistrado, fd=%d\n", ret->fd);
    ret->conn_bev = NULL;
    ret->conn_cb = NULL;
    ret->conn_arg = NULL;

    if (err == 0) {
      ret->connected = 1;
      if (cb) {
        cb(1, arg);  // éxito
      }
    } else {
      if (cb) {
        cb(0, arg);  // error
      }
    }
  }
#endif
}

ioa_socket_handle ioa_create_connecting_tcp_relay_socket(ioa_socket_handle s, ioa_addr *peer_addr, connect_cb cb,
                                                         void *arg) {
  ioa_socket_handle ret = create_unbound_relay_ioa_socket(s->e, s->family, s->st, TCP_RELAY_DATA_SOCKET);

  if (!ret) {
    return NULL;
  }

  ioa_addr new_local_addr;
  addr_cpy(&new_local_addr, &(s->local_addr));

#if !defined(SO_REUSEPORT)
  /*
   * trick for OSes which do not support SO_REUSEPORT.
   * Section 5.2 of RFC 6062 will not work correctly
   * for those OSes (for example, Linux pre-3.9 kernel).
   */
#if !defined(__CYGWIN__) && !defined(__CYGWIN32__) && !defined(__CYGWIN64__)
  close_socket_net_data(s);
#else
  addr_set_port(&new_local_addr, 0);
#endif
#endif

  if (bind_ioa_socket(ret, &new_local_addr, 1) < 0) {
    IOA_CLOSE_SOCKET(ret);
    ret = NULL;
    goto ccs_end;
  }

  addr_cpy(&(ret->remote_addr), peer_addr);

  set_ioa_socket_session(ret, s->session);



  #ifndef USE_FSTACK
    BUFFEREVENT_FREE(ret->conn_bev);
    ret->conn_bev = bufferevent_socket_new(ret->e->event_base, ret->fd, TURN_BUFFEREVENTS_OPTIONS);
    bufferevent_setcb(ret->conn_bev, NULL, NULL, connect_eventcb, ret);
    if (bufferevent_socket_connect(ret->conn_bev, (struct sockaddr *)peer_addr, get_ioa_addr_len(peer_addr)) < 0) {
      /* Error starting connection */
      set_ioa_socket_session(ret, NULL);
      IOA_CLOSE_SOCKET(ret);
      ret = NULL;
      goto ccs_end;
    }
  #else
    if (ret->fd < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Invalid socket fd for relay");
      IOA_CLOSE_SOCKET(ret);
      return NULL;
    }

    set_socket_options(ret);
    sock_bind_to_device(ret->fd, (unsigned char *)ret->e->relay_ifname);

    if (bind_ioa_socket(ret, &new_local_addr, 1) < 0) {
      perror("F-Stack bind failed");
      IOA_CLOSE_SOCKET(ret);
      return NULL;
    }

    if (my_connect(ret->fd, (struct sockaddr *)peer_addr, get_ioa_addr_len(peer_addr)) < 0) {
      perror("F-Stack connect failed");
      IOA_CLOSE_SOCKET(ret);
      return NULL;
    }

    ret->conn_arg = arg;
    ret->conn_cb = cb;

    // Registrar el socket en el loop para EV_WRITE y detectar conexión completada
    struct MyEvent *ev = TRACE_EVENT_NEW(ret->e->event_base, ret->fd, EV_WRITE, connect_eventcb, ret);
    if (!ev) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Failed to allocate MyEvent for connect");
      IOA_CLOSE_SOCKET(ret);
      return NULL;
    }
    my_event_add(ev, NULL);
    ret->conn_bev = ev;
#endif



ccs_end:

#if !defined(SO_REUSEPORT)
#if !defined(__CYGWIN__) && !defined(__CYGWIN32__) && !defined(__CYGWIN64__)
  /*
   * trick for OSes which do not support SO_REUSEPORT.
   * Section 5.2 of RFC 6062 will not work correctly
   * for those OSes (for example, Linux pre-3.9 kernel).
   */
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "About to call myscoket in ns_iolib_engine_impl.c - 1279");
  s->fd = my_socket(s->family, RELAY_STREAM_SOCKET_TYPE, RELAY_STREAM_SOCKET_PROTOCOL);
  if (s->fd < 0) {
    perror("TCP socket");
    if (ret) {
      set_ioa_socket_session(ret, NULL);
      IOA_CLOSE_SOCKET(ret);
      ret = NULL;
    }
  } else {
    set_socket_options(s);
    sock_bind_to_device(s->fd, (unsigned char *)s->e->relay_ifname);
    if (bind_ioa_socket(s, &new_local_addr, 1) < 0) {
      if (ret) {
        set_ioa_socket_session(ret, NULL);
        IOA_CLOSE_SOCKET(ret);
        ret = NULL;
      }
    } else {
      set_accept_cb(s, s->acb, s->acbarg);
    }
  }
#endif
#endif

  return ret;
}

/* <<== RFC 6062 */

void add_socket_to_parent(ioa_socket_handle parent_s, ioa_socket_handle s) {
  if (parent_s && s) {
    delete_socket_from_parent(s);
    s->parent_s = parent_s;
    s->fd = parent_s->fd;
  }
}

void delete_socket_from_parent(ioa_socket_handle s) {
  if (s && s->parent_s) {
    s->parent_s = NULL;
    s->fd = -1;
  }
}

void add_socket_to_map(ioa_socket_handle s, ur_addr_map *amap) {
  if (amap && s && (s->sockets_container != amap)) {
    delete_socket_from_map(s);
    ur_addr_map_del(amap, &(s->remote_addr), NULL);
    ur_addr_map_put(amap, &(s->remote_addr), (ur_addr_map_value_type)s);
    s->sockets_container = amap;
  }
}

void delete_socket_from_map(ioa_socket_handle s) {
  if (s && s->sockets_container) {

    ur_addr_map_del(s->sockets_container, &(s->remote_addr), NULL);
    s->sockets_container = NULL;
  }
}

ioa_socket_handle create_ioa_socket_from_fd(ioa_engine_handle e, ioa_socket_raw fd, ioa_socket_handle parent_s,
                                            SOCKET_TYPE st, SOCKET_APP_TYPE sat, const ioa_addr *remote_addr,
                                            const ioa_addr *local_addr) {
  ioa_socket_handle ret = NULL;

  if ((fd < 0) && !parent_s) {
    return NULL;
  }

  ret = (ioa_socket *)calloc(sizeof(ioa_socket), 1);

  ret->magic = SOCKET_MAGIC;

  ret->fd = fd;
  ret->st = st;
  ret->sat = sat;
  ret->e = e;

  if (local_addr) {
    ret->family = local_addr->ss.sa_family;
    ret->bound = 1;
    addr_cpy(&(ret->local_addr), local_addr);
  }

  if (remote_addr) {
    ret->connected = 1;
    if (!(ret->family)) {
      ret->family = remote_addr->ss.sa_family;
    }
    addr_cpy(&(ret->remote_addr), remote_addr);
  }

  if (parent_s) {
    add_socket_to_parent(parent_s, ret);
  } else {
    set_socket_options(ret);
  }

  return ret;
}

static void ssl_info_callback(SSL *ssl, int where, int ret) {
  UNUSED_ARG(ret);
  UNUSED_ARG(ssl);
  UNUSED_ARG(where);
}

typedef void (*ssl_info_callback_t)(const SSL *ssl, int type, int val);

static void set_socket_ssl(ioa_socket_handle s, SSL *ssl) {
  if (s && (s->ssl != ssl)) {
    if (s->ssl) {
      SSL_set_app_data(s->ssl, NULL);
      SSL_set_info_callback(s->ssl, (ssl_info_callback_t)NULL);
    }
    s->ssl = ssl;
    if (ssl) {
      SSL_set_app_data(ssl, s);
      SSL_set_info_callback(ssl, (ssl_info_callback_t)ssl_info_callback);
      SSL_set_options(ssl,
#if defined(SSL_OP_NO_RENEGOTIATION)
                      SSL_OP_NO_RENEGOTIATION
#else
#if defined(SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
                      SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
#endif
#endif
      );
    }
  }
}

/* Only must be called for DTLS_SOCKET */
ioa_socket_handle create_ioa_socket_from_ssl(ioa_engine_handle e, ioa_socket_handle parent_s, SSL *ssl, SOCKET_TYPE st,
                                             SOCKET_APP_TYPE sat, const ioa_addr *remote_addr,
                                             const ioa_addr *local_addr) {
  if (!parent_s) {
    return NULL;
  }

  ioa_socket_handle ret = create_ioa_socket_from_fd(e, parent_s->fd, parent_s, st, sat, remote_addr, local_addr);

  if (ret) {
    set_socket_ssl(ret, ssl);
  }

  return ret;
}

static void close_socket_net_data(ioa_socket_handle s) {
  if (s) {

    EVENT_DEL(s->read_event);
    if (s->list_ev) {
      #ifndef USE_FSTACK
      evconnlistener_free(s->list_ev);
      #else
      my_evconnlistener_free(s->list_ev);
      #endif
      s->list_ev = NULL;
    }
    #ifndef USE_FSTACK
      BUFFEREVENT_FREE(s->conn_bev);
      BUFFEREVENT_FREE(s->bev);
    #endif

    if (s->ssl) {
      if (!s->broken) {
        if (!(SSL_get_shutdown(s->ssl) & SSL_SENT_SHUTDOWN)) {
          /*
           * SSL_RECEIVED_SHUTDOWN tells SSL_shutdown to act as if we had already
           * received a close notify from the other end.  SSL_shutdown will then
           * send the final close notify in reply.  The other end will receive the
           * close notify and send theirs.  By this time, we will have already
           * closed the socket and the other end's real close notify will never be
           * received.  In effect, both sides will think that they have completed a
           * clean shutdown and keep their sessions valid.  This strategy will fail
           * if the socket is not ready for writing, in which case this hack will
           * lead to an unclean shutdown and lost session on the other end.
           */
          SSL_set_shutdown(s->ssl, SSL_RECEIVED_SHUTDOWN);
          SSL_shutdown(s->ssl);
          log_socket_event(s, "SSL shutdown received, socket to be closed", 0);
        }
      }
      SSL_free(s->ssl);
    }

    if (s->fd >= 0) {
      socket_closesocket(s->fd);
      s->fd = -1;
    }
  }
}

void detach_socket_net_data(ioa_socket_handle s) {
  if (s) {
    EVENT_DEL(s->read_event);
    s->read_cb = NULL;
    s->read_ctx = NULL;
    if (s->list_ev) {
      #ifndef USE_FSTACK
      evconnlistener_free(s->list_ev);
      #else
      my_evconnlistener_free(s->list_ev);
      #endif
      s->list_ev = NULL;
    }
    s->acb = NULL;
    s->acbarg = NULL;
    #ifndef USE_FSTACK
    BUFFEREVENT_FREE(s->conn_bev);
    #endif
    s->conn_arg = NULL;
    s->conn_cb = NULL;
    #ifndef USE_FSTACK
    BUFFEREVENT_FREE(s->bev);
    #endif
  }
}

void close_ioa_socket(ioa_socket_handle s) {
  if (s) {

    if (s->magic != SOCKET_MAGIC) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s wrong magic on socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st,
                    s->sat);
      return;
    }

    if (s->done) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s double free on socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st,
                    s->sat);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
      return;
    }

    s->done = 1;

    while (!buffer_list_empty(&(s->bufs))) {
      pop_elem_from_buffer_list(&(s->bufs));
    }

    ioa_network_buffer_delete(s->e, s->defer_nbh);

    if (s->bound && s->e && s->e->tp && ((s->sat == RELAY_SOCKET) || (s->sat == RELAY_RTCP_SOCKET))) {
      turnipports_release(
          s->e->tp, ((s->st == TCP_SOCKET) ? STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE : STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE),
          &(s->local_addr));
    }

    if (s->special_session) {
      free(s->special_session);
      s->special_session = NULL;
    }
    s->special_session_size = 0;

    delete_socket_from_map(s);
    delete_socket_from_parent(s);

    close_socket_net_data(s);

    if (s->session && s->session->client_socket == s) {
      // Detaching client socket from super session to prevent mem corruption
      // in case client_to_be_allocated_timeout_handler gets triggered
      s->session->client_socket = NULL;
    }

    s->session = NULL;
    s->sub_session = NULL;
    s->magic = 0;

    free(s);
  }
}

ioa_socket_handle detach_ioa_socket(ioa_socket_handle s) {
  ioa_socket_handle ret = NULL;

  if (!s) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Detaching NULL socket\n");
  } else {
    if ((s->magic != SOCKET_MAGIC) || (s->done)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on bad socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st,
                    s->sat);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
      return ret;
    }
    if (s->tobeclosed) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on tobeclosed socket: %p, st=%d, sat=%d\n", __FUNCTION__, s,
                    s->st, s->sat);
      return ret;
    }
    if (!(s->e)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on socket without engine: %p, st=%d, sat=%d\n", __FUNCTION__,
                    s, s->st, s->sat);
      return ret;
    }

    s->tobeclosed = 1;

    if (s->parent_s) {
      if ((s->st != UDP_SOCKET) && (s->st != DTLS_SOCKET)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s detach on non-UDP child socket: %p, st=%d, sat=%d\n", __FUNCTION__,
                      s, s->st, s->sat);
        return ret;
      }
    }

    evutil_socket_t udp_fd = -1;

    if (s->parent_s) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "About to call myscoket in ns_iolib_engine_impl.c - 1579");
      udp_fd = my_socket(s->local_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
      if (udp_fd < 0) {
        perror("socket");
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot allocate new socket\n", __FUNCTION__);
        return ret;
      }
      if (sock_bind_to_device(udp_fd, (unsigned char *)(s->e->relay_ifname)) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind udp server socket to device %s\n",
                      (char *)(s->e->relay_ifname));
      }

      if (addr_bind(udp_fd, &(s->local_addr), 1, 1, UDP_SOCKET) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind new detached udp server socket to local addr\n");
        socket_closesocket(udp_fd);
        return ret;
      }

      int connect_err = 0;
      if (addr_connect(udp_fd, &(s->remote_addr), &connect_err) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot connect new detached udp server socket to remote addr\n");
        socket_closesocket(udp_fd);
        return ret;
      }
      set_raw_socket_ttl_options(udp_fd, s->local_addr.ss.sa_family);
      set_raw_socket_tos_options(udp_fd, s->local_addr.ss.sa_family);
    }

    detach_socket_net_data(s);

    while (!buffer_list_empty(&(s->bufs))) {
      pop_elem_from_buffer_list(&(s->bufs));
    }

    ioa_network_buffer_delete(s->e, s->defer_nbh);

    ret = (ioa_socket *)calloc(sizeof(ioa_socket), 1);
    if (!ret) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot allocate new socket structure\n", __FUNCTION__);
      if (udp_fd >= 0) {
        socket_closesocket(udp_fd);
      }
      return ret;
    }

    memset(ret, 0, sizeof(ioa_socket));

    ret->magic = SOCKET_MAGIC;

    SSL *ssl = s->ssl;
    set_socket_ssl(s, NULL);
    set_socket_ssl(ret, ssl);
    ret->fd = s->fd;

    ret->family = get_ioa_socket_address_family(s);

    ret->st = s->st;
    ret->sat = s->sat;
    ret->bound = s->bound;
    ret->local_addr_known = s->local_addr_known;
    addr_cpy(&(ret->local_addr), &(s->local_addr));
    ret->connected = s->connected;
    addr_cpy(&(ret->remote_addr), &(s->remote_addr));

    delete_socket_from_map(s);
    delete_socket_from_parent(s);

    if (udp_fd >= 0) {

      ret->fd = udp_fd;

      set_socket_options(ret);
    }

    ret->current_ttl = s->current_ttl;
    ret->default_ttl = s->default_ttl;

    ret->current_tos = s->current_tos;
    ret->default_tos = s->default_tos;

    s->fd = -1;
  }

  return ret;
}

ts_ur_super_session *get_ioa_socket_session(ioa_socket_handle s) {
  if (s) {
    return s->session;
  }
  return NULL;
}

void set_ioa_socket_session(ioa_socket_handle s, ts_ur_super_session *ss) {
  if (s) {
    s->session = ss;
  }
}

void clear_ioa_socket_session_if(ioa_socket_handle s, void *ss) {
  if (s && ((void *)(s->session) == ss)) {
    s->session = NULL;
  }
}

tcp_connection *get_ioa_socket_sub_session(ioa_socket_handle s) {
  if (s) {
    return s->sub_session;
  }
  return NULL;
}

void set_ioa_socket_sub_session(ioa_socket_handle s, tcp_connection *tc) {
  if (s) {
    s->sub_session = tc;
  }
}

int get_ioa_socket_address_family(ioa_socket_handle s) {

  int first_time = 1;
beg:
  if (!(s && (s->magic == SOCKET_MAGIC) && !(s->done))) {
    return AF_INET;
  } else if (first_time && s->parent_s && (s != s->parent_s)) {
    first_time = 0;
    s = s->parent_s;
    goto beg;
  } else {
    return s->family;
  }
}

SOCKET_TYPE get_ioa_socket_type(ioa_socket_handle s) {
  if (s) {
    return s->st;
  }

  return UNKNOWN_SOCKET;
}

SOCKET_APP_TYPE get_ioa_socket_app_type(ioa_socket_handle s) {
  if (s) {
    return s->sat;
  }
  return UNKNOWN_APP_SOCKET;
}

void set_ioa_socket_app_type(ioa_socket_handle s, SOCKET_APP_TYPE sat) {
  if (s) {
    s->sat = sat;
  }
}

ioa_addr *get_local_addr_from_ioa_socket(ioa_socket_handle s) {
  if (s && (s->magic == SOCKET_MAGIC) && !(s->done)) {

    if (s->parent_s) {
      s = s->parent_s;
    }

    if (s->local_addr_known) {
      return &(s->local_addr);
    } else if (s->bound && (addr_get_port(&(s->local_addr)) > 0)) {
      s->local_addr_known = 1;
      return &(s->local_addr);
    } else {
      ioa_addr tmpaddr;
      if (addr_get_from_sock(s->fd, &tmpaddr) == 0) {
        if (addr_get_port(&tmpaddr) > 0) {
          s->local_addr_known = 1;
          s->bound = 1;
          if (addr_any(&(s->local_addr))) {
            addr_cpy(&(s->local_addr), &tmpaddr);
          } else {
            addr_set_port(&(s->local_addr), addr_get_port(&tmpaddr));
          }
          return &(s->local_addr);
        }
        if (addr_any(&(s->local_addr))) {
          addr_cpy(&(s->local_addr), &tmpaddr);
        }
        return &(s->local_addr);
      }
    }
  }

  return NULL;
}

ioa_addr *get_remote_addr_from_ioa_socket(ioa_socket_handle s) {
  if (s && (s->magic == SOCKET_MAGIC) && !(s->done)) {

    if (s->connected) {
      return &(s->remote_addr);
    }
  }

  return NULL;
}

int get_local_mtu_ioa_socket(ioa_socket_handle s) {
  if (s) {
    if (s->parent_s) {
      s = s->parent_s;
    }

    return get_socket_mtu(s->fd, s->family, (s->e && eve(s->e->verbose)));
  }
  return -1;
}

/*
 * Return: -1 - error, 0 or >0 - OK
 * *read_len -1 - no data, >=0 - data available
 */
int ssl_read(evutil_socket_t fd, SSL *ssl, ioa_network_buffer_handle nbh, int verbose) {
  int ret = 0;

  if (!ssl || !nbh) {
    return -1;
  }

  char *buffer = (char *)ioa_network_buffer_data(nbh);
  int buf_size = (int)ioa_network_buffer_get_capacity_udp();
  int read_len = (int)ioa_network_buffer_get_size(nbh);

  if (read_len < 1) {
    return -1;
  }

  char *new_buffer = buffer + buf_size;
  int old_buffer_len = read_len;

  int len = 0;

  if (eve(verbose)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: before read...\n", __FUNCTION__);
  }

  BIO *wbio = SSL_get_wbio(ssl);
  if (wbio) {
    BIO_set_fd(wbio, fd, BIO_NOCLOSE);
  }

  BIO *rbio = BIO_new_mem_buf(buffer, old_buffer_len);
  BIO_set_mem_eof_return(rbio, -1);

#if defined LIBRESSL_VERSION_NUMBER && LIBRESSL_VERSION_NUMBER < 0x3040000fL
  ssl->rbio = rbio;
#else
  SSL_set0_rbio(ssl, rbio);
#endif

  int if1 = SSL_is_init_finished(ssl);

  do {
    len = SSL_read(ssl, new_buffer, buf_size);
  } while (len < 0 && socket_eintr());

  int if2 = SSL_is_init_finished(ssl);

  if (eve(verbose)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: after read: %d\n", __FUNCTION__, len);
  }

  if (SSL_get_shutdown(ssl)) {

    ret = -1;

  } else if (!if1 && if2) {

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (verbose && SSL_get1_peer_certificate(ssl)) {
#else
    if (verbose && SSL_get_peer_certificate(ssl)) {
#endif
      printf("\n------------------------------------------------------------\n");
      X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1, XN_FLAG_MULTILINE);
      printf("\n\n Cipher: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
      printf("\n------------------------------------------------------------\n\n");
    }

    ret = 0;

  } else if (len < 0 && (socket_enobufs() || socket_eagain())) {
    if (eve(verbose)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: ENOBUFS/EAGAIN\n", __FUNCTION__);
    }
    ret = 0;
  } else {

    if (eve(verbose)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: read %d bytes\n", __FUNCTION__, (int)len);
    }

    if (len >= 0) {
      ret = len;
    } else {
      switch (SSL_get_error(ssl, len)) {
      case SSL_ERROR_NONE:
        //???
        ret = 0;
        break;
      case SSL_ERROR_WANT_READ:
        ret = 0;
        break;
      case SSL_ERROR_WANT_WRITE:
        ret = 0;
        break;
      case SSL_ERROR_ZERO_RETURN:
        ret = 0;
        break;
      case SSL_ERROR_SYSCALL: {
        int err = socket_errno();
        if (handle_socket_error()) {
          ret = 0;
        } else {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS Socket read error: %d\n", err);
          ret = -1;
        }
        break;
      }
      case SSL_ERROR_SSL:
        if (verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL read error: ");
          char buf[65536];
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n", ERR_error_string(ERR_get_error(), buf),
                        SSL_get_error(ssl, len));
        }
        if (verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL connection closed.\n");
        }
        ret = -1;
        break;
      default:
        if (verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error while reading!\n");
        }
        ret = -1;
      }
    }
  }

  if (ret > 0) {
    ioa_network_buffer_add_offset_size(nbh, (uint16_t)buf_size, 0, (size_t)ret);
  }
#if defined LIBRESSL_VERSION_NUMBER && LIBRESSL_VERSION_NUMBER < 0x3040000fL
  ssl->rbio = NULL;
  BIO_free(rbio);
#else
  SSL_set0_rbio(ssl, NULL);
#endif

  return ret;
}

static int socket_readerr(evutil_socket_t fd, ioa_addr *orig_addr) {
  if ((fd < 0) || !orig_addr) {
    return -1;
  }

#if defined(CMSG_SPACE) && defined(MSG_ERRQUEUE) && defined(IP_RECVERR)
#ifdef _MSC_VER
  // TODO: implement it!!!
  TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "The socket_readerr is not implement in _MSC_VER");
#else
  uint8_t ecmsg[TURN_CMSG_SZ + 1];
  int flags = MSG_ERRQUEUE;
  int len = 0;

  struct msghdr msg;
  struct iovec iov;
  char buffer[65536];

  char *cmsg = (char *)ecmsg;

  msg.msg_control = cmsg;
  msg.msg_controllen = TURN_CMSG_SZ;
  /* CMSG_SPACE(sizeof(recv_ttl)+sizeof(recv_tos)) */

  msg.msg_name = orig_addr;
  msg.msg_namelen = (socklen_t)get_ioa_addr_len(orig_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_iov->iov_base = buffer;
  msg.msg_iov->iov_len = sizeof(buffer);
  msg.msg_flags = 0;

  int try_cycle = 0;

  do {

    do {
      len = my_recvmsg(fd, &msg, flags);
    } while (len < 0 && socket_eintr());

  } while ((len > 0) && (try_cycle++ < MAX_ERRORS_IN_UDP_BATCH));

#endif
#endif

  return 0;
}

typedef unsigned char recv_ttl_t;
typedef unsigned char recv_tos_t;

int udp_recvfrom(evutil_socket_t fd, ioa_addr *orig_addr, const ioa_addr *like_addr, char *buffer, int buf_size,
                 int *ttl, int *tos, char *ecmsg, int flags, uint32_t *errcode) {
  int len = 0;

  if (fd < 0 || !orig_addr || !like_addr || !buffer) {
    return -1;
  }

  if (errcode) {
    *errcode = 0;
  }

  int slen = get_ioa_addr_len(like_addr);
  recv_ttl_t recv_ttl = TTL_DEFAULT;
  recv_tos_t recv_tos = TOS_DEFAULT;

#if defined(_MSC_VER) || !defined(CMSG_SPACE)
  do {
    len = my_recvfrom(fd, buffer, buf_size, flags, (struct sockaddr *)orig_addr, (socklen_t *)&slen);
    if(len > 0) {
      printf("DEBUG: udp_recvfrom received %d bytes\n", len);
    }
  } while (len < 0 && socket_eintr());
  if (len < 0 && errcode) {
    *errcode = (uint32_t)socket_errno();
  }
#else
  struct msghdr msg;
  struct iovec iov;

  char *cmsg = (char *)ecmsg;

  msg.msg_control = cmsg;
  msg.msg_controllen = TURN_CMSG_SZ;
  /* CMSG_SPACE(sizeof(recv_ttl)+sizeof(recv_tos)) */

  msg.msg_name = orig_addr;
  msg.msg_namelen = (socklen_t)slen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_iov->iov_base = buffer;
  msg.msg_iov->iov_len = (size_t)buf_size;
  msg.msg_flags = 0;

#if defined(MSG_ERRQUEUE)
  int try_cycle = 0;
try_again:
#endif

  do {
    len = my_recvmsg(fd, &msg, flags);
  } while (len < 0 && socket_eintr());

#if defined(MSG_ERRQUEUE)

  if (flags & MSG_ERRQUEUE) {
    if ((len > 0) && (try_cycle++ < MAX_ERRORS_IN_UDP_BATCH)) {
      goto try_again;
    }
  }

  if ((len < 0) && (!(flags & MSG_ERRQUEUE))) {
    // Linux
    int eflags = MSG_ERRQUEUE | MSG_DONTWAIT;
    uint32_t errcode1 = 0;
    udp_recvfrom(fd, orig_addr, like_addr, buffer, buf_size, ttl, tos, ecmsg, eflags, &errcode1);
    // try again...
    do {
      len = my_recvmsg(fd, &msg, flags);
    } while (len < 0 && socket_eintr());
  }
#endif

  if (len >= 0) {

    struct cmsghdr *cmsgh;

    // Receive auxiliary data in msg
    for (cmsgh = CMSG_FIRSTHDR(&msg); cmsgh != NULL; cmsgh = CMSG_NXTHDR(&msg, cmsgh)) {
      int l = cmsgh->cmsg_level;
      int t = cmsgh->cmsg_type;

      switch (l) {
      case IPPROTO_IP:
        switch (t) {
#if defined(IP_RECVTTL) && !defined(__sparc_v9__)
        case IP_RECVTTL:
        case IP_TTL:
          recv_ttl = *((recv_ttl_t *)CMSG_DATA(cmsgh));
          break;
#endif
#if defined(IP_RECVTOS)
        case IP_RECVTOS:
        case IP_TOS:
          recv_tos = *((recv_tos_t *)CMSG_DATA(cmsgh));
          break;
#endif
#if defined(IP_RECVERR)
        case IP_RECVERR: {
          struct turn_sock_extended_err *e = (struct turn_sock_extended_err *)CMSG_DATA(cmsgh);
          if (errcode) {
            *errcode = e->ee_errno;
          }
        } break;
#endif
        default:;
          /* no break */
        };
        break;
      case IPPROTO_IPV6:
        switch (t) {
#if defined(IPV6_RECVHOPLIMIT) && !defined(__sparc_v9__)
        case IPV6_RECVHOPLIMIT:
        case IPV6_HOPLIMIT:
          recv_ttl = *((recv_ttl_t *)CMSG_DATA(cmsgh));
          break;
#endif
#if defined(IPV6_RECVTCLASS)
        case IPV6_RECVTCLASS:
        case IPV6_TCLASS:
          recv_tos = *((recv_tos_t *)CMSG_DATA(cmsgh));
          break;
#endif
#if defined(IPV6_RECVERR)
        case IPV6_RECVERR: {
          struct turn_sock_extended_err *e = (struct turn_sock_extended_err *)CMSG_DATA(cmsgh);
          if (errcode) {
            *errcode = e->ee_errno;
          }
        } break;
#endif
        default:;
          /* no break */
        };
        break;
      default:;
        /* no break */
      };
    }
  }

#endif

  *ttl = recv_ttl;

  CORRECT_RAW_TTL(*ttl);

  *tos = recv_tos;

  CORRECT_RAW_TOS(*tos);

  return len;
}

#if TLS_SUPPORTED

static TURN_TLS_TYPE check_tentative_tls(ioa_socket_raw fd) {
  TURN_TLS_TYPE ret = TURN_TLS_NO;

  char s[12];
  int len = 0;

  do {
    len = (int)recv(fd, s, sizeof(s), MSG_PEEK);
  } while (len < 0 && socket_eintr());

  if (len > 0 && ((size_t)len == sizeof(s))) {
    if ((s[0] == 22) && (s[1] == 3) && (s[5] == 1) && (s[9] == 3)) {
      char max_supported = (char)(TURN_TLS_TOTAL - 2);
      if (s[10] > max_supported) {
        ret = TURN_TLS_v1_2; /* compatibility mode */
      } else {
        ret = (TURN_TLS_TYPE)(s[10] + 1);
      }
    } else if ((s[2] == 1) && (s[3] == 3)) {
      ret = TURN_TLS_v1_2; /* compatibility mode */
    }
  }

  return ret;
}
#endif

static size_t proxy_string_field(char *field, size_t max, uint8_t *buf, size_t index, size_t len) {
  size_t count = 0;
  while ((index < len) && (count < max)) {
    if ((0x20 == buf[index]) || (0x0D == buf[index])) {
      field[count] = 0x00;
      return ++index;
    }
    field[count++] = buf[index++];
  }
  return 0;
}

static ssize_t socket_parse_proxy_v1(ioa_socket_handle s, uint8_t *buf, size_t len) {
  if (len < 11) {
    return 0;
  }

  /* Check for proxy-v1 magic field */
  char magic[] = {0x50, 0x52, 0x4F, 0x58, 0x59, 0x20};
  if (memcmp(magic, buf, sizeof(magic))) {
    return -1;
  }

  /* Read family */
  char tcp4[] = {0x54, 0x43, 0x50, 0x34, 0x20};
  char tcp6[] = {0x54, 0x43, 0x50, 0x36, 0x20};
  int family;
  if (0 == memcmp(tcp4, &buf[6], sizeof(tcp4))) { /* IPv4 */
    family = AF_INET;
  } else if (0 == memcmp(tcp6, &buf[6], sizeof(tcp6))) { /* IPv6 */
    family = AF_INET6;
  } else {
    return -1;
  }

  char saddr[40];
  char daddr[40];
  char sport[6];
  char dport[6];

  size_t tlen = 11;
  /* Read source address */
  tlen = proxy_string_field(saddr, sizeof(saddr), buf, tlen, len);
  if (0 == tlen) {
    return -1;
  }

  /* Read dest address */
  tlen = proxy_string_field(daddr, sizeof(daddr), buf, tlen, len);
  if (0 == tlen) {
    return -1;
  }

  /* Read source port */
  tlen = proxy_string_field(sport, sizeof(sport), buf, tlen, len);
  if (0 == tlen) {
    return -1;
  }

  /* Read dest port */
  tlen = proxy_string_field(dport, sizeof(dport), buf, tlen, len);
  if (0 == tlen) {
    return -1;
  }

  /* Final line feed */
  if ((len <= tlen) || (0x0A != buf[tlen])) {
    return -1;
  }

  tlen++;

  int sport_int = atoi(sport);
  int dport_int = atoi(dport);
  if ((sport_int < 0) || (0xFFFF < sport_int)) {
    return -1;
  }
  if ((dport_int < 0) || (0xFFFF < dport_int)) {
    return -1;
  }

  if (AF_INET == family) {
    struct sockaddr_in remote, local;
    remote.sin_family = local.sin_family = AF_INET;
    if (1 != inet_pton(AF_INET, saddr, &remote.sin_addr.s_addr)) {
      return -1;
    }
    if (1 != inet_pton(AF_INET, daddr, &local.sin_addr.s_addr)) {
      return -1;
    }
    remote.sin_port = htons((uint16_t)sport_int);
    local.sin_port = htons((uint16_t)dport_int);

    addr_cpy4(&(s->local_addr), &local);
    addr_cpy4(&(s->remote_addr), &remote);

  } else {
    struct sockaddr_in6 remote, local;
    remote.sin6_family = local.sin6_family = AF_INET6;
    if (1 != inet_pton(AF_INET6, saddr, &remote.sin6_addr.s6_addr)) {
      return -1;
    }
    if (1 != inet_pton(AF_INET6, daddr, &local.sin6_addr.s6_addr)) {
      return -1;
    }
    remote.sin6_port = htons((uint16_t)sport_int);
    local.sin6_port = htons((uint16_t)dport_int);

    addr_cpy6(&(s->local_addr), &local);
    addr_cpy6(&(s->remote_addr), &remote);
  }
  return tlen;
}

static ssize_t socket_parse_proxy_v2(ioa_socket_handle s, uint8_t *buf, size_t len) {
  if (len < 16) {
    return 0;
  }

  /* Check for proxy-v2 magic field */
  char magic[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
  if (memcmp(magic, buf, sizeof(magic))) {
    return -1;
  }

  /* Check version */
  uint8_t version = buf[12] >> 4;
  if (version != 2) {
    return -1;
  }

  /* Read data */
  uint8_t command = buf[12] & 0xF;
  uint8_t family = buf[13] >> 4;
  uint8_t proto = buf[13] & 0xF;
  size_t plen = ((size_t)buf[14] << 8) | buf[15];

  size_t tlen = 16 + plen;
  if (len < tlen) {
    return 0;
  }

  /* A local connection is used by the proxy itself and does not carry a valid address */
  if (command == 0) {
    return tlen;
  }

  /* Accept only proxied TCP connections */
  if (command != 1 || proto != 1) {
    return -1;
  }

  /* Read the address */
  if (family == 1 && plen >= 12) { /* IPv4 */
    struct sockaddr_in remote, local;
    remote.sin_family = local.sin_family = AF_INET;
    memcpy(&remote.sin_addr.s_addr, &buf[16], 4);
    memcpy(&local.sin_addr.s_addr, &buf[20], 4);
    memcpy(&remote.sin_port, &buf[24], 2);
    memcpy(&local.sin_port, &buf[26], 2);

    addr_cpy4(&(s->local_addr), &local);
    addr_cpy4(&(s->remote_addr), &remote);

  } else if (family == 2 && plen >= 36) { /* IPv6 */
    struct sockaddr_in6 remote, local;
    remote.sin6_family = local.sin6_family = AF_INET6;
    memcpy(&remote.sin6_addr.s6_addr, &buf[16], 16);
    memcpy(&local.sin6_addr.s6_addr, &buf[32], 16);
    memcpy(&remote.sin6_port, &buf[48], 2);
    memcpy(&local.sin6_port, &buf[50], 2);

    addr_cpy6(&(s->local_addr), &local);
    addr_cpy6(&(s->remote_addr), &remote);

  } else {
    return -1;
  }

  return tlen;
}

static ssize_t socket_parse_proxy(ioa_socket_handle s, uint8_t *buf, size_t len) {
  ssize_t tlen = socket_parse_proxy_v2(s, buf, len);
  if (-1 == tlen) {
    tlen = socket_parse_proxy_v1(s, buf, len);
  }

  return tlen;
}

static int socket_input_worker(ioa_socket_handle s) {
  printf("DEBUG: socket_input_worker: fd=%d, st=%d, sat=%d\n", s ? s->fd : -1, s ? s->st : -1, s ? s->sat : -1);
  int len = 0;
  int ret = 0;
  size_t app_msg_len = 0;
  int ttl = TTL_IGNORE;
  int tos = TOS_IGNORE;
  ioa_addr remote_addr;

  int try_again = 0;
  int try_ok = 0;
  int try_cycle = 0;
  const int MAX_TRIES = 16;

  if (!s) {
    return 0;
  }

  if ((s->magic != SOCKET_MAGIC) || (s->done)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st, s->sat);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
    return -1;
  }

  if (!(s->e)) {
    return 0;
  }

  if (s->tobeclosed) {
    return 0;
  }

  if (s->connected) {
    addr_cpy(&remote_addr, &(s->remote_addr));
  }
  if (tcp_congestion_control && s->sub_session && s->bev) {
    if (s == s->sub_session->client_s && (s->sub_session->peer_s)) {
      if (!is_socket_writeable(s->sub_session->peer_s, STUN_BUFFER_SIZE, __FUNCTION__, 0)) {
        #ifndef USE_FSTACK
          if (bufferevent_enabled(s->bev, EV_READ)) {
            bufferevent_disable(s->bev, EV_READ);
          }
        #else
        my_event_disable_read(s);

        #endif
      }
    } else if (s == s->sub_session->peer_s && (s->sub_session->client_s)) {
      if (!is_socket_writeable(s->sub_session->client_s, STUN_BUFFER_SIZE, __FUNCTION__, 1)) {
        #ifndef USE_FSTACK
          if (bufferevent_enabled(s->bev, EV_READ)) {
            bufferevent_disable(s->bev, EV_READ);
          }
        #else
          my_event_disable_read(s); 
        #endif
      }
    }
  }

  if ((s->st == TLS_SOCKET) || (s->st == TLS_SCTP_SOCKET)) {
#if TLS_SUPPORTED
    #ifndef USE_FSTACK
    SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
    if (!ctx || SSL_get_shutdown(ctx)) {
      s->tobeclosed = 1;
      return 0;
    }
    #else
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Se esta usando TLS y no está adaptado a f-stack");
    #endif
#endif
  } else if (s->st == DTLS_SOCKET) {
    if (!(s->ssl) || SSL_get_shutdown(s->ssl)) {
      s->tobeclosed = 1;
      return 0;
    }
  }

  if (!(s->e)) {
    return 0;
  }

  if (s->st == TENTATIVE_TCP_SOCKET) {
    EVENT_DEL(s->read_event);
#if TLS_SUPPORTED
    TURN_TLS_TYPE tls_type = check_tentative_tls(s->fd);
    if (tls_type) {
      s->st = TLS_SOCKET;
      if (s->ssl) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d: ssl already exist\n", __FUNCTION__, s,
                      s->st, s->sat);
      }
      if (s->bev) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d: bev already exist\n", __FUNCTION__, s,
                      s->st, s->sat);
      }

      if (s->e->tls_ctx) {
        set_socket_ssl(s, SSL_new(s->e->tls_ctx));
      }
      #ifndef USE_FSTACK
        if (s->ssl) {
          s->bev = bufferevent_openssl_socket_new(s->e->event_base, s->fd, s->ssl, BUFFEREVENT_SSL_ACCEPTING,
                                                  TURN_BUFFEREVENTS_OPTIONS);
          bufferevent_setcb(s->bev, socket_input_handler_bev, socket_output_handler_bev, eventcb_bev, s);
          bufferevent_setwatermark(s->bev, EV_READ | EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
          bufferevent_enable(s->bev, EV_READ | EV_WRITE); /* Start reading. */
        }

      #else
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Se esta usando TLS y no está adaptado a f-stack");
      #endif
    } else
#endif // TLS_SUPPORTED
    {
      s->st = TCP_SOCKET;
      if (s->bev) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d: bev already exist\n", __FUNCTION__, s,
                      s->st, s->sat);
      }
      #ifndef USE_FSTACK
        s->bev = bufferevent_socket_new(s->e->event_base, s->fd, TURN_BUFFEREVENTS_OPTIONS);
        bufferevent_setcb(s->bev, socket_input_handler_bev, socket_output_handler_bev, eventcb_bev, s);
        bufferevent_setwatermark(s->bev, EV_READ | EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
        bufferevent_enable(s->bev, EV_READ | EV_WRITE); /* Start reading. */
      #else
        // F-Stack: registra socket para eventos de lectura y escritura
        struct MyEvent *ev = TRACE_EVENT_NEW(s->e->event_base, s->fd, EV_READ | EV_WRITE | EV_PERSIST, my_combined_handler, s);
        my_event_add(ev, NULL);
        s->read_event = ev;  // guarda referencia si necesitas desactivar/activar luego
      #endif
      }
  } else if (s->st == TENTATIVE_SCTP_SOCKET) {
    EVENT_DEL(s->read_event);
#if TLS_SUPPORTED
    TURN_TLS_TYPE tls_type = check_tentative_tls(s->fd);
    if (tls_type) {
      s->st = TLS_SCTP_SOCKET;
      if (s->ssl) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d: ssl already exist\n", __FUNCTION__, s,
                      s->st, s->sat);
      }
      if (s->bev) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d: bev already exist\n", __FUNCTION__, s,
                      s->st, s->sat);
      }
      if (s->e->tls_ctx) {
        set_socket_ssl(s, SSL_new(s->e->tls_ctx));
      }
      #ifndef USE_FSTACK
        if (s->ssl) {
          s->bev = bufferevent_openssl_socket_new(s->e->event_base, s->fd, s->ssl, BUFFEREVENT_SSL_ACCEPTING,
                                                  TURN_BUFFEREVENTS_OPTIONS);
          bufferevent_setcb(s->bev, socket_input_handler_bev, socket_output_handler_bev, eventcb_bev, s);
          bufferevent_setwatermark(s->bev, EV_READ | EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
          bufferevent_enable(s->bev, EV_READ | EV_WRITE); /* Start reading. */
        }
      #else
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Se esta usando TLS y no está adaptado a f-stack");
      #endif
    } else
#endif // TLS_SUPPORTED
    {
      s->st = SCTP_SOCKET;

      if (s->bev) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d: bev already exist\n",
                      __FUNCTION__, s, s->st, s->sat);
      }

    #ifndef USE_FSTACK
      s->bev = bufferevent_socket_new(s->e->event_base, s->fd, TURN_BUFFEREVENTS_OPTIONS);
      bufferevent_setcb(s->bev, socket_input_handler_bev, socket_output_handler_bev, eventcb_bev, s);
      bufferevent_setwatermark(s->bev, EV_READ | EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
      bufferevent_enable(s->bev, EV_READ | EV_WRITE); /* Start reading. */
    #else
      struct MyEvent *ev = TRACE_EVENT_NEW(s->e->event_base, s->fd, EV_READ | EV_WRITE | EV_PERSIST, my_combined_handler, s);
      my_event_add(ev, NULL);
      s->read_event = ev;  // guardar referencia para habilitar/deshabilitar después si hace falta
    #endif
    }
  }

try_start:

  if (!(s->e)) {
    return 0;
  }

  try_again = 0;
  try_ok = 0;

  stun_buffer_list_elem *buf_elem = new_blist_elem(s->e);
  len = -1;

  if (s->bev) { /* TCP & TLS  & SCTP & SCTP/TLS */
    struct evbuffer *inbuf = bufferevent_get_input(s->bev);
    if (inbuf) {
      ev_ssize_t blen = evbuffer_copyout(inbuf, buf_elem->buf.buf, STUN_BUFFER_SIZE);

      if (blen > 0) {
        int mlen = 0;

        if (blen > (ev_ssize_t)STUN_BUFFER_SIZE) {
          blen = (ev_ssize_t)STUN_BUFFER_SIZE;
        }

        if (s->st == TCP_SOCKET_PROXY) {
          ssize_t tlen = socket_parse_proxy(s, buf_elem->buf.buf, blen);
          blen = 0;
          if (tlen < 0) {
            s->tobeclosed = 1;
            s->broken = 1;
            ret = -1;
            log_socket_event(s, "proxy protocol violated", 1);
          } else if (tlen > 0) {
            bufferevent_read(s->bev, buf_elem->buf.buf, tlen);

            blen = evbuffer_copyout(inbuf, buf_elem->buf.buf, STUN_BUFFER_SIZE);
            s->st = TCP_SOCKET;
          }
        }

        if (blen) {
          if (is_stream_socket(s->st) && ((s->sat == TCP_CLIENT_DATA_SOCKET) || (s->sat == TCP_RELAY_DATA_SOCKET))) {
            mlen = blen;
          } else {
            mlen = stun_get_message_len_str(buf_elem->buf.buf, blen, 1, &app_msg_len);
          }

          if (mlen > 0 && mlen <= (int)blen) {
            len = (int)bufferevent_read(s->bev, buf_elem->buf.buf, mlen);
            if (len < 0) {
              ret = -1;
              s->tobeclosed = 1;
              s->broken = 1;
              log_socket_event(s, "socket read failed, to be closed", 1);
            } else if ((s->st == TLS_SOCKET) || (s->st == TLS_SCTP_SOCKET)) {
#if TLS_SUPPORTED
              SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
              if (!ctx || SSL_get_shutdown(ctx)) {
                ret = -1;
                s->tobeclosed = 1;
              }
#endif
            }
            if (ret != -1) {
              ret = len;
            }
          }
        }
      } else if (blen < 0) {
        s->tobeclosed = 1;
        s->broken = 1;
        ret = -1;
        log_socket_event(s, "socket buffer copy failed, to be closed", 1);
      }
    } else {
      s->tobeclosed = 1;
      s->broken = 1;
      ret = -1;
      log_socket_event(s, "socket input failed, socket to be closed", 1);
    }

    if (len == 0) {
      len = -1;
    }
  } else if (s->fd >= 0) { /* UDP and DTLS */
    ret = udp_recvfrom(s->fd, &remote_addr, &(s->local_addr), (char *)(buf_elem->buf.buf), UDP_STUN_BUFFER_SIZE, &ttl,
                       &tos, s->e->cmsg, 0, NULL);
    len = ret;
    if (s->ssl && (len > 0)) { /* DTLS */
      send_ssl_backlog_buffers(s);
      buf_elem->buf.len = (size_t)len;
      ret = ssl_read(s->fd, s->ssl, (ioa_network_buffer_handle)buf_elem, (s->e ? s->e->verbose : TURN_VERBOSE_NONE));
      addr_cpy(&remote_addr, &(s->remote_addr));
      if (ret < 0) {
        len = -1;
        s->tobeclosed = 1;
        s->broken = 1;
        log_socket_event(s, "SSL read failed, to be closed", 0);
      } else {
        len = (int)ioa_network_buffer_get_size((ioa_network_buffer_handle)buf_elem);
      }
      if ((ret != -1) && (len > 0)) {
        try_again = 1;
      }
    } else { /* UDP */
      if (ret >= 0) {
        try_again = 1;
      }
    }
  } else {
    s->tobeclosed = 1;
    s->broken = 1;
    ret = -1;
    log_socket_event(s, "socket unknown error, to be closed", 1);
  }

  if ((ret != -1) && (len >= 0)) {

    if (app_msg_len) {
      buf_elem->buf.len = app_msg_len;
    } else {
      buf_elem->buf.len = len;
    }

    if (ioa_socket_check_bandwidth(s, buf_elem, 1)) {

      if (s->read_cb) {
        ioa_net_data nd;

        memset(&nd, 0, sizeof(ioa_net_data));
        addr_cpy(&(nd.src_addr), &remote_addr);
        nd.nbh = buf_elem;
        nd.recv_ttl = ttl;
        nd.recv_tos = tos;

        s->read_cb(s, IOA_EV_READ, &nd, s->read_ctx, 1);

        if (nd.nbh) {
          free_blist_elem(s->e, buf_elem);
        }

        buf_elem = NULL;

        try_ok = 1;

      } else {
        ioa_network_buffer_delete(s->e, s->defer_nbh);
        s->defer_nbh = buf_elem;
        buf_elem = NULL;
      }
    }
  }

  if (buf_elem) {
    free_blist_elem(s->e, buf_elem);
    buf_elem = NULL;
  }

  if (try_again && try_ok && !(s->done) && !(s->tobeclosed) && ((++try_cycle) < MAX_TRIES) && !(s->parent_s)) {
    goto try_start;
  }

  return len;
}

static void socket_input_handler(evutil_socket_t fd, short what, void *arg) {
  printf("Entrando en %s\n", __FUNCTION__);

  if (!(what & EV_READ)) {
    return;
  }

  if (!arg) {
    read_spare_buffer(fd);
    return;
  }

  ioa_socket_handle s = (ioa_socket_handle)arg;

  if (!s) {
    read_spare_buffer(fd);
    return;
  }

  if ((s->magic != SOCKET_MAGIC) || (s->done)) {
    read_spare_buffer(fd);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on bad socket, ev=%d: %p, st=%d, sat=%d\n", __FUNCTION__, (int)what, s,
                  s->st, s->sat);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
    return;
  }

  if (fd != s->fd) {
    read_spare_buffer(fd);
    return;
  }

  if (!ioa_socket_tobeclosed(s)) {
    socket_input_worker(s);
  } else {
    read_spare_buffer(fd);
  }

  if ((s->magic != SOCKET_MAGIC) || (s->done)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s (1) on socket, ev=%d: %p, st=%d, sat=%d\n", __FUNCTION__, (int)what, s,
                  s->st, s->sat);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
    return;
  }

  close_ioa_socket_after_processing_if_necessary(s);
}

void close_ioa_socket_after_processing_if_necessary(ioa_socket_handle s) {
  if (s && ioa_socket_tobeclosed(s)) {

    if (s->special_session) {
      free(s->special_session);
      s->special_session = NULL;
    }
    s->special_session_size = 0;

    if (!(s->session) && !(s->sub_session)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s https server socket closed: %p, st=%d, sat=%d\n", __FUNCTION__, s,
                    get_ioa_socket_type(s), get_ioa_socket_app_type(s));
      IOA_CLOSE_SOCKET(s);
      return;
    }

    switch (s->sat) {
    case TCP_CLIENT_DATA_SOCKET:
    case TCP_RELAY_DATA_SOCKET: {
      tcp_connection *tc = s->sub_session;
      if (tc) {
        s->sub_session = NULL;
        delete_tcp_connection(tc);
      }
    } break;
    default: {
      ts_ur_super_session *ss = s->session;
      if (ss) {
        turn_turnserver *server = (turn_turnserver *)ss->server;
        if (server) {
          shutdown_client_connection(server, ss, 0, "general");
        }
      }
    }
    }
  }
}

void socket_input_handler_fstack(int fd, void *arg) {
  ioa_socket_handle s = (ioa_socket_handle)arg;
  printf("DEBUG: socket_input_handler_fstack: fd=%d, st=%d, sat=%d\n", fd, s ? s->st : -1, s ? s->sat : -1);
  if (!s) {
    read_spare_buffer(fd);  // opcional: tu lógica de limpiar datos
    return;
  }

  if ((s->magic != SOCKET_MAGIC) || (s->done)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on bad socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st, s->sat);
    read_spare_buffer(fd);
    return;
  }

  if (fd != s->fd) {
    read_spare_buffer(fd);
    return;
  }

  if (!ioa_socket_tobeclosed(s)) {
    if (socket_input_worker(s) <= 0) {
      // Si worker falla, marca para cerrar
      s->tobeclosed = 1;
    }
  } else {
    read_spare_buffer(fd);
  }

  if ((s->magic != SOCKET_MAGIC) || (s->done)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s (1) on socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st, s->sat);
    return;
  }

  close_ioa_socket_after_processing_if_necessary(s);
}


void my_combined_handler(int fd, short what, void *arg) {
  ioa_socket_handle s = (ioa_socket_handle)arg;
  if (!s || s->tobeclosed) return;

  if (what & EV_READ) {
    socket_input_handler_fstack(fd, s);
    printf("Socket %d read event handled.\n", fd);
  }
  if (what & EV_WRITE) {
    socket_output_handler_fstack(fd, s);
    printf("Socket %d write event handled.\n", fd);
  }
}

void socket_output_handler_fstack(int fd, void *arg) {
  UNUSED_ARG(fd);

  if (!tcp_congestion_control) return;

  if (!arg) return;

  ioa_socket_handle s = (ioa_socket_handle)arg;

  if (!s || (s->magic != SOCKET_MAGIC) || s->done)
    return;

  if (s->in_write)  // estamos escribiendo, espera a terminar
    return;

  if (s->tobeclosed) {
    my_event_disable_read(s);  // desactiva lectura si el socket se cerrará
    return;
  }

  if (s->sub_session) {
    ioa_socket_handle peer = NULL;

    if (s == s->sub_session->client_s && s->sub_session->peer_s) {
      peer = s->sub_session->peer_s;
    } else if (s == s->sub_session->peer_s && s->sub_session->client_s) {
      peer = s->sub_session->client_s;
    }

    if (peer) {
      if (!peer->read_enabled) {
        if (is_socket_writeable(peer, STUN_BUFFER_SIZE, __FUNCTION__, (s == s->sub_session->peer_s) ? 3 : 4)) {
          my_event_enable_read(peer);
          socket_input_handler_fstack(peer->fd, peer);  // invoca handler del peer manualmente
        }
      }
    }
  }
}


static void socket_output_handler_bev(struct bufferevent *bev, void *arg) {

  UNUSED_ARG(bev);
  UNUSED_ARG(arg);

  if (tcp_congestion_control) {

    if (bev && arg) {

      ioa_socket_handle s = (ioa_socket_handle)arg;

      if (s->in_write) {
        return;
      }

      if ((s->magic != SOCKET_MAGIC) || (s->done) || (bev != s->bev)) {
        return;
      }

      if (s->tobeclosed) {
        if (bufferevent_enabled(bev, EV_READ)) {
          bufferevent_disable(bev, EV_READ);
        }
        return;
      }

      if (s->sub_session) {

        if (s == s->sub_session->client_s) {
          if (s->sub_session->peer_s && s->sub_session->peer_s->bev) {
            if (!bufferevent_enabled(s->sub_session->peer_s->bev, EV_READ)) {
              if (is_socket_writeable(s->sub_session->peer_s, STUN_BUFFER_SIZE, __FUNCTION__, 3)) {
                bufferevent_enable(s->sub_session->peer_s->bev, EV_READ);
                socket_input_handler_bev(s->sub_session->peer_s->bev, s->sub_session->peer_s);
              }
            }
          }
        } else if (s == s->sub_session->peer_s) {
          if (s->sub_session->client_s && s->sub_session->client_s->bev) {
            if (!bufferevent_enabled(s->sub_session->client_s->bev, EV_READ)) {
              if (is_socket_writeable(s->sub_session->client_s, STUN_BUFFER_SIZE, __FUNCTION__, 4)) {
                bufferevent_enable(s->sub_session->client_s->bev, EV_READ);
                socket_input_handler_bev(s->sub_session->client_s->bev, s->sub_session->client_s);
              }
            }
          }
        }
      }
    }
  }
}

static int read_spare_buffer_bev(struct bufferevent *bev) {
  if (bev) {
    char some_buffer[8192];
    bufferevent_read(bev, some_buffer, sizeof(some_buffer));
  }
  return 0;
}

static void socket_input_handler_bev(struct bufferevent *bev, void *arg) {

  if (bev) {

    if (!arg) {
      read_spare_buffer_bev(bev);
      return;
    }

    ioa_socket_handle s = (ioa_socket_handle)arg;

    if (bev != s->bev) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p: wrong bev\n", __FUNCTION__, s);
      read_spare_buffer_bev(bev);
      return;
    }

    if ((s->magic != SOCKET_MAGIC) || (s->done)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s on socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st, s->sat);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
      read_spare_buffer_bev(bev);
      return;
    }

    {
      size_t cycle = 0;
      do {
        if (ioa_socket_tobeclosed(s)) {
          read_spare_buffer_bev(s->bev);
          break;
        }
        if (socket_input_worker(s) <= 0) {
          break;
        }
      } while ((cycle++ < 128) && (s->bev));
    }

    if ((s->magic != SOCKET_MAGIC) || (s->done)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!!%s (1) on socket: %p, st=%d, sat=%d\n", __FUNCTION__, s, s->st, s->sat);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
      return;
    }

    close_ioa_socket_after_processing_if_necessary(s);
  }
}

static void eventcb_bev(struct bufferevent *bev, short events, void *arg) {
  UNUSED_ARG(bev);

  if (events & BEV_EVENT_CONNECTED) {
    // Connect okay
  } else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
    if (arg) {
      ioa_socket_handle s = (ioa_socket_handle)arg;

      if (!is_stream_socket(s->st)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: socket type is wrong on the socket: %p, st=%d, sat=%d\n",
                      __FUNCTION__, s, s->st, s->sat);
        return;
      }

      if (s->magic != SOCKET_MAGIC) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: magic is wrong on the socket: %p, st=%d, sat=%d\n", __FUNCTION__, s,
                      s->st, s->sat);
        return;
      }

      if (s->done) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                      "!!! %s: closed socket: %p (1): done=%d, fd=%d, br=%d, st=%d, sat=%d, tbc=%d\n", __FUNCTION__, s,
                      (int)s->done, (int)s->fd, s->broken, s->st, s->sat, s->tobeclosed);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
        return;
      }

      if (events & BEV_EVENT_ERROR) {
        s->broken = 1;
      }

      s->tobeclosed = 1;

      if (s->special_session) {
        free(s->special_session);
        s->special_session = NULL;
      }
      s->special_session_size = 0;

      if (!(s->session) && !(s->sub_session)) {
        char sraddr[129] = "\0";
        addr_to_string(&(s->remote_addr), (uint8_t *)sraddr);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s https server socket closed: %p, st=%d, sat=%d, remote addr=%s\n",
                      __FUNCTION__, s, get_ioa_socket_type(s), get_ioa_socket_app_type(s), sraddr);
        IOA_CLOSE_SOCKET(s);
        return;
      }

      switch (s->sat) {
      case TCP_CLIENT_DATA_SOCKET:
      case TCP_RELAY_DATA_SOCKET: {
        tcp_connection *tc = s->sub_session;
        if (tc) {
          s->sub_session = NULL;
          delete_tcp_connection(tc);
        }
      } break;
      default: {
        ts_ur_super_session *ss = s->session;
        if (ss) {
          turn_turnserver *server = (turn_turnserver *)ss->server;
          if (server) {

            {
              char sraddr[129] = "\0";
              addr_to_string(&(s->remote_addr), (uint8_t *)sraddr);
              if (events & BEV_EVENT_EOF) {
                if (server->verbose) {
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: %s socket closed remotely %s\n",
                                (unsigned long long)(ss->id), socket_type_name(s->st), sraddr);
                }
                if (s == ss->client_socket) {
                  char msg[256];
                  snprintf(msg, sizeof(msg) - 1, "%s connection closed by client (callback)", socket_type_name(s->st));
                  shutdown_client_connection(server, ss, 0, msg);
                } else if (s == ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].s) {
                  char msg[256];
                  snprintf(msg, sizeof(msg) - 1, "%s connection closed by peer (ipv4 callback)",
                           socket_type_name(s->st));
                  shutdown_client_connection(server, ss, 0, msg);
                } else if (s == ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].s) {
                  char msg[256];
                  snprintf(msg, sizeof(msg) - 1, "%s connection closed by peer (ipv6 callback)",
                           socket_type_name(s->st));
                  shutdown_client_connection(server, ss, 0, msg);
                } else {
                  char msg[256];
                  snprintf(msg, sizeof(msg) - 1, "%s connection closed by remote party (callback)",
                           socket_type_name(s->st));
                  shutdown_client_connection(server, ss, 0, msg);
                }
              } else if (events & BEV_EVENT_ERROR) {
                if (EVUTIL_SOCKET_ERROR()) {
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "session %018llu: %s socket error: %s %s\n",
                                (unsigned long long)(ss->id), socket_type_name(s->st),
                                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()), sraddr);
                } else if (server->verbose) {
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: %s socket disconnected: %s\n",
                                (unsigned long long)(ss->id), socket_type_name(s->st), sraddr);
                }
                char msg[256];
                snprintf(msg, sizeof(msg) - 1, "%s socket buffer operation error (callback)", socket_type_name(s->st));
                shutdown_client_connection(server, ss, 0, msg);
              }
            }
          }
        }
      }
      };
    }
  }
}

static int ssl_send(ioa_socket_handle s, const char *buffer, int len, int verbose) {

  if (!s || !(s->ssl) || !buffer || (s->fd < 0)) {
    return -1;
  }

  SSL *ssl = s->ssl;

  if (eve(verbose)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: before write: buffer=%p, len=%d\n", __FUNCTION__, buffer, len);
  }

  if (s->parent_s) {
    /* Trick only for "children" sockets: */
    BIO *wbio = SSL_get_wbio(ssl);
    if (!wbio) {
      return -1;
    }
    int fd = BIO_get_fd(wbio, 0);
    int sfd = s->parent_s->fd;
    if (sfd >= 0) {
      if (fd != sfd) {
        BIO_set_fd(wbio, sfd, BIO_NOCLOSE);
      }
    }
  } else {
    BIO *wbio = SSL_get_wbio(ssl);
    if (!wbio) {
      return -1;
    }
    int fd = BIO_get_fd(wbio, 0);
    if (fd != s->fd) {
      BIO_set_fd(wbio, s->fd, BIO_NOCLOSE);
    }
  }

  int rc = 0;
  int try_again = 1;

#if !defined(TURN_IP_RECVERR)
  try_again = 0;
#endif

try_start:

  do {
    rc = SSL_write(ssl, buffer, len);
  } while (rc < 0 && socket_eintr());

  if (eve(verbose)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: after write: %d\n", __FUNCTION__, rc);
  }

  if (rc < 0 && (socket_enobufs() || socket_eagain())) {
    if (eve(verbose)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: ENOBUFS/EAGAIN\n", __FUNCTION__);
    }
    return 0;
  }

  if (rc >= 0) {

    if (eve(verbose)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrote %d bytes\n", __FUNCTION__, (int)rc);
    }

    return rc;

  } else {

    if (eve(verbose)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: failure: rc=%d, err=%d\n", __FUNCTION__, (int)rc,
                    (int)SSL_get_error(ssl, rc));
    }

    switch (SSL_get_error(ssl, rc)) {
    case SSL_ERROR_NONE:
      //???
      if (eve(verbose)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "wrote %d bytes\n", (int)rc);
      }
      return 0;
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_WANT_READ:
      return 0;
    case SSL_ERROR_SYSCALL: {
      int err = socket_errno();
      if (!handle_socket_error()) {
        if (s->st == DTLS_SOCKET) {
          if (is_connreset()) {
            if (try_again) {
              BIO *wbio = SSL_get_wbio(ssl);
              if (wbio) {
                int fd = BIO_get_fd(wbio, 0);
                if (fd >= 0) {
                  try_again = 0;
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket, tring to recover write operation...\n");
                  socket_readerr(fd, &(s->local_addr));
                  goto try_start;
                }
              }
            }
          }
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket lost packet... fine\n");
          return 0;
        }
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket write error unrecoverable: %d; buffer=%p, len=%d, ssl=%p\n",
                      err, buffer, (int)len, ssl);
        return -1;
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS Socket write error recoverable: %d\n", err);
        return 0;
      }
    }
    case SSL_ERROR_SSL:
      if (verbose) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: ");
        char buf[65536];
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, rc));
      }
      return -1;
    default:
      if (verbose) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error while writing!\n");
      }
      return -1;
    }
  }
}

static int send_ssl_backlog_buffers(ioa_socket_handle s) {
  int ret = 0;
  if (s) {
    stun_buffer_list_elem *buf_elem = s->bufs.head;
    while (buf_elem) {
      int rc = ssl_send(s, (char *)buf_elem->buf.buf + buf_elem->buf.offset - buf_elem->buf.coffset,
                        (size_t)buf_elem->buf.len, (s->e ? s->e->verbose : TURN_VERBOSE_NONE));
      if (rc < 1) {
        break;
      }
      ++ret;
      pop_elem_from_buffer_list(&(s->bufs));
      buf_elem = s->bufs.head;
    }
  }

  return ret;
}

int is_connreset(void) {
  if (socket_econnreset() || socket_econnrefused()) {
    return 1;
  }
  return 0;
}

int would_block(void) { return socket_ewouldblock(); }

int udp_send(ioa_socket_handle s, const ioa_addr *dest_addr, const char *buffer, int len) {
  int rc = 0;
  evutil_socket_t fd = -1;

  if (!s) {
    return -1;
  }

  if (s->parent_s) {
    fd = s->parent_s->fd;
  } else {
    fd = s->fd;
  }

  if (fd >= 0) {

    int try_again = 1;

    int cycle;

#if !defined(TURN_IP_RECVERR)
    try_again = 0;
#endif

  try_start:

    cycle = 0;

    if (dest_addr) {

      int slen = get_ioa_addr_len(dest_addr);

      do {
        rc = my_sendto(fd, buffer, len, 0, (const struct sockaddr *)dest_addr, (socklen_t)slen);
      } while (((rc < 0) && socket_eintr()) || ((rc < 0) && is_connreset() && (++cycle < TRIAL_EFFORTS_TO_SEND)));

    } else {
      do {
        rc = my_send(fd, buffer, len, 0);
      } while (((rc < 0) && socket_eintr()) || ((rc < 0) && is_connreset() && (++cycle < TRIAL_EFFORTS_TO_SEND)));
    }

    if (rc < 0) {
      if (socket_enobufs() || socket_eagain()) {
        // Lost packet due to overload ... fine.
        rc = len;
      } else if (is_connreset()) {
        if (try_again) {
          try_again = 0;
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "UDP Socket, tring to recover write operation...\n");
          socket_readerr(fd, &(s->local_addr));
          goto try_start;
        }
        // Lost packet - sent to nowhere... fine.
        rc = len;
      }
    }
  }

  return rc;
}

int send_data_from_ioa_socket_nbh(ioa_socket_handle s, ioa_addr *dest_addr, ioa_network_buffer_handle nbh, int ttl,
                                  int tos, int *skip) {
  int ret = -1;

  if (!s) {
    ioa_network_buffer_delete(NULL, nbh);
    return -1;
  }

  if (s->done || (s->fd == -1)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                  "!!! %s: (1) Trying to send data from closed socket: %p (1): done=%d, fd=%d, st=%d, sat=%d\n",
                  __FUNCTION__, s, (int)s->done, (int)s->fd, s->st, s->sat);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);

  } else if (nbh) {
    if (!ioa_socket_check_bandwidth(s, nbh, 0)) {
      /* Bandwidth exhausted, we pretend everything is fine: */
      ret = (int)(ioa_network_buffer_get_size(nbh));
      if (skip) {
        *skip = 1;
      }
    } else {
      if (!ioa_socket_tobeclosed(s) && s->e) {

        if (!(s->done || (s->fd == -1))) {
          set_socket_ttl(s, ttl);
          set_socket_tos(s, tos);

          if (s->connected && s->bev) {
            if ((s->st == TLS_SOCKET) || (s->st == TLS_SCTP_SOCKET)) {
#if TLS_SUPPORTED
              SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
              if (!ctx || SSL_get_shutdown(ctx)) {
                s->tobeclosed = 1;
                ret = 0;
              }
#endif
            }

            if (!(s->tobeclosed)) {

              ret = (int)ioa_network_buffer_get_size(nbh);

              if (!tcp_congestion_control || is_socket_writeable(s, (size_t)ret, __FUNCTION__, 2)) {
                s->in_write = 1;
                if (bufferevent_write(s->bev, ioa_network_buffer_data(nbh), ioa_network_buffer_get_size(nbh)) < 0) {
                  ret = -1;
                  perror("bufev send");
                  log_socket_event(s, "socket write failed, to be closed", 1);
                  s->tobeclosed = 1;
                  s->broken = 1;
                }
                /*
                bufferevent_flush(s->bev,
                                                EV_READ|EV_WRITE,
                                                BEV_FLUSH);
                                                */
                s->in_write = 0;
              } else {
                // drop the packet
                ;
              }
            }
          } else if (s->ssl) {
            send_ssl_backlog_buffers(s);
            ret = ssl_send(s, (char *)ioa_network_buffer_data(nbh), ioa_network_buffer_get_size(nbh),
                           (s->e ? s->e->verbose : TURN_VERBOSE_NONE));
            if (ret < 0) {
              s->tobeclosed = 1;
            } else if (ret == 0) {
              add_buffer_to_buffer_list(&(s->bufs), (char *)ioa_network_buffer_data(nbh),
                                        ioa_network_buffer_get_size(nbh));
            }
          } else if (s->fd >= 0) {

            if (s->connected && !(s->parent_s)) {
              dest_addr = NULL; /* ignore dest_addr */
            } else if (!dest_addr) {
              dest_addr = &(s->remote_addr);
            }

            ret = udp_send(s, dest_addr, (char *)ioa_network_buffer_data(nbh), ioa_network_buffer_get_size(nbh));
            if (ret < 0) {
              s->tobeclosed = 1;
#if defined(EADDRNOTAVAIL)
              int perr = socket_errno();
#endif
              perror("udp send");
#if defined(EADDRNOTAVAIL)
              if (dest_addr && (perr == EADDRNOTAVAIL)) {
                char sfrom[129];
                addr_to_string(&(s->local_addr), (uint8_t *)sfrom);
                char sto[129];
                addr_to_string(dest_addr, (uint8_t *)sto);
                TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: network error: address unreachable from %s to %s\n",
                              __FUNCTION__, sfrom, sto);
              }
#endif
            }
          }
        }
      }
    }
  }

  ioa_network_buffer_delete(s->e, nbh);

  return ret;
}

int send_data_from_ioa_socket_tcp(ioa_socket_handle s, const void *data, size_t sz) {
  int ret = -1;

  if (s && data) {

    if (s->done || (s->fd == -1) || ioa_socket_tobeclosed(s) || !(s->e)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                    "!!! %s: (1) Trying to send data from bad socket: %p (1): done=%d, fd=%d, st=%d, sat=%d\n",
                    __FUNCTION__, s, (int)s->done, (int)s->fd, s->st, s->sat);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);

    } else if (s->connected && s->bev) {
      if ((s->st == TLS_SOCKET) || (s->st == TLS_SCTP_SOCKET)) {
#if TLS_SUPPORTED
        SSL *ctx = bufferevent_openssl_get_ssl(s->bev);
        if (!ctx || SSL_get_shutdown(ctx)) {
          s->tobeclosed = 1;
          ret = 0;
        }
#endif
      }

      if (!(s->tobeclosed)) {

        ret = (int)sz;

        s->in_write = 1;
        if (bufferevent_write(s->bev, data, sz) < 0) {
          ret = -1;
          perror("bufev send");
          log_socket_event(s, "socket write failed, to be closed", 1);
          s->tobeclosed = 1;
          s->broken = 1;
        }
        s->in_write = 0;
      }
    }
  }

  return ret;
}

int send_str_from_ioa_socket_tcp(ioa_socket_handle s, const void *data) {
  if (data) {
    return send_data_from_ioa_socket_tcp(s, data, strlen((const char *)data));
  } else {
    return 0;
  }
}

int send_ulong_from_ioa_socket_tcp(ioa_socket_handle s, size_t data) {
  char str[129];
  snprintf(str, sizeof(str) - 1, "%lu", (unsigned long)data);

  return send_str_from_ioa_socket_tcp(s, str);
}

int register_callback_on_ioa_socket(ioa_engine_handle e, ioa_socket_handle s, int event_type, ioa_net_event_handler cb,
                                    void *ctx, int clean_preexisting) {
  if (s) {

    if (event_type & IOA_EV_READ) {

      if (e) {
        s->e = e;
      }

      if (s->e && !(s->parent_s)) {

        switch (s->st) {
        case DTLS_SOCKET:
        case UDP_SOCKET:
          if (s->read_event) {
            if (!clean_preexisting) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: software error: buffer preset 1\n", __FUNCTION__);
              return -1;
            }
          } else {
              #ifndef USE_FSTACK
                s->read_event = event_new(s->e->event_base, s->fd, EV_READ | EV_PERSIST, socket_input_handler, s);
                if (event_add(s->read_event, NULL)<0) {
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: event_add failed for socket %p\n", __FUNCTION__, s);
                  return -1;
                }else{
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: event_add ok for socket %p\n", __FUNCTION__, s);
                }
              #else
                s->read_event = TRACE_EVENT_NEW(s->e->event_base,s->fd,EV_READ | EV_PERSIST, socket_input_handler, s);
                if (my_event_add(s->read_event,NULL) <0) {
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: my_event_add failed for socket %p\n", __FUNCTION__, s);
                  return -1;
                }else{
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: my_event_add ok for socket %p\n", __FUNCTION__, s);
                } 
            #endif
            
          }
          break;
        case TENTATIVE_TCP_SOCKET:
        case TENTATIVE_SCTP_SOCKET:
          if (s->bev) {
            if (!clean_preexisting) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: software error: buffer preset 2\n", __FUNCTION__);
              return -1;
            }
          } else if (s->read_event) {
            if (!clean_preexisting) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: software error: buffer preset 3\n", __FUNCTION__);
              return -1;
            }
          } else {
            #ifndef USE_FSTACK
              s->read_event = event_new(s->e->event_base, s->fd, EV_READ | EV_PERSIST, socket_input_handler, s);
              event_add(s->read_event, NULL);
            #else
              s->read_event = TRACE_EVENT_NEW(s->e->event_base,s->fd,EV_READ | EV_PERSIST, socket_input_handler, s);
              my_event_add(s->read_event,NULL);
            #endif
          }
          break;
        case SCTP_SOCKET:
        case TCP_SOCKET:
        case TCP_SOCKET_PROXY:
          if (s->bev) {
            if (!clean_preexisting) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: software error: buffer preset 4\n", __FUNCTION__);
              return -1;
            }
          } else {
#if TLS_SUPPORTED
            if ((s->sat != TCP_CLIENT_DATA_SOCKET) && (s->sat != TCP_RELAY_DATA_SOCKET) && check_tentative_tls(s->fd)) {
              s->tobeclosed = 1;
              return -1;
            }
#endif
#ifndef USE_FSTACK
            s->bev = bufferevent_socket_new(s->e->event_base, s->fd, TURN_BUFFEREVENTS_OPTIONS);
            bufferevent_setcb(s->bev, socket_input_handler_bev, socket_output_handler_bev, eventcb_bev, s);
            bufferevent_setwatermark(s->bev, EV_READ | EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
            bufferevent_enable(s->bev, EV_READ | EV_WRITE); /* Start reading. */
#else

        // F-Stack: registra socket para eventos de lectura y escritura
        printf("DEBUG: %s: registering TLS TCP socket %p for read/write events\n", __FUNCTION__, s);
        struct MyEvent *ev = TRACE_EVENT_NEW(s->e->event_base, s->fd, EV_READ | EV_WRITE | EV_PERSIST, my_combined_handler, s);
        if (my_event_add(ev, NULL) < 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: my_event_add failed for socket %p\n", __FUNCTION__, s);
          //return -1;
        }else{
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: my_event_add ok for socket %p\n", __FUNCTION__, s); 
        }
        s->read_event = ev;  // guarda referencia si necesitas desactivar/activar luego

#endif
          }
          break;
        case TLS_SCTP_SOCKET:
        case TLS_SOCKET:
          if (s->bev) {
            if (!clean_preexisting) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: software error: buffer preset 5\n", __FUNCTION__);
              return -1;
            }
          } else {
#if TLS_SUPPORTED
            
            #ifndef USE_FSTACK
            if (!(s->ssl)) {
              //??? how we can get to this point ???
              set_socket_ssl(s, SSL_new(e->tls_ctx));
              s->bev = bufferevent_openssl_socket_new(s->e->event_base, s->fd, s->ssl, BUFFEREVENT_SSL_ACCEPTING,
                                                      TURN_BUFFEREVENTS_OPTIONS);
            } else {
              s->bev = bufferevent_openssl_socket_new(s->e->event_base, s->fd, s->ssl, BUFFEREVENT_SSL_OPEN,
                                                      TURN_BUFFEREVENTS_OPTIONS);
            }
            
            bufferevent_setcb(s->bev, socket_input_handler_bev, socket_output_handler_bev, eventcb_bev, s);
            bufferevent_setwatermark(s->bev, EV_READ | EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
            bufferevent_enable(s->bev, EV_READ | EV_WRITE); /* Start reading. */
            #else

                    // F-Stack: registra socket para eventos de lectura y escritura 
                    printf("DEBUG: %s: registering TLS socket %p for read/write events\n", __FUNCTION__, s);
            struct MyEvent *ev = TRACE_EVENT_NEW(s->e->event_base, s->fd, EV_READ | EV_WRITE | EV_PERSIST, my_combined_handler, s);
            if (my_event_add(ev, NULL) < 0) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: my_event_add failed for socket %p\n", __FUNCTION__, s);
              //return -1;
            }else{
              TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: my_event_add ok for socket %p\n", __FUNCTION__, s);
            }
            s->read_event = ev;  // guarda referencia si necesitas desactivar/activar luego
          #endif
#endif
          }
          break;
        default:
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: software error: unknown socket type: %d\n", __FUNCTION__,
                        (int)(s->st));
          return -1;
        }
      }

      s->read_cb = cb;
      s->read_ctx = ctx;
      printf("DEBUG: %s: registered callback on socket %p, event_type=%d, cb=%p, ctx=%p\n", __FUNCTION__, s, event_type,
             cb, ctx);
      return 0;
    }
  }

  /* unsupported event or else */
  return -1;
}

int ioa_socket_tobeclosed(ioa_socket_handle s) {
  if (s) {
    if (s->magic != SOCKET_MAGIC) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: magic is wrong on the socket: %p, st=%d, sat=%d\n", __FUNCTION__, s,
                    s->st, s->sat);
      return 1;
    }

    if (s->done) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s: check on already closed socket: %p, st=%d, sat=%d\n", __FUNCTION__, s,
                    s->st, s->sat);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "!!! %s socket: %p was closed\n", __FUNCTION__, s);
      return 1;
    }
    if (s->tobeclosed) {
      return 1;
    } else if (s->broken) {
      s->tobeclosed = 1;
      log_socket_event(s, "socket broken", 0);
      return 1;
    } else if (s->fd < 0) {
      s->tobeclosed = 1;
      log_socket_event(s, "socket fd<0", 0);
      return 1;
    } else if (s->ssl) {
      if (SSL_get_shutdown(s->ssl)) {
        s->tobeclosed = 1;
        log_socket_event(s, "socket SSL shutdown", 0);
        return 1;
      }
    }
  }
  return 0;
}

void set_ioa_socket_tobeclosed(ioa_socket_handle s) {
  if (s) {
    s->tobeclosed = 1;
  }
}

/*
 * Network buffer functions
 */
ioa_network_buffer_handle ioa_network_buffer_allocate(ioa_engine_handle e) {
  stun_buffer_list_elem *buf_elem = new_blist_elem(e);
  buf_elem->buf.len = 0;
  buf_elem->buf.offset = 0;
  buf_elem->buf.coffset = 0;
  return buf_elem;
}

/* We do not use special header in this simple implementation */
void ioa_network_buffer_header_init(ioa_network_buffer_handle nbh) { UNUSED_ARG(nbh); }

uint8_t *ioa_network_buffer_data(ioa_network_buffer_handle nbh) {
  stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
  return buf_elem->buf.buf + buf_elem->buf.offset - buf_elem->buf.coffset;
}

size_t ioa_network_buffer_get_size(ioa_network_buffer_handle nbh) {
  if (!nbh) {
    return 0;
  } else {
    stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
    return (size_t)(buf_elem->buf.len);
  }
}

size_t ioa_network_buffer_get_capacity(ioa_network_buffer_handle nbh) {
  if (!nbh) {
    return 0;
  } else {
    stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
    if (buf_elem->buf.offset < STUN_BUFFER_SIZE) {
      return (STUN_BUFFER_SIZE - buf_elem->buf.offset);
    }
    return 0;
  }
}

size_t ioa_network_buffer_get_capacity_udp(void) { return UDP_STUN_BUFFER_SIZE; }

void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len) {
  stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
  buf_elem->buf.len = (size_t)len;
}

void ioa_network_buffer_add_offset_size(ioa_network_buffer_handle nbh, uint16_t offset, uint8_t coffset, size_t len) {
  stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
  buf_elem->buf.len = (size_t)len;
  buf_elem->buf.offset += offset;
  buf_elem->buf.coffset += coffset;

  if ((buf_elem->buf.offset + buf_elem->buf.len - buf_elem->buf.coffset) >= sizeof(buf_elem->buf.buf) ||
      (buf_elem->buf.offset + sizeof(buf_elem->buf.channel) < buf_elem->buf.coffset)) {
    buf_elem->buf.coffset = 0;
    buf_elem->buf.len = 0;
    buf_elem->buf.offset = 0;
  }
}

uint16_t ioa_network_buffer_get_offset(ioa_network_buffer_handle nbh) {
  stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
  return buf_elem->buf.offset;
}

uint8_t ioa_network_buffer_get_coffset(ioa_network_buffer_handle nbh) {
  stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
  return buf_elem->buf.coffset;
}

void ioa_network_buffer_delete(ioa_engine_handle e, ioa_network_buffer_handle nbh) {
  stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
  free_blist_elem(e, buf_elem);
}

/////////// REPORTING STATUS /////////////////////

const char *get_ioa_socket_cipher(ioa_socket_handle s) {
  if (s && s->ssl) {
    return SSL_get_cipher(s->ssl);
  }
  return "no SSL";
}

const char *get_ioa_socket_ssl_method(ioa_socket_handle s) {
  if (s && s->ssl) {
    return turn_get_ssl_method(s->ssl, "UNKNOWN");
  }
  return "no SSL";
}

void stun_report_binding(void *a, STUN_PROMETHEUS_METRIC_TYPE type) {
#if !defined(TURN_NO_PROMETHEUS)
  UNUSED_ARG(a);
  switch (type) {
  case 0:
    prom_inc_stun_binding_request();
    break;
  case 1:
    prom_inc_stun_binding_response();
    break;
  case 2:
    prom_inc_stun_binding_error();
    break;
  default:
    break;
  }
#else
  UNUSED_ARG(a);
  UNUSED_ARG(type);
#endif
}

void turn_report_allocation_set(void *a, turn_time_t lifetime, int refresh) {
  if (a) {
    ts_ur_super_session *ss = (ts_ur_super_session *)(((allocation *)a)->owner);
    if (ss) {
      const char *status = "new";
      if (refresh) {
        status = "refreshed";
      }
      turn_turnserver *server = (turn_turnserver *)ss->server;
      if (server) {
        ioa_engine_handle e = turn_server_get_engine(server);
        if (e && e->verbose && ss->client_socket) {
          if (ss->client_socket->ssl) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                          "session %018llu: %s, realm=<%s>, username=<%s>, lifetime=%lu, cipher=%s, method=%s\n",
                          (unsigned long long)ss->id, status, (char *)ss->realm_options.name, (char *)ss->username,
                          (unsigned long)lifetime, SSL_get_cipher(ss->client_socket->ssl),
                          turn_get_ssl_method(ss->client_socket->ssl, "UNKNOWN"));
          } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: %s, realm=<%s>, username=<%s>, lifetime=%lu\n",
                          (unsigned long long)ss->id, status, (char *)ss->realm_options.name, (char *)ss->username,
                          (unsigned long)lifetime);
          }
        }
#if !defined(TURN_NO_HIREDIS)
        {
          char key[1024];
          if (ss->realm_options.name[0]) {
            snprintf(key, sizeof(key), "turn/realm/%s/user/%s/allocation/%018llu/status", ss->realm_options.name,
                     (char *)ss->username, (unsigned long long)ss->id);
          } else {
            snprintf(key, sizeof(key), "turn/user/%s/allocation/%018llu/status", (char *)ss->username,
                     (unsigned long long)ss->id);
          }
          uint8_t saddr[129];
          uint8_t rsaddr[129];
          addr_to_string(get_local_addr_from_ioa_socket(ss->client_socket), saddr);
          addr_to_string(get_remote_addr_from_ioa_socket(ss->client_socket), rsaddr);
          const char *type = socket_type_name(get_ioa_socket_type(ss->client_socket));
          const char *ssl = ss->client_socket->ssl ? turn_get_ssl_method(ss->client_socket->ssl, "UNKNOWN") : "NONE";
          const char *cipher = ss->client_socket->ssl ? get_ioa_socket_cipher(ss->client_socket) : "NONE";
          send_message_to_redis(e->rch, "set", key, "%s lifetime=%lu, type=%s, local=%s, remote=%s, ssl=%s, cipher=%s",
                                status, (unsigned long)lifetime, type, saddr, rsaddr, ssl, cipher);
          send_message_to_redis(e->rch, "publish", key,
                                "%s lifetime=%lu, type=%s, local=%s, remote=%s, ssl=%s, cipher=%s", status,
                                (unsigned long)lifetime, type, saddr, rsaddr, ssl, cipher);
        }
#endif
        {
          if (!refresh) {
            prom_inc_allocation(get_ioa_socket_type(ss->client_socket));
          }
        }
      }
    }
  }
}

void turn_report_allocation_delete(void *a, SOCKET_TYPE socket_type) {
  if (a) {
    ts_ur_super_session *ss = (ts_ur_super_session *)(((allocation *)a)->owner);
    if (ss) {
      turn_turnserver *server = (turn_turnserver *)ss->server;
      if (server) {
        ioa_engine_handle e = turn_server_get_engine(server);
        if (e && e->verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: delete: realm=<%s>, username=<%s>\n",
                        (unsigned long long)ss->id, (char *)ss->realm_options.name, (char *)ss->username);
        }
#if !defined(TURN_NO_HIREDIS)
        {
          char key[1024];
          if (ss->realm_options.name[0]) {
            snprintf(key, sizeof(key), "turn/realm/%s/user/%s/allocation/%018llu/status", ss->realm_options.name,
                     (char *)ss->username, (unsigned long long)ss->id);
          } else {
            snprintf(key, sizeof(key), "turn/user/%s/allocation/%018llu/status", (char *)ss->username,
                     (unsigned long long)ss->id);
          }
          send_message_to_redis(e->rch, "del", key, "");
          send_message_to_redis(e->rch, "publish", key, "deleted");

          // report total traffic usage for this allocation
          if (ss->realm_options.name[0]) {
            snprintf(key, sizeof(key), "turn/realm/%s/user/%s/allocation/%018llu/total_traffic", ss->realm_options.name,
                     (char *)ss->username, (unsigned long long)ss->id);
          } else {
            snprintf(key, sizeof(key), "turn/user/%s/allocation/%018llu/total_traffic", (char *)ss->username,
                     (unsigned long long)ss->id);
          }
          send_message_to_redis(e->rch, "publish", key, "rcvp=%lu, rcvb=%lu, sentp=%lu, sentb=%lu",
                                (unsigned long)(ss->t_received_packets), (unsigned long)(ss->t_received_bytes),
                                (unsigned long)(ss->t_sent_packets), (unsigned long)(ss->t_sent_bytes));
          if (ss->realm_options.name[0]) {
            snprintf(key, sizeof(key), "turn/realm/%s/user/%s/allocation/%018llu/total_traffic/peer",
                     ss->realm_options.name, (char *)ss->username, (unsigned long long)(ss->id));
          } else {
            snprintf(key, sizeof(key), "turn/user/%s/allocation/%018llu/total_traffic/peer", (char *)ss->username,
                     (unsigned long long)(ss->id));
          }
          send_message_to_redis(e->rch, "publish", key, "rcvp=%lu, rcvb=%lu, sentp=%lu, sentb=%lu",
                                (unsigned long)(ss->t_peer_received_packets),
                                (unsigned long)(ss->t_peer_received_bytes), (unsigned long)(ss->t_peer_sent_packets),
                                (unsigned long)(ss->t_peer_sent_bytes));
        }
#endif
        {
          if (ss->realm_options.name[0]) {

            // Set prometheus traffic metrics
            prom_set_finished_traffic(ss->realm_options.name, (const char *)ss->username,
                                      (unsigned long)(ss->t_received_packets), (unsigned long)(ss->t_received_bytes),
                                      (unsigned long)(ss->t_sent_packets), (unsigned long)(ss->t_sent_bytes), false);
            prom_set_finished_traffic(
                ss->realm_options.name, (const char *)ss->username, (unsigned long)(ss->t_peer_received_packets),
                (unsigned long)(ss->t_peer_received_bytes), (unsigned long)(ss->t_peer_sent_packets),
                (unsigned long)(ss->t_peer_sent_bytes), true);
          } else {
            // Set prometheus traffic metrics
            prom_set_finished_traffic(NULL, (const char *)ss->username, (unsigned long)(ss->t_received_packets),
                                      (unsigned long)(ss->t_received_bytes), (unsigned long)(ss->t_sent_packets),
                                      (unsigned long)(ss->t_sent_bytes), false);
            prom_set_finished_traffic(NULL, (const char *)ss->username, (unsigned long)(ss->t_peer_received_packets),
                                      (unsigned long)(ss->t_peer_received_bytes),
                                      (unsigned long)(ss->t_peer_sent_packets), (unsigned long)(ss->t_peer_sent_bytes),
                                      true);
          }
          prom_dec_allocation(socket_type);
        }
      }
    }
  }
}

void turn_report_session_usage(void *session, int force_invalid) {
  if (session) {
    ts_ur_super_session *ss = (ts_ur_super_session *)session;
    turn_turnserver *server = (turn_turnserver *)ss->server;
    if (server && (ss->received_packets || ss->sent_packets || force_invalid)) {
      ioa_engine_handle e = turn_server_get_engine(server);
      if (((ss->received_packets + ss->sent_packets + ss->peer_received_packets + ss->peer_sent_packets) & 4095) == 0 ||
          force_invalid) {
        if (e && e->verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                        "session %018llu: usage: realm=<%s>, username=<%s>, rp=%lu, rb=%lu, sp=%lu, sb=%lu\n",
                        (unsigned long long)(ss->id), (char *)ss->realm_options.name, (char *)ss->username,
                        (unsigned long)(ss->received_packets), (unsigned long)(ss->received_bytes),
                        (unsigned long)(ss->sent_packets), (unsigned long)(ss->sent_bytes));
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                        "session %018llu: peer usage: realm=<%s>, username=<%s>, rp=%lu, rb=%lu, sp=%lu, sb=%lu\n",
                        (unsigned long long)(ss->id), (char *)ss->realm_options.name, (char *)ss->username,
                        (unsigned long)(ss->peer_received_packets), (unsigned long)(ss->peer_received_bytes),
                        (unsigned long)(ss->peer_sent_packets), (unsigned long)(ss->peer_sent_bytes));
        }
#if !defined(TURN_NO_HIREDIS)
        {
          char key[1024];
          if (ss->realm_options.name[0]) {
            snprintf(key, sizeof(key), "turn/realm/%s/user/%s/allocation/%018llu/traffic", ss->realm_options.name,
                     (char *)ss->username, (unsigned long long)(ss->id));
          } else {
            snprintf(key, sizeof(key), "turn/user/%s/allocation/%018llu/traffic", (char *)ss->username,
                     (unsigned long long)(ss->id));
          }
          send_message_to_redis(e->rch, "publish", key, "rcvp=%lu, rcvb=%lu, sentp=%lu, sentb=%lu",
                                (unsigned long)(ss->received_packets), (unsigned long)(ss->received_bytes),
                                (unsigned long)(ss->sent_packets), (unsigned long)(ss->sent_bytes));
          if (ss->realm_options.name[0]) {
            snprintf(key, sizeof(key), "turn/realm/%s/user/%s/allocation/%018llu/traffic/peer", ss->realm_options.name,
                     (char *)ss->username, (unsigned long long)(ss->id));
          } else {
            snprintf(key, sizeof(key), "turn/user/%s/allocation/%018llu/traffic/peer", (char *)ss->username,
                     (unsigned long long)(ss->id));
          }
          send_message_to_redis(e->rch, "publish", key, "rcvp=%lu, rcvb=%lu, sentp=%lu, sentb=%lu",
                                (unsigned long)(ss->peer_received_packets), (unsigned long)(ss->peer_received_bytes),
                                (unsigned long)(ss->peer_sent_packets), (unsigned long)(ss->peer_sent_bytes));
        }
#endif
        ss->t_received_packets += ss->received_packets;
        ss->t_received_bytes += ss->received_bytes;
        ss->t_sent_packets += ss->sent_packets;
        ss->t_sent_bytes += ss->sent_bytes;
        ss->t_peer_received_packets += ss->peer_received_packets;
        ss->t_peer_received_bytes += ss->peer_received_bytes;
        ss->t_peer_sent_packets += ss->peer_sent_packets;
        ss->t_peer_sent_bytes += ss->peer_sent_bytes;

        {
          turn_time_t ct = get_turn_server_time(server);
          if (ct != ss->start_time) {
            ct = ct - ss->start_time;
            ss->received_rate = (uint32_t)(ss->t_received_bytes / ct);
            ss->sent_rate = (uint32_t)(ss->t_sent_bytes / ct);
            ss->total_rate = ss->received_rate + ss->sent_rate;
            ss->peer_received_rate = (uint32_t)(ss->t_peer_received_bytes / ct);
            ss->peer_sent_rate = (uint32_t)(ss->t_peer_sent_bytes / ct);
            ss->peer_total_rate = ss->peer_received_rate + ss->peer_sent_rate;
          }
        }

        report_turn_session_info(server, ss, force_invalid);

        ss->received_packets = 0;
        ss->received_bytes = 0;
        ss->sent_packets = 0;
        ss->sent_bytes = 0;
        ss->peer_received_packets = 0;
        ss->peer_received_bytes = 0;
        ss->peer_sent_packets = 0;
        ss->peer_sent_bytes = 0;
      }
    }
  }
}

/////////////// SSL ///////////////////

const char *get_ioa_socket_tls_cipher(ioa_socket_handle s) {
  if (s && (s->ssl)) {
    return SSL_get_cipher(s->ssl);
  }
  return "";
}

const char *get_ioa_socket_tls_method(ioa_socket_handle s) {
  if (s && (s->ssl)) {
    return turn_get_ssl_method(s->ssl, "UNKNOWN");
  }
  return "";
}

///////////// Super Memory Region //////////////

#define TURN_SM_SIZE (1024 << 11)

struct _super_memory {
  TURN_MUTEX_DECLARE(mutex_sm)
  char **super_memory;
  size_t *sm_allocated;
  size_t sm_total_sz;
  size_t sm_chunk;
  uint32_t id;
};

static void init_super_memory_region(super_memory_t *r) {
  if (r) {
    r->super_memory = (char **)malloc(sizeof(char *));
    r->super_memory[0] = (char *)calloc(1, TURN_SM_SIZE);

    r->sm_allocated = (size_t *)malloc(sizeof(size_t));
    r->sm_allocated[0] = 0;

    r->sm_total_sz = TURN_SM_SIZE;
    r->sm_chunk = 0;

    while (r->id == 0) {
      r->id = (uint32_t)turn_random();
    }

    TURN_MUTEX_INIT(&r->mutex_sm);
  }
}

void init_super_memory(void) { ; }

super_memory_t *new_super_memory_region(void) {
  super_memory_t *r = (super_memory_t *)calloc(1, sizeof(super_memory_t));
  init_super_memory_region(r);
  return r;
}

void *allocate_super_memory_region_func(super_memory_t *r, size_t size, const char *file, const char *func, int line) {
  UNUSED_ARG(file);
  UNUSED_ARG(func);
  UNUSED_ARG(line);

  void *ret = NULL;

  if (!r) {
    ret = calloc(1, size);
    return ret;
  }

  TURN_MUTEX_LOCK(&r->mutex_sm);

  size = ((size_t)((size + sizeof(void *)) / (sizeof(void *)))) * sizeof(void *);

  if (size >= TURN_SM_SIZE) {

    TURN_LOG_FUNC(
        TURN_LOG_LEVEL_INFO,
        "(%s:%s:%d): Size too large for super memory: region id = %u, chunk=%lu, total=%lu, allocated=%lu, want=%lu\n",
        file, func, line, (unsigned int)r->id, (unsigned long)r->sm_chunk, (unsigned long)r->sm_total_sz,
        (unsigned long)r->sm_allocated[r->sm_chunk], (unsigned long)size);

  } else {

    size_t i = 0;
    char *region = NULL;
    size_t *rsz = NULL;
    for (i = 0; i <= r->sm_chunk; ++i) {

      size_t left = (size_t)r->sm_total_sz - r->sm_allocated[i];

      if (left < size + sizeof(void *)) {
        continue;
      } else {
        region = r->super_memory[i];
        rsz = r->sm_allocated + i;
        break;
      }
    }

    if (!region) {
      r->sm_chunk += 1;
      r->super_memory = (char **)realloc(r->super_memory, (r->sm_chunk + 1) * sizeof(char *));
      r->super_memory[r->sm_chunk] = (char *)calloc(1, TURN_SM_SIZE);
      r->sm_allocated = (size_t *)realloc(r->sm_allocated, (r->sm_chunk + 1) * sizeof(size_t));
      r->sm_allocated[r->sm_chunk] = 0;
      region = r->super_memory[r->sm_chunk];
      rsz = r->sm_allocated + r->sm_chunk;
    }

    {
      char *ptr = region + *rsz;

      memset(ptr, 0, size);

      *rsz += size;

      ret = ptr;
    }
  }

  TURN_MUTEX_UNLOCK(&r->mutex_sm);

  if (!ret) {
    ret = calloc(1, size);
  }

  return ret;
}

void *allocate_super_memory_engine_func(ioa_engine_handle e, size_t size, const char *file, const char *func,
                                        int line) {
  if (e) {
    return allocate_super_memory_region_func(e->sm, size, file, func, line);
  }
  return allocate_super_memory_region_func(NULL, size, file, func, line);
}

//////////////////////////////////////////////////
