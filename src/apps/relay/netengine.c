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

#include "wrappers.h"
#include "mainrelay.h"

#include "ns_turn_ioalib.h"

//////////// Backward compatibility with OpenSSL 1.0.x //////////////
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER <= 0x3040000fL
#define SSL_CTX_up_ref(ctx) CRYPTO_add(&(ctx)->references, 1, CRYPTO_LOCK_SSL_CTX)
#endif

//////////// Barrier for the threads //////////////

#if !defined(TURN_NO_THREAD_BARRIERS)
static unsigned int barrier_count = 0;
static pthread_barrier_t barrier;
#endif

////////////// Auth Server ////////////////

typedef unsigned char authserver_id;

struct auth_server {
  authserver_id id;
  
  #ifndef USE_FSTACK
    struct event_base *event_base;
    struct bufferevent *in_buf;
    struct bufferevent *out_buf;
  #else
    struct MyEventBase *event_base;
    listener_fifo_t *in_buf;
    listener_fifo_t *out_buf;
  #endif
  pthread_t thr;
  redis_context_handle rch;
};

#define MIN_AUTHSERVER_NUMBER (3)
static authserver_id authserver_number = MIN_AUTHSERVER_NUMBER;
static struct auth_server authserver[256];

//////////////////////////////////////////////

#define get_real_general_relay_servers_number()                                                                        \
  (turn_params.general_relay_servers_number > 1 ? turn_params.general_relay_servers_number : 1)
#define get_real_udp_relay_servers_number()                                                                            \
  (turn_params.udp_relay_servers_number > 1 ? turn_params.udp_relay_servers_number : 1)

static struct relay_server *general_relay_servers[1 + ((turnserver_id)-1)];
static struct relay_server *udp_relay_servers[1 + ((turnserver_id)-1)];

static struct relay_server *get_relay_server(turnserver_id id);

//////////////////////////////////////////////

static void run_events(
  #ifndef USE_FSTACK
  struct event_base *eb,
  #else
  struct MyEventBase *eb,
  #endif
  ioa_engine_handle e);
static void setup_relay_server(struct relay_server *rs, ioa_engine_handle e, int to_set_rfc5780);

/////////////// BARRIERS ///////////////////

#if !defined(PTHREAD_BARRIER_SERIAL_THREAD)
#define PTHREAD_BARRIER_SERIAL_THREAD (-1)
#endif

static void barrier_wait_func(const char *func, int line) {
#if !defined(TURN_NO_THREAD_BARRIERS)
  int br = 0;
  do {
    br = pthread_barrier_wait(&barrier);
    if ((br < 0) && (br != PTHREAD_BARRIER_SERIAL_THREAD)) {
      int err = socket_errno();
      perror("barrier wait");
      printf("%s:%s:%d: %d\n", __FUNCTION__, func, line, err);
    }
  } while (((br < 0) && (br != PTHREAD_BARRIER_SERIAL_THREAD)) && socket_eintr());
#else
  UNUSED_ARG(func);
  UNUSED_ARG(line);
  sleep(5);
#endif
}

#define barrier_wait() barrier_wait_func(__FUNCTION__, __LINE__)

/////////////// Bandwidth //////////////////

static TURN_MUTEX_DECLARE(mutex_bps);

static band_limit_t allocate_bps(band_limit_t bps, int positive) {
  band_limit_t ret = 0;
  if (bps > 0) {
    TURN_MUTEX_LOCK(&mutex_bps);

    if (positive) {

      if (!(turn_params.bps_capacity)) {
        ret = bps;
        turn_params.bps_capacity_allocated += ret;
      } else if (turn_params.bps_capacity_allocated < turn_params.bps_capacity) {
        band_limit_t reserve = turn_params.bps_capacity - turn_params.bps_capacity_allocated;
        if (reserve <= bps) {
          ret = reserve;
          turn_params.bps_capacity_allocated = turn_params.bps_capacity;
        } else {
          ret = bps;
          turn_params.bps_capacity_allocated += ret;
        }
      }

    } else {

      if (turn_params.bps_capacity_allocated >= bps) {
        turn_params.bps_capacity_allocated -= bps;
      } else {
        turn_params.bps_capacity_allocated = 0;
      }
    }

    TURN_MUTEX_UNLOCK(&mutex_bps);
  }

  return ret;
}

band_limit_t get_bps_capacity_allocated(void) {
  band_limit_t ret = 0;
  TURN_MUTEX_LOCK(&mutex_bps);
  ret = turn_params.bps_capacity_allocated;
  TURN_MUTEX_UNLOCK(&mutex_bps);
  return ret;
}

band_limit_t get_bps_capacity(void) {
  band_limit_t ret = 0;
  TURN_MUTEX_LOCK(&mutex_bps);
  ret = turn_params.bps_capacity;
  TURN_MUTEX_UNLOCK(&mutex_bps);
  return ret;
}

void set_bps_capacity(band_limit_t value) {
  TURN_MUTEX_LOCK(&mutex_bps);
  turn_params.bps_capacity = value;
  TURN_MUTEX_UNLOCK(&mutex_bps);
}

band_limit_t get_max_bps(void) {
  band_limit_t ret = 0;
  TURN_MUTEX_LOCK(&mutex_bps);
  ret = turn_params.max_bps;
  TURN_MUTEX_UNLOCK(&mutex_bps);
  return ret;
}

void set_max_bps(band_limit_t value) {
  TURN_MUTEX_LOCK(&mutex_bps);
  turn_params.max_bps = value;
  TURN_MUTEX_UNLOCK(&mutex_bps);
}

/////////////// AUX SERVERS ////////////////

static void add_aux_server_list(const char *saddr, turn_server_addrs_list_t *list) {
  if (saddr && list) {
    ioa_addr addr;
    if (make_ioa_addr_from_full_string((const uint8_t *)saddr, 0, &addr) != 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong full address format: %s\n", saddr);
    } else {
      list->addrs = (ioa_addr *)realloc(list->addrs, sizeof(ioa_addr) * (list->size + 1));
      addr_cpy(&(list->addrs[(list->size)++]), &addr);
      {
        uint8_t s[1025];
        addr_to_string(&addr, s);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Aux server: %s\n", s);
      }
    }
  }
}

void add_aux_server(const char *saddr) { add_aux_server_list(saddr, &turn_params.aux_servers_list); }

/////////////// ALTERNATE SERVERS ////////////////

static void add_alt_server(const char *saddr, int default_port, turn_server_addrs_list_t *list) {
  if (saddr && list) {
    ioa_addr addr;

    TURN_MUTEX_LOCK(&(list->m));

    if (make_ioa_addr_from_full_string((const uint8_t *)saddr, default_port, &addr) != 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong IP address format: %s\n", saddr);
    } else {
      list->addrs = (ioa_addr *)realloc(list->addrs, sizeof(ioa_addr) * (list->size + 1));
      addr_cpy(&(list->addrs[(list->size)++]), &addr);
      {
        uint8_t s[1025];
        addr_to_string(&addr, s);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Alternate server added: %s\n", s);
      }
    }

    TURN_MUTEX_UNLOCK(&(list->m));
  }
}

static void del_alt_server(const char *saddr, int default_port, turn_server_addrs_list_t *list) {
  if (saddr && list && list->size && list->addrs) {

    ioa_addr addr;

    TURN_MUTEX_LOCK(&(list->m));

    if (make_ioa_addr_from_full_string((const uint8_t *)saddr, default_port, &addr) != 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong IP address format: %s\n", saddr);
    } else {

      size_t i;
      for (i = 0; i < list->size; ++i) {
        if (addr_eq(&(list->addrs[i]), &addr)) {
          break;
        }
      }

      if (i < list->size) {

        ioa_addr *new_addrs = (ioa_addr *)malloc(sizeof(ioa_addr) * (list->size - 1));
        if (!new_addrs) {
          return;
        }
        for (size_t j = 0; j < i; ++j) {
          addr_cpy(&(new_addrs[j]), &(list->addrs[j]));
        }
        for (size_t j = i; j < list->size - 1; ++j) {
          addr_cpy(&(new_addrs[j]), &(list->addrs[j + 1]));
        }

        free(list->addrs);
        list->addrs = new_addrs;
        list->size -= 1;

        {
          uint8_t s[1025];
          addr_to_string(&addr, s);
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Alternate server removed: %s\n", s);
        }
      }
    }

    TURN_MUTEX_UNLOCK(&(list->m));
  }
}

void add_alternate_server(const char *saddr) {
  add_alt_server(saddr, DEFAULT_STUN_PORT, &turn_params.alternate_servers_list);
}

void del_alternate_server(const char *saddr) {
  del_alt_server(saddr, DEFAULT_STUN_PORT, &turn_params.alternate_servers_list);
}

void add_tls_alternate_server(const char *saddr) {
  add_alt_server(saddr, DEFAULT_STUN_TLS_PORT, &turn_params.tls_alternate_servers_list);
}

void del_tls_alternate_server(const char *saddr) {
  del_alt_server(saddr, DEFAULT_STUN_TLS_PORT, &turn_params.tls_alternate_servers_list);
}

//////////////////////////////////////////////////

typedef struct update_ssl_ctx_cb_args {
  ioa_engine_handle engine;
  turn_params_t *params;
  #ifndef USE_FSTACK
  struct event *next;
  #else 
  struct MyEvent *next;
  #endif
} update_ssl_ctx_cb_args_t;

/*
 * Copy SSL context at "from", which may be NULL if no context in use
 */
static void replace_one_ssl_ctx(SSL_CTX **to, SSL_CTX *from) {
  if (*to) {
    SSL_CTX_free(*to);
  }

  if (from != NULL) {
    SSL_CTX_up_ref(from);
  }

  *to = from;
}

/*
 * Synchronise the ioa_engine's SSL certificates with the global ones
 */
static void update_ssl_ctx(evutil_socket_t sock, short events, update_ssl_ctx_cb_args_t *args) {
  ioa_engine_handle e = args->engine;
  turn_params_t *params = args->params;

  /* No mutex with "e" as these are only used in the same event loop */
  TURN_MUTEX_LOCK(&turn_params.tls_mutex);
  replace_one_ssl_ctx(&e->tls_ctx, params->tls_ctx);
#if DTLS_SUPPORTED
  replace_one_ssl_ctx(&e->dtls_ctx, params->dtls_ctx);
#endif
#ifndef USE_FSTACK
  struct event *next = args->next;
#else
  struct MyEvent *next = args->next;
#endif
  TURN_MUTEX_UNLOCK(&turn_params.tls_mutex);
#ifndef USE_FSTACK
  if (next != NULL) {
    event_active(next, EV_READ, 0);
  }
#endif
  UNUSED_ARG(sock);
  UNUSED_ARG(events);
}

void set_ssl_ctx(ioa_engine_handle e, turn_params_t *params) {
  update_ssl_ctx_cb_args_t *args = (update_ssl_ctx_cb_args_t *)malloc(sizeof(update_ssl_ctx_cb_args_t));
  args->engine = e;
  args->params = params;
  args->next = NULL;

  update_ssl_ctx(-1, 0, args);
  #ifndef USE_FSTACK
    struct event_base *base = e->event_base;
  #else
    struct MyEventBase *base = e->event_base;
  #endif
  if (base != NULL) {
    #ifndef USE_FSTACK
      struct event *ev = event_new(base, -1, EV_PERSIST, (event_callback_fn)update_ssl_ctx, (void *)args);
    #else
      struct MyEvent *ev = TRACE_EVENT_NEW(base,-1,EV_PERSIST,(event_callback_fn)update_ssl_ctx,(void *)args);
    #endif
    TURN_MUTEX_LOCK(&turn_params.tls_mutex);
    args->next = params->tls_ctx_update_ev;
    params->tls_ctx_update_ev = ev;
    TURN_MUTEX_UNLOCK(&turn_params.tls_mutex);
  } else {
    if (args) {
      free(args);
    }
  }
}

//////////////////////////////////////////////////

void add_listener_addr(const char *addr) {
  ioa_addr baddr;
  if (make_ioa_addr((const uint8_t *)addr, 0, &baddr) < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot add a listener address: %s\n", addr);
  } else {

    char sbaddr[129];
    addr_to_string_no_port(&baddr, (uint8_t *)sbaddr);

    size_t i = 0;
    for (i = 0; i < turn_params.listener.addrs_number; ++i) {
      if (addr_eq(turn_params.listener.encaddrs[i], &baddr)) {
        return;
      }
    }
    ++turn_params.listener.addrs_number;
    ++turn_params.listener.services_number;
    turn_params.listener.addrs =
        (char **)realloc(turn_params.listener.addrs, sizeof(char *) * turn_params.listener.addrs_number);
    turn_params.listener.addrs[turn_params.listener.addrs_number - 1] = strdup(sbaddr);
    turn_params.listener.encaddrs =
        (ioa_addr **)realloc(turn_params.listener.encaddrs, sizeof(ioa_addr *) * turn_params.listener.addrs_number);
    turn_params.listener.encaddrs[turn_params.listener.addrs_number - 1] = (ioa_addr *)malloc(sizeof(ioa_addr));
    addr_cpy(turn_params.listener.encaddrs[turn_params.listener.addrs_number - 1], &baddr);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Listener address to use: %s\n", sbaddr);
  }
}

int add_relay_addr(const char *addr) {
  ioa_addr baddr;
  if (make_ioa_addr((const uint8_t *)addr, 0, &baddr) < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot add a relay address: %s\n", addr);
    return -1;
  } else {

    char sbaddr[129];
    addr_to_string_no_port(&baddr, (uint8_t *)sbaddr);

    size_t i = 0;
    for (i = 0; i < turn_params.relays_number; ++i) {
      if (!strcmp(turn_params.relay_addrs[i], sbaddr)) {
        return 0;
      }
    }

    ++turn_params.relays_number;
    turn_params.relay_addrs = (char **)realloc(turn_params.relay_addrs, sizeof(char *) * turn_params.relays_number);
    turn_params.relay_addrs[turn_params.relays_number - 1] = strdup(sbaddr);

    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Relay address to use: %s\n", sbaddr);
    return 1;
  }
}

static void allocate_relay_addrs_ports(void) {
  int i;
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Wait for relay ports initialization...\n");
  for (i = 0; i < (int)turn_params.relays_number; i++) {
    ioa_addr baddr;
    if (make_ioa_addr((const uint8_t *)turn_params.relay_addrs[i], 0, &baddr) >= 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "  relay %s initialization...\n", turn_params.relay_addrs[i]);
      turnipports_add_ip(STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE, &baddr);
      turnipports_add_ip(STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE, &baddr);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "  relay %s initialization done\n", turn_params.relay_addrs[i]);
    }
  }
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Relay ports initialization done\n");
}

//////////////////////////////////////////////////

// communications between listener and relays ==>>

static int handle_relay_message(relay_server_handle rs, struct message_to_relay *sm);

static struct relay_server *get_relay_server(turnserver_id id) {
  struct relay_server *rs = NULL;
  if (id >= TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP) {
    size_t dest = id - TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP;
    if (dest >= get_real_udp_relay_servers_number()) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Too large UDP relay number: %d, total=%d\n", __FUNCTION__, (int)dest,
                    (int)get_real_udp_relay_servers_number());
    }
    rs = udp_relay_servers[dest];
    if (!rs) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong UDP relay number: %d, total=%d\n", __FUNCTION__, (int)dest,
                    (int)get_real_udp_relay_servers_number());
    }
  } else {
    size_t dest = id;
    if (dest >= get_real_general_relay_servers_number()) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Too large general relay number: %d, total=%d\n", __FUNCTION__, (int)dest,
                    (int)get_real_general_relay_servers_number());
    }
    rs = general_relay_servers[dest];
    if (!rs) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong general relay number: %d, total=%d\n", __FUNCTION__, (int)dest,
                    (int)get_real_general_relay_servers_number());
    }
  }
  return rs;
}

static TURN_MUTEX_DECLARE(auth_message_counter_mutex);
static authserver_id auth_message_counter = 1;

void send_auth_message_to_auth_server(struct auth_message *am) {
    TURN_MUTEX_LOCK(&auth_message_counter_mutex);
    if (auth_message_counter >= authserver_number) {
        auth_message_counter = 1;
    } else if (auth_message_counter < 1) {
        auth_message_counter = 1;
    }
    authserver_id sn = auth_message_counter++;
    TURN_MUTEX_UNLOCK(&auth_message_counter_mutex);

    #ifndef USE_FSTACK
    struct evbuffer *output = bufferevent_get_output(authserver[sn].out_buf);
    if (evbuffer_add(output, am, sizeof(struct auth_message)) < 0) {
      fprintf(stderr, "%s: Weird buffer error\n", __FUNCTION__);
    }
    #else
    if (authserver[sn].out_buf) {
        struct auth_message *copy = malloc(sizeof(*copy));
        if (!copy) {
            fprintf(stderr, "%s: Failed to allocate auth_message\n", __FUNCTION__);
            return;
        }
        memcpy(copy, am, sizeof(*copy));
        printf("AUTH: Enviando mensaje de autenticación a authserver[%d] para usuario '%s', realm '%s'\n", (int)sn, am->username, am->realm);
        if (my_fifo_push(authserver[sn].out_buf->fifo, copy) < 0) {
            fprintf(stderr, "%s: FIFO full, dropping message\n", __FUNCTION__);
            free(copy);
        }
    } else {
        fprintf(stderr, "%s: out_buf is NULL for auth server %d\n", __FUNCTION__, (int)sn);
    }
    #endif
}

#ifndef USE_FSTACK
  static void auth_server_receive_message(struct bufferevent *bev, void *ptr) {
    printf("Entrando en %s\n", __FUNCTION__);
    UNUSED_ARG(ptr);

    struct auth_message am;
    int n = 0;
    struct evbuffer *input = bufferevent_get_input(bev);

    while ((n = evbuffer_remove(input, &am, sizeof(struct auth_message))) > 0) {
      if (n != sizeof(struct auth_message)) {
        fprintf(stderr, "%s: Weird buffer error: size=%d\n", __FUNCTION__, n);
        continue;
      }

      {
        hmackey_t key;
        if (get_user_key(am.in_oauth, &(am.out_oauth), &(am.max_session_time), am.username, am.realm, key,
                        am.in_buffer.nbh) < 0) {
          am.success = 0;
        } else {
          memcpy(am.key, key, sizeof(hmackey_t));
          am.success = 1;
        }
      }

      struct evbuffer *output = NULL;
      struct relay_server *relay_server = get_relay_server(am.id);
      if (relay_server) {
        output = bufferevent_get_output(relay_server->auth_out_buf);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: can't find relay for turn_server_id: %d\n", __FUNCTION__, (int)am.id);
      }

      if (output) {
        evbuffer_add(output, &am, sizeof(struct auth_message));
      } else {
        ioa_network_buffer_delete(NULL, am.in_buffer.nbh);
        am.in_buffer.nbh = NULL;
      }
    }
  }
#else
void auth_server_receive_message_from_fifo(listener_fifo_t *lf, void *ptr) {
    UNUSED_ARG(ptr);

    struct auth_message *am;

    while ((am = (struct auth_message *)my_fifo_pop(lf->fifo)) != NULL) {
        printf("AUTH: Recibido mensaje en auth_server_receive_message_from_fifo para usuario '%s', realm '%s'\n", am->username, am->realm);

        hmackey_t key;
        //DEBUG: Verificar si el usuario está en static_accounts
        ur_string_map_value_type ukey = NULL;
if (ur_string_map_get(turn_params.default_users_db.ram_db.static_accounts, (ur_string_map_key_type)am->username, &ukey)) {
    printf("DEBUG: Usuario '%s' encontrado en static_accounts\n", am->username);
} else {
    printf("DEBUG: Usuario '%s' NO encontrado en static_accounts\n", am->username);
}
        printf("DEBUG: Esto se está lanzando?\n");
        int res = get_user_key(am->in_oauth, &(am->out_oauth), &(am->max_session_time),
                               am->username, am->realm, key, am->in_buffer.nbh);
        if (res < 0) {
            am->success = 0;
            printf("AUTH: Falló autenticación para usuario '%s', realm '%s'\n", am->username, am->realm);
        } else {
            memcpy(am->key, key, sizeof(hmackey_t));
            am->success = 1;
            printf("AUTH: Autenticación exitosa para usuario '%s', realm '%s'\n", am->username, am->realm);
        }

        struct relay_server *relay_server = get_relay_server(am->id);
        if (relay_server && relay_server->auth_out_buf) {
            printf("DEBUG: relay_server_id=%d, auth_out_buf=%p\n", (int)relay_server->id, (void*)relay_server->auth_out_buf);
            struct auth_message *copy = malloc(sizeof(*copy));
            if (copy) {
                memcpy(copy, am, sizeof(*am));
                printf("AUTH: Enviando respuesta de autenticación a relay_server %d\n", (int)am->id);
                if(my_fifo_push(relay_server->auth_out_buf->fifo, copy) < 0) {
                    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: FIFO full, dropping message\n", __FUNCTION__);
                    free(copy);
                }
            }
        } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: can't find relay for turn_server_id: %d\n", __FUNCTION__, (int)am->id);
            ioa_network_buffer_delete(NULL, am->in_buffer.nbh);
            am->in_buffer.nbh = NULL;
        }

        free(am);  // importante: liberar el original
    }
}
#endif

static int send_socket_to_general_relay(ioa_engine_handle e, struct message_to_relay *sm) {
  struct relay_server *rdest = sm->relay_server;
  printf("LOG: %s: Sending socket to general relay server\n", __FUNCTION__);
  if (!rdest) {
    size_t dest = (hash_int32(addr_get_port(&(sm->m.sm.nd.src_addr)))) % get_real_general_relay_servers_number();
    rdest = general_relay_servers[dest];
  }

  struct message_to_relay *smptr = sm;

  smptr->t = RMT_SOCKET;

    
  int success = 0;

  if (!rdest) {
    goto label_end;
  }

#ifndef USE_FSTACK
  struct evbuffer *output = bufferevent_get_output(rdest->out_buf);
  if (output) {
    if (evbuffer_add(output, smptr, sizeof(struct message_to_relay)) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot add message to relay output buffer\n", __FUNCTION__);
    } else {
      success = 1;
      printf("LOG: %s: Message added to relay output buffer\n", __FUNCTION__);
      smptr->m.sm.nd.nbh = NULL;
    }
  }
#else
  if (rdest->out_buf) {
    struct message_to_relay *copy = malloc(sizeof(*copy));
    if (!copy) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Failed to allocate message copy\n", __FUNCTION__);
    } else {
      memcpy(copy, smptr, sizeof(*copy));
      if (my_fifo_push(rdest->out_buf->fifo, copy) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: FIFO full, dropping message\n", __FUNCTION__);
        free(copy);
      } else {
        success = 1;
        smptr->m.sm.nd.nbh = NULL;
      }
    }
  }
#endif

label_end:

  if (!success) {
    ioa_network_buffer_delete(e, smptr->m.sm.nd.nbh);
    smptr->m.sm.nd.nbh = NULL;
    IOA_CLOSE_SOCKET(smptr->m.sm.s);
    return -1;
  }

  return 0;
}

static int send_socket_to_relay(turnserver_id id, uint64_t cid, stun_tid *tid, ioa_socket_handle s,
                                int message_integrity, MESSAGE_TO_RELAY_TYPE rmt, ioa_net_data *nd, int can_resume) {
  int ret = -1;
  printf("Entrando en %s\n",__FUNCTION__);
  struct message_to_relay sm;
  memset(&sm, 0, sizeof(struct message_to_relay));
  sm.t = rmt;

  ioa_socket_handle s_to_delete = s;

  struct relay_server *rs = get_relay_server(id);
  if (!rs) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: can't find relay for turn_server_id: %d\n", __FUNCTION__, (int)id);
    goto err;
  }

  switch (rmt) {
  case RMT_CB_SOCKET:
    if (nd && nd->nbh) {
      sm.m.cb_sm.id = id;
      sm.m.cb_sm.connection_id = (tcp_connection_id)cid;
      stun_tid_cpy(&(sm.m.cb_sm.tid), tid);
      sm.m.cb_sm.s = s;
      sm.m.cb_sm.message_integrity = message_integrity;

      addr_cpy(&(sm.m.cb_sm.nd.src_addr), &(nd->src_addr));
      sm.m.cb_sm.nd.recv_tos = nd->recv_tos;
      sm.m.cb_sm.nd.recv_ttl = nd->recv_ttl;
      sm.m.cb_sm.nd.nbh = nd->nbh;
      sm.m.cb_sm.can_resume = can_resume;

      nd->nbh = NULL;
      s_to_delete = NULL;
      ret = 0;
    }
    break;

  case RMT_MOBILE_SOCKET:
    if (nd && nd->nbh) {
      sm.m.sm.s = s;
      addr_cpy(&(sm.m.sm.nd.src_addr), &(nd->src_addr));
      sm.m.sm.nd.recv_tos = nd->recv_tos;
      sm.m.sm.nd.recv_ttl = nd->recv_ttl;
      sm.m.sm.nd.nbh = nd->nbh;
      sm.m.sm.can_resume = can_resume;

      nd->nbh = NULL;
      s_to_delete = NULL;
      ret = 0;
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Empty buffer with mobile socket\n", __FUNCTION__);
    }
    break;

  default:
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: UNKNOWN RMT message: %d\n", __FUNCTION__, (int)rmt);
    break;
  }

  if (ret == 0) {
#ifndef USE_FSTACK
    struct evbuffer *output = bufferevent_get_output(rs->out_buf);
    if (output) {
      evbuffer_add(output, &sm, sizeof(struct message_to_relay));
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Empty output buffer\n", __FUNCTION__);
      ret = -1;
      s_to_delete = s;
    }
#else
    if (rs->out_buf) {
      struct message_to_relay *copy = malloc(sizeof(*copy));
      if (!copy) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Failed to allocate message copy\n", __FUNCTION__);
        ret = -1;
        s_to_delete = s;
      } else {
        memcpy(copy, &sm, sizeof(*copy));
        if (my_fifo_push(rs->out_buf->fifo, copy) < 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: FIFO full, dropping message\n", __FUNCTION__);
          free(copy);
          ret = -1;
          s_to_delete = s;
        }
      }
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: out_buf is NULL for relay\n", __FUNCTION__);
      ret = -1;
      s_to_delete = s;
    }
#endif
  }

err:

  IOA_CLOSE_SOCKET(s_to_delete);
  if (nd && nd->nbh) {
    ioa_network_buffer_delete(NULL, nd->nbh);
    nd->nbh = NULL;
  }

  if (ret < 0) {
    if (rmt == RMT_MOBILE_SOCKET) {
      ioa_network_buffer_delete(NULL, sm.m.sm.nd.nbh);
      sm.m.sm.nd.nbh = NULL;
    } else if (rmt == RMT_CB_SOCKET) {
      ioa_network_buffer_delete(NULL, sm.m.cb_sm.nd.nbh);
      sm.m.cb_sm.nd.nbh = NULL;
    }
  }

  return ret;
}


int send_session_cancellation_to_relay(turnsession_id sid) {
  int ret = 0;
  printf("Entrando en %s\n",__FUNCTION__);
  struct message_to_relay sm;
  memset(&sm, 0, sizeof(struct message_to_relay));
  sm.t = RMT_CANCEL_SESSION;

  turnserver_id id = (turnserver_id)(sid / TURN_SESSION_ID_FACTOR);

  struct relay_server *rs = get_relay_server(id);
  if (!rs) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: can't find relay for turn_server_id: %d\n", __FUNCTION__, (int)id);
    ret = -1;
    goto err;
  }

  sm.relay_server = rs;
  sm.m.csm.id = sid;

#ifndef USE_FSTACK
  struct evbuffer *output = bufferevent_get_output(rs->out_buf);
  if (output) {
    evbuffer_add(output, &sm, sizeof(struct message_to_relay));
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Empty output buffer\n", __FUNCTION__);
    ret = -1;
  }
#else
  if (rs->out_buf) {
    struct message_to_relay *copy = malloc(sizeof(*copy));
    if (!copy) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Failed to allocate message copy\n", __FUNCTION__);
      ret = -1;
    } else {
      memcpy(copy, &sm, sizeof(*copy));
      if (my_fifo_push(rs->out_buf->fifo, copy) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: FIFO full, dropping message\n", __FUNCTION__);
        free(copy);
        ret = -1;
      }
    }
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: out_buf is NULL for relay\n", __FUNCTION__);
    ret = -1;
  }
#endif

err:
  return ret;
}

static int handle_relay_message(relay_server_handle rs, struct message_to_relay *sm) {
  if (rs && sm) {

    switch (sm->t) {

    case RMT_CANCEL_SESSION: {
      turn_cancel_session(&(rs->server), sm->m.csm.id);
    } break;
    case RMT_SOCKET: {

      if (sm->m.sm.s->defer_nbh) {
        if (!sm->m.sm.nd.nbh) {
          sm->m.sm.nd.nbh = sm->m.sm.s->defer_nbh;
          sm->m.sm.s->defer_nbh = NULL;
        } else {
          ioa_network_buffer_delete(rs->ioa_eng, sm->m.sm.s->defer_nbh);
          sm->m.sm.s->defer_nbh = NULL;
        }
      }

      ioa_socket_handle s = sm->m.sm.s;

      if (!s) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: socket EMPTY\n", __FUNCTION__);
      } else if (s->read_event || s->bev) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: socket wrongly preset: %p : %p\n", __FUNCTION__, s->read_event,
                      s->bev);
        IOA_CLOSE_SOCKET(s);
        sm->m.sm.s = NULL;
      } else {
        s->e = rs->ioa_eng;
        if (open_client_connection_session(&(rs->server), &(sm->m.sm)) < 0) {
          IOA_CLOSE_SOCKET(s);
          sm->m.sm.s = NULL;
        }
      }

      ioa_network_buffer_delete(rs->ioa_eng, sm->m.sm.nd.nbh);
      sm->m.sm.nd.nbh = NULL;
    } break;
    case RMT_CB_SOCKET:

      turnserver_accept_tcp_client_data_connection(
          &(rs->server), sm->m.cb_sm.connection_id, &(sm->m.cb_sm.tid), sm->m.cb_sm.s, sm->m.cb_sm.message_integrity,
          &(sm->m.cb_sm.nd),
          /*sm->m.cb_sm.can_resume*/
          /* Note: we cannot resume this call, it must be authenticated in-place.
           * There are two reasons for that:
           * 1) Technical. That's very difficult with the current code structure.
           * 2) Security (more important). We do not want 'stealing' connections between the users.
           * */
          0);

      ioa_network_buffer_delete(rs->ioa_eng, sm->m.cb_sm.nd.nbh);
      sm->m.cb_sm.nd.nbh = NULL;

      break;
    case RMT_MOBILE_SOCKET: {

      ioa_socket_handle s = sm->m.sm.s;

      if (!s) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: mobile socket EMPTY\n", __FUNCTION__);
      } else if (s->read_event || s->bev) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: mobile socket wrongly preset: %p : %p\n", __FUNCTION__, s->read_event,
                      s->bev);
        IOA_CLOSE_SOCKET(s);
        sm->m.sm.s = NULL;
      } else {
        s->e = rs->ioa_eng;
        if (open_client_connection_session(&(rs->server), &(sm->m.sm)) < 0) {
          IOA_CLOSE_SOCKET(s);
          sm->m.sm.s = NULL;
        }
      }

      ioa_network_buffer_delete(rs->ioa_eng, sm->m.sm.nd.nbh);
      sm->m.sm.nd.nbh = NULL;
      break;
    }
    default: {
      perror("Weird buffer type\n");
    }
    }
  }else{
    printf("DEBUG: No se recibió un mensaje de relay\n");
  }

  return 0;
}

static void handle_relay_auth_message(struct relay_server *rs, struct auth_message *am) {
  am->resume_func(am->success, am->out_oauth, am->max_session_time, am->key, am->pwd, &(rs->server), am->ctxkey,
                  &(am->in_buffer), am->realm);
  if (am->in_buffer.nbh) {
    ioa_network_buffer_delete(rs->ioa_eng, am->in_buffer.nbh);
    am->in_buffer.nbh = NULL;
  }
}
#ifndef USE_FSTACK
  static void relay_receive_message(struct bufferevent *bev, void *ptr) {
    struct message_to_relay sm;
    int n = 0;
    struct evbuffer *input = bufferevent_get_input(bev);
    struct relay_server *rs = (struct relay_server *)ptr;

    while ((n = evbuffer_remove(input, &sm, sizeof(struct message_to_relay))) > 0) {

      if (n != sizeof(struct message_to_relay)) {
        perror("Weird buffer error\n");
        continue;
      }

      handle_relay_message(rs, &sm);
    }
  }

  static void relay_receive_auth_message(struct bufferevent *bev, void *ptr) {
    struct auth_message am;
    int n = 0;
    struct evbuffer *input = bufferevent_get_input(bev);
    struct relay_server *rs = (struct relay_server *)ptr;

    while ((n = evbuffer_remove(input, &am, sizeof(struct auth_message))) > 0) {

      if (n != sizeof(struct auth_message)) {
        perror("Weird auth_buffer error\n");
        continue;
      }

      handle_relay_auth_message(rs, &am);
    }
  }
#else
  void relay_receive_message_from_fifo(listener_fifo_t *lf, void *ptr) {
    printf("LOG: %s: relay_receive_message_from_fifo\n", __FUNCTION__);
    struct relay_server *rs = (struct relay_server *)ptr;
    struct message_to_relay *sm;

    while ((sm = (struct message_to_relay *)my_fifo_pop(lf->fifo)) != NULL) {
      handle_relay_message(rs, sm);
      free(sm);  // muy importante
    }
  }

void relay_receive_auth_message_from_fifo(listener_fifo_t *lf, void *ptr) {
    printf("LOG: %s: Mensaje recibido\n",__FUNCTION__);
    struct relay_server *rs = (struct relay_server *)ptr;
    struct auth_message *am;

    while ((am = (struct auth_message *)my_fifo_pop(lf->fifo)) != NULL) {
        printf("AUTH: relay_receive_auth_message_from_fifo para usuario '%s', realm '%s', success=%d\n", am->username, am->realm, am->success);
        handle_relay_auth_message(rs, am);
        free(am);  // liberar si fue malloc() al enviar
    }
}
#endif
static int send_message_from_listener_to_client(ioa_engine_handle e, ioa_network_buffer_handle nbh, ioa_addr *origin,
                                                ioa_addr *destination) {
  printf("Entrando en %s\n",__FUNCTION__);
  struct message_to_listener mm;
  memset(&mm, 0, sizeof(mm));

  mm.t = LMT_TO_CLIENT;
  addr_cpy(&(mm.m.tc.origin), origin);
  addr_cpy(&(mm.m.tc.destination), destination);

  mm.m.tc.nbh = ioa_network_buffer_allocate(e);
  ioa_network_buffer_header_init(mm.m.tc.nbh);
  memcpy(ioa_network_buffer_data(mm.m.tc.nbh), ioa_network_buffer_data(nbh), ioa_network_buffer_get_size(nbh));
  ioa_network_buffer_set_size(mm.m.tc.nbh, ioa_network_buffer_get_size(nbh));

#ifndef USE_FSTACK
  struct evbuffer *output = bufferevent_get_output(turn_params.listener.out_buf);
  if (output) {
    evbuffer_add(output, &mm, sizeof(struct message_to_listener));
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Empty listener output buffer\n", __FUNCTION__);
  }
#else
  if (turn_params.listener.out_buf) {
    struct message_to_listener *copy = malloc(sizeof(*copy));
    if (!copy) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Failed to allocate message copy\n", __FUNCTION__);
    } else {
      memcpy(copy, &mm, sizeof(*copy));
      if (my_fifo_push(turn_params.listener.out_buf->fifo, copy) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: FIFO full, dropping message\n", __FUNCTION__);
        free(copy);
      }
    }
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: listener.out_buf is NULL\n", __FUNCTION__);
  }
#endif

  return 0;
}

static void listener_receive_message(
#ifndef USE_FSTACK
    struct bufferevent *bev,
#else
    listener_fifo_t *lf,
#endif
    void *ptr) {

  UNUSED_ARG(ptr);

  struct message_to_listener mm;
  int n = 0;

#ifndef USE_FSTACK
  struct evbuffer *input = bufferevent_get_input(bev);

  while ((n = evbuffer_remove(input, &mm, sizeof(struct message_to_listener))) > 0) {
    if (n != sizeof(struct message_to_listener)) {
      perror("Weird buffer error\n");
      continue;
    }
#else
  struct message_to_listener *msg;
  while ((msg = (struct message_to_listener *)my_fifo_pop(lf->fifo)) != NULL) {
    memcpy(&mm, msg, sizeof(mm));
    free(msg);
#endif

    if (mm.t != LMT_TO_CLIENT) {
      perror("Weird buffer type\n");
      continue;
    }

    size_t relay_thread_index = 0;

    if (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_THREAD) {
      for (size_t ri = 0; ri < get_real_general_relay_servers_number(); ri++) {
        if (!(general_relay_servers[ri])) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong general relay number: %zu, total %d\n",
                        __FUNCTION__, (size_t)ri, get_real_general_relay_servers_number());
        } else if (pthread_equal(general_relay_servers[ri]->thr, pthread_self())) {
          relay_thread_index = ri;
          break;
        }
      }
    }

    int found = 0;
    for (size_t i = 0; i < turn_params.listener.addrs_number; i++) {
      if (addr_eq_no_port(turn_params.listener.encaddrs[i], &mm.m.tc.origin)) {
        int o_port = addr_get_port(&mm.m.tc.origin);
        if (turn_params.listener.addrs_number == turn_params.listener.services_number) {
          if (o_port == turn_params.listener_port) {
            if (turn_params.listener.udp_services && turn_params.listener.udp_services[i] &&
                turn_params.listener.udp_services[i][relay_thread_index]) {
              found = 1;
              udp_send_message(turn_params.listener.udp_services[i][relay_thread_index], mm.m.tc.nbh,
                               &mm.m.tc.destination);
            }
          } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong origin port(1): %d\n", __FUNCTION__, o_port);
          }
        } else if ((turn_params.listener.addrs_number * 2) == turn_params.listener.services_number) {
          if (o_port == turn_params.listener_port) {
            if (turn_params.listener.udp_services && turn_params.listener.udp_services[i * 2] &&
                turn_params.listener.udp_services[i * 2][relay_thread_index]) {
              found = 1;
              udp_send_message(turn_params.listener.udp_services[i * 2][relay_thread_index], mm.m.tc.nbh,
                               &mm.m.tc.destination);
            }
          } else if (o_port == get_alt_listener_port()) {
            if (turn_params.listener.udp_services && turn_params.listener.udp_services[i * 2 + 1] &&
                turn_params.listener.udp_services[i * 2 + 1][relay_thread_index]) {
              found = 1;
              udp_send_message(turn_params.listener.udp_services[i * 2 + 1][relay_thread_index], mm.m.tc.nbh,
                               &mm.m.tc.destination);
            }
          } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong origin port(2): %d\n", __FUNCTION__, o_port);
          }
        } else {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong listener setup\n", __FUNCTION__);
        }
        break;
      }
    }

    if (!found) {
      uint8_t saddr[129];
      addr_to_string(&mm.m.tc.origin, saddr);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot find local source %s\n", __FUNCTION__, saddr);
    }

    ioa_network_buffer_delete(turn_params.listener.ioa_eng, mm.m.tc.nbh);
    mm.m.tc.nbh = NULL;
  }
}
// <<== communications between listener and relays

static ioa_engine_handle create_new_listener_engine(void) {
  #ifndef USE_FSTACK
    struct event_base *eb = turn_event_base_new();
  #else
    printf("Y esta otra basura?\n");
    struct MyEventBase *eb = my_event_base_new();
  #endif
  super_memory_t *sm = new_super_memory_region();
  ioa_engine_handle e =
      create_ioa_engine(sm, eb, turn_params.listener.tp, turn_params.relay_ifname, turn_params.relays_number,
                        turn_params.relay_addrs, turn_params.default_relays, turn_params.verbose
#if !defined(TURN_NO_HIREDIS)
                        ,
                        &turn_params.redis_statsdb
#endif
      );
  set_ssl_ctx(e, &turn_params);
  ioa_engine_set_rtcp_map(e, turn_params.listener.rtcpmap);
  return e;
}

static void *run_udp_listener_thread(void *arg) {
#ifdef USE_FSTACK
  //ff_thread_init();
#endif
  static int always_true = 1;

  ignore_sigpipe();

  barrier_wait();

  dtls_listener_relay_server_type *server = (dtls_listener_relay_server_type *)arg;

  while (always_true && server) {
    run_events(NULL, get_engine(server));
  }

  return arg;
}

static void setup_listener(void) {
  super_memory_t *sm = new_super_memory_region();

  turn_params.listener.tp = turnipports_create(sm, turn_params.min_port, turn_params.max_port);
#ifndef USE_FSTACK 
  turn_params.listener.event_base = turn_event_base_new();
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IO method: %s\n", event_base_get_method(turn_params.listener.event_base)); 
#else
  turn_params.listener.event_base = my_event_base_new();
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IO method: F-stack Epoll");
#endif

  turn_params.listener.ioa_eng = create_ioa_engine(
      sm, turn_params.listener.event_base, turn_params.listener.tp, turn_params.relay_ifname, turn_params.relays_number,
      turn_params.relay_addrs, turn_params.default_relays, turn_params.verbose
#if !defined(TURN_NO_HIREDIS)
      ,
      &turn_params.redis_statsdb
#endif
  );

  if (!turn_params.listener.ioa_eng) {
    exit(-1);
  }

  set_ssl_ctx(turn_params.listener.ioa_eng, &turn_params);
  turn_params.listener.rtcpmap = rtcp_map_create(turn_params.listener.ioa_eng);
  ioa_engine_set_rtcp_map(turn_params.listener.ioa_eng, turn_params.listener.rtcpmap);

  {
    #ifndef USE_FSTACK
    struct bufferevent *pair[2];

      bufferevent_pair_new(turn_params.listener.event_base, TURN_BUFFEREVENTS_OPTIONS, pair);
      turn_params.listener.in_buf = pair[0];
      turn_params.listener.out_buf = pair[1];
      bufferevent_setcb(turn_params.listener.in_buf, listener_receive_message, NULL, NULL, &turn_params.listener);
      bufferevent_enable(turn_params.listener.in_buf, EV_READ);
    #else
      listener_fifo_t *lf = create_listener_fifo(listener_receive_message, &turn_params.listener);
      register_listener_fifo(lf);
      turn_params.listener.in_buf = lf;
      turn_params.listener.out_buf = lf;
    #endif
  }

  if (turn_params.rfc5780 == true) {
    if (turn_params.listener.addrs_number < 2 || turn_params.external_ip) {
      turn_params.rfc5780 = false;
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "STUN CHANGE_REQUEST not supported: only one IP address is provided\n");
    } else {
      turn_params.listener.services_number = turn_params.listener.services_number * 2;
    }
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "RFC5780 disabled! /NAT behavior discovery/\n");
  }

  turn_params.listener.udp_services = (dtls_listener_relay_server_type ***)allocate_super_memory_engine(
      turn_params.listener.ioa_eng, sizeof(dtls_listener_relay_server_type **) * turn_params.listener.services_number);
  turn_params.listener.dtls_services = (dtls_listener_relay_server_type ***)allocate_super_memory_engine(
      turn_params.listener.ioa_eng, sizeof(dtls_listener_relay_server_type **) * turn_params.listener.services_number);

  turn_params.listener.aux_udp_services = (dtls_listener_relay_server_type ***)allocate_super_memory_engine(
      turn_params.listener.ioa_eng,
      (sizeof(dtls_listener_relay_server_type **) * turn_params.aux_servers_list.size) + sizeof(void *));
}

static void setup_barriers(void) {
  /* Adjust barriers: */

#if !defined(TURN_NO_THREAD_BARRIERS)

  if ((turn_params.net_engine_version == NEV_UDP_SOCKET_PER_ENDPOINT) && turn_params.general_relay_servers_number > 1) {

    /* UDP: */
    if (!turn_params.no_udp) {

      barrier_count += turn_params.listener.addrs_number;

      if (turn_params.rfc5780) {
        barrier_count += turn_params.listener.addrs_number;
      }
    }

    if (!turn_params.no_dtls && (turn_params.no_udp || (turn_params.listener_port != turn_params.tls_listener_port))) {

      barrier_count += turn_params.listener.addrs_number;

      if (turn_params.rfc5780) {
        barrier_count += turn_params.listener.addrs_number;
      }
    }

    if (!turn_params.no_udp || !turn_params.no_dtls) {
      barrier_count += (unsigned int)turn_params.aux_servers_list.size;
    }
  }
#endif

#if !defined(TURN_NO_THREAD_BARRIERS)
  {
    if (pthread_barrier_init(&barrier, NULL, barrier_count) != 0) {
      perror("barrier init");
    }
  }

#endif
}

static void setup_socket_per_endpoint_udp_listener_servers(void) {
  size_t i = 0;

  /* Adjust udp relay number */

  if (turn_params.general_relay_servers_number > 1) {

    if (!turn_params.no_udp) {

      turn_params.udp_relay_servers_number += turn_params.listener.addrs_number;

      if (turn_params.rfc5780) {
        turn_params.udp_relay_servers_number += turn_params.listener.addrs_number;
      }
    }

    if (!turn_params.no_dtls && (turn_params.no_udp || (turn_params.listener_port != turn_params.tls_listener_port))) {

      turn_params.udp_relay_servers_number += turn_params.listener.addrs_number;

      if (turn_params.rfc5780) {
        turn_params.udp_relay_servers_number += turn_params.listener.addrs_number;
      }
    }

    if (!turn_params.no_udp || !turn_params.no_dtls) {
      turn_params.udp_relay_servers_number += (unsigned int)turn_params.aux_servers_list.size;
    }
  }

  {
    if (!turn_params.no_udp || !turn_params.no_dtls) {

      for (i = 0; i < get_real_udp_relay_servers_number(); i++) {

        ioa_engine_handle e = turn_params.listener.ioa_eng;
        int is_5780 = turn_params.rfc5780;

        if (turn_params.general_relay_servers_number <= 1) {
          while (!(general_relay_servers[0]->ioa_eng)) {
            sched_yield();
          }
          udp_relay_servers[i] = general_relay_servers[0];
          continue;
        } else if (turn_params.general_relay_servers_number > 1) {
          e = create_new_listener_engine();
          is_5780 = is_5780 && (i >= (size_t)(turn_params.aux_servers_list.size));
        }

        super_memory_t *sm = new_super_memory_region();
        struct relay_server *udp_rs =
            (struct relay_server *)allocate_super_memory_region(sm, sizeof(struct relay_server));
        udp_rs->id = (turnserver_id)i + TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP;
        udp_rs->sm = sm;
        setup_relay_server(udp_rs, e, is_5780);
        udp_relay_servers[i] = udp_rs;
      }
    }
  }

  int udp_relay_server_index = 0;

  /* Create listeners */

  /* Aux UDP servers */
  for (i = 0; i < turn_params.aux_servers_list.size; i++) {

    size_t index = i;

    if (!turn_params.no_udp || !turn_params.no_dtls) {

      ioa_addr addr;
      char saddr[129];
      addr_cpy(&addr, &turn_params.aux_servers_list.addrs[i]);
      int port = (int)addr_get_port(&addr);
      addr_to_string_no_port(&addr, (uint8_t *)saddr);

      turn_params.listener.aux_udp_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          udp_relay_servers[udp_relay_server_index]->ioa_eng, sizeof(dtls_listener_relay_server_type *));
      turn_params.listener.aux_udp_services[index][0] =
          create_dtls_listener_server(turn_params.listener_ifname, saddr, port, turn_params.verbose,
                                      udp_relay_servers[udp_relay_server_index]->ioa_eng,
                                      &(udp_relay_servers[udp_relay_server_index]->server), 1, NULL);

      if (turn_params.general_relay_servers_number > 1) {
        ++udp_relay_server_index;
        pthread_t thr;
        if (pthread_create(&thr, NULL, run_udp_listener_thread, turn_params.listener.aux_udp_services[index][0])) {
          perror("Cannot create aux listener thread\n");
          exit(-1);
        }
        pthread_detach(thr);
      }
    }
  }

  /* Main servers */
  for (i = 0; i < turn_params.listener.addrs_number; i++) {

    int index = turn_params.rfc5780 ? i * 2 : i;

    /* UDP: */
    if (!turn_params.no_udp) {

      turn_params.listener.udp_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          udp_relay_servers[udp_relay_server_index]->ioa_eng, sizeof(dtls_listener_relay_server_type *));
      turn_params.listener.udp_services[index][0] = create_dtls_listener_server(
          turn_params.listener_ifname, turn_params.listener.addrs[i], turn_params.listener_port, turn_params.verbose,
          udp_relay_servers[udp_relay_server_index]->ioa_eng, &(udp_relay_servers[udp_relay_server_index]->server), 1,
          NULL);

      if (turn_params.general_relay_servers_number > 1) {
        ++udp_relay_server_index;
        pthread_t thr;
        if (pthread_create(&thr, NULL, run_udp_listener_thread, turn_params.listener.udp_services[index][0])) {
          perror("Cannot create listener thread\n");
          exit(-1);
        }
        pthread_detach(thr);
      }

      if (turn_params.rfc5780) {

        turn_params.listener.udp_services[index + 1] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
            udp_relay_servers[udp_relay_server_index]->ioa_eng, sizeof(dtls_listener_relay_server_type *));
        turn_params.listener.udp_services[index + 1][0] = create_dtls_listener_server(
            turn_params.listener_ifname, turn_params.listener.addrs[i], get_alt_listener_port(), turn_params.verbose,
            udp_relay_servers[udp_relay_server_index]->ioa_eng, &(udp_relay_servers[udp_relay_server_index]->server), 1,
            NULL);

        if (turn_params.general_relay_servers_number > 1) {
          ++udp_relay_server_index;
          pthread_t thr;
          if (pthread_create(&thr, NULL, run_udp_listener_thread, turn_params.listener.udp_services[index + 1][0])) {
            perror("Cannot create listener thread\n");
            exit(-1);
          }
          pthread_detach(thr);
        }
      }
    } else {
      turn_params.listener.udp_services[index] = NULL;
      if (turn_params.rfc5780) {
        turn_params.listener.udp_services[index + 1] = NULL;
      }
    }
    if (!turn_params.no_dtls && (turn_params.no_udp || (turn_params.listener_port != turn_params.tls_listener_port))) {

      turn_params.listener.dtls_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          udp_relay_servers[udp_relay_server_index]->ioa_eng, sizeof(dtls_listener_relay_server_type *));
      turn_params.listener.dtls_services[index][0] = create_dtls_listener_server(
          turn_params.listener_ifname, turn_params.listener.addrs[i], turn_params.tls_listener_port,
          turn_params.verbose, udp_relay_servers[udp_relay_server_index]->ioa_eng,
          &(udp_relay_servers[udp_relay_server_index]->server), 1, NULL);

      if (turn_params.general_relay_servers_number > 1) {
        ++udp_relay_server_index;
        pthread_t thr;
        if (pthread_create(&thr, NULL, run_udp_listener_thread, turn_params.listener.dtls_services[index][0])) {
          perror("Cannot create listener thread\n");
          exit(-1);
        }
        pthread_detach(thr);
      }

      if (turn_params.rfc5780) {

        turn_params.listener.dtls_services[index + 1] =
            (dtls_listener_relay_server_type **)allocate_super_memory_engine(
                udp_relay_servers[udp_relay_server_index]->ioa_eng, sizeof(dtls_listener_relay_server_type *));
        turn_params.listener.dtls_services[index + 1][0] = create_dtls_listener_server(
            turn_params.listener_ifname, turn_params.listener.addrs[i], get_alt_tls_listener_port(),
            turn_params.verbose, udp_relay_servers[udp_relay_server_index]->ioa_eng,
            &(udp_relay_servers[udp_relay_server_index]->server), 1, NULL);

        if (turn_params.general_relay_servers_number > 1) {
          ++udp_relay_server_index;
          pthread_t thr;
          if (pthread_create(&thr, NULL, run_udp_listener_thread, turn_params.listener.dtls_services[index + 1][0])) {
            perror("Cannot create listener thread\n");
            exit(-1);
          }
          pthread_detach(thr);
        }
      }
    } else {
      turn_params.listener.dtls_services[index] = NULL;
      if (turn_params.rfc5780) {
        turn_params.listener.dtls_services[index + 1] = NULL;
      }
    }
  }
}

static void setup_socket_per_thread_udp_listener_servers(void) {
  size_t i = 0;
  size_t relayindex = 0;

  /* Create listeners */

  for (relayindex = 0; relayindex < get_real_general_relay_servers_number(); relayindex++) {
    while (!(general_relay_servers[relayindex]->ioa_eng) || !(general_relay_servers[relayindex]->server.e)) {
      sched_yield();
    }
  }

  /* Aux UDP servers */
  for (i = 0; i < turn_params.aux_servers_list.size; i++) {

    int index = i;

    if (!turn_params.no_udp || !turn_params.no_dtls) {

      ioa_addr addr;
      char saddr[129];
      addr_cpy(&addr, &turn_params.aux_servers_list.addrs[i]);
      int port = (int)addr_get_port(&addr);
      addr_to_string_no_port(&addr, (uint8_t *)saddr);

      turn_params.listener.aux_udp_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          turn_params.listener.ioa_eng,
          sizeof(dtls_listener_relay_server_type *) * get_real_general_relay_servers_number());

      for (relayindex = 0; relayindex < get_real_general_relay_servers_number(); relayindex++) {
        turn_params.listener.aux_udp_services[index][relayindex] = create_dtls_listener_server(
            turn_params.listener_ifname, saddr, port, turn_params.verbose, general_relay_servers[relayindex]->ioa_eng,
            &(general_relay_servers[relayindex]->server), !relayindex, NULL);
      }
    }
  }

  /* Main servers */
  for (i = 0; i < turn_params.listener.addrs_number; i++) {

    int index = turn_params.rfc5780 ? i * 2 : i;

    /* UDP: */
    if (!turn_params.no_udp) {

      turn_params.listener.udp_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          turn_params.listener.ioa_eng,
          sizeof(dtls_listener_relay_server_type *) * get_real_general_relay_servers_number());

      for (relayindex = 0; relayindex < get_real_general_relay_servers_number(); relayindex++) {
        turn_params.listener.udp_services[index][relayindex] = create_dtls_listener_server(
            turn_params.listener_ifname, turn_params.listener.addrs[i], turn_params.listener_port, turn_params.verbose,
            general_relay_servers[relayindex]->ioa_eng, &(general_relay_servers[relayindex]->server), !relayindex,
            NULL);
      }

      if (turn_params.rfc5780) {

        turn_params.listener.udp_services[index + 1] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
            turn_params.listener.ioa_eng,
            sizeof(dtls_listener_relay_server_type *) * get_real_general_relay_servers_number());

        for (relayindex = 0; relayindex < get_real_general_relay_servers_number(); relayindex++) {
          turn_params.listener.udp_services[index + 1][relayindex] = create_dtls_listener_server(
              turn_params.listener_ifname, turn_params.listener.addrs[i], get_alt_listener_port(), turn_params.verbose,
              general_relay_servers[relayindex]->ioa_eng, &(general_relay_servers[relayindex]->server), !relayindex,
              NULL);
        }
      }
    } else {
      turn_params.listener.udp_services[index] = NULL;
      if (turn_params.rfc5780) {
        turn_params.listener.udp_services[index + 1] = NULL;
      }
    }
    if (!turn_params.no_dtls && (turn_params.no_udp || (turn_params.listener_port != turn_params.tls_listener_port))) {

      turn_params.listener.dtls_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          turn_params.listener.ioa_eng,
          sizeof(dtls_listener_relay_server_type *) * get_real_general_relay_servers_number());

      for (relayindex = 0; relayindex < get_real_general_relay_servers_number(); relayindex++) {
        turn_params.listener.dtls_services[index][relayindex] = create_dtls_listener_server(
            turn_params.listener_ifname, turn_params.listener.addrs[i], turn_params.tls_listener_port,
            turn_params.verbose, general_relay_servers[relayindex]->ioa_eng,
            &(general_relay_servers[relayindex]->server), !relayindex, NULL);
      }

      if (turn_params.rfc5780) {

        turn_params.listener.dtls_services[index + 1] =
            (dtls_listener_relay_server_type **)allocate_super_memory_engine(
                turn_params.listener.ioa_eng,
                sizeof(dtls_listener_relay_server_type *) * get_real_general_relay_servers_number());

        for (relayindex = 0; relayindex < get_real_general_relay_servers_number(); relayindex++) {
          turn_params.listener.dtls_services[index + 1][relayindex] = create_dtls_listener_server(
              turn_params.listener_ifname, turn_params.listener.addrs[i], get_alt_tls_listener_port(),
              turn_params.verbose, general_relay_servers[relayindex]->ioa_eng,
              &(general_relay_servers[relayindex]->server), !relayindex, NULL);
        }
      }
    } else {
      turn_params.listener.dtls_services[index] = NULL;
      if (turn_params.rfc5780) {
        turn_params.listener.dtls_services[index + 1] = NULL;
      }
    }
  }
}

static void setup_socket_per_session_udp_listener_servers(void) {
  size_t i = 0;

  /* Aux UDP servers */
  for (i = 0; i < turn_params.aux_servers_list.size; i++) {

    int index = i;

    if (!turn_params.no_udp || !turn_params.no_dtls) {

      ioa_addr addr;
      char saddr[129];
      addr_cpy(&addr, &turn_params.aux_servers_list.addrs[i]);
      int port = (int)addr_get_port(&addr);
      addr_to_string_no_port(&addr, (uint8_t *)saddr);

      turn_params.listener.aux_udp_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          turn_params.listener.ioa_eng, sizeof(dtls_listener_relay_server_type *));

      turn_params.listener.aux_udp_services[index][0] =
          create_dtls_listener_server(turn_params.listener_ifname, saddr, port, turn_params.verbose,
                                      turn_params.listener.ioa_eng, NULL, 1, send_socket_to_general_relay);
    }
  }

  /* Main servers */
  for (i = 0; i < turn_params.listener.addrs_number; i++) {

    int index = turn_params.rfc5780 ? i * 2 : i;

    /* UDP: */
    if (!turn_params.no_udp) {

      turn_params.listener.udp_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          turn_params.listener.ioa_eng, sizeof(dtls_listener_relay_server_type *));

      turn_params.listener.udp_services[index][0] = create_dtls_listener_server(
          turn_params.listener_ifname, turn_params.listener.addrs[i], turn_params.listener_port, turn_params.verbose,
          turn_params.listener.ioa_eng, NULL, 1, send_socket_to_general_relay);

      if (turn_params.rfc5780) {

        turn_params.listener.udp_services[index + 1] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
            turn_params.listener.ioa_eng, sizeof(dtls_listener_relay_server_type *));

        turn_params.listener.udp_services[index + 1][0] = create_dtls_listener_server(
            turn_params.listener_ifname, turn_params.listener.addrs[i], get_alt_listener_port(), turn_params.verbose,
            turn_params.listener.ioa_eng, NULL, 1, send_socket_to_general_relay);
      }
    } else {
      turn_params.listener.udp_services[index] = NULL;
      if (turn_params.rfc5780) {
        turn_params.listener.udp_services[index + 1] = NULL;
      }
    }
    if (!turn_params.no_dtls && (turn_params.no_udp || (turn_params.listener_port != turn_params.tls_listener_port))) {

      turn_params.listener.dtls_services[index] = (dtls_listener_relay_server_type **)allocate_super_memory_engine(
          turn_params.listener.ioa_eng, sizeof(dtls_listener_relay_server_type *));

      turn_params.listener.dtls_services[index][0] = create_dtls_listener_server(
          turn_params.listener_ifname, turn_params.listener.addrs[i], turn_params.tls_listener_port,
          turn_params.verbose, turn_params.listener.ioa_eng, NULL, 1, send_socket_to_general_relay);

      if (turn_params.rfc5780) {

        turn_params.listener.dtls_services[index + 1] =
            (dtls_listener_relay_server_type **)allocate_super_memory_engine(turn_params.listener.ioa_eng,
                                                                             sizeof(dtls_listener_relay_server_type *));

        turn_params.listener.dtls_services[index + 1][0] = create_dtls_listener_server(
            turn_params.listener_ifname, turn_params.listener.addrs[i], get_alt_tls_listener_port(),
            turn_params.verbose, turn_params.listener.ioa_eng, NULL, 1, send_socket_to_general_relay);
      }
    } else {
      turn_params.listener.dtls_services[index] = NULL;
      if (turn_params.rfc5780) {
        turn_params.listener.dtls_services[index + 1] = NULL;
      }
    }
  }
}

static void setup_tcp_listener_servers(ioa_engine_handle e, struct relay_server *relay_server) {
  size_t i = 0;

  tls_listener_relay_server_type **tcp_services = (tls_listener_relay_server_type **)allocate_super_memory_engine(
      turn_params.listener.ioa_eng, sizeof(tls_listener_relay_server_type *) * turn_params.listener.services_number);
  tls_listener_relay_server_type **tls_services = (tls_listener_relay_server_type **)allocate_super_memory_engine(
      turn_params.listener.ioa_eng, sizeof(tls_listener_relay_server_type *) * turn_params.listener.services_number);

  tls_listener_relay_server_type **aux_tcp_services = (tls_listener_relay_server_type **)allocate_super_memory_engine(
      turn_params.listener.ioa_eng, sizeof(tls_listener_relay_server_type *) * turn_params.aux_servers_list.size + 1);

  /* Create listeners */

  /* Aux TCP servers */
  if (!turn_params.tcp_use_proxy && (!turn_params.no_tls || !turn_params.no_tcp)) {

    for (i = 0; i < turn_params.aux_servers_list.size; i++) {

      ioa_addr addr;
      char saddr[129];
      addr_cpy(&addr, &turn_params.aux_servers_list.addrs[i]);
      int port = (int)addr_get_port(&addr);
      addr_to_string_no_port(&addr, (uint8_t *)saddr);

      aux_tcp_services[i] = create_tls_listener_server(turn_params.listener_ifname, saddr, port, turn_params.verbose, e,
                                                       send_socket_to_general_relay, relay_server);
    }
  }

  /* Main servers */
  for (i = 0; i < turn_params.listener.addrs_number; i++) {

    int index = turn_params.rfc5780 ? i * 2 : i;

    /* TCP: */
    if (!turn_params.no_tcp) {
      tcp_services[index] =
          create_tls_listener_server(turn_params.listener_ifname, turn_params.listener.addrs[i],
                                     turn_params.tcp_use_proxy ? turn_params.tcp_proxy_port : turn_params.listener_port,
                                     turn_params.verbose, e, send_socket_to_general_relay, relay_server);
      if (turn_params.rfc5780) {
        tcp_services[index + 1] =
            turn_params.tcp_use_proxy
                ? NULL
                : create_tls_listener_server(turn_params.listener_ifname, turn_params.listener.addrs[i],
                                             get_alt_listener_port(), turn_params.verbose, e,
                                             send_socket_to_general_relay, relay_server);
      }
    } else {
      tcp_services[index] = NULL;
      if (turn_params.rfc5780) {
        tcp_services[index + 1] = NULL;
      }
    }
    if (!turn_params.no_tls && !turn_params.tcp_use_proxy &&
        (turn_params.no_tcp || (turn_params.listener_port != turn_params.tls_listener_port))) {
      tls_services[index] = create_tls_listener_server(turn_params.listener_ifname, turn_params.listener.addrs[i],
                                                       turn_params.tls_listener_port, turn_params.verbose, e,
                                                       send_socket_to_general_relay, relay_server);
      if (turn_params.rfc5780) {
        tls_services[index + 1] = create_tls_listener_server(turn_params.listener_ifname, turn_params.listener.addrs[i],
                                                             get_alt_tls_listener_port(), turn_params.verbose, e,
                                                             send_socket_to_general_relay, relay_server);
      }
    } else {
      tls_services[index] = NULL;
      if (turn_params.rfc5780) {
        tls_services[index + 1] = NULL;
      }
    }
  }
}

static int get_alt_addr(ioa_addr *addr, ioa_addr *alt_addr) {
  if (!addr || !turn_params.rfc5780 || (turn_params.listener.addrs_number < 2)) {
  } else {
    size_t index = 0xffff;
    size_t i = 0;
    int alt_port = -1;
    int port = addr_get_port(addr);

    if (port == turn_params.listener_port) {
      alt_port = get_alt_listener_port();
    } else if (port == get_alt_listener_port()) {
      alt_port = turn_params.listener_port;
    } else if (port == turn_params.tls_listener_port) {
      alt_port = get_alt_tls_listener_port();
    } else if (port == get_alt_tls_listener_port()) {
      alt_port = turn_params.tls_listener_port;
    } else {
      return -1;
    }

    for (i = 0; i < turn_params.listener.addrs_number; i++) {
      if (turn_params.listener.encaddrs && turn_params.listener.encaddrs[i]) {
        if (addr->ss.sa_family == turn_params.listener.encaddrs[i]->ss.sa_family) {
          index = i;
          break;
        }
      }
    }
    if (index != 0xffff) {
      for (i = 0; i < turn_params.listener.addrs_number; i++) {
        size_t ind = (index + i + 1) % turn_params.listener.addrs_number;
        if (turn_params.listener.encaddrs && turn_params.listener.encaddrs[ind]) {
          ioa_addr *caddr = turn_params.listener.encaddrs[ind];
          if (caddr->ss.sa_family == addr->ss.sa_family) {
            addr_cpy(alt_addr, caddr);
            addr_set_port(alt_addr, alt_port);
            return 0;
          }
        }
      }
    }
  }

  return -1;
}

static void run_events(
  #ifndef USE_FSTACK
  struct event_base *eb,
  #else
  struct MyEventBase *eb,
  #endif
  ioa_engine_handle e) {
  if (!eb && e) {
    eb = e->event_base;
  }

  if (!eb) {
    return;
  }

  struct timeval timeout;

  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  #ifndef USE_FSTACK
  event_base_loopexit(eb, &timeout);

  event_base_dispatch(eb);
  #else
  int tiempo_ms = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
    my_event_loop(eb,tiempo_ms);
  #endif
}

void run_listener_server(struct listener_server *ls) {
  unsigned int cycle = 0;
#ifndef USE_FSTACK
  while (!turn_params.stop_turn_server) {
#endif
#if !defined(TURN_NO_SYSTEMD)
    sd_notify(0, "READY=1");
#endif

    if (eve(turn_params.verbose)) {
      if ((cycle++ & 15) == 0) {
        //TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cycle=%u\n", __FUNCTION__, cycle);
      }
    }

    if (turn_params.drain_turn_server && global_allocation_count == 0) {
      turn_params.stop_turn_server = true;
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Drain complete, shutting down now...\n");
    }

    run_events(ls->event_base, ls->ioa_eng);

    rollover_logfile();
#ifndef USE_FSTACK
  }
  //ff_stop_run?
#endif
  #ifdef USE_FSTACK
  if(turn_params.stop_turn_server){
  #endif
#if !defined(TURN_NO_SYSTEMD)

  sd_notify(0, "STOPPING=1");


#endif
  #ifdef USE_FSTACK
  my_stop();
  }
  #endif
}

static void setup_relay_server(struct relay_server *rs, ioa_engine_handle e, int to_set_rfc5780) {
  struct bufferevent *pair[2];

  if (e) {
    rs->event_base = e->event_base;
    rs->ioa_eng = e;
  } else {
    #ifndef USE_FSTACK
    rs->event_base = turn_event_base_new();
    #else
    rs->event_base = turn_params.listener.event_base; //es necesario usar el mismo event_base que el listener
    #endif
    rs->ioa_eng = create_ioa_engine(rs->sm, rs->event_base, turn_params.listener.tp, turn_params.relay_ifname,
                                    turn_params.relays_number, turn_params.relay_addrs, turn_params.default_relays,
                                    turn_params.verbose
#if !defined(TURN_NO_HIREDIS)
                                    ,
                                    &turn_params.redis_statsdb
#endif
    );
    set_ssl_ctx(rs->ioa_eng, &turn_params);
    ioa_engine_set_rtcp_map(rs->ioa_eng, turn_params.listener.rtcpmap);
  }

  #ifndef USE_FSTACK
    bufferevent_pair_new(rs->event_base, TURN_BUFFEREVENTS_OPTIONS, pair);
    rs->in_buf = pair[0];
    rs->out_buf = pair[1];
    bufferevent_setcb(rs->in_buf, relay_receive_message, NULL, NULL, rs);
    bufferevent_enable(rs->in_buf, EV_READ);

    bufferevent_pair_new(rs->event_base, TURN_BUFFEREVENTS_OPTIONS, pair);
    rs->auth_in_buf = pair[0];
    rs->auth_out_buf = pair[1];
    bufferevent_setcb(rs->auth_in_buf, relay_receive_auth_message, NULL, NULL, rs);
    bufferevent_enable(rs->auth_in_buf, EV_READ);
  #else
    listener_fifo_t *lf = create_listener_fifo(relay_receive_message_from_fifo, rs);
    register_listener_fifo(lf);
    rs->in_buf = lf;
    rs->out_buf = lf;

    lf = create_listener_fifo(relay_receive_auth_message_from_fifo, rs);
    register_listener_fifo(lf);
    rs->auth_in_buf = lf;
    rs->auth_out_buf = lf;
  #endif

  init_turn_server(
      &(rs->server), rs->id, turn_params.verbose, rs->ioa_eng, turn_params.ct, turn_params.fingerprint,
      DONT_FRAGMENT_SUPPORTED, start_user_check, check_new_allocation_quota, release_allocation_quota,
      turn_params.external_ip, &turn_params.check_origin, &turn_params.no_tcp_relay, &turn_params.no_udp_relay,
      &turn_params.stale_nonce, &turn_params.max_allocate_lifetime, &turn_params.channel_lifetime,
      &turn_params.permission_lifetime, &turn_params.stun_only, &turn_params.no_stun, turn_params.software_attribute,
      &turn_params.web_admin_listen_on_workers, &turn_params.alternate_servers_list,
      &turn_params.tls_alternate_servers_list, &turn_params.aux_servers_list, turn_params.udp_self_balance,
      &turn_params.no_multicast_peers, &turn_params.allow_loopback_peers, &turn_params.ip_whitelist,
      &turn_params.ip_blacklist, send_socket_to_relay, &turn_params.secure_stun, &turn_params.mobility,
      turn_params.server_relay, send_turn_session_info, send_https_socket, allocate_bps, turn_params.oauth,
      turn_params.oauth_server_name, turn_params.acme_redirect, turn_params.allocation_default_address_family,
      &turn_params.log_binding, &turn_params.stun_backward_compatibility, &turn_params.respond_http_unsupported);
  if (to_set_rfc5780) {
    set_rfc5780(&(rs->server), get_alt_addr, send_message_from_listener_to_client);
  }

  if (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_THREAD) {
    setup_tcp_listener_servers(rs->ioa_eng, rs);
  }
}

static void *run_general_relay_thread(void *arg) {
#ifdef USE_FSTACK
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Calling //ff_thread_init in run_general_thread\n");
#endif
  static int always_true = 1;
  struct relay_server *rs = (struct relay_server *)arg;

  int udp_reuses_the_same_relay_server = (turn_params.general_relay_servers_number <= 1) ||
                                         (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_THREAD) ||
                                         (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_SESSION);

  int we_need_rfc5780 = udp_reuses_the_same_relay_server && turn_params.rfc5780;

  ignore_sigpipe();

  setup_relay_server(rs, NULL, we_need_rfc5780);

  barrier_wait();

  while (always_true) {
    run_events(rs->event_base, rs->ioa_eng);
  }

  return arg;
}

static void setup_general_relay_servers(void) {
    size_t i = 0;
#ifndef USE_FSTACK
    /* Modo libevent: misma lógica que antes (con hilos si turn_params.general_relay_servers_number > 0) */
    for (i = 0; i < get_real_general_relay_servers_number(); i++) {
        if (turn_params.general_relay_servers_number == 0) {
            general_relay_servers[i] = (struct relay_server*)
                allocate_super_memory_engine(turn_params.listener.ioa_eng,
                                            sizeof(struct relay_server));
            general_relay_servers[i]->id = (turnserver_id)i;
            general_relay_servers[i]->sm = NULL;
            setup_relay_server(general_relay_servers[i],
                               turn_params.listener.ioa_eng,
                               ((turn_params.net_engine_version == NEV_UDP_SOCKET_PER_THREAD) ||
                                (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_SESSION)) &&
                                   turn_params.rfc5780);
            general_relay_servers[i]->thr = pthread_self();
        } else {
            super_memory_t *sm = new_super_memory_region();
            general_relay_servers[i] = (struct relay_server*)
                allocate_super_memory_region(sm, sizeof(struct relay_server));
            general_relay_servers[i]->id = (turnserver_id)i;
            general_relay_servers[i]->sm = sm;
            if (pthread_create(&(general_relay_servers[i]->thr),
                               NULL,
                               run_general_relay_thread,
                               general_relay_servers[i])) {
                perror("Cannot create relay thread\n");
                exit(-1);
            }
            pthread_detach(general_relay_servers[i]->thr);
        }
    }
#else
    /* Modo F‑Stack: sin hilos, sólo registro los relay servers a mi event_base compartido */
    ioa_engine_handle shared_eng = turn_params.listener.ioa_eng;

    for (i = 0; i < get_real_general_relay_servers_number(); i++) {
        general_relay_servers[i] = (struct relay_server*)
            allocate_super_memory_engine(shared_eng,
                                        sizeof(struct relay_server));
        general_relay_servers[i]->id = (turnserver_id)i;
        general_relay_servers[i]->sm = NULL;

        /* Todos usan el mismo event_base e ioa_eng */
        setup_relay_server(general_relay_servers[i],
                           shared_eng,
                           ((turn_params.net_engine_version == NEV_UDP_SOCKET_PER_THREAD) ||
                            (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_SESSION)) &&
                               turn_params.rfc5780);

        /* No creamos hilos: run_events() se lanzará desde el main loop */
        general_relay_servers[i]->thr = pthread_self();
    }
#endif
}

static int run_auth_server_flag = 1;

static void *run_auth_server_thread(void *arg) {
#ifdef USE_FSTACK
  //ff_thread_init();
#endif
  ignore_sigpipe();

  struct auth_server *as = (struct auth_server *)arg;

  authserver_id id = as->id;

  if (id == 0) {

    reread_realms();
    update_white_and_black_lists();

    barrier_wait();

    while (run_auth_server_flag) {
#if defined(DB_TEST)
      run_db_test();
#endif
      sleep(5);
      reread_realms();
      update_white_and_black_lists();
    }

  } else {

    memset(as, 0, sizeof(struct auth_server));

    as->id = id;
    #ifndef USE_FSTACK
    as->event_base = turn_event_base_new();
    #else
    as->event_base = my_event_base_new();
    #endif

    struct bufferevent *pair[2];

    #ifndef USE_FSTACK
      bufferevent_pair_new(as->event_base, TURN_BUFFEREVENTS_OPTIONS, pair);
      as->in_buf = pair[0];
      as->out_buf = pair[1];
      bufferevent_setcb(as->in_buf, auth_server_receive_message, NULL, NULL, as);
      bufferevent_enable(as->in_buf, EV_READ);
    #else
      listener_fifo_t *lf = create_listener_fifo(auth_server_receive_message_from_fifo, as);
      register_listener_fifo(lf);
      as->in_buf = lf;
      as->out_buf = lf;
    #endif

#if !defined(TURN_NO_HIREDIS)
    as->rch = get_redis_async_connection(as->event_base, &turn_params.redis_statsdb, 1);
#endif

    barrier_wait();

    while (run_auth_server_flag) {
      if (!turn_params.no_auth_pings) {
        auth_ping(as->rch);
      }

      run_events(as->event_base, NULL);
    }
  }

  return arg;
}
void setup_auth_servers_fstack(void) {
    for (authserver_id sn = 0; sn < authserver_number; ++sn) {
        authserver[sn].id = sn;
        //authserver[sn].event_base = my_event_base_new();  
        authserver[sn].event_base = turn_params.listener.event_base; // usar el mismo event_base que el listener
        listener_fifo_t *lf = create_listener_fifo(auth_server_receive_message_from_fifo, &authserver[sn]);
        register_listener_fifo(lf);
        authserver[sn].in_buf = lf;
        authserver[sn].out_buf = lf;
        // Si usas Redis, inicializa aquí también
        // authserver[sn].rch = get_redis_async_connection(...);
    }
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total auth servers (F-Stack): %d\n", authserver_number);
}
static void setup_auth_server(struct auth_server *as) {
  pthread_attr_t attr;
  if (pthread_attr_init(&attr) || pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) ||
      pthread_create(&(as->thr), &attr, run_auth_server_thread, as)) {
    perror("Cannot create auth thread\n");
    exit(-1);
  }
}

static void *run_admin_server_thread(void *arg) {
  ignore_sigpipe();

  setup_admin_thread();

  barrier_wait();

  while (adminserver.event_base) {
    run_events(adminserver.event_base, NULL);
  }

  return arg;
}
static void run_admin_server_fstack() {
  ignore_sigpipe();

  setup_admin_thread();

  //barrier_wait();

  while (adminserver.event_base) {
    run_events(adminserver.event_base, NULL);
  }
}

static void setup_admin_server(void) {
  memset(&adminserver, 0, sizeof(struct admin_server));
  adminserver.listen_fd = -1;
  adminserver.verbose = turn_params.verbose;

  #ifndef USE_FSTACK
    if (pthread_create(&(adminserver.thr), NULL, run_admin_server_thread, &adminserver)) {
      perror("Cannot create cli thread\n");
      exit(-1);
    }

    pthread_detach(adminserver.thr);
  #else
    //adminserver.event_base = my_event_base_new();

    setup_admin_thread();
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "F-stack-j: Admin auth server registrado en event_base principal");
    //run_admin_server_fstack();
  #endif
}

void setup_server(void) {
#if defined(WINDOWS)
  evthread_use_windows_threads();
#else
  //evthread_use_pthreads(); //esto no se si se ejecuta, pero creo que no porque no estoy usando libevent
#endif

  TURN_MUTEX_INIT(&mutex_bps);
  TURN_MUTEX_INIT(&auth_message_counter_mutex);

  authserver_number = 1 + (authserver_id)(turn_params.cpus / 2);

  if (authserver_number < MIN_AUTHSERVER_NUMBER) {
    authserver_number = MIN_AUTHSERVER_NUMBER;
  }

#if !defined(TURN_NO_THREAD_BARRIERS)

  /* relay threads plus auth threads plus main listener thread */
  /* plus admin thread */
  /* udp address listener thread(s) will start later */
  barrier_count = turn_params.general_relay_servers_number + authserver_number + 1 + 1;

#endif

  setup_listener(); // usa event_base, que hay que cambiarlo a MyeventBase
  allocate_relay_addrs_ports();
  setup_barriers();
  setup_general_relay_servers();
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total General servers: %d\n", (int)get_real_general_relay_servers_number());

  if (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_THREAD) {
    setup_socket_per_thread_udp_listener_servers();
  } else if (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_ENDPOINT) {
    setup_socket_per_endpoint_udp_listener_servers();
  } else if (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_SESSION) {
    setup_socket_per_session_udp_listener_servers();
  }

  if (turn_params.net_engine_version != NEV_UDP_SOCKET_PER_THREAD) {
    setup_tcp_listener_servers(turn_params.listener.ioa_eng, NULL);
  }

  {
    int tot = 0;
    if (udp_relay_servers[0]) {
      tot = get_real_udp_relay_servers_number();
    }
    if (tot) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total UDP servers: %d\n", (int)tot);
    }
  }

  {
    int tot = get_real_general_relay_servers_number();
    if (tot) {
      int i;
      for (i = 0; i < tot; i++) {
        if (!(general_relay_servers[i])) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "General server %d is not initialized !\n", (int)i);
        }
      }
    }
  }

  {
    #ifndef USE_FSTACK
    authserver_id sn = 0;
    for (sn = 0; sn < authserver_number; ++sn) {
      authserver[sn].id = sn;
      setup_auth_server(&(authserver[sn]));
    }
    #else //habría que implementar código friendly con f-stack
      setup_auth_servers_fstack();
      //TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Coturn sin autenticación, debido a f-stack");
    #endif
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total auth threads: %d\n", authserver_number);
  }

  setup_admin_server();
  #ifndef USE_FSTACK
    barrier_wait();
  #endif
}

void init_listener(void) { memset(&turn_params.listener, 0, sizeof(struct listener_server)); }

void enable_drain_mode(void) {
  // Tell each turn_server we are draining
  for (size_t i = 0; i < get_real_general_relay_servers_number(); i++) {
    if (general_relay_servers[i]) {
      general_relay_servers[i]->server.is_draining = true;
    }
  }
  for (size_t i = 0; i < get_real_udp_relay_servers_number(); i++) {
    if (udp_relay_servers[i]) {
      udp_relay_servers[i]->server.is_draining = true;
    }
  }
  turn_params.drain_turn_server = true;
}
///////////////////////////////
