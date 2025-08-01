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

#ifndef __MAIN_RELAY__
#define __MAIN_RELAY__

#include <limits.h>
#include "wrappers.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//librerias jose

#include <rte_ring.h>

//librerias jose

#include <locale.h>

#include <pthread.h>
#include <sched.h>

#include <signal.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <getopt.h>

#if defined(__unix__) || defined(unix) || defined(__APPLE__)
#include <ifaddrs.h>
#include <libgen.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/utsname.h>

#include <grp.h>
#include <pwd.h>
#endif

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "ns_turn_openssl.h"

#include "ns_turn_khash.h"
#include "ns_turn_utils.h"

#include "turn_admin_server.h"
#include "userdb.h"

#include "dtls_listener.h"
#include "tls_listener.h"

#include "ns_turn_maps.h"
#include "ns_turn_server.h"

#include "apputils.h"

#include "ns_ioalib_impl.h"

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <openssl/modes.h>

#if !defined(TURN_NO_SYSTEMD)
#include <systemd/sd-daemon.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

////////////// DEFINES ////////////////////////////

#define DEFAULT_CONFIG_FILE "turnserver.conf"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define DEFAULT_CIPHER_LIST OSSL_default_cipher_list()
#if TLS_SUPPORTED
#define DEFAULT_CIPHERSUITES OSSL_default_ciphersuites()
#endif
#else // OPENSSL_VERSION_NUMBER < 0x30000000L
#define DEFAULT_CIPHER_LIST "DEFAULT"
#if TLS_SUPPORTED && defined(TLS_DEFAULT_CIPHERSUITES)
#define DEFAULT_CIPHERSUITES TLS_DEFAULT_CIPHERSUITES
#endif
#endif // OPENSSL_VERSION_NUMBER >= 0x30000000L

#define DEFAULT_EC_CURVE_NAME "prime256v1"

#define MAX_NUMBER_OF_GENERAL_RELAY_SERVERS ((uint8_t)(0x80))

#define TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP MAX_NUMBER_OF_GENERAL_RELAY_SERVERS
#define TURNSERVER_ID_BOUNDARY_BETWEEN_UDP_AND_TCP TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP

#define DEFAULT_CPUS_NUMBER (2)

/////////// TYPES ///////////////////////////////////

enum _DH_KEY_SIZE { DH_566, DH_1066, DH_2066, DH_CUSTOM };

typedef enum _DH_KEY_SIZE DH_KEY_SIZE;

///////// LISTENER SERVER TYPES /////////////////////

struct message_to_listener_to_client {
  ioa_addr origin;
  ioa_addr destination;
  ioa_network_buffer_handle nbh;
};

enum _MESSAGE_TO_LISTENER_TYPE { LMT_UNKNOWN, LMT_TO_CLIENT };
typedef enum _MESSAGE_TO_LISTENER_TYPE MESSAGE_TO_LISTENER_TYPE;

struct message_to_listener {
  MESSAGE_TO_LISTENER_TYPE t;
  union {
    struct message_to_listener_to_client tc;
  } m;
};

struct listener_server {
  rtcp_map *rtcpmap;
  turnipports *tp;
#ifndef USE_FSTACK
  struct event_base *event_base;
#else
  struct MyEventBase *event_base;
#endif
  ioa_engine_handle ioa_eng;
  #ifndef USE_FSTACK
  struct bufferevent *in_buf;
  struct bufferevent *out_buf;
  #else
  struct listener_fifo_t *in_buf;
  struct listener_fifo_t *out_buf;
 #endif
  char **addrs;
  ioa_addr **encaddrs;
  size_t addrs_number;
  size_t services_number;
  dtls_listener_relay_server_type ***udp_services;
  dtls_listener_relay_server_type ***dtls_services;
  dtls_listener_relay_server_type ***aux_udp_services;
};

enum _NET_ENG_VERSION {
  NEV_UNKNOWN = 0,
  NEV_MIN,
  NEV_UDP_SOCKET_PER_SESSION = NEV_MIN,
  NEV_UDP_SOCKET_PER_ENDPOINT,
  NEV_UDP_SOCKET_PER_THREAD,
  NEV_MAX = NEV_UDP_SOCKET_PER_THREAD,
  NEV_TOTAL
};

typedef enum _NET_ENG_VERSION NET_ENG_VERSION;

/////////// PARAMS //////////////////////////////////

typedef struct _turn_params_ {

  //////////////// OpenSSL group //////////////////////

  SSL_CTX *tls_ctx;
  SSL_CTX *dtls_ctx;

  DH_KEY_SIZE dh_key_size;

  char cipher_list[1025];
  char ec_curve_name[33];

  char ca_cert_file[1025];
  char cert_file[1025];
  char pkey_file[1025];
  bool rpk_enabled;
  char tls_password[513];
  char dh_file[1025];

  bool enable_tlsv1;
  bool enable_tlsv1_1;
  bool no_tlsv1_2;
  bool no_tls;
  bool no_dtls;

  #ifndef USE_FSTACK
    struct event *tls_ctx_update_ev;
  #else
    struct MyEvent *tls_ctx_update_ev;
  #endif
  TURN_MUTEX_DECLARE(tls_mutex)

  //////////////// Common params ////////////////////

  int verbose;
  bool turn_daemon;
  bool software_attribute;
  bool web_admin_listen_on_workers;

  bool do_not_use_config_file;

  char pidfile[1025];
  char acme_redirect[1025];

  ////////////////  Listener server /////////////////

  int listener_port;
  int tls_listener_port;
  int alt_listener_port;
  int alt_tls_listener_port;
  int tcp_proxy_port;
  bool rfc5780;

  bool no_udp;
  bool no_tcp;
  bool tcp_use_proxy;

  bool no_tcp_relay;
  bool no_udp_relay;

  char listener_ifname[1025];

  redis_stats_db_t redis_statsdb;
  bool use_redis_statsdb;

  struct listener_server listener;

  ip_range_list_t ip_whitelist;
  ip_range_list_t ip_blacklist;

  NET_ENG_VERSION net_engine_version;
  const char *net_engine_version_txt[NEV_TOTAL];

  //////////////// Relay servers /////////////

  uint16_t min_port;
  uint16_t max_port;

  bool check_origin;

  bool no_multicast_peers;
  bool allow_loopback_peers;

  char relay_ifname[1025];
  size_t relays_number;
  char **relay_addrs;
  int default_relays;

  // Single global public IP.
  // If multiple public IPs are used
  // then ioa_addr mapping must be used.
  ioa_addr *external_ip;

  turnserver_id general_relay_servers_number;
  turnserver_id udp_relay_servers_number;

  ////////////// Auth server ////////////////

  char oauth_server_name[1025];
  char domain[1025];
  int oauth;

  /////////////// AUX SERVERS ////////////////

  turn_server_addrs_list_t aux_servers_list;
  int udp_self_balance;

  /////////////// ALTERNATE SERVERS ////////////////

  turn_server_addrs_list_t alternate_servers_list;
  turn_server_addrs_list_t tls_alternate_servers_list;

  /////////////// stop/drain server ////////////////
  bool drain_turn_server;
  /////////////// stop server ////////////////
  bool stop_turn_server;

  ////////////// MISC PARAMS ////////////////

  bool stun_only;
  bool no_stun;
  bool secure_stun;
  int server_relay;
  int fingerprint;
  char rest_api_separator;
  vint stale_nonce;
  vint max_allocate_lifetime;
  vint channel_lifetime;
  vint permission_lifetime;
  bool mobility;
  turn_credential_type ct;
  bool use_auth_secret_with_timestamp;
  band_limit_t max_bps;
  band_limit_t bps_capacity;
  band_limit_t bps_capacity_allocated;
  vint total_quota;
  vint user_quota;
  bool prometheus;
  int prometheus_port;
  char prometheus_address[INET6_ADDRSTRLEN];
  char prometheus_path[1025];
  bool prometheus_username_labels;

  /////// Users DB ///////////

  default_users_db_t default_users_db;

  /////// CPUs //////////////

  unsigned long cpus;

  ///////// Encryption /////////
  char secret_key_file[1025];
  unsigned char secret_key[1025];
  ALLOCATION_DEFAULT_ADDRESS_FAMILY allocation_default_address_family;
  bool no_auth_pings;
  bool no_dynamic_ip_list;
  bool no_dynamic_realms;

  bool log_binding;
  bool stun_backward_compatibility;
  bool respond_http_unsupported;
} turn_params_t;

extern turn_params_t turn_params;

////////////////  Listener server /////////////////

static inline int get_alt_listener_port(void) {
  if (turn_params.alt_listener_port < 1) {
    return turn_params.listener_port + 1;
  }
  return turn_params.alt_listener_port;
}

static inline int get_alt_tls_listener_port(void) {
  if (turn_params.alt_tls_listener_port < 1) {
    return turn_params.tls_listener_port + 1;
  }
  return turn_params.alt_tls_listener_port;
}

void add_aux_server(const char *saddr);

void add_alternate_server(const char *saddr);
void del_alternate_server(const char *saddr);
void add_tls_alternate_server(const char *saddr);
void del_tls_alternate_server(const char *saddr);

////////// Addrs ////////////////////

void add_listener_addr(const char *addr);
int add_relay_addr(const char *addr);

////////// SSL CTX ////////////////////
void set_ssl_ctx(ioa_engine_handle e, turn_params_t *params);

///////// Auth ////////////////

void send_auth_message_to_auth_server(struct auth_message *am);

/////////// Setup server ////////

void init_listener(void);
void setup_server(void);
void run_listener_server(struct listener_server *ls);
void enable_drain_mode(void);

////////// BPS ////////////////

band_limit_t get_bps_capacity_allocated(void);
band_limit_t get_bps_capacity(void);
void set_bps_capacity(band_limit_t value);
band_limit_t get_max_bps(void);
void set_max_bps(band_limit_t value);

///////// AES ENCRYPTION AND DECRYPTION ////////

struct ctr_state {
  unsigned char ivec[16];
  unsigned int num;
  unsigned char ecount[16];
};
unsigned char *base64encode(const void *b64_encode_this, int encode_this_many_bytes);
void encrypt_aes_128(unsigned char *in, const unsigned char *mykey);
unsigned char *base64decode(const void *b64_decode_this, int decode_this_many_bytes);
void decrypt_aes_128(char *in, const unsigned char *mykey);
int decodedTextSize(char *input);
char *decryptPassword(char *in, const unsigned char *mykey);
int init_ctr(struct ctr_state *state, const unsigned char iv[8]);

///////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__MAIN_RELAY__
