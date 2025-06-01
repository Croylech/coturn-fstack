#include "wrappers.h"

#ifdef USE_FSTACK
#include <ff_api.h>

#define socket_fn     ff_socket
#define bind_fn       ff_bind
#define listen_fn     ff_listen
#define accept_fn     ff_accept
#define connect_fn    ff_connect
#define recvfrom_fn   ff_recvfrom
#define sendto_fn     ff_sendto
#define recv_fn       ff_recv
#define send_fn       ff_send
#define setsockopt_fn ff_setsockopt
#define getsockopt_fn ff_getsockopt
#define close_fn      ff_close
#define epoll_create_fn ff_epoll_create
#define epoll_ctl_fn    ff_epoll_ctl
#define epoll_wait_fn   ff_epoll_wait

#else

#define socket_fn     socket
#define bind_fn       bind
#define listen_fn     listen
#define accept_fn     accept
#define connect_fn    connect
#define recvfrom_fn   recvfrom
#define sendto_fn     sendto
#define recv_fn       recv
#define send_fn       send
#define setsockopt_fn setsockopt
#define getsockopt_fn getsockopt
#define close_fn      close
#define epoll_create_fn epoll_create
#define epoll_ctl_fn    epoll_ctl
#define epoll_wait_fn   epoll_wait

#endif

// Funciones de socket
int my_socket(int domain, int type, int protocol) {
    return socket_fn(domain, type, protocol);
}

int my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return bind_fn(sockfd, addr, addrlen);
}

int my_listen(int sockfd, int backlog) {
    return listen_fn(sockfd, backlog);
}

int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    return accept_fn(sockfd, addr, addrlen);
}

int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return connect_fn(sockfd, addr, addrlen);
}

// Envío y recepción
ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen) {
    return recvfrom_fn(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen) {
    return sendto_fn(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t my_recv(int sockfd, void *buf, size_t len, int flags) {
    return recv_fn(sockfd, buf, len, flags);
}

ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    return send_fn(sockfd, buf, len, flags);
}

// Opciones
int my_setsockopt(int sockfd, int level, int optname,
                  const void *optval, socklen_t optlen) {
    return setsockopt_fn(sockfd, level, optname, optval, optlen);
}

int my_getsockopt(int sockfd, int level, int optname,
                  void *optval, socklen_t *optlen) {
    return getsockopt_fn(sockfd, level, optname, optval, optlen);
}

// Cierre
int my_close(int sockfd) {
    return close_fn(sockfd);
}

// epoll
int my_epoll_create(int size) {
    return epoll_create_fn(size);
}

int my_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    return epoll_ctl_fn(epfd, op, fd, event);
}

int my_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    return epoll_wait_fn(epfd, events, maxevents, timeout);
}
