#ifndef WRAPPERS_H
#define WRAPPERS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Funciones de creación y gestión de sockets
int my_socket(int domain, int type, int protocol);
int my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int my_listen(int sockfd, int backlog);
int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// Envío y recepción
ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t my_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags);

// Opciones de socket
int my_setsockopt(int sockfd, int level, int optname,
                  const void *optval, socklen_t optlen);
int my_getsockopt(int sockfd, int level, int optname,
                  void *optval, socklen_t *optlen);

// Cierre de socket
int my_close(int sockfd);

// epoll
int my_epoll_create(int size);
int my_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int my_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#ifdef __cplusplus
}
#endif

#endif // WRAPPERS_H
