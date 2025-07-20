#ifndef WRAPPERS_H
#define WRAPPERS_H




#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stddef.h>
#include <rte_ring.h>
#include <rte_timer.h>
#include <string.h>
#include <ff_config.h>
#include <ff_api.h>
#include <ff_epoll.h>
#include <sys/ioctl.h>



#ifdef __cplusplus
extern "C" {
#endif

#define TRACE_EVENT_NEW(base, fd, evs, cb, ctx)                        \
  ({                                                                  \
    printf("DEBUG: registering callback %s at %p\n", #cb, (void*)(cb)); \
    my_event_new((base), (fd), (evs), (cb), (ctx));                    \
  })
//forward declarationss
#define FIFO_CAPACITY 3036
#define MAX_FIFOS 100
typedef struct _ioa_socket *ioa_socket_handle;





struct MyEventBase{
    int epfd;
};


#define INTERNAL_RING_SIZE 1024


struct InternalMessage {
    void *data;
    size_t len;
};

struct InternalChannel {
    struct rte_ring *ring;
    void (*on_message)(void *ctx, struct InternalMessage *msg);
    void *ctx;
};
struct  MyEvent{
    struct MyEventBase *base;
    int fd;
    short events;  // EV_READ / EV_WRITE etc.
    void (*callback)(int fd, short event, void *arg);
    void *arg;
};
struct MyEvConnListener;
typedef void (*my_evconnlistener_cb)(struct MyEvConnListener *, int, struct sockaddr *, int socklen, void *);

struct MyEvConnListener {
    struct MyEventBase *base;
    struct MyEvent *event;
    my_evconnlistener_cb cb;
    void *user_data;
    int fd;
    int flags;
};

struct My_evconnlistener_event {
	struct MyEvConnListener base;
	struct MyEvent *listener;
};
typedef struct my_fifo my_fifo_t;
typedef struct listener_fifo_t listener_fifo_t; // Define listener_fifo_t como alias

typedef void (*listener_cb_t)(listener_fifo_t *lf, void *ctx);

struct listener_fifo_t {
    my_fifo_t *fifo;
    listener_cb_t callback;
    void *ctx;
};



struct my_fifo {
    void **items;
    int capacity;
    int head;
    int tail;
};








static listener_fifo_t *fifo_list[MAX_FIFOS];
static int fifo_count = 0;

// Funciones de creación y gestión de sockets
void my_stop();
int my_ioctl(int fd, unsigned long request, ...);
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

ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags);

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
int my_event_add(struct MyEvent *ev,const struct timeval *tv);
//events
struct MyEventBase* my_event_base_new();
struct MyEvent* my_event_new(struct MyEventBase *base, int fd, int events, void (*cb)(int, short, void*), void *arg);
void my_event_loop(struct MyEventBase *base, int timeout_ms);
void my_event_free(struct MyEvent *ev);
void my_event_del(struct MyEvent *ev);
void my_event_base_free(struct MyEventBase *base);
struct MyEvConnListener *my_evconnlistener_new(struct MyEventBase *base,
                      my_evconnlistener_cb cb,
                      void *ptr,
                      unsigned flags,
                      int backlog,
                      int fd);
void my_event_disable_read(ioa_socket_handle s);
void my_event_enable_read(ioa_socket_handle s);
static void my_listener_read_cb(int fd, short what, void *p);
void my_evconnlistener_free(struct MyEvConnListener *listener);
void my_evconnlistener_enable(struct MyEvConnListener *listener);
void my_evconnlistener_disable(struct MyEvConnListener *listener);
my_fifo_t *allocate_my_fifo(void);
void free_my_fifo(my_fifo_t *f);
int my_fifo_push(my_fifo_t *f, void *item);
void *my_fifo_pop(my_fifo_t *f);
int my_fifo_is_empty(my_fifo_t *f);
listener_fifo_t *create_listener_fifo(listener_cb_t cb, void *ctx);
void process_registered_listener_fifos(void);
void process_listener_fifo(listener_fifo_t *lf);
void register_listener_fifo(listener_fifo_t *fifo);
#ifdef __cplusplus
}
#endif

#endif // WRAPPERS_H
