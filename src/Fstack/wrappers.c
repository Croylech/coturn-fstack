#include "wrappers.h"
#include <event.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <rte_cycles.h>
#include <stdint.h>
#include "ns_ioalib_impl.h"
#include <ff_api.h>
#include <ff_epoll.h>


#ifdef USE_FSTACK
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
#define recvmsg_fn      ff_recvmsg

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
#define recvmsg_fn      recvmsg

#endif

// //comprobración de sockets

// static inline int restore_fstack_fd(int sockfd) {
//     if(sockfd <= ngx_max_sockets) {
//         return sockfd;
//     }

//     return sockfd - ngx_max_sockets;
// }

// /* Tell whether a 'sockfd' belongs to fstack. */
// int is_fstack_fd(int sockfd) {
//     if (unlikely(inited == 0)) {
//         return 0;
//     }

//     return sockfd >= ngx_max_sockets;
// }


// Funciones de socket
int my_socket(int domain, int type, int protocol) {
    return socket_fn(domain, type, protocol);
}
void my_stop(){
    ff_stop_run();
}
#include <stdarg.h>
#include <sys/ioctl.h>

int my_ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    void *argp;
    int ret;

    va_start(ap, request);
    argp = va_arg(ap, void *);
    va_end(ap);
    #ifndef USE_FSTACK
    ret = ioctl(fd, request, argp);
    #else
    ret = ff_ioctl(fd,request,argp);
    #endif

    return ret;
}


int my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#ifdef USE_FSTACK
    return ff_bind(sockfd, (const struct linux_sockaddr *)addr, addrlen);
#else
    return bind(sockfd, addr, addrlen);
#endif
}

int my_listen(int sockfd, int backlog) {
    return listen_fn(sockfd, backlog);
}

int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
#ifdef USE_FSTACK
    return ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
#else
    return accept(sockfd, addr, addrlen);
#endif
}
int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#ifdef USE_FSTACK
    return ff_connect(sockfd, (const struct linux_sockaddr *)addr, addrlen);
#else
    return connect(sockfd, addr, addrlen);
#endif
}

// Envío y recepción
ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen) {
    printf("LOG: my_recvfrom called fd=%d len=%zu flags=%x\n", sockfd, len, flags);
#ifdef USE_FSTACK
    ssize_t ret = ff_recvfrom(sockfd, buf, len, flags, (struct linux_sockaddr *)src_addr, addrlen);
#else
    ssize_t ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
#endif
    printf("LOG: my_recvfrom fd=%d returned ret=%zd\n", sockfd, ret);
    return ret;
}

ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen) {
#ifdef USE_FSTACK
    return ff_sendto(sockfd, buf, len, flags, (const struct linux_sockaddr *)dest_addr, addrlen);
#else
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#endif
}

ssize_t my_recv(int sockfd, void *buf, size_t len, int flags) {
    printf("LOG: my_recv called fd=%d len=%zu flags=%x\n", sockfd, len, flags);
    ssize_t ret = recv_fn(sockfd, buf, len, flags);
    printf("LOG: my_recv fd=%d returned ret=%zd\n", sockfd, ret);
    return ret;
}

ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    return send_fn(sockfd, buf, len, flags);
}

ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags){
    //printf("LOG: my_recvmsg called fd=%d flags=%x\n", sockfd, flags);
    ssize_t ret = recvmsg_fn(sockfd, msg, flags);
    //printf("LOG: my_recvmsg fd=%d returned ret=%zd\n", sockfd, ret);

    //if (ret > 0 && msg && msg->msg_iov && msg->msg_iovlen > 0 && msg->msg_iov[0].iov_base) {
        //size_t print_len = ret < 32 ? ret : 32; // solo los primeros 32 bytes
        //unsigned char *data = (unsigned char *)msg->msg_iov[0].iov_base;
        //printf("LOG: my_recvmsg data (hex, resumido): ");
        //for (size_t i = 0; i < print_len; ++i) {
        //    printf("%02x ", data[i]);
        //}
        //printf("\n");
    //}

    return ret;
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

//events

struct MyEventBase* my_event_base_new() {
    printf("LOG: my_event_base_new called\n");
    struct MyEventBase *base = malloc(sizeof(struct MyEventBase));
    if (!base)
        return NULL;

    base->epfd = ff_epoll_create(1024);
    if (base->epfd < 0) {
        free(base);
        return NULL;
    }

    return base;
}

struct MyEvent* my_event_new(struct MyEventBase *base, int fd, int events, void (*cb)(int, short, void*), void *arg) {
    printf("LOG: my_event_new called for fd=%d events=%x\n", fd, events);
    struct MyEvent *ev = malloc(sizeof(struct MyEvent));
    if (ev == NULL) {
        printf("ERROR: my_event_new malloc failed for fd=%d\n", fd);
        return NULL;
    }

    ev->base = base;
    ev->callback = cb;
    ev->arg = arg;
    ev->events = events;
    ev->fd = fd;

    printf("LOG: my_event_new created event struct for fd=%d\n", fd);
    return ev;
}

int my_event_add(struct MyEvent *ev,const struct timeval *tv){
    printf("LOG: my_event_add called for fd=%d events=%x\n", ev->fd, ev->events);

    struct epoll_event epev = {0};
    if (ev->events & EV_READ)  epev.events |= EPOLLIN;
    if (ev->events & EV_WRITE) epev.events |= EPOLLOUT;
    if (!(ev->events & EV_PERSIST)) epev.events |= EPOLLONESHOT;
    epev.data.ptr = ev;
    int ret = ff_epoll_ctl(ev->base->epfd, EPOLL_CTL_ADD, ev->fd, &epev);
    printf("LOG: ff_epoll_ctl ADD fd=%d events=%x ret=%d\n", ev->fd, epev.events, ret);
    return ret;
}

void my_event_loop(struct MyEventBase *base, int timeout_ms) {
    //printf("LOG: my_event_loop started with timeout_ms=%d\n", timeout_ms);
    struct epoll_event events[64];
    //uint64_t hz = rte_get_timer_hz();  // ciclos por segundo
    //uint64_t timeout_cycles = ((uint64_t)timeout_ms * hz) / 1000;
    //uint64_t deadline = rte_get_timer_cycles() + timeout_cycles;

    
    int n = ff_epoll_wait(base->epfd, events, 64, 0);
    if(n != 0){
        printf("LOG: ff_epoll_wait returned n=%d\n", n);
    }
    //printf("LOG: ff_epoll_wait returned n=%d\n", n);
    if (n < 0) {
        printf("ERROR: ff_epoll_wait error n=%d\n", n);
        return;
    }

    for (int i = 0; i < n; ++i) {
        struct MyEvent *ev = (struct MyEvent *)events[i].data.ptr;
        printf("LOG: Event received for fd=%d events=%x\n", ev ? ev->fd : -1, events[i].events);
        if (!ev || !ev->callback) {
            printf("WARN: Event with NULL ev or callback\n");
            continue;
        }

        short revents = 0;
        if (events[i].events & EPOLLIN)  revents |= EV_READ;
        if (events[i].events & EPOLLOUT) revents |= EV_WRITE;
        if (events[i].events & (EPOLLERR | EPOLLHUP)) revents |= EV_CLOSED;

        printf("LOG: Calling callback for fd=%d revents=%x\n", ev->fd, revents);

        ev->callback(ev->fd, revents, ev->arg);
    
        process_registered_listener_fifos();
        //ff_swi_net_excute();
    }
}

void my_event_free(struct MyEvent *ev){
    if(ev){
        free(ev);
    }else{
        printf("ERROR:my_event_free\n");
    }
    
}
void my_event_del(struct MyEvent *ev){
    // if (!ev || !ev->base)
    // return -1;

    // Construir estructura epoll_event para eliminar (aunque no se usa mucho aquí)
    struct epoll_event epev;
    epev.events = 0;
    epev.data.ptr = NULL;

    int ret = ff_epoll_ctl(ev->base->epfd, EPOLL_CTL_DEL, ev->fd, &epev);
    // if (ret < 0) {
    //     printf(" ERROR: ff_epoll_del");
    //     return -1;
    // }

    // return 0;
}
void my_event_base_free(struct MyEventBase *base) {
    if (!base)
        return;

    if (base->epfd >= 0) {
        ff_close(base->epfd);
        base->epfd = -1;
    }

    free(base);
}

struct MyEvConnListener *
my_evconnlistener_new(struct MyEventBase *base,
                      my_evconnlistener_cb cb,
                      void *ptr,
                      unsigned flags,
                      int backlog,
                      int fd)
{
    struct My_evconnlistener_event *lev = calloc(1, sizeof(struct My_evconnlistener_event));
	if (!lev)
		return NULL;
        
	if (backlog > 0) {
		if (ff_listen(fd, backlog) < 0)
			return NULL;
	} else if (backlog < 0) {
		if (ff_listen(fd, 128) < 0)
			return NULL;
	}


    lev->base.base = base;
    lev->base.cb = cb;
    lev->base.user_data = ptr;
    lev->base.fd = fd;
    lev->base.flags = flags;

    lev->listener = my_event_new(base, fd, EV_READ | EV_PERSIST, my_listener_read_cb,lev);

    if (!lev->listener) {
        free(lev);
        return NULL;
    }

    if (my_event_add(lev->listener, NULL) < 0) {
        my_event_free(lev->listener);
        free(lev);
        return NULL;
    }
    return &lev->base;
}
    static void my_listener_read_cb(int fd, short what, void *p){

	struct MyEvConnListener *lev = p;
	int err;
	my_evconnlistener_cb cb;
	int errorcb;
	void *user_data;
	//LOCK(lev); no estoy en estructura multihilo
	//while (1) {
		struct linux_sockaddr ss;
		ev_socklen_t socklen = sizeof(ss);
		//int new_fd = evutil_accept4_(fd, (struct sockaddr*)&ss, &socklen, lev->accept4_flags);
        int new_fd = ff_accept4(fd, &ss, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC);

		// if (new_fd < 0)
		// 	break;
		if (socklen == 0) {
			/* This can happen with some older linux kernels in
			 * response to nmap. */
			ff_close(new_fd);
			//continue;
		}

		if (lev->cb == NULL) {
			ff_close(new_fd);
			//UNLOCK(lev);
			return;
		}
		//++lev->refcnt;
		cb = lev->cb;
		user_data = lev->user_data;

		cb(lev, new_fd, (struct sockaddr*)&ss, (int)socklen,
		    user_data);
		// if (lev->refcnt == 1) {
		// 	int freed = listener_decref_and_unlock(lev);
		// 	EVUTIL_ASSERT(freed);
		// 	return;
		// }
		//--lev->refcnt;
		// if (!lev->enabled) {
		// 	/* the callback could have disabled the listener */
		// 	UNLOCK(lev);
		// 	return;
		// }
	// } while
	// err = evutil_socket_geterror(fd);
	// if (EVUTIL_ERR_ACCEPT_RETRIABLE(err)) {
	// 	UNLOCK(lev);
	// 	return;
	// // }
	// if (lev->errorcb != NULL) {
	// 	++lev->refcnt;
	// 	errorcb = lev->errorcb;
	// 	user_data = lev->user_data;
	// 	errorcb(lev, user_data);
	// 	listener_decref_and_unlock(lev);
	// } else {
	// 	event_sock_warn(fd, "Error from accept() call");
	// 	UNLOCK(lev);
	// }
}

void my_evconnlistener_free(struct MyEvConnListener *listener) {
    if (!listener) return;
    my_event_del(listener->event);
    my_event_free(listener->event);
    free(listener);
}
void my_evconnlistener_enable(struct MyEvConnListener *listener) {
    if (listener && listener->event)
        my_event_add(listener->event, NULL);
}

void my_evconnlistener_disable(struct MyEvConnListener *listener) {
    if (listener && listener->event)
        my_event_del(listener->event);
}
my_fifo_t *allocate_my_fifo(void) {
    my_fifo_t *f = malloc(sizeof(my_fifo_t));
    if (!f) return NULL;
    f->capacity = FIFO_CAPACITY;
    f->items = calloc(f->capacity, sizeof(void *));
    if (!f->items) {
        free(f);
        return NULL;
    }
    f->head = f->tail = 0;
    return f;
}

void free_my_fifo(my_fifo_t *f) {
    if (!f) return;
    free(f->items);
    free(f);
}

// int my_fifo_push(my_fifo_t *f, void *item) {
//     int next = (f->tail + 1) % f->capacity;
//     if (next == f->head) return -1;  // full
//     f->items[f->tail] = item;
//     f->tail = next;
//     return 0;
// }

// void *my_fifo_pop(my_fifo_t *f) {
//     if (f->head == f->tail) return NULL;
//     void *item = f->items[f->head];
//     f->head = (f->head + 1) % f->capacity;
//     return item;
// }

#include <assert.h>
#include <stdio.h>

int my_fifo_push(my_fifo_t *f, void *item) {
    int next = (f->tail + 1) % f->capacity;

    // Mide la longitud actual (número de items en cola)
    int len = (f->tail - f->head + f->capacity) % f->capacity;

    fprintf(stderr,
        "[FIFO PUSH] %p before: head=%d tail=%d len=%d cap=%d → ",
        (void*)f, f->head, f->tail, len, f->capacity);

    if (next == f->head) {
        // ¡Cola llena!
        fprintf(stderr, "FULL (cannot push)\n");
        assert(len + 1 <= f->capacity);  // aquí lanzará si algo no cuadra
        return -1;
    }

    f->items[f->tail] = item;
    f->tail = next;

    len = (f->tail - f->head + f->capacity) % f->capacity;
    fprintf(stderr,
        "OK after: head=%d tail=%d len=%d cap=%d\n",
        f->head, f->tail, len, f->capacity);

    return 0;
}

void *my_fifo_pop(my_fifo_t *f) {
    // Mide la longitud actual antes de pop
    int len = (f->tail - f->head + f->capacity) % f->capacity;
    fprintf(stderr,
        "[FIFO POP ] %p before: head=%d tail=%d len=%d cap=%d → ",
        (void*)f, f->head, f->tail, len, f->capacity);

    if (f->head == f->tail) {
        // ¡Cola vacía!
        fprintf(stderr, "EMPTY (cannot pop)\n");
        assert(len >= 0);  // para verificar que no nos hayamos pasado
        return NULL;
    }

    void *item = f->items[f->head];
    f->head = (f->head + 1) % f->capacity;

    len = (f->tail - f->head + f->capacity) % f->capacity;
    fprintf(stderr,
        "OK after: head=%d tail=%d len=%d cap=%d\n",
        f->head, f->tail, len, f->capacity);

    return item;
}


int my_fifo_is_empty(my_fifo_t *f) {
    return f->head == f->tail;
}
listener_fifo_t *create_listener_fifo(listener_cb_t cb, void *ctx) {
    listener_fifo_t *lf = malloc(sizeof(listener_fifo_t));
    lf->fifo = allocate_my_fifo();
    lf->callback = cb;
    lf->ctx = ctx;
    return lf;
}
void register_listener_fifo(listener_fifo_t *fifo) {
    if (fifo_count < MAX_FIFOS)
        fifo_list[fifo_count++] = fifo;
}

void process_registered_listener_fifos(void) {
    for (int i = 0; i < fifo_count; ++i)
        process_listener_fifo(fifo_list[i]);
}
void process_listener_fifo(listener_fifo_t *lf){
    if (!lf || !lf->callback || !lf->fifo) return;

    // Procesa todos los elementos en la FIFO
    while (!my_fifo_is_empty(lf->fifo)) {
        lf->callback(lf, lf->ctx);
    }
}

void my_event_disable_read(ioa_socket_handle s) {
  if (!s || !s->e || !s->e->event_base) {
    printf("WARN: my_event_disable_read called with invalid socket\n");
    return;
  }

  struct epoll_event ev;
  ev.events = EPOLLOUT;
  ev.data.ptr = s->read_event;
  struct MyEventBase *eb = s->e->event_base;
  s->read_enabled = 0;

  int ret = ff_epoll_ctl(eb->epfd, EPOLL_CTL_MOD, s->fd, &ev);
  printf("LOG: my_event_disable_read fd=%d ret=%d\n", s->fd, ret);
}

void my_event_enable_read(ioa_socket_handle s){
    if (!s || !s->e || !s->e->event_base) {
        printf("WARN: my_event_enable_read called with invalid socket\n");
        return;
    }
    struct epoll_event ev = {0};
    ev.events |= EPOLLIN | EPOLLOUT; 
    ev.data.ptr = s->read_event;
    struct MyEventBase *eb = s->e->event_base;
    s->read_enabled = 1;
    int ret = ff_epoll_ctl(eb->epfd, EPOLL_CTL_MOD,s->fd, &ev);
    printf("LOG: my_event_enable_read fd=%d ret=%d\n", s->fd, ret);
}