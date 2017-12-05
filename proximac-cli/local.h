#ifndef LOCAL_H_
#define LOCAL_H_

#include "constant.h"
#include "tree.h"

struct pid {
    RB_ENTRY(pid) rb_link;
    int pid;
    char* name;
};

RB_HEAD(pid_tree, pid);
RB_PROTOTYPE(pid_tree, pid, rb_link, pid_cmp);
extern struct pid_tree pid_list;

int tell_kernel_to_hook();

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    uv_tcp_t handle;
} listener_t;

struct remote_ctx;

typedef void (*remote_read)(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
typedef void (*remote_write)(uv_write_t* req, int status);
typedef void (*connect_to_remote)(uv_connect_t* req, int status);

typedef struct proxy_server {
    remote_write remote_write_cb;
    remote_read remote_read_cb;
    connect_to_remote connect_to_remote_cb;
} proxy_server_t;

typedef struct server_ctx {
    struct proxy_server *proxy;
    
    uv_tcp_t server_handle;
    uv_tcp_t remote_handle;
    int server_stage;
    int remote_stage;
    int remote_auth_stage;
    char remote_addr[256];
    char addrlen;
    uint16_t port;
    char* buf;
    size_t buf_len;
    struct remote_ctx* remote_ctx;
} server_ctx_t;


// common callback functions
void server_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf);
void remote_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf);

void remote_after_close_cb(uv_handle_t* handle);
void final_after_close_cb(uv_handle_t* handle);
void server_after_close_cb(uv_handle_t* handle);

void server_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void server_accept_cb(uv_stream_t* server, int status);

#endif
