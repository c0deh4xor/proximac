#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <uv.h>
#include <unistd.h>
#include <getopt.h>

#include "jconf.h"
#include "local.h"
#include "utils.h"

static void http_connect_to_remote_cb(uv_connect_t* req, int status);
static void http_remote_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void http_remote_write_cb(uv_write_t* req, int status);
extern conf_t conf;

static void http_connect_to_remote_cb(uv_connect_t* req, int status)
{
    server_ctx_t* server_ctx = (server_ctx_t*)req->data;
    if (status) {
        // cleanup
        if (status != UV_ECANCELED) {
            TRY_CLOSE(server_ctx, &server_ctx->remote_handle, remote_after_close_cb);
        }

        LOGE("Fail connect to remote server: status=%d", status);
        free(req);
        return;
    }

    LOGI("connect to proxy server: status=%d", status);
    uv_read_start(req->handle, remote_alloc_cb, http_remote_read_cb);

    write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
    wr->req.data = server_ctx;

    // send connect command
    char connectReq[280];
    snprintf(connectReq, sizeof(connectReq),
             "CONNECT %s:%d HTTP/1.0\r\n\r\n",
             server_ctx->remote_addr, server_ctx->port);
    
    // add credential
//    unsigned char username_len = strlen(conf.username);
//    unsigned char password_len = strlen(conf.password);
//    if(username_len > 0) {
//        long len = strlen(connectReq);
//        snprintf(connectReq + len, sizeof(connectReq),
//                 "\r\nProxy-Authorization: basic %s",
//                 "");
//    }
    
    LOGD("proxy connect:%s", connectReq);
    long len = strlen(connectReq);
    char* httpreq = malloc(len);
    memcpy(httpreq, connectReq, len);
    wr->buf = uv_buf_init(httpreq, (int)len);
    
    uv_write(&wr->req, (uv_stream_t*)&server_ctx->remote_handle, &wr->buf, 1, http_remote_write_cb);
}

static void http_remote_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    server_ctx_t* server_ctx = stream->data;
    if (nread <= 0) {
        if (nread == 0) {
            if (buf->len > 0) {
                free(buf->base);
            }
            return;
        }
        TRY_CLOSE(server_ctx, &server_ctx->remote_handle, remote_after_close_cb);
    } else {
        // LOGI("reponse: %s", buf->base);
        if (server_ctx->remote_stage == 0) {
            char* resp = buf->base;
            //TODO auth
            if (!strstr(resp, "200")) { //success
                LOGD("-- tunnel connected -- ");
                server_ctx->server_stage = 1;
                write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
                if (server_ctx->buf_len > 0) {
                    char* tmpbuf = malloc(server_ctx->buf_len);
                    memcpy(tmpbuf, server_ctx->buf, server_ctx->buf_len);
                    free(server_ctx->buf);
                    server_ctx->buf = NULL;
                    wr->req.data = server_ctx;
                    wr->buf = uv_buf_init(tmpbuf, (unsigned int)server_ctx->buf_len);
                    uv_write(&wr->req, (uv_stream_t*)&server_ctx->remote_handle, &wr->buf, 1, http_remote_write_cb);
                }

                uv_read_start((uv_stream_t*)&server_ctx->server_handle, server_alloc_cb, server_read_cb);
                server_ctx->remote_stage = 2;
            }
        } else if (server_ctx->remote_stage == 2) {
            write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
            wr->req.data = server_ctx;
            wr->buf = uv_buf_init(buf->base, (unsigned int)nread);
            uv_write(&wr->req, (uv_stream_t*)&server_ctx->server_handle, &wr->buf, 1, http_remote_write_cb);
        }
    }
}

static void http_remote_write_cb(uv_write_t* req, int status)
{
    write_req_t* wr = (write_req_t*)req;
    server_ctx_t* server_ctx = req->data;
    if (status) {
        if (status != UV_ECANCELED) {
            LOGW("remote_write_cb TRY_CLOSE");
            if (req->handle == &server_ctx->server_handle) {
                TRY_CLOSE(server_ctx, &server_ctx->server_handle, server_after_close_cb);
            } else {
                TRY_CLOSE(server_ctx, &server_ctx->remote_handle, remote_after_close_cb);
            }
        }
    }

    assert(wr->req.type == UV_WRITE);
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

struct proxy_server http_proxy = {
    .remote_write_cb = http_remote_write_cb,
    .remote_read_cb = http_remote_read_cb,
    .connect_to_remote_cb = http_connect_to_remote_cb,
};
