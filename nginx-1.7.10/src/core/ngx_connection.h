
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;//�׽��־��

    struct sockaddr    *sockaddr;//����sockaddr��ַ
    socklen_t           socklen;    /*sockaddr��ַ���� size of sockaddr */
    size_t              addr_text_max_len;//�洢ip��ַ���ַ���addr_text��󳤶�
    ngx_str_t           addr_text;//���ַ�����ʽ�洢ip��ַ

	//�׽������͡�types��SOCK_STREAMʱ����ʾ��tcp
    int                 type;

	//TCPʵ�ּ���ʱ��backlog���У�����ʾ��������ͨ���������ֽ���tcp���ӵ���û���κν��̿�ʼ���������������
    int                 backlog;
    int                 rcvbuf;//�׽��ֽ��ջ�������С
    int                 sndbuf;//�׽��ַ��ͻ�������С
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;//���µ�tcp���ӳɹ�������Ĵ�����

	//Ŀǰ��Ҫ����HTTP����mail��ģ�飬���ڱ��浱ǰ�����˿ڶ�Ӧ�ŵ�����������
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;//���Ϊ�µ�tcp���Ӵ����ڴ�أ����ڴ�صĳ�ʼ��СӦ����pool_size��
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;//�������Ȼû���յ��û������ݣ��Ͷ���������

	//ǰһ��ngx_listening_t�ṹ��������ɵ�����
    ngx_listening_t    *previous;
    ngx_connection_t   *connection;//��ǰ���������Ӧ��ngx_connection_t�ṹ��

    unsigned            open:1;//Ϊ1��ʾ���������Ч��Ϊ0��ʾ�����ر�
    unsigned            remain:1;//Ϊ1��ʾ���ر�ԭ�ȴ򿪵ļ����˿ڣ�Ϊ0��ʾ�ر������򿪵ļ����˿�
    unsigned            ignore:1;//Ϊ1��ʾ�������õ�ǰngx_listening_t�ṹ���е��׽��֣�Ϊ0ʱ������ʼ���׽���

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;//Ϊ1��ʾ��ǰ�ṹ���Ӧ���׽����Ѿ�����
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;//Ϊ1��ʾ�������ַת��Ϊ�ַ�����ʽ�ĵ�ַ

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_SPDY_BUFFERED      0x02


/* ��nginx��connection���Ƕ�tcp���ӵķ�װ�����а������ӵ�socket�����¼���д�¼�������nginx��װ��connection�����Ժܷ����ʹ��nginx��������������ص����飬���磬�������ӣ�������������ݵ� */
struct ngx_connection_s {
	//����δʹ��ʱ��data���ڳ䵱���ӳ��п��������е�nextָ�롣����ʹ��ʱ��ģ�������HTTP�У�dataָ��ngx_http_request_t
    void               *data;
    ngx_event_t        *read; //���¼����¼������data��������ngx_connection_s�ṹ��ָ��
    ngx_event_t        *write; //���¼����¼������data��������ngx_connection_s�ṹ��ָ��

    ngx_socket_t        fd;//�׽��ֶ�Ӧ�ľ��

    ngx_recv_pt         recv;//ֱ�ӽ��������ַ����ķ���
    ngx_send_pt         send;//ֱ�ӷ��������ַ����ķ���
    ngx_recv_chain_pt   recv_chain;//�����������������ַ����ķ���
    ngx_send_chain_pt   send_chain;//�����������������ַ����ķ���

    ngx_listening_t    *listening;//������Ӷ�Ӧ��ngx_listening_t�������󣬴�������listening�����˿ڵ��¼�����

    off_t               sent;//����������ѷ��͵��ֽ��������ѷ��͵�ƫ����

    ngx_log_t          *log;//��־����

	/*�ڴ�ء�һ����acceptһ���µ�����ʱ���ᴴ��һ���ڴ�أ�����������ӽ���ʱ�������ڴ�ء��ڴ�ش�С��������listening��Ա��pool_size������*/
    ngx_pool_t         *pool;

    struct sockaddr    *sockaddr; //���ӿͻ��˵�sockaddr
    socklen_t           socklen; //sockaddr�ṹ��ĳ���
    ngx_str_t           addr_text; //���ӿͻ����ַ�����ʽ��IP��ַ

    ngx_str_t           proxy_protocol_addr;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

	//���������˿ڶ�Ӧ��sockaddr�ṹ�壬ʵ���Ͼ���listening���������sockaddr��Ա
    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    ngx_buf_t          *buffer;//�û����ܡ�����ͻ��˷������ַ�����buffer���������ڴ�ط���ģ���С���ɾ���

	/*��������ǰ������˫������Ԫ�ص���ʽ��ӵ�ngx_cycle_t���Ľṹ���reuseable_connection_queue˫�������У���ʾ�������õ�����*/
    ngx_queue_t         queue;

	/*����ʹ�ô�����ngx_connection_t�ṹ��ÿ�ν���һ�����Կͻ��˵����ӣ������������˷�������������ʱ��number�����1*/
    ngx_atomic_uint_t   number;

    ngx_uint_t          requests;//������������

    unsigned            buffered:8;

	//�����ӵ���־����ռ��3λ��ȡֵ��ΧΪ0��7����ʵ��ֻ������5��ֵ����ngx_connection_log_error_eö�ٱ�ʾ��
    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            unexpected_eof:1;//Ϊ1��ʾ���ڴ��ַ�������
    unsigned            timedout:1;//Ϊ1��ʾ�����Ѿ���ʱ
    unsigned            error:1;//Ϊ1��ʾ���Ӵ�������г��ִ���
    unsigned            destroyed:1;//Ϊ1��ʾ�����Ѿ�����

    unsigned            idle:1;//Ϊ1��ʾ���Ӵ��ڿ���״̬����keepalive���������м��״̬
    unsigned            reusable:1;//Ϊ1��ʾ���ӿ����ã��������queue�ֶζ�Ӧʹ��
    unsigned            close:1;//Ϊ1��ʾ���ӹر�

    unsigned            sendfile:1;//Ϊ1��ʾ���ڽ��ļ��е����ݷ������ӵ���һ��
    
	/*Ϊ1��ʾֻ�������׽��ֶ�Ӧ�ķ��ͻ�������������������õĴ�С��ֵʱ���¼�����ģ��Ż�ַ����¼�������ngx_handle_write_event�����е�lowat�����Ƕ�Ӧ��*/
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            aio_sendfile:1;
    unsigned            busy_count:2;
    ngx_buf_t          *busy_sendfile;
#endif

#if (NGX_THREADS)
    ngx_atomic_t        lock;
#endif
};


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
