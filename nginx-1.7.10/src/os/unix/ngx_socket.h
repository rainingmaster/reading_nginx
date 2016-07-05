
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>


#define NGX_WRITE_SHUTDOWN SHUT_WR

typedef int  ngx_socket_t;

/*  int  socket(int protofamily, int type, int protocol);//����sockfd */
/*
    protofamily����Э�����ֳ�ΪЭ���壨family�������õ�Э�����У�AF_INET(IPV4)��AF_INET6(IPV6)��AF_LOCAL�����AF_UNIX��Unix��socket����AF_ROUTE�ȵȡ�Э���������socket�ĵ�ַ���ͣ���ͨ���б�����ö�Ӧ�ĵ�ַ����AF_INET������Ҫ��ipv4��ַ��32λ�ģ���˿ںţ�16λ�ģ�����ϡ�AF_UNIX������Ҫ��һ������·������Ϊ��ַ��
    type��ָ��socket���͡����õ�socket�����У�SOCK_STREAM��SOCK_DGRAM��SOCK_RAW��SOCK_PACKET��SOCK_SEQPACKET�ȵȣ�socket����������Щ������
    protocol������˼�壬����ָ��Э�顣���õ�Э���У�IPPROTO_TCP��IPPTOTO_UDP��IPPROTO_SCTP��IPPROTO_TIPC�ȣ����Ƿֱ��ӦTCP����Э�顢UDP����Э�顢STCP����Э�顢TIPC����Э�飨���Э���ҽ��ᵥ����ƪ���ۣ�����
*/
#define ngx_socket          socket
#define ngx_socket_n        "socket()"


#if (NGX_HAVE_FIONBIO)

int ngx_nonblocking(ngx_socket_t s);
int ngx_blocking(ngx_socket_t s);

#define ngx_nonblocking_n   "ioctl(FIONBIO)"
#define ngx_blocking_n      "ioctl(!FIONBIO)"

#else

#define ngx_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define ngx_nonblocking_n   "fcntl(O_NONBLOCK)"

#define ngx_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define ngx_blocking_n      "fcntl(!O_NONBLOCK)"

#endif

int ngx_tcp_nopush(ngx_socket_t s);
int ngx_tcp_push(ngx_socket_t s);

#if (NGX_LINUX)

#define ngx_tcp_nopush_n   "setsockopt(TCP_CORK)"
#define ngx_tcp_push_n     "setsockopt(!TCP_CORK)"

#else

#define ngx_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
#define ngx_tcp_push_n     "setsockopt(!TCP_NOPUSH)"

#endif


#define ngx_shutdown_socket    shutdown
#define ngx_shutdown_socket_n  "shutdown()"

#define ngx_close_socket    close
#define ngx_close_socket_n  "close() socket"


#endif /* _NGX_SOCKET_H_INCLUDED_ */
