
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
};


struct ngx_cycle_s {
	/*����������ģ��洢������Ľṹ��ָ�룬��������һ�����飬ÿ�������Ա����һ��ָ�룬���ָ��ָ����һ���洢��ָ�������*/
    void                  ****conf_ctx;
    ngx_pool_t               *pool;//�ڴ��

	/*��־ģ�����ṩ�����ɻ���ngx_log_t��־����Ĺ��ܣ������logʵ�������ڻ�û��ִ��ngx_init_cycle����ǰ��Ҳ���ǻ�û��������ǰ���������Ϣ��Ҫ�������־���ͻ���ʱʹ��log���������������Ļ����ngx_init_cycle����ִ�к󣬽������nginx.conf�����ļ��е�������������ȷ����־�ļ�����ʱ���log���¸�ֵ*/
    ngx_log_t                *log;
	/*����ngx_init_cycle�����󣬻���new_log�ĵ�ַ���������logָ��*/
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

	//fiels��������ngx_connection_t��ָ����ɵ����飬files_n����ָ������������ļ������ֵ��������files�����Ա
    ngx_connection_t        **files;

	//�������ӳأ���free_connection_n���ʹ��
    ngx_connection_t         *free_connections; //������������
    ngx_uint_t                free_connection_n; //��������������

	//���ظ�ʹ�õ�˫�����Ӷ��У���Ա������ngx_connection_t
    ngx_queue_t               reusable_connections_queue; //���������Ӷ���

	//�洢ngx_listening_t��Ա
    ngx_array_t               listening;

	//������Nginx����Ҫ������Ŀ¼�����Ŀ¼�����ڣ������ͼ������������Ŀ¼ʧ�ܽ��ᵼ��Nginx����ʧ�ܡ�
    ngx_array_t               paths;

	//����Nginx�Ѿ��򿪵������ļ�(ngx_open_file_t�ṹ��)�ĵ�����
    ngx_list_t                open_files;

	//������洢ngx_shm_zone_t��ÿ��Ԫ�ر�ʾһ�鹲���ڴ档
    ngx_list_t                shared_memory;

	//��ʾ��ǰ�������������Ӷ�����������������connections��Ա���ʹ��
    ngx_uint_t                connection_n;
    ngx_uint_t                files_n;

	//ָ��ǰ�����е��������Ӷ���ÿ�����Ӷ����Ӧһ��д�¼���һ�����¼�
    ngx_connection_t         *connections;
	//ָ��ǰ�����е�����д�¼�����connection_nͬʱ��ʾ���ж��¼�������
    ngx_event_t              *read_events;
	//ָ��ǰ�����е�����д�¼�����connection_nͬʱ��ʾ����д�¼�������
    ngx_event_t              *write_events;

	/*�ɵ�ngx_cycle_t��������������һ��ngx_cycle_t�����еĳ�Ա������ngx_init_cycle���������������ڣ���Ҫ����һ����ʱ��ngx_cycle_t���󱣴�һЩ�������ڵ���ngx_init_cycle����ʱ���Ϳ��԰Ѿɵ�ngx_cycle_t�Ķ��󴫽�ȥ������ʱold_clcle����ͻᱣ�����ǰ�ڵ�ngx_clcle_t����*/
    ngx_cycle_t              *old_cycle;

	//�����ļ�����ڰ�װĿ¼��·������
    ngx_str_t                 conf_file;
	//Nginx���������ļ�ʱ��Ҫ���⴦�����������Я���Ĳ�����һ����-gѡ��Я���Ĳ���
    ngx_str_t                 conf_param;
	//Nginx�����ļ����ڵ�·��
    ngx_str_t                 conf_prefix;
	//Nginx��װĿ¼��·��
    ngx_str_t                 prefix;
	//���ڽ��̼�ͬ�����ļ�������
    ngx_str_t                 lock_file;
	//ʹ��gethostnameϵͳ���õõ���������
    ngx_str_t                 hostname;
};


typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes;
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;
     ngx_int_t                rlimit_sigpending;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     uint64_t                *cpu_affinity;

     char                    *username;
     ngx_uid_t                user;
     ngx_gid_t                group;

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;

#if (NGX_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
uint64_t ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
