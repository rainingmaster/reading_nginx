
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_probe.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_init_phases(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_headers_in_hash(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_phase_handlers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);

static ngx_int_t ngx_http_add_addresses(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_opt_t *lsopt);
static ngx_int_t ngx_http_add_address(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_opt_t *lsopt);
static ngx_int_t ngx_http_add_server(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_addr_t *addr);

static char *ngx_http_merge_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static char *ngx_http_merge_locations(ngx_conf_t *cf,
    ngx_queue_t *locations, void **loc_conf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static ngx_int_t ngx_http_init_locations(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_cmp_locations(const ngx_queue_t *one,
    const ngx_queue_t *two);
static ngx_int_t ngx_http_join_exact_locations(ngx_conf_t *cf,
    ngx_queue_t *locations);
static void ngx_http_create_locations_list(ngx_queue_t *locations,
    ngx_queue_t *q);
static ngx_http_location_tree_node_t *
    ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix);

static ngx_int_t ngx_http_optimize_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_array_t *ports);
static ngx_int_t ngx_http_server_names(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_cmp_conf_addrs(const void *one, const void *two);
static int ngx_libc_cdecl ngx_http_cmp_dns_wildcards(const void *one,
    const void *two);

static ngx_int_t ngx_http_init_listening(ngx_conf_t *cf,
    ngx_http_conf_port_t *port);
static ngx_listening_t *ngx_http_add_listening(ngx_conf_t *cf,
    ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#endif

ngx_uint_t   ngx_http_max_module;


ngx_int_t  (*ngx_http_top_header_filter) (ngx_http_request_t *r);
ngx_int_t  (*ngx_http_top_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


ngx_str_t  ngx_http_html_default_types[] = {
    ngx_string("text/html"),
    ngx_null_string
};


static ngx_command_t  ngx_http_commands[] = {

    { ngx_string("http"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_http_module_ctx = {
    ngx_string("http"),
     //没有在此处建立creat_conf/init_conf，而是在ngx_http_block中建立一系列main、svr、loc的conf
    NULL,
    NULL
};


ngx_module_t  ngx_http_module = {
    NGX_MODULE_V1,
    &ngx_http_module_ctx,                  /* module context */
    ngx_http_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * http 的命令解析
 * 在ngx_conf_handler中调用
 * 建立main_conf,loc_conf,scr_conf
 * main级即http层
 * 填充main_conf->phase_engine下面各个阶段的处理方法
 */
static char *
ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   mi, m, s;
    ngx_conf_t                   pcf;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t         *ctx;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    /* the main http context */
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * 分级存储所有main/srv/loc
     * 配置带回给上一级ngx_conf_handler，将存在cycle->conf_ctx中
     */
    *(ngx_http_conf_ctx_t **) conf = ctx;


    /* count the number of the http modules and set up their indices */

    //算出 http 模块的索引，存在全局变量中
    ngx_http_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_http_max_module++;
    }


    /* the http main_conf context, it is the same in the all http contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_http_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */
    //server级设置
    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null loc_conf context, it is used to merge
     * the server{}s' loc_conf's
     */
    //用于合并server级的local设置
    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all http modules
     */
    /*
     * 设置的结构相当于:
     * http{
     *      ...
     *      ...
     *      各个 module 的 [http_conf]、(空的 sever_conf)、(空的 location_conf)  (存储在ngx_http_core_main_conf_t->ctx)
     *      server{
     *          ...
     *          ...
     *          各个 module 的 [sever_conf]、(空的 location_conf)  (存储在ngx_http_core_srv_conf->ctx)
     *           location{
     *                 ...
     *                 ...
     *                 各个 module 的 [location_conf]  (存在core_srv_conf->ctx)
     *            }
     *      }
     * }
     * 其中空的子级配置供各个方法存放本级的设置，最后在最后一级用 *_merge_* 合并
     */

    /*
     * 建立空的 srv 和loc 配置，相当于 http 下面也有一个 location
     */
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index; //也是按照 0,1,2... 增加，且与 module 中位置对应

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    //暂存之前的conf，会使用上面新生成的 ctx 解析 block 中的命令
    pcf = *cf;
    cf->ctx = ctx;

    //执行conf前置函数
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* parse inside the http{} block */

    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL); //读取完 http {} 内命令

    if (rv != NGX_CONF_OK) {
        goto failed;
    }

    /*
     * init http{} main_conf's, merge the server{}s' srv_conf's
     * and its location{}s' loc_conf's
     */

    /*
     * 此ctx上下文为本函数新new的http模块的上下文。
     * 此处即取ngx_http_core_module的create_main_conf方法的返回值，
     * 即ngx_http_core_create_main_conf(cf)返回值
     * 仅仅申请一些空间和初始化变量
     */
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    //执行conf建立函数
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init http{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]); //第二个参数为对应模块create_main_conf方法返回值
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        //合并cmcf->servers
        rv = ngx_http_merge_servers(cf, cmcf, module, mi);
        if (rv != NGX_CONF_OK) {
            goto failed;
        }
    }

    /* 
     * 合并完的状态:
     * main_conf[ngx_http_core_module.ctx_index]  (ngx_http_core_main_conf_t)
     *  -> servers.elts 指向数组 (ngx_http_core_srv_conf_t)
     *    -> ctx  (ngx_http_conf_ctx_t*)
     *      -> loc_conf[ngx_http_core_module.ctx_index]  (ngx_http_core_loc_conf_t)
     *        -> locations (queue)
     */

    /* create location trees */

    for (s = 0; s < cmcf->servers.nelts; s++) {

        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (ngx_http_init_locations(cf, cscfp[s], clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }


    //为各个模块的handler数组申请空间
    if (ngx_http_init_phases(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    //建立与请求头相关的哈希表
    if (ngx_http_init_headers_in_hash(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    /*
     * 执行conf后置函数
     */
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        //调用postconfiguration的函数，实现对handler的初始化，相应的handler都会被存入相应phase[NGX_HTTP_XXX_PHASE]的handler数组中。
        if (module->postconfiguration) {

            //执行conf后置函数阶段的探针
            ngx_http_probe_module_post_config(ngx_modules[m]);

            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (ngx_http_variables_init_vars(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * http{}'s cf->ctx was needed while the configuration merging
     * and in postconfiguration process
     */

    //还原conf
    *cf = pcf;


    //初始化各个http阶段的phases中的hanler方法，填充之前申请的数组
    if (ngx_http_init_phase_handlers(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    /* optimize the lists of ports, addresses and server names */

    if (ngx_http_optimize_servers(cf, cmcf, cmcf->ports) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}


/* 建立各个模块的handler数组
 * 为各个模块的handler数组申请空间
 * 设定的位置都是估计的位置，之后push会增加空间
 */
static ngx_int_t
ngx_http_init_phases(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers,
                       cf->pool, 2, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers,
                       cf->pool, 4, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_init_headers_in_hash(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_array_t         headers_in;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    ngx_http_header_t  *header;

    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (header = ngx_http_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &cmcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_init_phase_handlers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_int_t                   j;
    ngx_uint_t                  i, n;
    ngx_uint_t                  find_config_index, use_rewrite, use_access;
    ngx_http_handler_pt        *h;
    ngx_http_phase_handler_t   *ph;
    ngx_http_phase_handler_pt   checker;

    //cmcf为ngx_http_core_create_main_conf(cf)的返回值

    //server 级的重新和 location 级的重写，设置为 "未设置值"
    cmcf->phase_engine.server_rewrite_index = (ngx_uint_t) -1; //设置为最大的整形
    cmcf->phase_engine.location_rewrite_index = (ngx_uint_t) -1; //设置为最大的整形
    find_config_index = 0;
    use_rewrite = cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
    use_access = cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;

    n = use_rewrite + use_access + cmcf->try_files + 1 /* find config phase */;

    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts; //算出所有handler的总量
    }

    //申请一个ngx_http_phase_handler_t数组空间，用于存储所有的handler
    ph = ngx_pcalloc(cf->pool,
                     n * sizeof(ngx_http_phase_handler_t) + sizeof(void *)); //加一个空指针，最后一个为handlers空
    if (ph == NULL) {
        return NGX_ERROR;
    }

    /*
     * 最后用于执行和跳转的结构，cmcf->phases[i].handlers.elts中所有handlers将转换成本结构的handler
     * 由于cmcf->phases[i].handlers是个数组，因此cmcf->phase_engine.handlers中的checker会重复
     * 有的又只有checker，而没有handler
     * 一个二维数组，转成了一维数组
     */
    cmcf->phase_engine.handlers = ph;
    //将赋予到 ph->next 中，用于一维数组的状态跳转
    n = 0;

    /* 除了 NGX_HTTP_LOG_PHASE 外所有 http 阶段 */
    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        /*
         * 对应阶段的处理函数，大多将赋予到ph->handler。见最下面的循环
         * 会在各个 NGX_HTTP_MODULE 的 postconfiguration 函数中填充
         */
        h = cmcf->phases[i].handlers.elts;
        
        /* 
         * 使用break将跳出本switch但仍将执行for循环的剩余语句；
         * 使用continue则直接跳至i++进行下一次for循环执行；
         * 按照原来的http执行顺序处理
         */
        switch (i) {
        /*在cmcf->phase_engine.handlers中的起始index*/
        /*index=0*/case NGX_HTTP_SERVER_REWRITE_PHASE: //*1
            if (cmcf->phase_engine.server_rewrite_index == (ngx_uint_t) -1) {
                cmcf->phase_engine.server_rewrite_index = n;
            }
            checker = ngx_http_core_rewrite_phase;

            break;

        //本阶段无cmcf->phases[2].handlers.elts方法，因此ph->handler无内容
        /*index=2*/case NGX_HTTP_FIND_CONFIG_PHASE: //*2
            find_config_index = n; //记录本阶段在cmcf->phase_engine.handlers中的起始位置

            ph->checker = ngx_http_core_find_config_phase;
            /* ph->next = 0; */
            n++; /* n++，随着下面的 ph++ 到达下一阶段 */
            ph++; /* ph++ ，直接到达下阶段的index*/

            continue;

        /*index=3*/case NGX_HTTP_REWRITE_PHASE: //*3
            if (cmcf->phase_engine.location_rewrite_index == (ngx_uint_t) -1) {
                cmcf->phase_engine.location_rewrite_index = n;
            }
            checker = ngx_http_core_rewrite_phase;

            break;

        //本阶段无cmcf->phases[4].handlers.elts方法，因此ph->handler无内容
        /*index=6*/case NGX_HTTP_POST_REWRITE_PHASE: //*4
            if (use_rewrite) {
                ph->checker = ngx_http_core_post_rewrite_phase;
                ph->next = find_config_index; //返回到查找config阶段
                n++; /* n++，随着下面的 ph++ 到达下一阶段 */
                ph++; /* ph++ ，直接到达下阶段的index*/
            }

            continue;

        /*
         *index=7 * case NGX_HTTP_PREACCESS_PHASE: //*5
         *  checker = ngx_http_core_generic_phase;
         */

        /*index=9*/case NGX_HTTP_ACCESS_PHASE: //*6
            checker = ngx_http_core_access_phase;
            /*
             * 如果 NGX_HTTP_ACCESS_PHASE 的 handlers 大于0，即 use_access=1 直接跳过下个阶段，即直接到 NGX_HTTP_CONTENT_PHASE(或NGX_HTTP_TRY_FILES_PHASE)
             * 如果 NGX_HTTP_ACCESS_PHASE 的 handlers 等于0，即 use_access=0 n将会在 NGX_HTTP_CONTENT_PHASE 阶段的 next 多加 1 (NGX_HTTP_TRY_FILES_PHASE 不受影响)
             */
            n++;
            break;

        /*index=12*/case NGX_HTTP_POST_ACCESS_PHASE: //*7
            if (use_access) {
                ph->checker = ngx_http_core_post_access_phase;
                /* ph->handler = NULL; */
                ph->next = n;
                ph++;
            }

            continue;

        case NGX_HTTP_TRY_FILES_PHASE: //*8
            if (cmcf->try_files) { //try_files没有打开，不配置此项
                ph->checker = ngx_http_core_try_files_phase;
                n++;
                ph++;
            }

            continue;

        /*index=12*/case NGX_HTTP_CONTENT_PHASE: //*9
            checker = ngx_http_core_content_phase;
            break;

        /*
         * 其余阶段的都是用ngx_http_core_generic_phase一般处理方法
         * 但是也需 cmcf->phases[i].handlers.nelts > 0 的阶段才会增加
         */
        default: //*0、5
            checker = ngx_http_core_generic_phase;
        }

        //nelts为此phases的handlers数量，加上后即跳到下一个阶段
        n += cmcf->phases[i].handlers.nelts; //跳到下一个阶段phases的第一个handlers

        //填充数组
        for (j = cmcf->phases[i].handlers.nelts - 1; j >=0; j--) {
            ph->checker = checker;
            ph->handler = h[j]; //指向cmcf->phases[i].handlers.elts，逆序，从后往前填充
            ph->next = n; //下一个阶段phases中第一个handlers的索引，本ph的都固定
            ph++;
        }
    }

    return NGX_OK;
}


/*
 * 按照各个 http_*_module 合并 server 级配置
 * 在 ngx_http_block 中调用
 * 包括合并 svr 级和 loc 级，设置是按照不同 module 独立的
 */
static char *
ngx_http_merge_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                        *rv;
    ngx_uint_t                   s;
    ngx_http_conf_ctx_t         *ctx, saved;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;

    cscfp = cmcf->servers.elts;
    ctx = (ngx_http_conf_ctx_t *) cf->ctx;
    saved = *ctx; // main 层的设置
    rv = NGX_CONF_OK;

    //遍历所有 core_server_conf
    for (s = 0; s < cmcf->servers.nelts; s++) {

        /* merge the server{}s' srv_conf's */

        ctx->srv_conf = cscfp[s]->ctx->srv_conf; //ngx_http_core_srv_conf_t->ctx->svr_conf 所有 server 层生成的 svr_conf

        //调用每个 module 的 merge_srv_conf 合并srv配置方法
        if (module->merge_srv_conf) {
            /*
             * 将 main 层生成的 srv_conf (见 ngx_http_block) 与 server 层生成的 srv_conf (见 ngx_http_core_server )
             * 调用对应 module 合并方法合并
             * 合并完存储于 cscfp[s]->ctx->srv_conf[ctx_index] (server 层生成的 srv_conf)
             */
            rv = module->merge_srv_conf(cf, saved.srv_conf[ctx_index],
                                        cscfp[s]->ctx->srv_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        //按照各个 http_*_module 合并 location 级配置
        if (module->merge_loc_conf) {

            /* merge the server{}'s loc_conf */

            ctx->loc_conf = cscfp[s]->ctx->loc_conf;

            /*
             * 将 main 层生成的 loc_conf (见 ngx_http_block) 与 server 层生成的 loc_conf (见 ngx_http_core_server )
             * 调用对应 module 合并方法合并
             * 合并完存储于 cscfp[s]->ctx->loc_conf[ctx_index] (server 层生成的 loc_conf)
             */
            rv = module->merge_loc_conf(cf, saved.loc_conf[ctx_index],
                                        cscfp[s]->ctx->loc_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }

            /* merge the locations{}' loc_conf's */


            clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

            /*
             * 将 server 层生成的 loc_conf (见 ngx_http_core_server ) 与 location 层生成的 loc_conf (见 ngx_http_core_location )
             * 调用对应 module 合并方法合并
             * 合并完存储于 clcf->locations 节点ngx_http_core_loc_conf_t 的loc_conf (location 层生成的 loc_conf)
             */
            rv = ngx_http_merge_locations(cf, clcf->locations /* queue */,
                                          cscfp[s]->ctx->loc_conf,
                                          module, ctx_index);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }
    }

failed:

    *ctx = saved;

    return rv;
}


/*
 * 按照各个 http_*_module 合并 location 级配置
 */
static char *
ngx_http_merge_locations(ngx_conf_t *cf, ngx_queue_t *locations,
    void **loc_conf, ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                       *rv;
    ngx_queue_t                *q;
    ngx_http_conf_ctx_t        *ctx, saved;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    if (locations == NULL) {
        return NGX_CONF_OK;
    }

    ctx = (ngx_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;

    //遍历整个双向链表
    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;
        ctx->loc_conf = clcf->loc_conf;

        //合并 location 设置，存储于 clcf->loc_conf[ctx_index] 中
        rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
                                    clcf->loc_conf[ctx_index]);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

        //递归，处理 location{} 中嵌套的 location{}
        rv = ngx_http_merge_locations(cf, clcf->locations, clcf->loc_conf,
                                      module, ctx_index);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    *ctx = saved;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_init_locations(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_uint_t                   n;
    ngx_queue_t                 *q, *locations, *named, tail;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_location_queue_t   *lq;
    ngx_http_core_loc_conf_t   **clcfp;
#if (NGX_PCRE)
    ngx_uint_t                   r;
    ngx_queue_t                 *regex;
#endif

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    ngx_queue_sort(locations, ngx_http_cmp_locations);

    named = NULL;
    n = 0;
#if (NGX_PCRE)
    regex = NULL;
    r = 0;
#endif

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_locations(cf, NULL, clcf) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_PCRE)

        if (clcf->regex) {
            r++;

            if (regex == NULL) {
                regex = q;
            }

            continue;
        }

#endif

        if (clcf->named) {
            n++;

            if (named == NULL) {
                named = q;
            }

            continue;
        }

        if (clcf->noname) {
            break;
        }
    }

    if (q != ngx_queue_sentinel(locations)) {
        ngx_queue_split(locations, q, &tail);
    }

    if (named) {
        clcfp = ngx_palloc(cf->pool,
                           (n + 1) * sizeof(ngx_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        cscf->named_locations = clcfp;

        for (q = named;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, named, &tail);
    }

#if (NGX_PCRE)

    if (regex) {

        clcfp = ngx_palloc(cf->pool,
                           (r + 1) * sizeof(ngx_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        pclcf->regex_locations = clcfp;

        for (q = regex;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, regex, &tail);
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_queue_t                *q, *locations;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    if (ngx_queue_empty(locations)) {
        return NGX_OK;
    }

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_http_join_exact_locations(cf, locations) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_create_locations_list(locations, ngx_queue_head(locations));

    pclcf->static_locations = ngx_http_create_locations_tree(cf, locations, 0);
    if (pclcf->static_locations == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * 添加 location 站点
 * 将在 locations 上建立一个 queue
 * 将 clcf 的信息赋予到 lq (ngx_http_location_queue_t) 中
 */
ngx_int_t
ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
    ngx_http_core_loc_conf_t *clcf)
{
    ngx_http_location_queue_t  *lq;

    if (*locations == NULL) {
        *locations = ngx_palloc(cf->temp_pool,
                                sizeof(ngx_http_location_queue_t));
        if (*locations == NULL) {
            return NGX_ERROR;
        }

        ngx_queue_init(*locations);
    }

    lq = ngx_palloc(cf->temp_pool, sizeof(ngx_http_location_queue_t));
    if (lq == NULL) {
        return NGX_ERROR;
    }

    if (clcf->exact_match
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->named || clcf->noname)
    {
        lq->exact = clcf;
        lq->inclusive = NULL;

    } else {
        lq->exact = NULL;
        lq->inclusive = clcf;
    }

    lq->name = &clcf->name;
    lq->file_name = cf->conf_file->file.name.data;
    lq->line = cf->conf_file->line;

    ngx_queue_init(&lq->list);

    ngx_queue_insert_tail(*locations, &lq->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_http_cmp_locations(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_int_t                   rc;
    ngx_http_core_loc_conf_t   *first, *second;
    ngx_http_location_queue_t  *lq1, *lq2;

    lq1 = (ngx_http_location_queue_t *) one;
    lq2 = (ngx_http_location_queue_t *) two;

    first = lq1->exact ? lq1->exact : lq1->inclusive;
    second = lq2->exact ? lq2->exact : lq2->inclusive;

    if (first->noname && !second->noname) {
        /* shift no named locations to the end */
        return 1;
    }

    if (!first->noname && second->noname) {
        /* shift no named locations to the end */
        return -1;
    }

    if (first->noname || second->noname) {
        /* do not sort no named locations */
        return 0;
    }

    if (first->named && !second->named) {
        /* shift named locations to the end */
        return 1;
    }

    if (!first->named && second->named) {
        /* shift named locations to the end */
        return -1;
    }

    if (first->named && second->named) {
        return ngx_strcmp(first->name.data, second->name.data);
    }

#if (NGX_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }

#endif

    rc = ngx_filename_cmp(first->name.data, second->name.data,
                          ngx_min(first->name.len, second->name.len) + 1);

    if (rc == 0 && !first->exact_match && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_join_exact_locations(ngx_conf_t *cf, ngx_queue_t *locations)
{
    ngx_queue_t                *q, *x;
    ngx_http_location_queue_t  *lq, *lx;

    q = ngx_queue_head(locations);

    while (q != ngx_queue_last(locations)) {

        x = ngx_queue_next(q);

        lq = (ngx_http_location_queue_t *) q;
        lx = (ngx_http_location_queue_t *) x;

        if (lq->name->len == lx->name->len
            && ngx_filename_cmp(lq->name->data, lx->name->data, lx->name->len)
               == 0)
        {
            if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "duplicate location \"%V\" in %s:%ui",
                              lx->name, lx->file_name, lx->line);

                return NGX_ERROR;
            }

            lq->inclusive = lx->inclusive;

            ngx_queue_remove(x);

            continue;
        }

        q = ngx_queue_next(q);
    }

    return NGX_OK;
}


static void
ngx_http_create_locations_list(ngx_queue_t *locations, ngx_queue_t *q)
{
    u_char                     *name;
    size_t                      len;
    ngx_queue_t                *x, tail;
    ngx_http_location_queue_t  *lq, *lx;

    if (q == ngx_queue_last(locations)) {
        return;
    }

    lq = (ngx_http_location_queue_t *) q;

    if (lq->inclusive == NULL) {
        ngx_http_create_locations_list(locations, ngx_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    for (x = ngx_queue_next(q);
         x != ngx_queue_sentinel(locations);
         x = ngx_queue_next(x))
    {
        lx = (ngx_http_location_queue_t *) x;

        if (len > lx->name->len
            || ngx_filename_cmp(name, lx->name->data, len) != 0)
        {
            break;
        }
    }

    q = ngx_queue_next(q);

    if (q == x) {
        ngx_http_create_locations_list(locations, x);
        return;
    }

    ngx_queue_split(locations, q, &tail);
    ngx_queue_add(&lq->list, &tail);

    if (x == ngx_queue_sentinel(locations)) {
        ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
        return;
    }

    ngx_queue_split(&lq->list, x, &tail);
    ngx_queue_add(locations, &tail);

    ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));

    ngx_http_create_locations_list(locations, x);
}


/*
 * to keep cache locality for left leaf nodes, allocate nodes in following
 * order: node, left subtree, right subtree, inclusive subtree
 */

static ngx_http_location_tree_node_t *
ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix)
{
    size_t                          len;
    ngx_queue_t                    *q, tail;
    ngx_http_location_queue_t      *lq;
    ngx_http_location_tree_node_t  *node;

    q = ngx_queue_middle(locations);

    lq = (ngx_http_location_queue_t *) q;
    len = lq->name->len - prefix;

    node = ngx_palloc(cf->pool,
                      offsetof(ngx_http_location_tree_node_t, name) + len);
    if (node == NULL) {
        return NULL;
    }

    node->left = NULL;
    node->right = NULL;
    node->tree = NULL;
    node->exact = lq->exact;
    node->inclusive = lq->inclusive;

    node->auto_redirect = (u_char) ((lq->exact && lq->exact->auto_redirect)
                           || (lq->inclusive && lq->inclusive->auto_redirect));

    node->len = (u_char) len;
    ngx_memcpy(node->name, &lq->name->data[prefix], len);

    ngx_queue_split(locations, q, &tail);

    if (ngx_queue_empty(locations)) {
        /*
         * ngx_queue_split() insures that if left part is empty,
         * then right one is empty too
         */
        goto inclusive;
    }

    node->left = ngx_http_create_locations_tree(cf, locations, prefix);
    if (node->left == NULL) {
        return NULL;
    }

    ngx_queue_remove(q);

    if (ngx_queue_empty(&tail)) {
        goto inclusive;
    }

    node->right = ngx_http_create_locations_tree(cf, &tail, prefix);
    if (node->right == NULL) {
        return NULL;
    }

inclusive:

    if (ngx_queue_empty(&lq->list)) {
        return node;
    }

    node->tree = ngx_http_create_locations_tree(cf, &lq->list, prefix + len);
    if (node->tree == NULL) {
        return NULL;
    }

    return node;
}


ngx_int_t
ngx_http_add_listen(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_listen_opt_t *lsopt)
{
    in_port_t                   p;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    struct sockaddr_in         *sin;
    ngx_http_conf_port_t       *port;
    ngx_http_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (cmcf->ports == NULL) {
        cmcf->ports = ngx_array_create(cf->temp_pool, 2,
                                       sizeof(ngx_http_conf_port_t));
        if (cmcf->ports == NULL) {
            return NGX_ERROR;
        }
    }

    sa = &lsopt->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = &lsopt->u.sockaddr_in6;
        p = sin6->sin6_port;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        p = 0;
        break;
#endif

    default: /* AF_INET */
        sin = &lsopt->u.sockaddr_in;
        p = sin->sin_port;
        break;
    }

    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {

        if (p != port[i].port || sa->sa_family != port[i].family) {
            continue;
        }

        /* a port is already in the port list */

        return ngx_http_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */

    port = ngx_array_push(cmcf->ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;
    port->addrs.elts = NULL;

    return ngx_http_add_address(cf, cscf, port, lsopt);
}


static ngx_int_t
ngx_http_add_addresses(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
{
    u_char                *p;
    size_t                 len, off;
    ngx_uint_t             i, default_server;
    struct sockaddr       *sa;
    ngx_http_conf_addr_t  *addr;
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un    *saun;
#endif
#if (NGX_HTTP_SSL)
    ngx_uint_t             ssl;
#endif
#if (NGX_HTTP_SPDY)
    ngx_uint_t             spdy;
#endif

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    sa = &lsopt->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        off = offsetof(struct sockaddr_in6, sin6_addr);
        len = 16;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        off = offsetof(struct sockaddr_un, sun_path);
        len = sizeof(saun->sun_path);
        break;
#endif

    default: /* AF_INET */
        off = offsetof(struct sockaddr_in, sin_addr);
        len = 4;
        break;
    }

    p = lsopt->u.sockaddr_data + off;

    addr = port->addrs.elts;

    for (i = 0; i < port->addrs.nelts; i++) {

        if (ngx_memcmp(p, addr[i].opt.u.sockaddr_data + off, len) != 0) {
            continue;
        }

        /* the address is already in the address list */

        if (ngx_http_add_server(cf, cscf, &addr[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        default_server = addr[i].opt.default_server;

#if (NGX_HTTP_SSL)
        ssl = lsopt->ssl || addr[i].opt.ssl;
#endif
#if (NGX_HTTP_SPDY)
        spdy = lsopt->spdy || addr[i].opt.spdy;
#endif

        if (lsopt->set) {

            if (addr[i].opt.set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "duplicate listen options for %s", addr[i].opt.addr);
                return NGX_ERROR;
            }

            addr[i].opt = *lsopt;
        }

        /* check the duplicate "default" server for this address:port */

        if (lsopt->default_server) {

            if (default_server) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "a duplicate default server for %s", addr[i].opt.addr);
                return NGX_ERROR;
            }

            default_server = 1;
            addr[i].default_server = cscf;
        }

        addr[i].opt.default_server = default_server;
#if (NGX_HTTP_SSL)
        addr[i].opt.ssl = ssl;
#endif
#if (NGX_HTTP_SPDY)
        addr[i].opt.spdy = spdy;
#endif

        return NGX_OK;
    }

    /* add the address to the addresses list that bound to this port */

    return ngx_http_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */

static ngx_int_t
ngx_http_add_address(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
{
    ngx_http_conf_addr_t  *addr;

    if (port->addrs.elts == NULL) {
        if (ngx_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(ngx_http_conf_addr_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

#if (NGX_HTTP_SPDY && NGX_HTTP_SSL                                            \
     && !defined TLSEXT_TYPE_application_layer_protocol_negotiation           \
     && !defined TLSEXT_TYPE_next_proto_neg)
    if (lsopt->spdy && lsopt->ssl) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "nginx was built without OpenSSL ALPN or NPN "
                           "support, SPDY is not enabled for %s", lsopt->addr);
    }
#endif

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->opt = *lsopt;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
#if (NGX_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    addr->default_server = cscf;
    addr->servers.elts = NULL;

    return ngx_http_add_server(cf, cscf, addr);
}


/* add the server core module configuration to the address:port */

static ngx_int_t
ngx_http_add_server(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                  i;
    ngx_http_core_srv_conf_t  **server;

    if (addr->servers.elts == NULL) {
        if (ngx_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(ngx_http_core_srv_conf_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a duplicate listen %s", addr->opt.addr);
                return NGX_ERROR;
            }
        }
    }

    server = ngx_array_push(&addr->servers);
    if (server == NULL) {
        return NGX_ERROR;
    }

    *server = cscf;

    return NGX_OK;
}


static ngx_int_t
ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_array_t *ports)
{
    ngx_uint_t             p, a;
    ngx_http_conf_port_t  *port;
    ngx_http_conf_addr_t  *addr;

    if (ports == NULL) {
        return NGX_OK;
    }

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_http_conf_addr_t), ngx_http_cmp_conf_addrs);

        /*
         * check whether all name-based servers have the same
         * configuration as a default server for given address:port
         */

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (addr[a].servers.nelts > 1
#if (NGX_PCRE)
                || addr[a].default_server->captures
#endif
               )
            {
                if (ngx_http_server_names(cf, cmcf, &addr[a]) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }

        if (ngx_http_init_listening(cf, &port[p]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_names(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_conf_addr_t *addr)
{
    ngx_int_t                   rc;
    ngx_uint_t                  n, s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_http_server_name_t     *name;
    ngx_http_core_srv_conf_t  **cscfp;
#if (NGX_PCRE)
    ngx_uint_t                  regex, i;

    regex = 0;
#endif

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

#if (NGX_PCRE)
            if (name[n].regex) {
                regex++;
                continue;
            }
#endif

            rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NGX_HASH_WILDCARD_KEY);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid server name or wildcard \"%V\" on %s",
                              &name[n].name, addr->opt.addr);
                return NGX_ERROR;
            }

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                              "conflicting server name \"%V\" on %s, ignored",
                              &name[n].name, addr->opt.addr);
            }
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

#if (NGX_PCRE)

    if (regex == 0) {
        return NGX_OK;
    }

    addr->nregex = regex;
    addr->regex = ngx_palloc(cf->pool, regex * sizeof(ngx_http_server_name_t));
    if (addr->regex == NULL) {
        return NGX_ERROR;
    }

    i = 0;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
            if (name[n].regex) {
                addr->regex[i++] = name[n];
            }
        }
    }

#endif

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_http_conf_addr_t  *first, *second;

    first = (ngx_http_conf_addr_t *) one;
    second = (ngx_http_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


static int ngx_libc_cdecl
ngx_http_cmp_dns_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_dns_strcmp(first->key.data, second->key.data);
}


/* 初始化监听 */
static ngx_int_t
ngx_http_init_listening(ngx_conf_t *cf, ngx_http_conf_port_t *port)
{
    ngx_uint_t                 i, last, bind_wildcard;
    ngx_listening_t           *ls;
    ngx_http_port_t           *hport;
    ngx_http_conf_addr_t      *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    /*
     * If there is a binding to an "*:port" then we need to bind() to
     * the "*:port" only and ignore other implicit bindings.  The bindings
     * have been already sorted: explicit bindings are on the start, then
     * implicit bindings go, and wildcard binding is in the end.
     */

    if (addr[last - 1].opt.wildcard) {
        addr[last - 1].opt.bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    //所有的监听
    while (i < last) {

        if (bind_wildcard && !addr[i].opt.bind) {
            i++;
            continue;
        }

        //将对应地址加入监听
        ls = ngx_http_add_listening(cf, &addr[i]);
        if (ls == NULL) {
            return NGX_ERROR;
        }

        hport = ngx_pcalloc(cf->pool, sizeof(ngx_http_port_t));
        if (hport == NULL) {
            return NGX_ERROR;
        }

        ls->servers = hport;

        if (i == last - 1) {
            hport->naddrs = last;

        } else {
            hport->naddrs = 1;
            i = 0;
        }

        switch (ls->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            if (ngx_http_add_addrs6(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            if (ngx_http_add_addrs(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        }

        addr++;
        last--;
    }

    return NGX_OK;
}


static ngx_listening_t *
ngx_http_add_listening(ngx_conf_t *cf, ngx_http_conf_addr_t *addr)
{
    ngx_listening_t           *ls;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    //创建一个与之交互信息的ngx_listening_t，里面包含监听的套接字
    ls = ngx_create_listening(cf, &addr->opt.u.sockaddr, addr->opt.socklen);
    if (ls == NULL) {
        return NULL;
    }

    ls->addr_ntop = 1;

    //处理器为初始化http连接
    ls->handler = ngx_http_init_connection;

    cscf = addr->default_server;
    ls->pool_size = cscf->connection_pool_size;
    ls->post_accept_timeout = cscf->client_header_timeout;

    clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    ls->logp = clcf->error_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

#if (NGX_WIN32)
    {
    ngx_iocp_conf_t  *iocpcf = NULL;

    if (ngx_get_conf(cf->cycle->conf_ctx, ngx_events_module)) {
        iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
    }
    if (iocpcf && iocpcf->acceptex_read) {
        ls->post_accept_buffer_size = cscf->client_header_buffer_size;
    }
    }
#endif

    ls->backlog = addr->opt.backlog;
    ls->rcvbuf = addr->opt.rcvbuf;
    ls->sndbuf = addr->opt.sndbuf;

    ls->keepalive = addr->opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = addr->opt.tcp_keepidle;
    ls->keepintvl = addr->opt.tcp_keepintvl;
    ls->keepcnt = addr->opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ls->accept_filter = addr->opt.accept_filter;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ls->deferred_accept = addr->opt.deferred_accept;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = addr->opt.ipv6only;
#endif

#if (NGX_HAVE_SETFIB)
    ls->setfib = addr->opt.setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    ls->fastopen = addr->opt.fastopen;
#endif

    return ls;
}


static ngx_int_t
ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in_addr_t        *addrs;
    struct sockaddr_in        *sin;
    ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin = &addr[i].opt.u.sockaddr_in;
        addrs[i].addr = sin->sin_addr.s_addr;
        addrs[i].conf.default_server = addr[i].default_server;
#if (NGX_HTTP_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NGX_HTTP_SPDY)
        addrs[i].conf.spdy = addr[i].opt.spdy;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in6_addr_t       *addrs6;
    struct sockaddr_in6       *sin6;
    ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in6_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin6 = &addr[i].opt.u.sockaddr_in6;
        addrs6[i].addr6 = sin6->sin6_addr;
        addrs6[i].conf.default_server = addr[i].default_server;
#if (NGX_HTTP_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NGX_HTTP_SPDY)
        addrs6[i].conf.spdy = addr[i].opt.spdy;
#endif

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        addrs6[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}

#endif


char *
ngx_http_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_array_t     **types;
    ngx_str_t        *value, *default_type;
    ngx_uint_t        i, n, hash;
    ngx_hash_key_t   *type;

    types = (ngx_array_t **) (p + cmd->offset);

    if (*types == (void *) -1) {
        return NGX_CONF_OK;
    }

    default_type = cmd->post;

    if (*types == NULL) {
        *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
        if (*types == NULL) {
            return NGX_CONF_ERROR;
        }

        if (default_type) {
            type = ngx_array_push(*types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->key = *default_type;
            type->key_hash = ngx_hash_key(default_type->data,
                                          default_type->len);
            type->value = (void *) 4;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 1 && value[i].data[0] == '*') {
            *types = (void *) -1;
            return NGX_CONF_OK;
        }

        hash = ngx_hash_strlow(value[i].data, value[i].data, value[i].len);
        value[i].data[value[i].len] = '\0';

        type = (*types)->elts;
        for (n = 0; n < (*types)->nelts; n++) {

            if (ngx_strcmp(value[i].data, type[n].key.data) == 0) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate MIME type \"%V\"", &value[i]);
                goto next;
            }
        }

        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = (void *) 4;

    next:

        continue;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_merge_types(ngx_conf_t *cf, ngx_array_t **keys, ngx_hash_t *types_hash,
    ngx_array_t **prev_keys, ngx_hash_t *prev_types_hash,
    ngx_str_t *default_types)
{
    ngx_hash_init_t  hash;

    if (*keys) {

        if (*keys == (void *) -1) {
            return NGX_CONF_OK;
        }

        hash.hash = types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, (*keys)->elts, (*keys)->nelts) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (prev_types_hash->buckets == NULL) {

        if (*prev_keys == NULL) {

            if (ngx_http_set_default_types(cf, prev_keys, default_types)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

        } else if (*prev_keys == (void *) -1) {
            *keys = *prev_keys;
            return NGX_CONF_OK;
        }

        hash.hash = prev_types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, (*prev_keys)->elts, (*prev_keys)->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    *types_hash = *prev_types_hash;

    return NGX_CONF_OK;

}


ngx_int_t
ngx_http_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
    ngx_str_t *default_type)
{
    ngx_hash_key_t  *type;

    *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
    if (*types == NULL) {
        return NGX_ERROR;
    }

    while (default_type->len) {

        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_ERROR;
        }

        type->key = *default_type;
        type->key_hash = ngx_hash_key(default_type->data,
                                      default_type->len);
        type->value = (void *) 4;

        default_type++;
    }

    return NGX_OK;
}
