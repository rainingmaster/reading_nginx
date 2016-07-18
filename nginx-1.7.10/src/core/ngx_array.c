
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}


/* 往数组中加入元素 */
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) { //长度=容量，已经满了

        /* the array is full */

        size = a->size * a->nalloc; //当前数组所占总空间大小

        p = a->pool; //数组所在内存池

        /* 内存池大小仍足够 */
        if ((u_char *) a->elts + size == p->d.last //数组末尾为内存池末尾
            && p->d.last + a->size <= p->d.end) //内存池大小仍可以装下一个内容
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size; //内存使用空间增加
            a->nalloc++; //容量加1

        } else { //内存池大小已经不够了
            /* allocate a new array */

            new = ngx_palloc(p, 2 * size); //申请一个原来大小2倍的内存空间
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size); //拷贝到新的空间
            a->elts = new;
            a->nalloc *= 2; //容量翻倍
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;//新模块地址=数组起始指针elts+结构体大小size*数组之前长度
    a->nelts++;//数组长度加1

    return elt; //返回新元素的地址
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
