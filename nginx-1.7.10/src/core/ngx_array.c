
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


/* �������м���Ԫ�� */
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) { //����=�������Ѿ�����

        /* the array is full */

        size = a->size * a->nalloc; //��ǰ������ռ�ܿռ��С

        p = a->pool; //���������ڴ��

        /* �ڴ�ش�С���㹻 */
        if ((u_char *) a->elts + size == p->d.last //����ĩβΪ�ڴ��ĩβ
            && p->d.last + a->size <= p->d.end) //�ڴ�ش�С�Կ���װ��һ������
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size; //�ڴ�ʹ�ÿռ�����
            a->nalloc++; //������1

        } else { //�ڴ�ش�С�Ѿ�������
            /* allocate a new array */

            new = ngx_palloc(p, 2 * size); //����һ��ԭ����С2�����ڴ�ռ�
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size); //�������µĿռ�
            a->elts = new;
            a->nalloc *= 2; //��������
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;//��ģ���ַ=������ʼָ��elts+�ṹ���Сsize*����֮ǰ����
    a->nelts++;//���鳤�ȼ�1

    return elt; //������Ԫ�صĵ�ַ
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
