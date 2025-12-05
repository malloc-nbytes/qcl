/**
 * Queryable Configuration Language
 * Copyright (C) 2025 malloc-nbytes
 * Contact: zdhdev@yahoo.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 *
 * AUTHORS (any contributors put your name here):
 *   malloc-nbytes
 *
 * USAGE:
 *   Include this header and define the implementation macro (*before* the header):
 *     #define QCL_IMPL
 *     #include "qcl.h"
 *     ... other includes
 *
 * TODO:
 *   Impl map_destroy() to map macro code gen.
 */

#ifndef QCL_INCLUDED_H
#define QCL_INCLUDED_H

#ifdef QCL_IMPL

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/**
 * A simple generic map datastructure with C macro magic.
 */
#define QCL_MAP_DEFAULT_CAPACITY 2048
#define QCL_MAP_TYPE(ktype, vtype, mapname) \
        typedef unsigned (*qcl_##mapname##_hash_sig)(ktype *); \
        typedef int      (*qcl_##mapname##_cmp_sig)(ktype *, ktype *); \
        \
        typedef struct __##mapname##_node { \
                ktype k; \
                vtype v; \
                struct __##mapname##_node *n; \
        } __##mapname##_node; \
        \
        typedef struct { \
                struct { \
                        __##mapname##_node **data; \
                        size_t len; \
                        size_t cap; \
                        size_t sz; \
                } tbl; \
                qcl_##mapname##_hash_sig hash; \
                qcl_##mapname##_cmp_sig cmp; \
        } mapname; \
        \
        mapname  mapname##_create(qcl_##mapname##_hash_sig hash, qcl_##mapname##_cmp_sig cmp); \
        void     mapname##_destroy(mapname *map); \
        void     mapname##_insert(mapname *map, ktype k, vtype v); \
        int      mapname##_contains(mapname *map, ktype k); \
        vtype   *mapname##_get(mapname *map, ktype k); \
        \
        mapname \
        mapname##_create(qcl_##mapname##_hash_sig hash, \
                         qcl_##mapname##_cmp_sig cmp) \
        { \
                __##mapname##_node **data \
                        = (__##mapname##_node **)calloc(QCL_MAP_DEFAULT_CAPACITY, sizeof(__##mapname##_node *)); \
                return (mapname) { \
                        .tbl = { \
                                .data = data, \
                                .len = 0, \
                                .cap = QCL_MAP_DEFAULT_CAPACITY, \
                                .sz = 0, \
                        }, \
                        .hash = hash, \
                        .cmp = cmp, \
                }; \
        } \
        \
        void \
        mapname##_insert(mapname *map, ktype k, vtype v) \
        { \
                unsigned idx = map->hash(&k) % map->tbl.cap; \
                __##mapname##_node *it = map->tbl.data[idx]; \
                __##mapname##_node *prev = NULL; \
                while (it) { \
                        if (!map->cmp(&it->k, &k)) { \
                                it->v = v; \
                                return; \
                        } \
                        prev = it; \
                        it = it->n; \
                } \
                it = (__##mapname##_node *)malloc(sizeof(__##mapname##_node)); \
                it->k = k; \
                it->v = v; \
                it->n = NULL; \
                if (prev) { \
                        prev->n = it; \
                } else { \
                        map->tbl.data[idx] = it; \
                        ++map->tbl.len; \
                } \
                ++map->tbl.sz; \
        } \
        \
        int \
        mapname##_contains(mapname *map, ktype k) \
        { \
                return mapname##_get(map, k) != NULL; \
        } \
        \
        vtype * \
        mapname##_get(mapname *map, ktype k) \
        { \
                unsigned idx = map->hash(&k) % map->tbl.cap; \
                __##mapname##_node *it = map->tbl.data[idx]; \
                while (it) { \
                        if (!map->cmp(&it->k, &k)) { \
                                return &it->v; \
                        } \
                        it = it->n; \
                } \
                return NULL; \
        } \

#define QCL_ARRAY_TYPE(ty, name)                \
        typedef struct name {                   \
                ty *data;                       \
                size_t len, cap;                \
        } name

#define qcl_array_empty(arr_ty)                 \
        (arr_ty) {                              \
                .data = NULL,                   \
                .len = 0,                       \
                .cap = 0,                       \
        }

#define qcl_array(ty, name)                                             \
        struct {                                                        \
                ty *data;                                               \
                size_t len, cap;                                        \
        } (name) = { .data = (typeof(ty) *)malloc(sizeof(ty)), .len = 0, .cap = 1 };

#define qcl_array_append(da, value)                                     \
        do {                                                            \
                if ((da).len >= (da).cap) {                             \
                        (da).cap = (da).cap ? (da).cap * 2 : 2;         \
                        (da).data = (typeof(*((da).data)) *)            \
                                realloc((da).data,                      \
                                        (da).cap * sizeof(*((da).data))); \
                }                                                       \
                (da).data[(da).len++] = (value);                        \
        } while (0)

#define qcl_array_free(da)                      \
        do {                                    \
                if ((da).data != NULL) {        \
                        free((da).data);        \
                }                               \
                (da).len = (da).cap = 0;        \
        } while (0)

#define qcl_array_at(da, i) ((da).data[i])

#define qcl_array_clear(da) (da).len = 0;

#define qcl_array_rm_at(da, idx)                                        \
        do {                                                            \
                for (size_t __i_ = (idx); __i_ < (da).len-1; ++__i_)    \
                        (da).data[__i_] = (da).data[__i_+1];            \
                (da).len--;                                             \
        } while (0)

// ####################
// # ARENA            #
// ####################

#define QCL_ARENA_DEFAULT_ALLOC_SIZE 4096
#ifndef QCL_ARENA_ALIGN_SIZE
#define QCL_ARENA_ALIGN_SIZE 16
#endif
#define _QCL_ARENA_ALIGN_MASK (QCL_ARENA_ALIGN_SIZE-1)

typedef struct {
        uint8_t *buf;
        size_t   cap;
        size_t   offset;
} _qcl_arena;

static void
_qcl_arena_init(_qcl_arena *a,
                size_t      bytes)
{
        a->buf    = (uint8_t *)calloc(bytes, 1);
        a->cap    = bytes;
        a->offset = 0;
}

static inline size_t
_qcl_arena_alignup(size_t n)
{
        return (n + _QCL_ARENA_ALIGN_MASK) & ~_QCL_ARENA_ALIGN_MASK;
}

static void *
_qcl_arena_alloc(_qcl_arena *a, size_t size)
{
        size_t aligned    = _qcl_arena_alignup(size);
        size_t new_offset = a->offset + aligned;

        if (new_offset > a->cap) {
                a->cap *= 2;
                if (!(a->buf = (uint8_t *)realloc(a->buf, a->cap))) {
                        fprintf(stderr, "FATAL: _qcl_arena_alloc: could not realloc buffer\n");
                        exit(1);
                }
        }

        void *p   = a->buf + a->offset;
        a->offset = new_offset;
        return p;
}

#if 0
static void *
_qcl_arena_allocz(_qcl_arena *a, size_t size)
{
        void *p = _qcl_arena_alloc(a, size);
        if (p) memset(p, 0, size);
        return p;
}
#endif

static void
_qcl_arena_clear(_qcl_arena *a)
{
        a->offset = 0;
}

static void
_qcl_arena_free(_qcl_arena *a)
{
        if (a->buf) free(a->buf);
        a->buf    = NULL;
        a->cap    = 0;
        a->offset = 0;
}

// ####################
// # KEYWORDS         #
// ####################

#define QCL_KWD_NULL  "null"
#define QCL_KWD_IF    "if"
#define QCL_KWD_ELSE  "else"
#define QCL_KWD_TRUE  "true"
#define QCL_KWD_FALSE "false"
#define QCL_KWD_CL {   \
        QCL_KWD_NULL,  \
        QCL_KWD_IF,    \
        QCL_KWD_ELSE,  \
        QCL_KWD_TRUE,  \
        QCL_KWD_FALSE, \
        NULL,          \
}

static int
_qcl_is_kw(const char *s)
{
        static const char *kwds[] = QCL_KWD_CL;
        for (size_t i = 0; kwds[i]; ++i) {
                if (!strcmp(s, kwds[i])) {
                        return 1;
                }
        }
        return 0;
}

typedef enum {
        _QCL_TT_NONE = 0,
        _QCL_TT_EOF,
        _QCL_TT_IDENTIFIER,
        _QCL_TT_KEYWORD,
        _QCL_TT_STRING,
        _QCL_TT_DIGIT,
        _QCL_TT_LPAREN,
        _QCL_TT_RPAREN,
        _QCL_TT_LCURLY,
        _QCL_TT_RCURLY,
        _QCL_TT_LSQR, // 10
        _QCL_TT_RSQR,
        _QCL_TT_EQUALS,
        _QCL_TT_COMMA,
        _QCL_TT_COLON,
        _QCL_TT_PLUS,
        _QCL_TT_DOLLAR,
        _QCL_TT_SEMICOLON,
        _QCL_TT_BANG,
} _qcl_tt;

typedef struct {
        size_t      r;
        size_t      c;
        const char *fp;
} _qcl_loc;

typedef struct _qcl_token {
        char              *lx;
        _qcl_tt            ty;
        _qcl_loc           loc;
        struct _qcl_token *n;
} _qcl_token;

typedef struct {
        _qcl_token *hd;
        _qcl_token *tl;
        const char *fp;
        struct {
                const char *msg;
                _qcl_loc    loc;
        } err;
        _qcl_arena tarena;
} _qcl_lexer;

static _qcl_token *
_qcl_token_alloc(const char *st,
                 size_t      st_n,
                 _qcl_tt     ty,
                 size_t      r,
                 size_t      c,
                 const char *fp,
                 _qcl_arena *a)
{
        _qcl_token *t = (_qcl_token *)_qcl_arena_alloc(a, sizeof(_qcl_token));
        t->lx         = strndup(st, st_n);
        t->ty         = ty;
        t->loc.r      = r;
        t->loc.c      = c;
        t->loc.fp     = fp;
        return t;
}

static void
_qcl_lexer_append(_qcl_lexer *l, _qcl_token *t)
{
        if (!l->hd && !l->tl) {
                l->hd = l->tl = t;
        } else {
                l->tl->n = t;
                l->tl = l->tl->n;
        }
}

static size_t
_qcl_consume_while(const char *st,
                   int (*pred)(int))
{
        size_t i = 0;
        while (st[i] && pred(st[i])) ++i;
        return i;
}

static int
_qcl_isident(int c)
{
        return isalnum(c) || c == '_' || c == '-';
}
static int _qcl_notsinglequote(int c) { return c != '\''; }
static int _qcl_notquote(int c)       { return c != '"';  }
static int
_qcl_issym(int c)
{
        return _qcl_notsinglequote(c)
                && _qcl_notquote(c)
                && !_qcl_isident(c)
                && c != '\n'
                && c != ' '
                && c != '\t';
}

static _qcl_token *
_qcl_lexer_peek(const _qcl_lexer *l,
                size_t            p)
{
        _qcl_token *it = l->hd;
        for (size_t i = 0; it && i < p; ++i) {
                it = it->n;
        }
        return it;
}

static _qcl_token *
_qcl_lexer_next(_qcl_lexer *l)
{
        if (!l->hd) return NULL;
        _qcl_token *t = l->hd;
        l->hd = l->hd->n;
        return t;
}

static void
_qcl_lexer_dump(const _qcl_lexer *l)
{
        _qcl_token *it = l->hd;
        while (it) {
                printf("{ lx=%s, ty=%d, r=%zu, c=%zu, fp=%s }\n",
                       it->lx, it->ty, it->loc.r, it->loc.c, it->loc.fp);
                it = it->n;
        }
}

QCL_MAP_TYPE(const char *, _qcl_tt, symmap);

static unsigned
_qcl_symmap_hash(const char **s)
{
        // TODO: not sure why this wont this work

        /* unsigned hash = 5381; */
        /* int c; */

        /* while ((c = *(*s)++)) */
        /*         hash = ((hash << 5) + hash) + c; /\* hash * 33 + c *\/ */

        /* return hash; */
        return **s;
}

static int
_qcl_symmap_cmp(const char **s0,
                const char **s1)
{
        return strcmp(*s0, *s1);
}

static size_t
_qcl_determine_sym(const char *st,
                   size_t      len,
                   _qcl_tt    *ty,
                   symmap     *map)
{
        *ty = _QCL_TT_NONE;

        char buf[256] = {0};
        (void)strncpy(buf, st, len);

        for (int i = len-1; i >= 0; --i) {
                if (symmap_contains(map, buf)) {
                        *ty = *symmap_get(map, buf);
                        return (size_t)i+1;
                }

                assert(i < 256);

                buf[i] = 0;
        }

        return _QCL_TT_NONE;
}

static _qcl_lexer
_qcl_lex_file(const char *fp,
              const char *src)
{
        symmap symmap = symmap_create(_qcl_symmap_hash, _qcl_symmap_cmp);

        _qcl_lexer lexer = {
                .hd = NULL,
                .tl = NULL,
                .fp = fp,
                .err = {
                        .msg = NULL,
                        .loc = {0},
                },
                .tarena = {0},
        };

        _qcl_arena_init(&lexer.tarena, QCL_ARENA_DEFAULT_ALLOC_SIZE * sizeof(_qcl_token));
        symmap_insert(&symmap, "=", _QCL_TT_EQUALS);
        symmap_insert(&symmap, "[", _QCL_TT_LSQR);
        symmap_insert(&symmap, "]", _QCL_TT_RSQR);
        symmap_insert(&symmap, ",", _QCL_TT_COMMA);
        symmap_insert(&symmap, "{", _QCL_TT_LCURLY);
        symmap_insert(&symmap, "}", _QCL_TT_RCURLY);
        symmap_insert(&symmap, "$", _QCL_TT_DOLLAR);
        symmap_insert(&symmap, ";", _QCL_TT_SEMICOLON);
        symmap_insert(&symmap, ":", _QCL_TT_COLON);
        symmap_insert(&symmap, "!", _QCL_TT_BANG);

        size_t r = 1, c = 1, i = 0;
        while (src[i]) {
                char ch = src[i];

                if (ch == ' ' || ch == '\t') {
                        ++i, ++c;
                } else if (ch == '\n') {
                        ++i, ++r, c = 1;
                } else if (ch == '#') {
                        while (src[i] != '\n') ++i, ++c;
                        ++i, ++r, c = 1;
                } else if (isalpha(ch) || ch == '_' || ch == '-') {
                        size_t len = _qcl_consume_while(src+i, _qcl_isident);
                        _qcl_token *t = _qcl_token_alloc(src+i, len,
                                                         _QCL_TT_IDENTIFIER,
                                                         r, c, lexer.fp,
                                                         &lexer.tarena);
                        if (_qcl_is_kw(t->lx)) {
                                t->ty = _QCL_TT_KEYWORD;
                        }
                        _qcl_lexer_append(&lexer, t);
                        i += len, c += len;
                } else if (isdigit(ch)) {
                        size_t len = _qcl_consume_while(src+i, isdigit);
                        _qcl_token *t = _qcl_token_alloc(src+i, len,
                                                         _QCL_TT_DIGIT,
                                                         r, c, lexer.fp,
                                                         &lexer.tarena);
                        _qcl_lexer_append(&lexer, t);
                        i += len, c += len;
                } else if (ch == '"' || ch == '\'') {
                        size_t len;
                        if (ch == '"') {
                                len = _qcl_consume_while(src+i+1, _qcl_notquote);
                        } else {
                                len = _qcl_consume_while(src+i+1, _qcl_notsinglequote);
                        }
                        _qcl_token *t = _qcl_token_alloc(src+i+1, len,
                                                         _QCL_TT_STRING,
                                                         r, c, lexer.fp,
                                                         &lexer.tarena);
                        _qcl_lexer_append(&lexer, t);
                        i += len+2, c += len+2;
                } else {
                        size_t len     = _qcl_consume_while(src+i, _qcl_issym);
                        size_t old_len = len;
                        _qcl_tt ty     = _QCL_TT_NONE;
                        len            = _qcl_determine_sym(src+i, len, &ty, &symmap);
                        if (ty == _QCL_TT_NONE) {
                                // TODO: put error in error struct of lexer.
                                char buf[256] = {0};
                                strncpy(buf, src+i, old_len);
                                printf("error: unknown symbol: %s\n", buf);
                                exit(1);
                        }
                        _qcl_token *t = _qcl_token_alloc(src+i, len,
                                                         ty, r, c, lexer.fp,
                                                         &lexer.tarena);
                        _qcl_lexer_append(&lexer, t);
                        i += len, c += len;
                }
        }

        _qcl_token *t = _qcl_token_alloc("EOF", 3, _QCL_TT_EOF, r, c, lexer.fp, &lexer.tarena);
        _qcl_lexer_append(&lexer, t);

        //symmap_destroy(&symmap);

        return lexer;
}

static char *
_qcl_load_file(const char *path)
{
        FILE   *f;
        char   *buf;
        size_t  size;

        if ((f = fopen(path, "rb")) == NULL)
                return NULL;

        fseek(f, 0, SEEK_END);
        size = ftell(f);
        fseek(f, 0, SEEK_SET);

        buf = (char *)malloc(size + 1);
        fread(buf, 1, size, f);
        fclose(f);

        buf[size] = '\0';

        return buf;
}

// ###############
// # DECLARES    #
// ###############

typedef struct _qcl_expr _qcl_expr;
typedef struct _qcl_stmt _qcl_stmt;

typedef struct _qcl_visitor _qcl_visitor;
static void *_qcl_accept_expr_unary(_qcl_expr *rhs, _qcl_visitor *v);
static void *_qcl_accept_expr_env(_qcl_expr *rhs, _qcl_visitor *v);
static void *_qcl_accept_expr_string(_qcl_expr *e, _qcl_visitor *v);
static void *_qcl_accept_expr_identifier(_qcl_expr *e, _qcl_visitor *v);
static void *_qcl_accept_expr_list(_qcl_expr *e, _qcl_visitor *v);
static void *_qcl_accept_expr_bool(_qcl_expr *e, _qcl_visitor *v);
static void *_qcl_accept_stmt_assigment(_qcl_stmt *s, _qcl_visitor *v);
static void *_qcl_accept_stmt_if(_qcl_stmt *s, _qcl_visitor *v);
static void *_qcl_accept_stmt_block(_qcl_stmt *s, _qcl_visitor *v);

typedef enum {
        _QCL_TYPE_STRING = 0,
} _qcl_type_kind;

typedef struct {
        _qcl_type_kind kind;
} _qcl_type;

typedef struct {
        _qcl_type base;
} _qcl_type_string;

// ########################
// # EXPRESSIONS          #
// ########################

typedef enum {
        _QCL_EXPR_KIND_IDENTIFIER,
        _QCL_EXPR_KIND_STRING,
        _QCL_EXPR_KIND_LIST,
        _QCL_EXPR_KIND_BOOL,
        _QCL_EXPR_KIND_IF,
        _QCL_EXPR_KIND_ENV,
        _QCL_EXPR_KIND_UNARY,
} _qcl_expr_kind;

typedef struct _qcl_expr {
        _qcl_expr_kind  kind;
        _qcl_type      *type;
        _qcl_loc        loc;
        void *(*accept)(struct _qcl_expr *e, _qcl_visitor *v);
} _qcl_expr;

QCL_ARRAY_TYPE(_qcl_expr *, _qcl_expr_array);

typedef struct {
        _qcl_expr    base;
        const char  *s;
} _qcl_expr_string;

typedef struct {
        _qcl_expr    base;
        const char  *id;
} _qcl_expr_identifier;

typedef struct {
        _qcl_expr base;
        _qcl_expr_array exprs;
} _qcl_expr_list;

typedef struct {
        _qcl_expr base;
        int       b;
} _qcl_expr_bool;

typedef struct {
        _qcl_expr base;
        _qcl_expr *rhs;
} _qcl_expr_env;

typedef struct {
        _qcl_expr  base;
        const char *op;
        _qcl_expr  *rhs;
} _qcl_expr_unary;

static _qcl_expr_env *
_qcl_expr_env_alloc(_qcl_expr *rhs)
{
        _qcl_expr_env *expr =
                (_qcl_expr_env *)malloc(sizeof(_qcl_expr_env));
        expr->rhs = rhs;
        expr->base = (_qcl_expr) {
                .kind = _QCL_EXPR_KIND_ENV,
                .loc  = {0},
        };
        expr->base.accept = _qcl_accept_expr_env;
        return expr;
}

static _qcl_expr_string *
_qcl_expr_string_alloc(const char *s)
{
        _qcl_expr_string *expr =
                (_qcl_expr_string *)malloc(sizeof(_qcl_expr_string));
        expr->s = s;
        expr->base = (_qcl_expr) {
                .kind = _QCL_EXPR_KIND_STRING,
                .loc  = {0},
        };
        expr->base.accept = _qcl_accept_expr_string;
        return expr;
}

static _qcl_expr_identifier *
_qcl_expr_identifier_alloc(const char *id)
{
        _qcl_expr_identifier *e =
                (_qcl_expr_identifier *)malloc(sizeof(_qcl_expr_identifier));
        e->id = id;
        e->base = (_qcl_expr) {
                .kind = _QCL_EXPR_KIND_IDENTIFIER,
                .loc  = {0},
        };
        e->base.accept = _qcl_accept_expr_identifier;
        return e;
}

static _qcl_expr_list *
_qcl_expr_list_alloc(_qcl_expr_array ar)
{
        _qcl_expr_list *e =
                (_qcl_expr_list *)malloc(sizeof(_qcl_expr_list));
        e->exprs = ar;
        e->base = (_qcl_expr) {
                .kind = _QCL_EXPR_KIND_LIST,
                .loc  = {0},
        };
        e->base.accept = _qcl_accept_expr_list;
        return e;
}

static _qcl_expr_bool *
_qcl_expr_bool_alloc(int b)
{
        _qcl_expr_bool *e =
                (_qcl_expr_bool *)malloc(sizeof(_qcl_expr_bool));
        e->b = b;
        e->base = (_qcl_expr) {
                .kind = _QCL_EXPR_KIND_BOOL,
                .loc  = {0},
        };
        e->base.accept = _qcl_accept_expr_bool;
        return e;
}

static _qcl_expr_unary *
_qcl_expr_unary_alloc(const char *op, _qcl_expr *rhs)
{
        _qcl_expr_unary *e =
                (_qcl_expr_unary *)malloc(sizeof(_qcl_expr_unary));
        e->rhs = rhs;
        e->op  = op;
        e->base = (_qcl_expr) {
                .kind = _QCL_EXPR_KIND_UNARY,
                .loc  = {0},
        };
        e->base.accept = _qcl_accept_expr_unary;
        return e;
}

// ########################
// # STATEMENTS           #
// ########################

typedef enum {
        _QCL_STMT_KIND_ASSIGNMENT = 0,
        _QCL_STMT_KIND_EXPR,
        _QCL_STMT_KIND_IF,
        _QCL_STMT_KIND_BLOCK,
} _qcl_stmt_kind;

typedef struct _qcl_stmt {
        _qcl_stmt_kind kind;
        _qcl_loc       loc;
        void *(*accept)(struct _qcl_stmt *s, _qcl_visitor *v);
} _qcl_stmt;

QCL_ARRAY_TYPE(_qcl_stmt *, _qcl_stmt_array);

typedef struct {
        _qcl_stmt    base;
        const char  *id;
        _qcl_expr   *expr;
} _qcl_stmt_assignment;

typedef struct {
        _qcl_stmt  base;
        _qcl_expr *expr;
} _qcl_stmt_expr;

typedef struct {
        _qcl_stmt       base;
        _qcl_stmt_array stmts;
} _qcl_stmt_block;

typedef struct {
        _qcl_stmt base;
        _qcl_expr *cond;
        _qcl_stmt *then;
        _qcl_stmt *else_; // can be NULL
} _qcl_stmt_if;

static _qcl_stmt_assignment *
_qcl_stmt_assignment_alloc(const char *id,
                           _qcl_expr  *expr)
{
        _qcl_stmt_assignment *s =
                (_qcl_stmt_assignment *)malloc(sizeof(_qcl_stmt_assignment));
        s->id   = id;
        s->expr = expr;
        s->base = (_qcl_stmt) {
                .kind = _QCL_STMT_KIND_ASSIGNMENT,
                .loc  = {0},
        };
        s->base.accept = _qcl_accept_stmt_assigment;
        return s;
}

static _qcl_stmt_if *
_qcl_stmt_if_alloc(_qcl_expr *cond,
                   _qcl_stmt *then,
                   _qcl_stmt *else_)
{
        _qcl_stmt_if *s =
                (_qcl_stmt_if *)malloc(sizeof(_qcl_stmt_if));
        s->cond  = cond;
        s->then  = then;
        s->else_ = else_;
        s->base = (_qcl_stmt) {
                .kind = _QCL_STMT_KIND_IF,
                .loc  = {0},
        };
        s->base.accept = _qcl_accept_stmt_if;
        return s;
}

static _qcl_stmt_block *
_qcl_stmt_block_alloc(_qcl_stmt_array stmts)
{
        _qcl_stmt_block *s =
                (_qcl_stmt_block *)malloc(sizeof(_qcl_stmt_block));
        s->stmts  = stmts;
        s->base = (_qcl_stmt) {
                .kind = _QCL_STMT_KIND_BLOCK,
                .loc  = {0},
        };
        s->base.accept = _qcl_accept_stmt_block;
        return s;
}

// #####################
// # PARSING           #
// #####################

typedef struct {
        _qcl_stmt_array stmts;
} _qcl_program;

#define _QCL_SP(l, i) \
        _qcl_lexer_peek(l, i) && _qcl_lexer_peek(l, i)

static _qcl_stmt *_qcl_parse_stmt(_qcl_lexer *lexer);

static _qcl_token *
_qcl_expect(_qcl_lexer *lexer,
            _qcl_tt     ty)
{
        _qcl_token *it = _qcl_lexer_next(lexer);
        if (!it || it->ty != ty) return NULL;
        return it;
}

static _qcl_expr *_qcl_parse_expr(_qcl_lexer *lexer);

static _qcl_expr_array
_qcl_parse_comma_sep_exprs(_qcl_lexer *lexer)
{
        _qcl_expr_array ar = qcl_array_empty(_qcl_expr_array);

        while (1) {
                _qcl_expr *e = _qcl_parse_expr(lexer);
                if (!e) break;
                qcl_array_append(ar, e);

                if (_QCL_SP(lexer, 0)->ty == _QCL_TT_COMMA) {
                        (void)_qcl_lexer_next(lexer);
                } else {
                        break;
                }
        }

        (void)_qcl_expect(lexer, _QCL_TT_RSQR);

        return ar;
}

static _qcl_expr *
_qcl_parse_primary_expr(_qcl_lexer *lexer)
{
        _qcl_expr *expr = NULL;

        while (1) {
                _qcl_token *hd = _qcl_lexer_peek(lexer, 0);
                if (!hd) return expr;

                switch (hd->ty) {
                case _QCL_TT_IDENTIFIER: {
                        expr = (_qcl_expr *)_qcl_expr_identifier_alloc(_qcl_lexer_next(lexer)->lx);
                        expr->loc = hd->loc;
                } break;
                case _QCL_TT_STRING: {
                        expr = (_qcl_expr *)_qcl_expr_string_alloc(_qcl_lexer_next(lexer)->lx);
                        expr->loc = hd->loc;
                } break;
                case _QCL_TT_LSQR: {
                        (void)_qcl_lexer_next(lexer);
                        _qcl_expr_array exprs = _qcl_parse_comma_sep_exprs(lexer);
                        expr = (_qcl_expr *)_qcl_expr_list_alloc(exprs);
                        expr->loc = hd->loc;
                } break;
                case _QCL_TT_DOLLAR: {
                        (void)_qcl_lexer_next(lexer); // $
                        _qcl_expr *rhs = _qcl_parse_expr(lexer);
                        expr = (_qcl_expr *)_qcl_expr_env_alloc(rhs);
                } break;
                case _QCL_TT_COLON: {
                        (void)_qcl_lexer_next(lexer); // :
                        return expr;
                } break;
                case _QCL_TT_KEYWORD: {
                        if (!strcmp(hd->lx, QCL_KWD_TRUE)) {
                                (void)_qcl_lexer_next(lexer);
                                expr = (_qcl_expr *)_qcl_expr_bool_alloc(1);
                                expr->loc = hd->loc;
                        } else if (!strcmp(hd->lx, QCL_KWD_FALSE)) {
                                (void)_qcl_lexer_next(lexer);
                                expr = (_qcl_expr *)_qcl_expr_bool_alloc(0);
                                expr->loc = hd->loc;
                        } else {
                                return expr;
                        }
                } break;
                default: return expr;
                }
        }

        return NULL; // unreachable
}

_qcl_expr *
_qcl_parse_unary_expr(_qcl_lexer *lexer)
{
        _qcl_token *cur = _qcl_lexer_peek(lexer, 0);
        if (cur && (cur->ty == _QCL_TT_BANG)) {
                _qcl_token *loc_tok     = _qcl_lexer_next(lexer);
                const char *op          = loc_tok->lx;
                _qcl_expr  *rhs         = (_qcl_expr *)_qcl_parse_unary_expr(lexer);
                ((_qcl_expr *)rhs)->loc = loc_tok->loc;
                return (_qcl_expr *)_qcl_expr_unary_alloc(op, rhs);
        }
        return _qcl_parse_primary_expr(lexer);
}

static _qcl_expr *
_qcl_parse_additive_expr(_qcl_lexer *lexer)
{
        // TODO
        return _qcl_parse_unary_expr(lexer);
}

static _qcl_expr *
_qcl_parse_expr(_qcl_lexer *lexer)
{
        return _qcl_parse_additive_expr(lexer);
}

static _qcl_stmt_assignment *
_qcl_parse_stmt_assignment(_qcl_lexer *lexer)
{
        const char *id;
        _qcl_expr  *expr;

        if (!(id = _qcl_expect(lexer, _QCL_TT_IDENTIFIER)->lx)) {
                return NULL;
        }

        (void)_qcl_expect(lexer, _QCL_TT_EQUALS);

        if (!(expr = _qcl_parse_expr(lexer))) {
                return NULL;
        }

        (void)_qcl_expect(lexer, _QCL_TT_SEMICOLON);

        return _qcl_stmt_assignment_alloc(id, expr);
}

/* static _qcl_stmt_expr * */
/* _qcl_parse_stmt_expr(_qcl_lexer *lexer) */
/* { */
/*         assert(0); */
/* } */

static _qcl_stmt_if *
_qcl_parse_stmt_if(_qcl_lexer *lexer)
{
        _qcl_expr  *e;
        _qcl_stmt  *then;
        _qcl_stmt  *else_;
        _qcl_token *t1;
        _qcl_token *t2;
        int         t1_else;
        int         t2_if;

        (void)_qcl_lexer_next(lexer); // if

        e     = _qcl_parse_expr(lexer);
        then  = _qcl_parse_stmt(lexer);
        else_ = NULL;

        t1 = _qcl_lexer_peek(lexer, 0);
        t2 = _qcl_lexer_peek(lexer, 1);

        t1_else = t1 && t1->ty == _QCL_TT_KEYWORD && !strcmp(t1->lx, QCL_KWD_ELSE);
        t2_if   = t2 && t2->ty == _QCL_TT_KEYWORD && !strcmp(t2->lx, QCL_KWD_IF);

        if (t1_else && t2_if) {
                (void)_qcl_lexer_next(lexer); // else
                else_ = (_qcl_stmt *)_qcl_parse_stmt_if(lexer);
        } else if (t1_else) {
                _qcl_lexer_next(lexer); // else
                else_ = _qcl_parse_stmt(lexer);
        }

        return _qcl_stmt_if_alloc(e, then, else_);
}

static _qcl_stmt *
_qcl_parse_stmt_keyword(_qcl_lexer *lexer)
{
        _qcl_token *hd = _qcl_lexer_peek(lexer, 0);

        if (!strcmp(hd->lx, QCL_KWD_IF)) {
                return (_qcl_stmt *)_qcl_parse_stmt_if(lexer);
        } else {
                assert(0 && "unimplemented");
        }
}

static _qcl_stmt_block *
_qcl_parse_stmt_block(_qcl_lexer *lexer)
{
        _qcl_stmt_array ar = qcl_array_empty(_qcl_stmt_array);

        (void)_qcl_expect(lexer, _QCL_TT_LCURLY);

        while (_QCL_SP(lexer, 0)->ty != _QCL_TT_RCURLY) {
                qcl_array_append(ar, _qcl_parse_stmt(lexer));
        }

        (void)_qcl_expect(lexer, _QCL_TT_RCURLY);

        return _qcl_stmt_block_alloc(ar);
}

static _qcl_stmt *
_qcl_parse_stmt(_qcl_lexer *lexer)
{
        _qcl_token *hd;

        if (!(hd = _qcl_lexer_peek(lexer, 0))) return NULL;

        /* if (hd->ty == _QCL_TT_SEMICOLON) { */
        /*         (void)_qcl_lexer_next(lexer); // '\n' */
        /*         return _qcl_parse_stmt(lexer); */
        /* } */

        if (hd->ty == _QCL_TT_KEYWORD) {
                return _qcl_parse_stmt_keyword(lexer);
        } else if (hd->ty == _QCL_TT_IDENTIFIER
                   && _QCL_SP(lexer, 1)->ty == _QCL_TT_EQUALS) {
                return (_qcl_stmt *)_qcl_parse_stmt_assignment(lexer);
        } else if (hd->ty == _QCL_TT_LCURLY) {
                return (_qcl_stmt *)_qcl_parse_stmt_block(lexer);
        } else {
                assert(0);
                //return (_qcl_stmt *)_qcl_parse_stmt_expr(lexer);
        }
}

static _qcl_program
_qcl_create_program(_qcl_lexer *lexer)
{
        _qcl_program prog = (_qcl_program) {
                .stmts = qcl_array_empty(_qcl_stmt_array),
        };

        while (_QCL_SP(lexer, 0)->ty != _QCL_TT_EOF) {
                if (lexer->hd->ty == _QCL_TT_SEMICOLON) {
                        _qcl_lexer_next(lexer);
                        continue;
                }
                _qcl_stmt *stmt = _qcl_parse_stmt(lexer);
                if (!stmt) break;
                qcl_array_append(prog.stmts, stmt);
        }

        return prog;
}

// ######################
// # VISITOR            #
// ######################

typedef void *(*_qcl_visit_expr_string_sig)(_qcl_visitor *v, _qcl_expr_string *s);
typedef void *(*_qcl_visit_expr_identifier_sig)(_qcl_visitor *v, _qcl_expr_identifier *s);
typedef void *(*_qcl_visit_expr_list_sig)(_qcl_visitor *v, _qcl_expr_list *s);
typedef void *(*_qcl_visit_expr_bool_sig)(_qcl_visitor *v, _qcl_expr_bool *s);
typedef void *(*_qcl_visit_expr_env_sig)(_qcl_visitor *v, _qcl_expr_env *s);
typedef void *(*_qcl_visit_expr_unary_sig)(_qcl_visitor *v, _qcl_expr_unary *s);
typedef void *(*_qcl_visit_stmt_assignment_sig)(_qcl_visitor *v, _qcl_stmt_assignment *s);
typedef void *(*_qcl_visit_stmt_if_sig)(_qcl_visitor *v, _qcl_stmt_if *s);
typedef void *(*_qcl_visit_stmt_block_sig)(_qcl_visitor *v, _qcl_stmt_block *s);

typedef struct _qcl_visitor {
        void *context;

        // Expressions
        _qcl_visit_expr_string_sig     visit_expr_string;
        _qcl_visit_expr_identifier_sig visit_expr_identifier;
        _qcl_visit_expr_list_sig       visit_expr_list;
        _qcl_visit_expr_bool_sig       visit_expr_bool;
        _qcl_visit_expr_env_sig        visit_expr_env;
        _qcl_visit_expr_unary_sig      visit_expr_unary;

        // Statements
        _qcl_visit_stmt_assignment_sig visit_stmt_assignment;
        _qcl_visit_stmt_if_sig         visit_stmt_if;
        _qcl_visit_stmt_block_sig      visit_stmt_block;
} _qcl_visitor;

static _qcl_visitor *
_qcl_visitor_alloc(void                           *context,
                   _qcl_visit_expr_string_sig      visit_expr_string,
                   _qcl_visit_expr_identifier_sig  visit_expr_identifier,
                   _qcl_visit_expr_list_sig        visit_expr_list,
                   _qcl_visit_expr_bool_sig        visit_expr_bool,
                   _qcl_visit_expr_env_sig         visit_expr_env,
                   _qcl_visit_expr_unary_sig       visit_expr_unary,
                   _qcl_visit_stmt_assignment_sig  visit_stmt_assignment,
                   _qcl_visit_stmt_if_sig          visit_stmt_if,
                   _qcl_visit_stmt_block_sig       visit_stmt_block)
{
        _qcl_visitor *v = (_qcl_visitor *)malloc(sizeof(_qcl_visitor));

        v->context = context;

        v->visit_expr_identifier = visit_expr_identifier;
        v->visit_expr_list       = visit_expr_list;
        v->visit_expr_bool       = visit_expr_bool;
        v->visit_expr_string     = visit_expr_string;
        v->visit_expr_env        = visit_expr_env;
        v->visit_expr_unary      = visit_expr_unary;

        v->visit_stmt_assignment = visit_stmt_assignment;
        v->visit_stmt_if         = visit_stmt_if;
        v->visit_stmt_block      = visit_stmt_block;

        return v;
}

static void *
_qcl_accept_expr_unary(_qcl_expr *e, _qcl_visitor *v)
{
        if (v->visit_expr_unary) {
                return v->visit_expr_unary(v, (_qcl_expr_unary *)e);
        }
        return NULL;
}

static void *
_qcl_accept_expr_env(_qcl_expr *e, _qcl_visitor *v)
{
        if (v->visit_expr_env) {
                return v->visit_expr_env(v, (_qcl_expr_env *)e);
        }
        return NULL;
}

static void *
_qcl_accept_expr_string(_qcl_expr *e, _qcl_visitor *v)
{
        if (v->visit_expr_string) {
                return v->visit_expr_string(v, (_qcl_expr_string *)e);
        }
        return NULL;
}

static void *
_qcl_accept_expr_identifier(_qcl_expr    *e,
                            _qcl_visitor *v)
{
        if (v->visit_expr_identifier) {
                return v->visit_expr_identifier(v, (_qcl_expr_identifier *)e);
        }
        return NULL;
}

static void *
_qcl_accept_expr_list(_qcl_expr    *e,
                      _qcl_visitor *v)
{
        if (v->visit_expr_list) {
                return v->visit_expr_list(v, (_qcl_expr_list *)e);
        }
        return NULL;
}

static void *
_qcl_accept_expr_bool(_qcl_expr    *e,
                      _qcl_visitor *v)
{
        if (v->visit_expr_bool) {
                return v->visit_expr_bool(v, (_qcl_expr_bool *)e);
        }
        return NULL;
}

static void *
_qcl_accept_stmt_assigment(_qcl_stmt    *s,
                           _qcl_visitor *v)
{
        if (v->visit_stmt_assignment) {
                return v->visit_stmt_assignment(v, (_qcl_stmt_assignment *)s);
        }
        return NULL;
}

static void *
_qcl_accept_stmt_if(_qcl_stmt    *s,
                    _qcl_visitor *v)
{
        if (v->visit_stmt_if) {
                return v->visit_stmt_if(v, (_qcl_stmt_if *)s);
        }
        return NULL;
}

static void *
_qcl_accept_stmt_block(_qcl_stmt    *s,
                       _qcl_visitor *v)
{
        if (v->visit_stmt_block) {
                return v->visit_stmt_block(v, (_qcl_stmt_block *)s);
        }
        return NULL;
}

// ######################
// # INTERPRETER        #
// ######################

typedef enum {
        QCL_VALUE_KIND_STRING = 0,
        QCL_VALUE_KIND_LIST,
        QCL_VALUE_KIND_BOOL,
} qcl_value_kind;

typedef struct { qcl_value_kind kind; } qcl_value;

QCL_ARRAY_TYPE(qcl_value *, qcl_value_array);

typedef struct {
        qcl_value base;
        const char *s;
} qcl_value_string;

typedef struct {
        qcl_value       base;
        qcl_value_array values;
} qcl_value_list;

typedef struct {
        qcl_value base;
        int       b;
} qcl_value_bool;

static qcl_value_string *qcl_value_string_alloc(const char *s);
static qcl_value_list   *qcl_value_list_alloc(qcl_value_array values);
static qcl_value_bool   *qcl_value_bool_alloc(int b);

static qcl_value_bool *
_qcl_value_istruthy(const qcl_value *v)
{
        int b = 0;

        if (v->kind == QCL_VALUE_KIND_STRING) {
                b = strlen(((qcl_value_string *)v)->s) > 0;
        } else if (v->kind == QCL_VALUE_KIND_BOOL) {
                b = ((qcl_value_bool *)v)->b;
        } else if (v->kind == QCL_VALUE_KIND_LIST) {
                b = ((qcl_value_list *)v)->values.len > 0;
        } else {
                assert(0 && "unimplemented");
        }

        return qcl_value_bool_alloc(b);
}

static qcl_value *
_qcl_value_copy(const qcl_value *v)
{
        if (v->kind == QCL_VALUE_KIND_STRING) {
                return (qcl_value *)qcl_value_string_alloc(((qcl_value_string *)v)->s);
        } else if (v->kind == QCL_VALUE_KIND_LIST) {
                qcl_value_array ar = qcl_array_empty(qcl_value_array);
                qcl_value_list *lst = (qcl_value_list *)v;
                for (size_t i = 0; i < lst->values.len; ++i) {
                        qcl_array_append(ar, _qcl_value_copy(lst->values.data[i]));
                }
                return (qcl_value *)qcl_value_list_alloc(ar);
        } else if (v->kind == QCL_VALUE_KIND_BOOL) {
                return (qcl_value *)qcl_value_bool_alloc(((qcl_value_bool *)v)->b);
        } else {
                assert(0 && "unimplemented");
        }
}

static qcl_value_string *
qcl_value_string_alloc(const char *s)
{
        qcl_value_string *v = (qcl_value_string *)malloc(sizeof(qcl_value_string));
        v->s                = s;
        v->base.kind        = QCL_VALUE_KIND_STRING;
        return v;
}

static qcl_value_list *
qcl_value_list_alloc(qcl_value_array values)
{
        qcl_value_list *v = (qcl_value_list *)malloc(sizeof(qcl_value_list));
        v->values         = values;
        v->base.kind      = QCL_VALUE_KIND_LIST;
        return v;
}

static qcl_value_bool *
qcl_value_bool_alloc(int b)
{
        qcl_value_bool *v = (qcl_value_bool *)malloc(sizeof(qcl_value_bool));
        v->b              = b;
        v->base.kind      = QCL_VALUE_KIND_BOOL;
        return v;
}

QCL_MAP_TYPE(const char *, qcl_value *, symtbl);

static unsigned
symtbl_hash(const char **sym)
{
        return **sym;
}

static int
symtbl_cmp(const char **sym0,
           const char **sym1)
{
        return strcmp(*sym0, *sym1);
}

typedef struct {
        symtbl tbl;
} _qcl_interpret_context;

static void *
_qcl_interpret_visit_stmt_assignment(_qcl_visitor         *v,
                                     _qcl_stmt_assignment *s)
{
        _qcl_interpret_context *ctx = (_qcl_interpret_context *)v->context;
        qcl_value *value = (qcl_value *)s->expr->accept(s->expr, v);
        symtbl_insert(&ctx->tbl, s->id, value);
        return NULL;
}

static void *
_qcl_interpret_visit_stmt_if(_qcl_visitor *v,
                             _qcl_stmt_if *s)
{
        qcl_value *e = s->cond->accept(s->cond, v);
        qcl_value_bool *b = _qcl_value_istruthy(e);

        if (b->b) {
                s->then->accept(s->then, v);
        } else if (s->else_) {
                s->else_->accept(s->else_, v);
        }

        return NULL;
}

static void *
_qcl_interpret_visit_stmt_block(_qcl_visitor    *v,
                                _qcl_stmt_block *s)
{
        for (size_t i = 0; i < s->stmts.len; ++i) {
                s->stmts.data[i]->accept(s->stmts.data[i], v);
        }
        return NULL;
}

static void *
_qcl_interpret_visit_expr_string(_qcl_visitor     *v,
                                 _qcl_expr_string *e)
{
        (void)v;
        return qcl_value_string_alloc(e->s);
}

static void *
_qcl_interpret_visit_expr_identifier(_qcl_visitor         *v,
                                     _qcl_expr_identifier *e)
{
        _qcl_interpret_context *ctx = (_qcl_interpret_context *)v->context;

        if (!symtbl_contains(&ctx->tbl, e->id)) {
                // TODO: set error flag
                fprintf(stderr, "variable %s is not declared\n", e->id);
                exit(1);
        }

        qcl_value *value = _qcl_value_copy(*(qcl_value **)symtbl_get(&ctx->tbl, e->id));
        assert(value);

        return value;
}

static void *
_qcl_interpret_visit_expr_list(_qcl_visitor   *v,
                               _qcl_expr_list *e)
{
        _qcl_interpret_context *ctx = (_qcl_interpret_context *)v->context;

        qcl_value_array values = qcl_array_empty(qcl_value_array);

        for (size_t i = 0; i < e->exprs.len; ++i) {
                qcl_array_append(values, e->exprs.data[i]->accept(e->exprs.data[i], v));
        }

        return qcl_value_list_alloc(values);
}

static void *
_qcl_interpret_visit_expr_bool(_qcl_visitor   *v,
                               _qcl_expr_bool *e)
{
        (void)v;
        return qcl_value_bool_alloc(e->b);
}

static void *
_qcl_interpret_visit_expr_env(_qcl_visitor   *v,
                              _qcl_expr_env *e)
{
        qcl_value *var = e->rhs->accept(e->rhs, v);
        assert(var->kind == QCL_VALUE_KIND_STRING);
        char *env = getenv(((qcl_value_string *)var)->s);
        if (env) return qcl_value_string_alloc(strdup(env));
        return qcl_value_string_alloc("");
}

static void *
_qcl_interpret_visit_expr_unary(_qcl_visitor    *v,
                                _qcl_expr_unary *e)
{
        assert(!strcmp(e->op, "!"));
        qcl_value *rhs = e->rhs->accept(e->rhs, v);
        qcl_value_bool *tru = _qcl_value_istruthy(rhs);
        tru->b = !tru->b;
        return tru;
}

static _qcl_visitor *
_interpreter_visitor_alloc(_qcl_interpret_context *ctx)
{
        return _qcl_visitor_alloc((void *)ctx,
                                  _qcl_interpret_visit_expr_string,
                                  _qcl_interpret_visit_expr_identifier,
                                  _qcl_interpret_visit_expr_list,
                                  _qcl_interpret_visit_expr_bool,
                                  _qcl_interpret_visit_expr_env,
                                  _qcl_interpret_visit_expr_unary,
                                  _qcl_interpret_visit_stmt_assignment,
                                  _qcl_interpret_visit_stmt_if,
                                  _qcl_interpret_visit_stmt_block);
}

static _qcl_interpret_context
_qcl_interpret(_qcl_program *p)
{
        _qcl_interpret_context ctx = (_qcl_interpret_context) {
                .tbl = symtbl_create(symtbl_hash, symtbl_cmp),
        };

        _qcl_visitor *v = _interpreter_visitor_alloc(&ctx);

        for (size_t i = 0; i < p->stmts.len; ++i) {
                p->stmts.data[i]->accept(p->stmts.data[i], v);
        }

        return ctx;
}

typedef struct {
        _qcl_interpret_context interpreter;
} qcl_config;

static qcl_config
qcl_parse_file(const char *fp)
{
        char         *src;
        _qcl_lexer    lexer;
        _qcl_program  prog;

        assert(src = _qcl_load_file(fp));
        lexer = _qcl_lex_file(fp, src);
        prog  = _qcl_create_program(&lexer);

        return (qcl_config) {
                .interpreter = _qcl_interpret(&prog),
        };
}

static qcl_value *
qcl_value_get(qcl_config *config,
              const char *var)
{
        if (!symtbl_contains(&config->interpreter.tbl, var)) return NULL;
        return *(qcl_value **)symtbl_get(&config->interpreter.tbl, var);
}

#endif // QCL_IMPL

#endif // QCL_INCLUDED_H
