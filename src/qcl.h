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

#define QCL_KWD_NULL "null"
#define QCL_KWD_IF   "if"
#define QCL_KWD_CL {  \
        QCL_KWD_NULL, \
        QCL_KWD_IF,   \
        NULL,         \
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
        _QCL_TT_SEMICOLON,
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
        //_qcl_token *t = (_qcl_token *)malloc(sizeof(_qcl_token));
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
        symmap_insert(&symmap, ";", _QCL_TT_SEMICOLON);

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
static void *_qcl_accept_expr_string(_qcl_expr *e, _qcl_visitor *v);
static void *_qcl_accept_expr_identifier(_qcl_expr *e, _qcl_visitor *v);
static void *_qcl_accept_stmt_assigment(_qcl_stmt *s, _qcl_visitor *v);

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
        _QCL_EXPR_KIND_IF,
} _qcl_expr_kind;

typedef struct _qcl_expr {
        _qcl_expr_kind  kind;
        _qcl_type      *type;
        _qcl_loc        loc;
        void *(*accept)(struct _qcl_expr *e, _qcl_visitor *v);
} _qcl_expr;

typedef struct {
        _qcl_expr    base;
        const char  *s;
} _qcl_expr_string;

typedef struct {
        _qcl_expr    base;
        const char  *id;
} _qcl_expr_identifier;

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

// ########################
// # STATEMENTS           #
// ########################

typedef enum {
        QCL_STMT_KIND_ASSIGNMENT = 0,
        QCL_STMT_KIND_EXPR,
} _qcl_stmt_kind;

typedef struct _qcl_stmt {
        _qcl_stmt_kind kind;
        _qcl_loc       loc;
        void *(*accept)(struct _qcl_stmt *s, _qcl_visitor *v);
} _qcl_stmt;

typedef struct {
        _qcl_stmt    base;
        const char  *id;
        _qcl_expr   *expr;
} _qcl_stmt_assignment;

typedef struct {
        _qcl_stmt  base;
        _qcl_expr *expr;
} _qcl_stmt_expr;

static _qcl_stmt_assignment *
_qcl_stmt_assignment_alloc(const char *id,
                           _qcl_expr  *expr)
{
        _qcl_stmt_assignment *s =
                (_qcl_stmt_assignment *)malloc(sizeof(_qcl_stmt_assignment));
        s->id   = id;
        s->expr = expr;
        s->base = (_qcl_stmt) {
                .kind = QCL_STMT_KIND_ASSIGNMENT,
                .loc  = {0},
        };
        s->base.accept = _qcl_accept_stmt_assigment;
        return s;
}

// #####################
// # PARSING           #
// #####################

QCL_ARRAY_TYPE(_qcl_stmt *, _qcl_stmt_array);

typedef struct {
        _qcl_stmt_array stmts;
} _qcl_program;

#define _QCL_SP(l, i) \
        _qcl_lexer_peek(l, i) && _qcl_lexer_peek(l, i)

static _qcl_token *
_qcl_expect(_qcl_lexer *lexer,
            _qcl_tt     ty)
{
        _qcl_token *it = _qcl_lexer_next(lexer);
        if (!it || it->ty != ty) return NULL;
        return it;
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
                default: return expr;
                }
        }

        return NULL; // unreachable
}

static _qcl_expr *
_qcl_parse_additive_expr(_qcl_lexer *lexer)
{
        // TODO
        return _qcl_parse_primary_expr(lexer);
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

static _qcl_stmt_expr *
_qcl_parse_stmt_expr(_qcl_lexer *lexer)
{
        assert(0);
}

static _qcl_stmt *
_qcl_parse_stmt_keyword(_qcl_lexer *lexer)
{
        assert(0);
}

static _qcl_stmt *
_qcl_parse_stmt(_qcl_lexer *lexer)
{
        _qcl_token *hd;

        if (!(hd = _qcl_lexer_peek(lexer, 0))) return NULL;

        if (hd->ty == _QCL_TT_KEYWORD) {
                return _qcl_parse_stmt_keyword(lexer);
        } else if (hd->ty == _QCL_TT_IDENTIFIER
                   && _QCL_SP(lexer, 1)->ty == _QCL_TT_EQUALS) {
                return (_qcl_stmt *)_qcl_parse_stmt_assignment(lexer);
        } else {
                return (_qcl_stmt *)_qcl_parse_stmt_expr(lexer);
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
typedef void *(*_qcl_visit_stmt_assignment_sig)(_qcl_visitor *v, _qcl_stmt_assignment *s);

typedef struct _qcl_visitor {
        void *context;

        // Expressions
        _qcl_visit_expr_string_sig     visit_expr_string;
        _qcl_visit_expr_identifier_sig visit_expr_identifier;

        // Statements
        _qcl_visit_stmt_assignment_sig visit_stmt_assignment;
} _qcl_visitor;

static _qcl_visitor *
_qcl_visitor_alloc(void                           *context,
                   _qcl_visit_expr_string_sig      visit_expr_string,
                   _qcl_visit_expr_identifier_sig  visit_expr_identifier,
                   _qcl_visit_stmt_assignment_sig  visit_stmt_assignment)
{
        _qcl_visitor *v = (_qcl_visitor *)malloc(sizeof(_qcl_visitor));

        v->context = context;

        v->visit_stmt_assignment = visit_stmt_assignment;
        v->visit_expr_identifier = visit_expr_identifier;
        v->visit_expr_string     = visit_expr_string;

        return v ;
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
_qcl_accept_stmt_assigment(_qcl_stmt *s, _qcl_visitor *v)
{
        if (v->visit_stmt_assignment) {
                return v->visit_stmt_assignment(v, (_qcl_stmt_assignment *)s);
        }
        return NULL;
}

// ######################
// # INTERPRETER        #
// ######################

typedef enum {
        QCL_VALUE_KIND_STRING = 0,
} qcl_value_kind;

typedef struct {
        qcl_value_kind kind;
} qcl_value;

typedef struct {
        qcl_value base;
        const char *s;
} qcl_value_string;

static qcl_value_string *
qcl_value_string_alloc(const char *s)
{
        qcl_value_string *v = (qcl_value_string *)malloc(sizeof(qcl_value_string));
        v->s = s;
        v->base.kind = QCL_VALUE_KIND_STRING;
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

        printf("%s = %s\n", s->id, ((qcl_value_string *)value)->s);

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

        qcl_value *value = *(qcl_value **)symtbl_get(&ctx->tbl, e->id);
        assert(value);

        return value;
}

static _qcl_visitor *
_interpreter_visitor_alloc(_qcl_interpret_context *ctx)
{
        return _qcl_visitor_alloc((void *)ctx,
                                  _qcl_interpret_visit_expr_string,
                                  _qcl_interpret_visit_expr_identifier,
                                  _qcl_interpret_visit_stmt_assignment);
}

static void
_qcl_interpret(_qcl_program *p)
{
        _qcl_interpret_context ctx = (_qcl_interpret_context) {
                .tbl = symtbl_create(symtbl_hash, symtbl_cmp),
        };

        _qcl_visitor *v = _interpreter_visitor_alloc(&ctx);

        for (size_t i = 0; i < p->stmts.len; ++i) {
                p->stmts.data[i]->accept(p->stmts.data[i], v);
        }
}

typedef struct {} qcl_config;

static qcl_config
qcl_parse_file(const char *fp)
{
        char         *src;
        _qcl_lexer    lexer;
        _qcl_program  prog;

        assert(src = _qcl_load_file(fp));
        lexer = _qcl_lex_file(fp, src);
        /* _qcl_lexer_dump(&lexer); */
        /* assert(0); */
        prog  = _qcl_create_program(&lexer);
        _qcl_interpret(&prog);
}

#endif // QCL_IMPL

#endif // QCL_INCLUDED_H
