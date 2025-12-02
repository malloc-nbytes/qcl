#ifndef QCL_INCLUDED_H
#define QCL_INCLUDED_H

#ifdef QCL_IMPL

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
        mapname mapname##_create(qcl_##mapname##_hash_sig hash, qcl_##mapname##_cmp_sig cmp); \
        void mapname##_destroy(mapname *map); \
        void mapname##_insert(mapname *map, ktype k, vtype v); \
        int mapname##_contains(mapname *map, ktype k); \
        vtype *mapname##_get(mapname *map, ktype k); \
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

#define QCL_ARRAY_TYPE(ty, name) \
    typedef struct name {        \
        ty *data;                \
        size_t len, cap;         \
    } name

#define qcl_array_empty(arr_ty)                 \
        (arr_ty) {                              \
                .data = NULL,                   \
                .len = 0,                       \
                .cap = 0,                       \
        }

#define qcl_array_init_type(da)                 \
    do {                                        \
        (da).data = malloc(sizeof(*(da).data)); \
        (da).cap = 1;                           \
        (da).len = 0;                           \
    } while (0)

#define qcl_array(ty, name)                                        \
    struct {                                                       \
        ty *data;                                                  \
        size_t len, cap;                                           \
    } (name) = { .data = (typeof(ty) *)malloc(sizeof(ty)), .len = 0, .cap = 1 };

#define qcl_array_append(da, value)                                     \
    do {                                                                \
        if ((da).len >= (da).cap) {                                     \
            (da).cap = (da).cap ? (da).cap * 2 : 2;                     \
            (da).data = (typeof(*((da).data)) *)                        \
                realloc((da).data,                                      \
                        (da).cap * sizeof(*((da).data)));               \
        }                                                               \
        (da).data[(da).len++] = (value);                                \
    } while (0)

#define qcl_array_free(da)       \
    do {                         \
        if ((da).data != NULL) { \
                free((da).data); \
        }                        \
        (da).len = (da).cap = 0; \
    } while (0)

#define qcl_array_at_s(da, i)                                      \
    ((i) < (da).len ? (da).data[i] : (fprintf(stderr,              \
    "[qcl_array error]: index %zu is out of bounds (len = %zu)\n", \
    (size_t)(i), (size_t)(da).len), exit(1), (da).data[0]))

#define qcl_array_at(da, i) ((da).data[i])

#define qcl_array_clear(da) (da).len = 0;

#define qcl_array_rm_at(da, idx) \
    do {                                                     \
        for (size_t __i_ = (idx); __i_ < (da).len-1; ++__i_) \
            (da).data[__i_] = (da).data[__i_+1];             \
        (da).len--;                                          \
    } while (0)

typedef enum {
        QCL_TT_NONE = 0,
        QCL_TT_EOF,
        QCL_TT_IDENTIFIER,
        QCL_TT_STRING,
        QCL_TT_DIGIT,
        QCL_TT_LPAREN,
        QCL_TT_RPAREN,
        QCL_TT_LCURLY,
        QCL_TT_RCURLY,
        QCL_TT_LSQR,
        QCL_TT_RSQR, // 10
        QCL_TT_EQUALS,
        QCL_TT_COMMA,
        QCL_TT_NEWLINE,
        QCL_TT_COLON,
        QCL_TT_PLUS,
} qcl_tt;

typedef struct {
        size_t r, c;
        const char *fp;
} qcl_loc;

typedef struct qcl_token {
        char *lx;
        qcl_tt ty;
        qcl_loc loc;
        struct qcl_token *n;
} qcl_token;

typedef struct {
        qcl_token *hd;
        qcl_token *tl;
        const char *fp;
        struct {
                const char *msg;
                qcl_loc loc;
        } err;
} qcl_lexer;

static qcl_token *
_qcl_token_alloc(const char *st,
                 size_t      st_n,
                 qcl_tt      ty,
                 size_t      r,
                 size_t      c,
                 const char *fp)
{
        qcl_token *t = (qcl_token *)malloc(sizeof(qcl_token));
        t->lx        = strndup(st, st_n);
        t->ty        = ty;
        t->loc.r     = r;
        t->loc.c     = c;
        t->loc.fp    = fp;
        return t;
}

static void
_qcl_lexer_append(qcl_lexer *l, qcl_token *t)
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

static void
_qcl_lexer_dump(const qcl_lexer *l)
{
        qcl_token *it = l->hd;
        while (it) {
                printf("{ lx=%s, ty=%d, r=%zu, c=%zu, fp=%s }\n",
                       it->lx, it->ty, it->loc.r, it->loc.c, it->loc.fp);
                it = it->n;
        }
}

QCL_MAP_TYPE(const char *, qcl_tt, symmap)

static unsigned
_qcl_symmap_hash(const char **s)
{
        // ╭∩╮(-_-)╭∩╮ why the fuck wont this work

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

static qcl_tt
_qcl_determine_sym(const char *st,
                   size_t      len,
                   symmap     *map)
{
        char buf[256] = {0};
        (void)strncpy(buf, st, len);

        for (int i = len-1; i >= 0; --i) {
                if (symmap_contains(map, buf)) {
                        return *symmap_get(map, buf);
                }

                buf[i] = 0;
        }

        return QCL_TT_NONE;
}

static qcl_lexer
_qcl_lex_file(const char *fp,
              const char *src)
{
        symmap symmap = symmap_create(_qcl_symmap_hash, _qcl_symmap_cmp);
        symmap_insert(&symmap, "+", QCL_TT_PLUS);

        qcl_lexer lexer = {
                .hd = NULL,
                .tl = NULL,
                .fp = fp,
        };

        size_t r = 1, c = 1, i = 0;
        while (src[i]) {
                char ch = src[i];

                if (ch == ' ' || ch == '\t') {
                        ++i, ++c;
                } else if (ch == '\n' || ch == '\r') {
                        qcl_token *t = _qcl_token_alloc("\n", 1,
                                                        QCL_TT_NEWLINE,
                                                        r, c, lexer.fp);
                        _qcl_lexer_append(&lexer, t);
                        ++i, ++r, c = 1;
                } else if (ch == '#') {
                        while (src[i] != '\n') ++i, ++c;
                        ++i, ++r, c = 0;
                } else if (isalpha(ch) || ch == '_' || ch == '-') {
                        size_t len = _qcl_consume_while(src+i, _qcl_isident);
                        qcl_token *t = _qcl_token_alloc(src+i, len,
                                                        QCL_TT_IDENTIFIER,
                                                        r, c, lexer.fp);
                        _qcl_lexer_append(&lexer, t);
                        i += len, c += len;
                } else if (isdigit(ch)) {
                        size_t len = _qcl_consume_while(src+i, isdigit);
                        qcl_token *t = _qcl_token_alloc(src+i, len,
                                                        QCL_TT_DIGIT,
                                                        r, c, lexer.fp);
                        _qcl_lexer_append(&lexer, t);
                        i += len, c += len;
                } else if (ch == '"' || ch == '\'') {
                        size_t len;
                        if (ch == '"') {
                                len = _qcl_consume_while(src+i, _qcl_notquote);
                        } else {
                                len = _qcl_consume_while(src+i, _qcl_notsinglequote);
                        }
                        qcl_token *t = _qcl_token_alloc(src+i+1, len,
                                                        QCL_TT_STRING,
                                                        r, c, lexer.fp);
                        _qcl_lexer_append(&lexer, t);
                        i += len+2, c += len+2;
                } else {
                        size_t len = _qcl_consume_while(src+i, _qcl_issym);
                        qcl_tt ty = _qcl_determine_sym(src+i, len, &symmap);
                        if (ty == QCL_TT_NONE) {
                                char buf[256] = {0};
                                strncpy(buf, src+i, len);
                                printf("error: unknown symbol: %s\n", buf);
                                exit(1);
                        }
                        qcl_token *t = _qcl_token_alloc(src+i, len,
                                                        ty, r, c, lexer.fp);
                        _qcl_lexer_append(&lexer, t);
                        i += len, c += len;
                }
        }

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

        buf = (char *)malloc(size);
        fread(buf, 1, size, f);
        fclose(f);

        return buf;
}

#endif // QCL_IMPL

#endif // QCL_INCLUDED_H
