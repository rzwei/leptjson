#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "leptjson.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stddef.h>
typedef struct
{
    const char *json;
    char *stack;
    size_t size, top;
} lept_context;

#define EXPECT(c, ch)             \
    do                            \
    {                             \
        assert(*c->json == (ch)); \
        c->json++;                \
    } while (0)

#define ISDIGIT(x) ('0' <= (x) && (x) <= '9')
#define ISDIGIT1TO9(x) ('1' <= (x) && (x) <= '9')

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define PUTC(c, ch)                                         \
    do                                                      \
    {                                                       \
        *(char *)lept_context_push(c, sizeof(char)) = (ch); \
    } while (0)

static void *lept_context_push(lept_context *c, size_t size)
{
    void *ret;
    assert(size > 0);
    if (c->top + size >= c->size)
    {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;
        c->stack = (char *)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void *lept_context_pop(lept_context *c, size_t size)
{
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}
static void lept_parse_whitespace(lept_context *c)
{
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_null(lept_context *c, lept_value *v)
{
    EXPECT(c, 'n');
    if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 3;
    v->type = LEPT_NULL;
    return LEPT_PARSE_OK;
}
static int lept_parse_true(lept_context *c, lept_value *v)
{
    EXPECT(c, 't');
    if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 3;
    v->type = LEPT_TRUE;
    return LEPT_PARSE_OK;
}
static int lept_parse_false(lept_context *c, lept_value *v)
{
    EXPECT(c, 'f');
    if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 4;
    v->type = LEPT_FALSE;
    return LEPT_PARSE_OK;
}
static int lept_parse_literal(lept_context *c, lept_value *v, const char *literal, lept_type type)
{
    int i = 0;
    while (literal[i] != '\0')
    {
        if (literal[i] != c->json[i])
            return LEPT_PARSE_INVALID_VALUE;
        i++;
    }
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context *c, lept_value *v)
{
    const char *p = c->json;
    if (*p == '-')
        p++;
    if (*p == '0')
    {
        p++;
        if (*p != '\0' && *p != '.')
            return LEPT_PARSE_ROOT_NOT_SINGULAR;
    }
    else
    {
        if (!ISDIGIT1TO9(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }
    if (*p == '.')
    {
        p++;
        if (!ISDIGIT(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }

    if (*p == 'e' || *p == 'E')
    {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        if (!ISDIGIT1TO9(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }
    errno = 0;
    v->n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
        return LEPT_PARSE_NUMBER_TOO_BIG;
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}
static const char *lept_parse_hex4(const char *p, unsigned *u)
{
    *u = 0;
    for (int i = 0; i < 4; ++i)
    {
        char c = *p++;
        *u <<= 4;
        if ('0' <= c && c <= '9')
            *u |= c - '0';
        else if ('a' <= c && c <= 'z')
            *u |= c - 'a' + 10;
        else if ('A' <= c && c <= 'Z')
            *u |= c - 'A' + 10;
        else
            return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context *c, unsigned u)
{
    assert(u <= 0x10ffff);
    if (0x0000 <= u && u <= 0x007f)
    {
        PUTC(c, u & 0xFF);
    }
    else if (0x0080 <= u && u <= 0x07ff)
    {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF)); /* 0xC0 = 11000000 */
        PUTC(c, 0x80 | (u & 0x3F));
    }
    if (u >= 0x0800 && u <= 0xFFFF)
    {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF)); /* 0xE0 = 11100000 */
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));  /* 0x80 = 10000000 */
        PUTC(c, 0x80 | (u & 0x3F));         /* 0x3F = 00111111 */
    }
    else if (0x10000 <= u && u <= 0x10ffff)
    {
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF)); /* 0x07 = 00000111 */
        PUTC(c, 0x80 | ((u >> 12) & 0x3F)); /* 0x80 = 10000000 */
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));  /* 0x80 = 10000000 */
        PUTC(c, 0x80 | (u & 0x3F));         /* 0x3F = 00111111 */
    }
}
static int lept_parse_string(lept_context *c, lept_value *v)
{
    unsigned u;
    size_t head = c->top, len;

#define STRING_ERROR(ret) \
    do                    \
    {                     \
        c->top = head;    \
        return ret;       \
    } while (0)

    const char *p;
    EXPECT(c, '\"');
    p = c->json;
    // while (true)
    for (;;)
    {
        char ch = *p++;
        switch (ch)
        {
        case '\\':
        {
            switch (*p++)
            {
            case 'f':
                PUTC(c, '\f');
                break;
            case 'b':
                PUTC(c, '\b');
                break;
            case 'n':
                PUTC(c, '\n');
                break;
            case 'r':
                PUTC(c, '\r');
                break;
            case 't':
                PUTC(c, '\t');
                break;
            case '\\':
                PUTC(c, '\\');
                break;
            case '\"':
                PUTC(c, '\"');
                break;
            case '/':
                PUTC(c, '/');
                break;
            case 'u':
                if (!(p = lept_parse_hex4(p, &u)))
                    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                if (0xD800 <= u && u <= 0xDBFF)
                {
                    unsigned u2;
                    if (*p++ != '\\')
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    if (*p++ != 'u')
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    if (!(p = lept_parse_hex4(p, &u2)))
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                    if (u2 < 0xDC00 || u2 > 0xDFFF)
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                }
                lept_encode_utf8(c, u);
                break;
            default:
                c->top = head;
                return LEPT_PARSE_INVALID_STRING_ESCAPE;
            }
            break;
        }
        case '\"':
            len = c->top - head;
            lept_set_string(v, (const char *)lept_context_pop(c, len), len);
            c->json = p;
            return LEPT_PARSE_OK;
        case '\0':
            STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
        default:
            if ((unsigned int)ch < 0x20)
            {
                STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
            }
            PUTC(c, ch);
        }
    }
}
void lept_free(lept_value *v)
{
    assert(v != NULL);
    if (v->type == LEPT_STRING)
        free(v->s);
    v->type = LEPT_NULL;
}

void lept_set_string(lept_value *v, const char *s, size_t len)
{
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->s = (char *)malloc(len + 1);
    memcpy(v->s, s, len);
    v->s[len] = '\0';
    v->len = len;
    v->type = LEPT_STRING;
}
static int lept_parse_value(lept_context *c, lept_value *v)
{
    switch (*c->json)
    {
    case '"':
        return lept_parse_string(c, v);
    case 'n':
        return lept_parse_literal(c, v, "null", LEPT_NULL);
        // return lept_parse_null(c, v);
    case 't':
        return lept_parse_literal(c, v, "true", LEPT_TRUE);
        // return lept_parse_true(c, v);
    case 'f':
        return lept_parse_literal(c, v, "false", LEPT_FALSE);
        // return lept_parse_false(c, v);
    case '\0':
        return LEPT_PARSE_EXPECT_VALUE;
    default:
        return lept_parse_number(c, v);
    }
}

lept_type lept_get_type(const lept_value *v)
{
    return v->type;
}

double lept_get_number(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}

int lept_get_boolean(const lept_value *v)
{
    assert(v != NULL);
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value *v, int b)
{
    lept_free(v);
    if (b == 0)
        v->type = LEPT_FALSE;
    else
        v->type = LEPT_TRUE;
}

void lept_set_number(lept_value *v, double n)
{
    lept_free(v);
    v->n = n;
    v->type = LEPT_NUMBER;
}

const char *lept_get_string(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s;
}

size_t lept_get_string_length(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->len;
}

int lept_parse(lept_value *v, const char *json)
{
    assert(v != NULL);
    lept_context c;
    c.stack = NULL;
    c.size = c.top = 0;
    c.json = json;
    lept_init(v);
    lept_parse_whitespace(&c);
    int ret = lept_parse_value(&c, v);
    if (ret == LEPT_PARSE_OK)
    {
        lept_parse_whitespace(&c);
        if (*c.json != '\0')
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}