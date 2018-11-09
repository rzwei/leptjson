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

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define PUTS(c, s, len) memcpy(lept_context_push(c, len), s, len)

static void lept_stringify_string(lept_context *c, const char *s, size_t len)
{
	static const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	assert(s != NULL);
	size_t i, size;
	char *p, *head;
	p = head = (char *)lept_context_push(c, size = len * 6 + 2);
	*p++ = '"';
	for (i = 0; i < len; ++i)
	{
		unsigned char ch = (unsigned char)s[i];
		switch (ch)
		{
		case '"':
			*p++ = '\\'; *p++ = '\"';
			break;
		case '\\':
			*p++ = '\\'; *p++ = '\\';
			break;
		case '\b':
			*p++ = '\\'; *p++ = 'b';
			break;
		case '\t':
			*p++ = '\\'; *p++ = 't';
			break;
		case '\r':
			*p++ = '\\'; *p++ = 'r';
			break;
		case '\n':
			*p++ = '\\'; *p++ = 'n';
			break;
		case '\f':
			*p++ = '\\'; *p++ = 'f';
			break;
		default:
			if (ch < 0x20)
			{
				*p++ = '\\'; *p++ = 'u';
				*p++ = '0'; *p++ = '0';
				*p++ = hex_digits[ch >> 4];
				*p++ = hex_digits[ch & 15];
			}
			else
			{
				*p++ = s[i];
			}
		}
	}
	*p++ = '"';
	c->top -= size - (p - head);
}

int lept_stringify_value(lept_context *c, const lept_value *v)
{
	switch (v->type)
	{
	case LEPT_NULL:
		PUTS(c, "null", 4);
		break;
	case LEPT_TRUE:
		PUTS(c, "true", 4);
		break;
	case LEPT_FALSE:
		PUTS(c, "false", 5);
		break;
	case LEPT_NUMBER:
		c->top -= 32 - sprintf((char *)lept_context_push(c, 32), "%.17g", v->n);
		break;
	case LEPT_STRING:
		lept_stringify_string(c, v->s, v->len);
		break;
	case LEPT_ARRAY:
	{
		PUTC(c, '[');
		size_t len = lept_get_array_size(v);
		for (size_t i = 0; i < len; ++i)
		{
			lept_stringify_value(c, lept_get_array_element(v, i));
			if (i != len - 1)
				PUTC(c, ',');
		}
		PUTC(c, ']');
	}
	break;
	case LEPT_OBJECT:
	{
		PUTC(c, '{');
		size_t n = lept_get_object_size(v);
		for (size_t i = 0; i < n; ++i)
		{
			lept_stringify_string(c, lept_get_object_key(v, i), lept_get_object_key_length(v, i));
			PUTC(c, ':');
			lept_stringify_value(c, lept_get_object_value(v, i));
			if (i != n - 1)
				PUTC(c, ',');
		}
		PUTC(c, '}');
	}
	break;
	}
	return LEPT_STRINGIFY_OK;
}

int lept_stringify(const lept_value *v, char **json, size_t *length)
{
	lept_context c;
	int ret;
	assert(v != NULL && json != NULL);
	c.stack = (char *)malloc(LEPT_PARSE_STRINGIFY_INIT_SIZE);
	c.top = 0;
	if ((ret = lept_stringify_value(&c, v)) != LEPT_STRINGIFY_OK)
	{
		free(c.stack);
		*json = NULL;
		return ret;
	}
	if (length)
		*length = c.top;
	PUTC(&c, '\0');
	*json = c.stack;
	return LEPT_STRINGIFY_OK;
}

static void lept_parse_whitespace(lept_context *c)
{
	const char *p = c->json;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
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
	if (*p == '-') p++;
	if (*p == '0')
	{
		p++;
		if (*p != '\0' && *p != '.' && *p != ' ')
			return LEPT_PARSE_ROOT_NOT_SINGULAR;
	}
	else
	{
		if (!ISDIGIT1TO9(*p))
			return LEPT_PARSE_INVALID_VALUE;
		for (p++; ISDIGIT(*p); p++) ;
	}
	if (*p == '.')
	{
		p++;
		if (!ISDIGIT(*p))
			return LEPT_PARSE_INVALID_VALUE;
		for (p++; ISDIGIT(*p); p++) ;
	}

	if (*p == 'e' || *p == 'E')
	{
		p++;
		if (*p == '+' || *p == '-')
			p++;
		if (!ISDIGIT1TO9(*p))
			return LEPT_PARSE_INVALID_VALUE;
		for (p++; ISDIGIT(*p); p++) ;
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
		else if ('a' <= c && c <= 'f')
			*u |= c - 'a' + 10;
		else if ('A' <= c && c <= 'F')
			*u |= c - 'A' + 10;
		else
			return NULL;
	}
	return p;
}

static void lept_encode_utf8(lept_context *c, unsigned u)
{
	assert(u <= 0x10FFFF);
	if (0x0000 <= u && u <= 0x007F)
	{
		PUTC(c, u & 0xFF);
	}
	else if (0x0080 <= u && u <= 0x07FF)
	{
		PUTC(c, 0xC0 | ((u >> 6) & 0xFF)); /* 0xC0 = 11000000 */
		PUTC(c, 0x80 | (u & 0x3F));
	}
	if (u >= 0x0800 && u <= 0xFFFF)
	{
		PUTC(c, 0xE0 | ((u >> 12) & 0xFF)); /* 0xE0 = 11100000 */
		PUTC(c, 0x80 | ((u >> 6) & 0x3F));  /* 0x80 = 10000000 */
		PUTC(c, 0x80 | (u & 0x3F));            /* 0x3F = 00111111 */
	}
	else if (0x10000 <= u && u <= 0x10FFFF)
	{
		PUTC(c, 0xF0 | ((u >> 18) & 0xFF)); /* 0x07 = 00000111 */
		PUTC(c, 0x80 | ((u >> 12) & 0x3F)); /* 0x80 = 10000000 */
		PUTC(c, 0x80 | ((u >> 6) & 0x3F));  /* 0x80 = 10000000 */
		PUTC(c, 0x80 | (u & 0x3F));            /* 0x3F = 00111111 */
	}
}

static int lept_parse_string_raw(lept_context *c, char **s, size_t *len)
{
	unsigned u;
	size_t head = c->top;

#define STRING_ERROR(ret) \
    do                    \
    {                     \
        c->top = head;    \
        return ret;       \
    } while (0)

	const char *p;
	EXPECT(c, '\"');
	p = c->json;
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
			*len = c->top - head;
			*s = (char *)lept_context_pop(c, *len * sizeof(char));
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

static int lept_parse_string(lept_context *c, lept_value *v)
{
	int ret;
	char *s;
	size_t len;

	if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
		lept_set_string(v, s, len);
	return ret;
}
void lept_free(lept_value *v)
{
	assert(v != NULL);
	if (v->type == LEPT_STRING)
		free(v->s);
	else if (v->type == LEPT_ARRAY)
	{
		for (size_t i = 0; i < v->size; ++i)
			lept_free(v->e + i);
		free(v->e);
	}
	else if (v->type == LEPT_OBJECT)
	{
		size_t len = lept_get_object_size(v);
		for (size_t i = 0; i < len; ++i)
		{
			lept_free(lept_get_object_value(v, i));
			free((char *)lept_get_object_key(v, i));
		}
		free(v->m);
	}
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

static int lept_parse_array(lept_context *c, lept_value *v);
static int lept_parse_object(lept_context *c, lept_value *v);
static int lept_parse_value(lept_context *c, lept_value *v)
{
	switch (*c->json)
	{
	case '"':
		return lept_parse_string(c, v);
	case 'n':
		return lept_parse_literal(c, v, "null", LEPT_NULL);
	case 't':
		return lept_parse_literal(c, v, "true", LEPT_TRUE);
	case 'f':
		return lept_parse_literal(c, v, "false", LEPT_FALSE);
	case '\0':
		return LEPT_PARSE_EXPECT_VALUE;
	case '[':
		return lept_parse_array(c, v);
	case '{':
		return lept_parse_object(c, v);
	default:
		return lept_parse_number(c, v);
	}
}

static int lept_parse_array(lept_context *c, lept_value *v)
{
	size_t size = 0;
	int ret;
	EXPECT(c, '[');
	lept_parse_whitespace(c);
	if (*c->json == ']')
	{
		c->json++;
		v->type = LEPT_ARRAY;
		v->size = 0;
		v->e = NULL;
		return LEPT_PARSE_OK;
	}
	for (;;)
	{
		lept_value e;
		lept_init(&e);
		if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
			return ret;
		memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
		lept_parse_whitespace(c);
		size++;
		if (*c->json == ',')
		{
			c->json++;
			lept_parse_whitespace(c);
		}
		else if (*c->json == ']')
		{
			c->json++;
			v->type = LEPT_ARRAY;
			v->size = size;
			size *= sizeof(lept_value);
			memcpy(v->e = (lept_value *)malloc(size), lept_context_pop(c, size), size);
			return LEPT_PARSE_OK;
		}
		else
		{
			size *= sizeof(lept_value);
			lept_context_pop(c, size);
			return LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
		}
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
	if (b == 0)  v->type = LEPT_FALSE;
	else v->type = LEPT_TRUE;
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

size_t lept_get_array_size(const lept_value *v)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	return v->size;
}

lept_value *lept_get_array_element(const lept_value *v, size_t index)
{
	assert(v != NULL && v->type == LEPT_ARRAY && index < v->size);
	return &v->e[index];
}

size_t lept_get_object_size(const lept_value *v)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	return v->obj_size;
}
const char *lept_get_object_key(const lept_value *v, size_t index)
{
	assert(v != NULL && v->type == LEPT_OBJECT && index < v->obj_size);
	return (v->m + index)->k;
}
size_t lept_get_object_key_length(const lept_value *v, size_t index)
{
	assert(v != NULL && v->type == LEPT_OBJECT && index < v->obj_size);
	return (v->m + index)->klen;
}
lept_value *lept_get_object_value(const lept_value *v, size_t index)
{
	assert(v != NULL && v->type == LEPT_OBJECT && index < v->obj_size);
	return &(v->m + index)->v;
}

size_t lept_find_object_index(const lept_value *v, const char *key, size_t klen)
{
	size_t i;
	assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
	for (i = 0; i < v->obj_size; ++i)
	{
		if (v->m[i].klen == klen && memcmp(v->m[i].k, key, klen) == 0)
			return i;
	}
	return LEPT_KEY_NOT_EXIST;
}

lept_value *lept_find_object_value(lept_value *v, const char *key, size_t klen)
{
	size_t index = lept_find_object_index(v, key, klen);
	if (index == LEPT_KEY_NOT_EXIST)
		return NULL;
	return lept_get_object_value(v, index);
}

int lept_is_equal(lept_value *lhs, lept_value *rhs)
{
	assert(lhs != NULL && rhs != NULL);
	if (lhs->type != rhs->type)
		return 0;
	switch (lhs->type)
	{
	case LEPT_STRING:
	{
		size_t len = lept_get_string_length(lhs);
		return len == lept_get_string_length(rhs) && memcmp(lhs->s, rhs->s, len) == 0;
	}
	case LEPT_ARRAY:
	{
		size_t len = lept_get_array_size(lhs);
		if (len != lept_get_array_size(rhs))
			return 0;
		for (size_t i = 0; i < len; ++i)
			if (!lept_is_equal(lhs->e + i, rhs->e + i))
				return 0;
		return 1;
	}
	case LEPT_OBJECT:
	{
		size_t len = lept_get_object_size(lhs);
		if (len != lept_get_object_size(rhs))
			return 0;
		for (size_t i = 0; i < len; ++i)
		{
			lept_value *rv = lept_find_object_value(rhs, lept_get_object_key(lhs, i), lept_get_object_key_length(lhs, i));
			if (rv == NULL || !lept_is_equal(lept_get_object_value(lhs, i), rv))
				return 0;
		}
		return 1;
	}
	case LEPT_NUMBER:
		return lhs->n == rhs->n;
	default:
		return 1;
	}
}

void lept_copy(lept_value *dst, const lept_value *src)
{
	assert(src != NULL && dst != NULL && src != dst);
	lept_free(dst);
	memcpy(dst, src, sizeof(lept_value));
	switch (src->type)
	{
	case LEPT_STRING:
	{
		size_t len = lept_get_string_length(src);
		dst->s = (char *)malloc(len + 1);
		memcpy(dst->s, src->s, len);
		dst->s[len] = '\0';
	}
	break;
	case LEPT_ARRAY:
	{
		size_t len = lept_get_array_size(src);
		dst->e = (lept_value *)malloc(len * sizeof(lept_value));
		for (size_t i = 0; i < len; ++i)
			lept_copy(dst->e + i, src->e + i);
	}
	break;
	case LEPT_OBJECT:
	{
		size_t len = lept_get_object_size(src);
		dst->m = (lept_member *)malloc(len * sizeof(lept_member));
		for (size_t i = 0; i < len; ++i)
		{
			size_t klen = lept_get_object_key_length(src, i);
			(dst->m + i)->klen = klen;
			(dst->m + i)->k = (char *)malloc((klen + 1) * sizeof(char));
			memcpy((dst->m + i)->k, lept_get_object_key(src, i), klen);
			(dst->m + i)->k[klen] = '\0';
			lept_copy(&((dst->m + i)->v), &((src->m + i)->v));
		}
	}
	break;
	case LEPT_NUMBER:
		dst->n = src->n;
		break;
	default:
		break;
	}
}


void lept_move(lept_value *dst, lept_value *src)
{
	assert(dst != NULL && src != NULL && src != dst);
	lept_free(dst);
	memcpy(dst, src, sizeof(lept_value));
	lept_init(src);
}

void lept_swap(lept_value *lhs, lept_value *rhs)
{
	assert(lhs != NULL && rhs != NULL);
	if (lhs != rhs)
	{
		lept_value temp;
		memcpy(&temp, rhs, sizeof(lept_value));
		memcpy(rhs, lhs, sizeof(lept_value));
		memcpy(lhs, &temp, sizeof(lept_value));
	}
}

size_t lept_get_array_capacity(const lept_value *v)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	return v->capacity;
}

void lept_reserve_array(lept_value *v, size_t capacity)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	if (v->capacity < capacity)
	{
		v->capacity = capacity;
		v->e = (lept_value *)realloc(v->e, capacity * sizeof(lept_value));
	}
}

void lept_shrink_array(lept_value *v)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	if (v->capacity > v->size)
	{
		v->capacity = v->size;
		v->e = (lept_value *)realloc(v->e, v->capacity * sizeof(lept_value));
	}
}

lept_value *lept_pushback_array_element(lept_value *v)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	if (v->size == v->capacity)
		lept_reserve_array(v, v->capacity == 0 ? 1 : v->capacity * 2);
	lept_init(v->e + v->size);
	return v->e + (v->size++);
}

void lept_popback_array_element(lept_value *v)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	lept_free(v->e + (--(v->size)));
}

lept_value *lept_insert_array_element(lept_value *v, size_t index)
{
	assert(v != NULL && 0 <= index);
	size_t len = lept_get_array_size(v);
	assert(index <= len);
	lept_reserve_array(v, v->size + 1);
	v->size++;
	for (size_t i = v->size - 1; i > index; --i)
		lept_move(lept_get_array_element(v, i), lept_get_array_element(v, i - 1));
	return lept_get_array_element(v, index);
}

void lept_erase_array_element(lept_value *v, size_t index, size_t count)
{
	assert(v != NULL && 0 <= index && count >= 0);
	if (count == 0)
		return;
	size_t len = lept_get_array_size(v);
	if (count > len - count)
		count = len - count;
	for (size_t i = index; i + count < len; ++i)
		lept_move(lept_get_array_element(v, i), lept_get_array_element(v, i + count));
	v->size -= count;
}

void lept_clear_array(lept_value *v)
{
	assert(v != NULL);
	size_t len = lept_get_array_size(v);
	for (size_t i = 0; i < len; ++i)
		lept_free(lept_get_array_element(v, i));
	v->size = 0;
}

void lept_set_array(lept_value *v, size_t capacity)
{
	assert(v != NULL);
	lept_free(v);
	v->type = LEPT_ARRAY;
	v->size = 0;
	v->capacity = capacity;
	v->e = capacity > 0 ? (lept_value *)malloc(capacity * sizeof(lept_value)) : NULL;
}

void lept_set_object(lept_value *v, size_t capacity)
{
	assert(v != NULL);
	lept_free(v);
	v->type = LEPT_OBJECT;
	v->obj_size = 0;
	v->obj_capacity = capacity;
	v->m = capacity > 0 ? (lept_member *)malloc(capacity * sizeof(lept_member)) : NULL;
}

size_t lept_get_object_capacity(const lept_value *v)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	return v->obj_capacity;
}

void lept_reserve_object(lept_value *v, size_t capacity)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	if (v->capacity < capacity)
	{
		v->capacity = capacity;
		v->m = (lept_member *)realloc(v->e, capacity * sizeof(lept_member));
	}
}

void lept_shrink_object(lept_value *v)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	if (v->obj_capacity > v->obj_size)
	{
		v->obj_capacity = v->obj_size;
		v->m = (lept_member *)realloc(v->m, v->obj_capacity * sizeof(lept_member));
	}
}

void lept_remove_object_value(lept_value *v, size_t index)
{
	assert(v != NULL && v->type == LEPT_OBJECT && index < v->obj_size);
	size_t len = lept_get_object_size(v);

	free(lept_get_object_key(v, index));
	lept_free(lept_get_object_value(v, index));

	for (size_t i = index; i + 1 < len; ++i)
	{
		memcpy(v->m + i, v->m + i + 1, sizeof(lept_member));
	}
	(v->m + (v->obj_size - 1))->k = NULL;
	lept_init(&(v->m + (v->obj_size - 1))->v);
	v->obj_size--;
}

void lept_clear_object(lept_value *v)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	size_t len = v->obj_size;
	for (size_t i = 0; i < len; ++i)
	{
		lept_member *ele = v->m + i;
		free(ele->k);
		lept_free(&ele->v);
	}
	v->size = 0;
}

lept_value *lept_set_object_value(lept_value *v, const char *key, size_t klen)
{
	assert(v != NULL && key != NULL);
	size_t index = lept_find_object_index(v, key, klen);

	if (index != LEPT_KEY_NOT_EXIST) return lept_get_object_value(v, index);

	lept_reserve_object(v, v->obj_size + 1);
	lept_member *ele = v->m + v->obj_size;

	ele->k = (char *)malloc((klen + 1) * sizeof(char));
	memcpy(ele->k, key, klen);
	ele->k[klen] = '\0';
	lept_init(&ele->v);
	ele->klen = klen;
	v->obj_size++;
	return &(ele)->v;
}

static int lept_parse_object(lept_context *c, lept_value *v)
{
	size_t size;
	lept_member m;
	int ret;
	char *key;
	size_t len;

	EXPECT(c, '{');
	lept_parse_whitespace(c);
	if (*c->json == '}')
	{
		c->json++;
		v->type = LEPT_OBJECT;
		v->obj_size = 0;
		v->m = NULL;
		return LEPT_PARSE_OK;
	}
	m.k = NULL;
	size = 0;
	for (;;)
	{
		lept_init(&m.v);
		lept_parse_whitespace(c);
		if (*c->json == '}')
		{
			c->json++;
			ret = LEPT_PARSE_OK;
			break;
		}
		if (*c->json != '\"')
		{
			ret = LEPT_PARSE_MISS_KEY;
			break;
		}
		if ((ret = lept_parse_string_raw(c, &key, &len)) != LEPT_PARSE_OK)
		{
			break;
		}

		m.k = (char *)malloc((len + 1) * sizeof(char));
		memcpy(m.k, key, len);
		m.k[len] = '\0';
		m.klen = len;

		lept_parse_whitespace(c);

		if (*c->json == ':')
			c->json++;
		else
		{
			free(m.k);
			ret = LEPT_PARSE_MISS_COLON;
			break;
		}
		lept_parse_whitespace(c);
		if ((ret = lept_parse_value(c, &m.v) != LEPT_PARSE_OK))
		{
			free(m.k);
			break;
		}

		memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
		size++;
		m.k = NULL;

		lept_parse_whitespace(c);
		if (*c->json == ',')
			c->json++;
		else if (*c->json == '}')
		{
			c->json++;
			ret = LEPT_PARSE_OK;
			break;
		}
		else
		{
			ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
			break;
		}
	}
	if (ret == LEPT_PARSE_OK)
	{
		lept_init(v);
		v->type = LEPT_OBJECT;
		v->obj_size = size;
		size *= sizeof(lept_member);
		memcpy(v->m = (lept_member *)malloc(size), lept_context_pop(c, size), size);
	}
	else
	{
		lept_free(v);
		for (size_t i = 0; i < size; ++i)
		{
			lept_member *u = (lept_member *)lept_context_pop(c, sizeof(lept_member));
			lept_free(&u->v);
			free(u->k);
		}
	}
	return ret;
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