#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "leptjson.h"
static int main_ret = 0;
static int test_count = 0;
static int test_pass = 0;

#define EXPECT_EQ_BASE(equality, expect, actual, format)                                                           \
    do                                                                                                             \
    {                                                                                                              \
        test_count++;                                                                                              \
        if (equality)                                                                                              \
            test_pass++;                                                                                           \
        else                                                                                                       \
        {                                                                                                          \
            fprintf(stderr, "%s:%d: expect: " format " actual: " format "\n", __FILE__, __LINE__, expect, actual); \
            main_ret = 1;                                                                                          \
        }                                                                                                          \
    } while (0)

#define EXPECT_EQ_INT(expect, actual) EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%d")
#define EXPECT_EQ_DOUBLE(expect, actual) EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%.17g")

#define EXPECT_EQ_STRING(expect, actual, length) \
    EXPECT_EQ_BASE(sizeof(expect) - 1 == length && memcmp(expect, actual, length) == 0, expect, actual, "%s")

#define EXPECT_TRUE(actual) EXPECT_EQ_BASE((actual != 0), "true", "false", "%s")
#define EXPECT_FALSE(actual) EXPECT_EQ_BASE((actual == 0), "false", "true", "%s")

#define EXPECT_EQ_SIZE_T(expect, actual) EXPECT_EQ_BASE((expect) == (actual), (size_t)expect, (size_t)actual, "%zu");

#define TEST_ERROR(error, json)                      \
    do                                               \
    {                                                \
        lept_value v;                                \
        v.type = LEPT_FALSE;                         \
        EXPECT_EQ_INT(error, lept_parse(&v, json));  \
        EXPECT_EQ_INT(LEPT_NULL, lept_get_type(&v)); \
        lept_free(&v);                               \
    } while (0)

#define TEST_NUMBER(expect, json)                           \
    do                                                      \
    {                                                       \
        lept_value v;                                       \
        EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, json)); \
        EXPECT_EQ_INT(LEPT_NUMBER, lept_get_type(&v));      \
        EXPECT_EQ_DOUBLE(expect, lept_get_number(&v));      \
        lept_free(&v);                                      \
    } while (0)

#define TEST_STRING(expect, json)                                                  \
    do                                                                             \
    {                                                                              \
        lept_value v;                                                              \
        lept_init(&v);                                                             \
        EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, json));                        \
        EXPECT_EQ_INT(LEPT_STRING, lept_get_type(&v));                             \
        EXPECT_EQ_STRING(expect, lept_get_string(&v), lept_get_string_length(&v)); \
        lept_free(&v);                                                             \
    } while (0)

static void test_parse_null()
{
    lept_value v;
    lept_init(&v);
    lept_set_boolean(&v, 0);
    EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "null"));
    EXPECT_EQ_INT(LEPT_NULL, lept_get_type(&v));
    lept_free(&v);
}

static void test_parse_true()
{
    lept_value v;
    lept_init(&v);
    lept_set_boolean(&v, 0);
    EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "true"));
    EXPECT_EQ_INT(LEPT_TRUE, lept_get_type(&v));
    lept_free(&v);
}

static void test_parse_false()
{
    lept_value v;
    lept_init(&v);
    lept_set_boolean(&v, 0);
    EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "false"));
    EXPECT_EQ_INT(LEPT_FALSE, lept_get_type(&v));
    lept_free(&v);
}

static void test_parse_expect_value()
{
    TEST_ERROR(LEPT_PARSE_EXPECT_VALUE, "");
    TEST_ERROR(LEPT_PARSE_EXPECT_VALUE, " ");
}

static void test_parse_invalid_value()
{
#if 1
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "+0");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "+1");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, ".123"); /* at least one digit before '.' */
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "1.");   /* at least one digit after '.' */
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "INF");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "inf");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "NAN");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "nan");
#endif
    lept_value v;
    v.type = LEPT_FALSE;
    EXPECT_EQ_INT(LEPT_PARSE_INVALID_VALUE, lept_parse(&v, "nul"));
    EXPECT_EQ_INT(LEPT_NULL, lept_get_type(&v));

    v.type = LEPT_FALSE;
    EXPECT_EQ_INT(LEPT_PARSE_INVALID_VALUE, lept_parse(&v, "?"));
    EXPECT_EQ_INT(LEPT_NULL, lept_get_type(&v));
}
static void test_parse_number_too_big()
{
#if 1
    TEST_ERROR(LEPT_PARSE_NUMBER_TOO_BIG, "1e309");
    TEST_ERROR(LEPT_PARSE_NUMBER_TOO_BIG, "-1e309");
#endif
}
static void test_parse_root_not_singular()
{
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "null x");
#if 1
    /* invalid number */
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "0123"); /* after zero should be '.' or nothing */
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "0x0");
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "0x123");
#endif
}
static void test_parse_number()
{
    TEST_NUMBER(0.0, "0");
    TEST_NUMBER(0.0, "-0");
    TEST_NUMBER(0.0, "-0.0");
    TEST_NUMBER(1.0, "1");
    TEST_NUMBER(-1.0, "-1");
    TEST_NUMBER(1.5, "1.5");
    TEST_NUMBER(-1.5, "-1.5");
    TEST_NUMBER(3.1416, "3.1416");
    TEST_NUMBER(1E10, "1E10");
    TEST_NUMBER(1e10, "1e10");
    TEST_NUMBER(1E+10, "1E+10");
    TEST_NUMBER(1E-10, "1E-10");
    TEST_NUMBER(-1E10, "-1E10");
    TEST_NUMBER(-1e10, "-1e10");
    TEST_NUMBER(-1E+10, "-1E+10");
    TEST_NUMBER(-1E-10, "-1E-10");
    TEST_NUMBER(1.234E+10, "1.234E+10");
    TEST_NUMBER(1.234E-10, "1.234E-10");
    TEST_NUMBER(0.0, "1e-10000"); /* must underflow */

    TEST_NUMBER(1.0000000000000002, "1.0000000000000002");           /* the smallest number > 1 */
    TEST_NUMBER(4.9406564584124654e-324, "4.9406564584124654e-324"); /* minimum denormal */
    TEST_NUMBER(-4.9406564584124654e-324, "-4.9406564584124654e-324");
    TEST_NUMBER(2.2250738585072009e-308, "2.2250738585072009e-308"); /* Max subnormal double */
    TEST_NUMBER(-2.2250738585072009e-308, "-2.2250738585072009e-308");
    TEST_NUMBER(2.2250738585072014e-308, "2.2250738585072014e-308"); /* Min normal positive double */
    TEST_NUMBER(-2.2250738585072014e-308, "-2.2250738585072014e-308");
    TEST_NUMBER(1.7976931348623157e+308, "1.7976931348623157e+308"); /* Max double */
    TEST_NUMBER(-1.7976931348623157e+308, "-1.7976931348623157e+308");
}

static void test_parse_string()
{
    TEST_STRING("", "\"\"");

    TEST_STRING("Hello", "\"Hello\"");
    TEST_STRING("Hello\nWorld", "\"Hello\\nWorld\"");
    TEST_STRING("\" \\ / \b \f \n \r \t", "\"\\\" \\\\ \\/ \\b \\f \\n \\r \\t\"");

    TEST_STRING("Hello\0World", "\"Hello\\u0000World\"");
    TEST_STRING("\x24", "\"\\u0024\"");                    /* Dollar sign U+0024 */
    TEST_STRING("\xC2\xA2", "\"\\u00A2\"");                /* Cents sign U+00A2 */
    TEST_STRING("\xE2\x82\xAC", "\"\\u20AC\"");            /* Euro sign U+20AC */
    TEST_STRING("\xF0\x9D\x84\x9E", "\"\\uD834\\uDD1E\""); /* G clef sign U+1D11E */
    TEST_STRING("\xF0\x9D\x84\x9E", "\"\\ud834\\udd1e\""); /* G clef sign U+1D11E */
}

static void test_parse_missing_quotation_mark()
{
    TEST_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK, "\"");
    TEST_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK, "\"abc");
}

static void test_parse_invalid_string_escape()
{
#if 1
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\v\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\'\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\0\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\x12\"");
#endif
}

static void test_parse_invalid_string_char()
{
#if 1
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_CHAR, "\"\x01\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_CHAR, "\"\x1F\"");
#endif
}

static void test_parse_invalid_unicode_hex()
{
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u0\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u01\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u012\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u/000\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\uG000\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u0/00\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u0G00\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u0/00\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u00G0\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u000/\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u000G\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX, "\"\\u 123\"");
}

static void test_parse_invalid_unicode_surrogate()
{
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uDBFF\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\\\\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\uDBFF\"");
    TEST_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\uE000\"");
}

static void test_access_null()
{
    lept_value v;
    lept_init(&v);
    lept_set_string(&v, "a", 1);
    lept_set_null(&v);
    EXPECT_EQ_INT(LEPT_NULL, lept_get_type(&v));
    lept_free(&v);
}

static void test_access_boolean()
{
    /* \TODO */
    /* Use EXPECT_TRUE() and EXPECT_FALSE() */
    lept_value v;
    lept_init(&v);
    lept_set_string(&v, "a", 1);
    lept_set_boolean(&v, 1);
    EXPECT_TRUE(lept_get_boolean(&v));
    lept_set_boolean(&v, 0);
    EXPECT_FALSE(lept_get_boolean(&v));
    lept_free(&v);
}

static void test_access_number()
{
    /* \TODO */
    lept_value v;
    lept_init(&v);
    lept_set_string(&v, "1", 1);
    lept_set_number(&v, 123.0);
    EXPECT_EQ_DOUBLE(123.0, lept_get_number(&v));
    lept_free(&v);
}

static void test_access_string()
{
    lept_value v;
    lept_init(&v);
    lept_set_string(&v, "", 0);
    EXPECT_EQ_STRING("", lept_get_string(&v), lept_get_string_length(&v));
    lept_set_string(&v, "hello", 5);
    EXPECT_EQ_STRING("hello", lept_get_string(&v), lept_get_string_length(&v));
    lept_free(&v);
}

static void test_parse_miss_comma_or_square_bracket()
{
#if 1
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1}");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1 2");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[[]");
#endif
}

#define SET_STEP(n)                   \
    do                                \
    {                                 \
        for (int i = 0; i < (n); ++i) \
            printf("%c", ' ');        \
    } while (0)

static void serialize(const lept_value *v, int step, int last)
{
    if (v == NULL)
        return;
    if (v->type == LEPT_NULL)
    {
        printf("null");
        if (!last)
            printf(",");
    }
    else if (v->type == LEPT_TRUE)
    {
        printf("true");
        if (!last)
            printf(",");
    }
    else if (v->type == LEPT_FALSE)
    {
        printf("false");
        if (!last)
            printf(",");
    }
    else if (v->type == LEPT_STRING)
    {
        printf("\"%s\"", v->s);
        if (!last)
            printf(",");
    }
    else if (v->type == LEPT_NUMBER)
    {
        printf("%f", v->n);
        if (!last)
            printf(",");
    }
    if (v->type == LEPT_ARRAY)
    {
        printf("[");
        for (int i = 0; i < v->size; ++i)
            serialize(v->e + i, step + 2, i == v->size - 1);
        printf("]");
        if (!last)
            printf(",");
    }
    else if (v->type == LEPT_OBJECT)
    {
        printf("{\n");
        for (int i = 0; i < v->obj_size; ++i)
        {
            SET_STEP(step + 2);
            printf("\"%s\" : ", lept_get_object_key(v, i));
            serialize(lept_get_object_value(v, i), step + 2, i == v->obj_size - 1);
            printf("\n");
        }
        SET_STEP(step);
        printf("}");
        if (!last)
            printf(", ");
    }
}

static void show_lept_value(int step, const lept_value *v)
{

    if (v == NULL)
        return;
    SET_STEP(step);
    if (v->type == LEPT_NULL)
    {
        printf("type : LEPT_NULL, value = NULL\n");
    }
    else if (v->type == LEPT_TRUE)
    {
        printf("type : LEPT_TRUE, value = TRUE\n");
    }
    else if (v->type == LEPT_FALSE)
    {
        printf("type : LEPT_FALSE, value = FALSE\n");
    }
    else if (v->type == LEPT_STRING)
    {
        printf("type : LEPT_STRING, value = %s\n", v->s);
    }
    else if (v->type == LEPT_NUMBER)
    {
        printf("type : LEPT_NUMBER, value = %g\n", v->n);
    }
    else if (v->type == LEPT_ARRAY)
    {
        printf("type : LEPT_ARRAY, value = [\n");
        for (int i = 0; i < v->size; ++i)
            show_lept_value(step + 2, v->e + i);
        SET_STEP(step);
        printf("]\n");
    }
    else if (v->type == LEPT_OBJECT)
    {
        printf("type = LEPT_OBJECT, value = {\n");
        for (int i = 0; i < v->obj_size; ++i)
        {
            SET_STEP(step + 2);
            printf("key = %s, value = ", lept_get_object_key(v, i));
            show_lept_value(step + 2, lept_get_object_value(v, i));
        }
        SET_STEP(step);
        printf("}\n");
    }
}

static void test_parse_array()
{
    lept_value v;
    // lept_init(&v);
    // EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "[ ]"));
    // EXPECT_EQ_INT(LEPT_ARRAY, lept_get_type(&v));
    // EXPECT_EQ_SIZE_T(0, lept_get_array_size(&v));
    // lept_free(&v);
    // const char *json = "[ null , false , true , 123 , \"abc\" ]";
    // lept_parse(&v, json);
    // show_lept_value(0, &v);
    // lept_free(&v);
    // json = "[ [ ] , [ 0 ] , [ 0 , 1 ] , [ 0 , 1 , 2 ] ]";
    // lept_parse(&v, json);
    // show_lept_value(0, &v);
    // lept_free(&v);

    size_t i, j;
    // lept_value v;
    lept_init(&v);
    EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "[ null , false , true , 123 , \"abc\" ]"));
    EXPECT_EQ_INT(LEPT_ARRAY, lept_get_type(&v));
    EXPECT_EQ_SIZE_T(5, lept_get_array_size(&v));
    EXPECT_EQ_INT(LEPT_NULL, lept_get_type(lept_get_array_element(&v, 0)));
    EXPECT_EQ_INT(LEPT_FALSE, lept_get_type(lept_get_array_element(&v, 1)));
    EXPECT_EQ_INT(LEPT_TRUE, lept_get_type(lept_get_array_element(&v, 2)));
    EXPECT_EQ_INT(LEPT_NUMBER, lept_get_type(lept_get_array_element(&v, 3)));
    EXPECT_EQ_INT(LEPT_STRING, lept_get_type(lept_get_array_element(&v, 4)));
    EXPECT_EQ_DOUBLE(123.0, lept_get_number(lept_get_array_element(&v, 3)));
    EXPECT_EQ_STRING("abc", lept_get_string(lept_get_array_element(&v, 4)), lept_get_string_length(lept_get_array_element(&v, 4)));
    lept_free(&v);

    lept_init(&v);
    EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "[ [ ] , [ 0 ] , [ 0 , 1 ] , [ 0 , 1 , 2 ] ]"));
    EXPECT_EQ_INT(LEPT_ARRAY, lept_get_type(&v));
    EXPECT_EQ_SIZE_T(4, lept_get_array_size(&v));
    for (i = 0; i < 4; i++)
    {
        lept_value *a = lept_get_array_element(&v, i);
        EXPECT_EQ_INT(LEPT_ARRAY, lept_get_type(a));
        EXPECT_EQ_SIZE_T(i, lept_get_array_size(a));
        for (j = 0; j < i; j++)
        {
            lept_value *e = lept_get_array_element(a, j);
            EXPECT_EQ_INT(LEPT_NUMBER, lept_get_type(e));
            EXPECT_EQ_DOUBLE((double)j, lept_get_number(e));
        }
    }
    lept_free(&v);
}

static void test_parse_miss_key()
{
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{:1,");
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{1:1,");
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{true:1,");
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{false:1,");
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{null:1,");
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{[]:1,");
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{{}:1,");
    TEST_ERROR(LEPT_PARSE_MISS_KEY, "{\"a\":1,");
}

static void test_parse_miss_colon()
{
    TEST_ERROR(LEPT_PARSE_MISS_COLON, "{\"a\"}");
    TEST_ERROR(LEPT_PARSE_MISS_COLON, "{\"a\",\"b\"}");
}

static void test_parse_miss_comma_or_curly_bracket()
{
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1]");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1 \"b\"");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":{}");
}

static void test_parse_object()
{
    lept_value v;
    const char *json = "{\"a\":\"a\"}";
    // lept_init(&v);
    // lept_parse(&v, json);
    // show_lept_value(0, &v);

    // serialize(&v, 0, 1);

    // lept_free(&v);

    // lept_init(&v);
    // json = "{\"a\":[1,2], \"b\":{\"a\":\"c\"}}";
    // lept_parse(&v, json);
    // show_lept_value(0, &v);
    // serialize(&v, 0, 1);
    // lept_free(&v);

    //json = "{\"name\":\"BeJson\",\"url\":\"http://www.bejson.com\",\"page\":88,\"isNonProfit\":true,\"address\":{\"street\":\"xxx\",\"city\":\"xxxxa\",\"country\":\"china\"},\"links\":[{\"name\":\"Google\",\"url\":\"http://www.google.com\"},{\"name\":\"Baidu\",\"url\":\"http://www.baidu.com\"},{\"name\":\"SoSo\",\"url\":\"http://www.SoSo.com\"}]}";
    json = "{\"links\":[{\"name\":\"Google\",\"url\":\"http://www.google.com\"},{\"name\":\"Baidu\",\"url\":\"http://www.baidu.com\"},{\"name\":\"SoSo\",\"url\":\"http://www.SoSo.com\"}]}";
    //json = "{\"preset_words\":{\"words\":[{\"id\":\"be424a4fdffe2202b7cfd8dff516f9aeabd56968\",\"type\":\"activity\",\"query\":\"要买对的先上知乎\",\"real_query\":\"要买对的先上知乎\",\"weight\":2,\"begin_ts\":1541001600,\"end_ts\":1541952000,\"valid\":1,\"floorpage_url\":\"https://event.zhihu.com/2018-11-11/\",\"floorpage_logo\":\"https://pic4.zhimg.com/v2-ccfb3df2aede5080ab6bb053a55f5a11.png\",\"floorpage_flag\":\"进行中\"},{\"id\":\"2f20e7c58bf8ace14809825b46950d142a1faddf\",\"type\":\"general\",\"query\":\"罗永浩宣告T系列的失败\",\"real_query\":\"罗永浩T系列\",\"weight\":1,\"begin_ts\":1540971300,\"end_ts\":1541057700,\"valid\":1},{\"id\":\"56afb69f603aa2def2829065b939bcb8db705493\",\"type\":\"general\",\"query\":\"直面「互联网隐私焦虑」\",\"real_query\":\"互联网隐私\",\"weight\":1,\"begin_ts\":1540972680,\"end_ts\":1541059080,\"valid\":1},{\"id\":\"f9bf62c30a5809881a43ee1b06203ac390c47f5e\",\"type\":\"general\",\"query\":\"罗斯50分，老兵不哭！\",\"real_query\":\"罗斯50分\",\"weight\":2,\"begin_ts\":1541048690,\"end_ts\":1541135092,\"valid\":1}],\"next_request_ts\":1541050171}}";
    lept_parse(&v, json);
    // show_lept_value(0, &v);
    serialize(&v, 0, 1);
    printf("\n");
    lept_free(&v);
}

static void test_parse()
{
    test_parse_null();
    test_parse_expect_value();
    test_parse_invalid_value();
    test_parse_root_not_singular();
    test_parse_true();
    test_parse_false();
    test_parse_number();
    test_parse_number_too_big();

    test_parse_string();
    test_access_boolean();
    test_access_number();
    test_access_string();

    test_parse_invalid_string_char();
    test_parse_invalid_string_escape();
    test_parse_missing_quotation_mark();

    test_parse_invalid_unicode_surrogate();
    test_parse_invalid_unicode_hex();

    test_parse_array();
    test_parse_miss_comma_or_square_bracket();

    test_parse_miss_key();
    test_parse_miss_colon();
    test_parse_miss_comma_or_curly_bracket();

    test_parse_object();
}
int main()
{
#ifdef _WINDOWS
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
    test_parse();
    printf("%d/%d (%3.2f%%) passed\n", test_pass, test_count, test_pass * 100.0 / test_count);

    _CrtDumpMemoryLeaks();
    return 0;
}