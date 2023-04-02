#include "leptjson.h"
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch) do {assert(*c->json == (ch)); c->json++;} while(0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)
#define PUTS(c, s, len) memcpy(lept_context_push(c, len), s, len)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
} lept_context;

static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0) {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size) {
            c->size += c->size >> 1; // expand by 1.5
        }
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}


/* ws = *(%x20 / %x09 / %x0A / %x0D) */
static void lept_parse_whitespace(lept_context* c) {
    const char* p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    c->json = p;
}
/* parse true/false/null */
static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
    size_t i;
    EXPECT(c, literal[0]); // after this, c is moved forward
    for (i = 0; literal[i + 1]; i++) {
        if (c->json[i] != literal[i + 1]) {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        while (ISDIGIT(*p)) p++;
    }
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while (ISDIGIT(*p)) p++;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while (ISDIGIT(*p)) p++;
    }

    // check large number
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) {
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }

    if (c->json == p) {
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}



static const char* lept_parse_hex4(const char* p, unsigned* u) {
    size_t i;
    char c;
    *u = 0;
    for (i = 0; i < 4; i++, p++) {
        c = *p;
        *u <<= 4;
        if (c >= '0' && c <= '9') {
            *u |= c - '0';
        } else if (c >= 'a' && c <= 'f') {
            *u |= c - ('a' - 10);
        } else if (c >= 'A' && c <= 'F') {
            *u |= c - ('A' - 10);
        } else {
            return NULL;
        }
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
    assert(u <= 0x10FFFF);
    if (u <= 0x007F) {
        PUTC(c, u & 0xFF);
    } else if (u <= 0x07FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | (u & 0x3F));
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0xFF));
    } else {
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0x3F));
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
    size_t head = c->top;
    const char* p;
    EXPECT(c, '\"'); // string must be quoted
    p = c->json;
    char ne;
    unsigned u, next_u;
    while (1) {
        char ch = *p++;
        switch (ch)
        {
        case '\"':
            *len = c->top - head;
            *str = (char*)lept_context_pop(c, *len);
            c->json = p;
            return LEPT_PARSE_OK;
        case '\\':
            ne = *p++;
            switch (ne) {
            case '\"':
                PUTC(c, '\"');
                break;
            case '\\':
                PUTC(c, '\\');
                break;
            case 'b':
                PUTC(c, '\b');
                break;
            case 'n':
                PUTC(c, '\n');
                break;
            case 't':
                PUTC(c, '\t');
                break;
            case 'r':
                PUTC(c, '\r');
                break;
            case '/':
                PUTC(c, '/');
                break;
            case 'f':
                PUTC(c, '\f');
                break;
            case 'u':
                if (!(p = lept_parse_hex4(p, &u))) {
                    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                }
                if (u >= 0xD800 && u <= 0xDBFF) {
                    if (*p++ != '\\') {
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    }
                    if (*p++ != 'u') {
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    }
                    if (!(p = lept_parse_hex4(p, &next_u))) {
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                    }
                    if (next_u < 0xDC00 || next_u > 0xDFFF) {
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    }
                    u = (((u - 0xD800) << 10) | (next_u - 0xDC00)) + 0x10000;
                }
                lept_encode_utf8(c, u);
                break;
            default:
                STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
            }
            break;
        case '\0':
            STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
        default:
            if ((unsigned char)ch < 0x20) {
                STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
            }
            PUTC(c, ch);
        }
    }

}


static int lept_parse_string(lept_context* c, lept_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK) {
        lept_set_string(v, s, len);
    }
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v); // forward declaration

static int lept_parse_array(lept_context* c, lept_value* v) {
    size_t size = 0, head = c->top;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }
    while (1) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            break;
        }
        lept_parse_whitespace(c);
        void* st_ptr = lept_context_push(c, sizeof(lept_value));
        memcpy(st_ptr, &e, sizeof(lept_value));
        size++;
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size_t array_memory_size = size * sizeof(lept_value);
            v->u.a.e = (lept_value*)malloc(array_memory_size);
            void* arr_ptr = lept_context_pop(c, array_memory_size);
            memcpy(v->u.a.e, arr_ptr, array_memory_size);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    while (size--) {
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    }
    return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v) {
    size_t size;
    lept_member m;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.m = 0;
        v->u.o.size = 0;
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    while (1) {
        char* s;
        lept_init(&m.v);
        /* TODO parse key to m.k, m.klen */
        lept_parse_whitespace(c);
        if (*c->json != '\"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        size_t len;
        if ((ret = lept_parse_string_raw(c, &s, &len)) != LEPT_PARSE_OK) {
            break;
        }
        m.k = (char*)malloc(len + 1); // for null-terminator
        memcpy(m.k, s, len);
        m.k[len] = '\0';
        m.klen = len;

        /* TODO parse ws colon ws */
        lept_parse_whitespace(c);
        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);

        /* parse value */
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            break;
        }
        void* member_ptr = lept_context_push(c, sizeof(lept_member));
        memcpy(member_ptr, &m, sizeof(lept_member));
        size++;
        m.k = NULL;

        /* TODO parse ws [comma | right-curly-brace] ws */
        lept_parse_whitespace(c);
        if (*c->json == '}') {
            c->json++;
            v->type = LEPT_OBJECT;
            size_t object_memory_size = size * sizeof(lept_member);
            v->u.o.size = size;
            v->u.o.m = (lept_member*)malloc(object_memory_size);
            void* object_ptr = lept_context_pop(c, object_memory_size);
            memcpy(v->u.o.m, object_ptr, object_memory_size);
            return LEPT_PARSE_OK;
        } else if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    free(m.k);
    /* TODO pop and free members on the stack */
    while (size--) {
        lept_member* m = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(m->k);
        lept_free(&m->v);
    }
    v->type = LEPT_NULL;
    return ret;
}

/* parse a single value, return LEPT_PARSE_OK is success */
static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json)
    {
    case 'n':
        return lept_parse_literal(c, v, "null", LEPT_NULL);
    case 't':
        return lept_parse_literal(c, v, "true", LEPT_TRUE);
    case 'f':
        return lept_parse_literal(c, v, "false", LEPT_FALSE);
    case '\0': // no value 
        return LEPT_PARSE_EXPECT_VALUE;
    case '\"':
        return lept_parse_string(c, v);
    case '[':
        return lept_parse_array(c, v);
    case '{':
        return lept_parse_object(c, v);
    default:
        return lept_parse_number(c, v);
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

static void lept_stringify_string(lept_context* c, const char* s, size_t len) {
    size_t i;
    assert(s != NULL);
    PUTC(c, '\"');
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch)
        {
        case '\"': PUTS(c, "\\\"", 2); break;
        case '\\': PUTS(c, "\\\\", 2); break;
        case '\b': PUTS(c, "\\b", 2); break;
        case '\f': PUTS(c, "\\f", 2); break;
        case '\n': PUTS(c, "\\n", 2); break;
        case '\r': PUTS(c, "\\r", 2); break;
        case '\t': PUTS(c, "\\t", 2); break;
        default:
            if (ch < 0x20) {
                char buffer[7];
                sprintf(buffer, "\\u%04X", ch);
                PUTS(c, buffer, 6);
            } else {
                PUTC(c, s[i]);
            }
        }
    }
    PUTC(c, '\"');
}


static void lept_stringify_value(lept_context* c, const lept_value* v) {
    size_t i;
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
        c->top -= 32 - sprintf(lept_context_push(c, 32), "%.17g", v->u.n);
        break;
    case LEPT_STRING:
        lept_stringify_string(c, v->u.s.s, v->u.s.len);
        break;
    case LEPT_ARRAY:
        PUTC(c, '[');
        for (i = 0; i < v->u.a.size; i++) {
            if (i > 0) {
                PUTC(c, ',');
            }
            lept_stringify_value(c, &v->u.a.e[i]);
        }
        PUTC(c, ']');
        break;
    case LEPT_OBJECT:
        PUTC(c, '{');
        for (i = 0; i < v->u.a.size; i++) {
            if (i > 0) {
                PUTC(c, ',');
            }
            lept_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
            PUTC(c, ':');
            lept_stringify_value(c, &v->u.o.m[i].v);
        }
        PUTC(c, '}');
        break;
    default:
        assert(0 && "invalid type");
    }
}

char* lept_stringify(const lept_value* v, size_t* length) {
    assert(v != NULL);
    lept_context c;
    c.stack = (char*)malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length) {
        *length = c.top;
    }
    PUTC(&c, '\0');
    return c.stack;
}


lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char*)malloc(len + 1); // for null-terminator
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}

void lept_free(lept_value* v) {
    assert(v != NULL);
    size_t i;
    switch (v->type) {
    case LEPT_STRING:
        free(v->u.s.s);
        break;
    case LEPT_ARRAY:
        for (i = 0; i < v->u.a.size; i++) {
            lept_free(&v->u.a.e[i]);
        }
        free(v->u.a.e);
        break;
    case LEPT_OBJECT:
        for (i = 0; i < v->u.o.size; i++) {
            free(v->u.o.m[i].k);
            lept_free(&v->u.o.m[i].v);
        }
        free(v->u.o.m);
        break;
    default:
        break;
    }
    v->type = LEPT_NULL;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
    assert(v != NULL);
    lept_free(v);
    if (b) {
        v->type = LEPT_TRUE;
    } else {
        v->type = LEPT_FALSE;
    }
}

void lept_set_number(lept_value* v, double n) {
    assert(v != NULL);
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return v->u.a.e + index;
}

size_t lept_get_object_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

