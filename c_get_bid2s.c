#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>

#include "mysql.h"

#define HEX_LEN 16
#define B64U_LEN 11

bool c_get_bid2s_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *c_get_bid2s(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, unsigned char *is_null, unsigned char *error);

bool c_get_bid2s_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
	if (args->arg_count != 1) {
		strcpy(message, "`c_get_bid2s`() requires 1 parameter: the string to have bid2s collected from");
		return 1;
	}

	args->arg_type[0] = STRING_RESULT;

	initid->maybe_null = 0; // cannot return null
    initid->max_length = 32;

	return 0;
}

bool is_hex(char *s, int len) {
    for (int i = 0; i < len; i++) {
        if (!isxdigit(s[i])) {
            return 0;
        }
    }

    return 1;
}

bool is_b64u_char(char c) {
    return c == '-' || c == '_' || isalnum(c);
}

bool is_b64u(char *s, int len) {
    for (int i = 0; i < len; i++) {
        if (is_b64u_char(s[i])) {
            continue;
        }
        return 0;
    }

    return 1;
}

const unsigned char base64_dtable[256] = {
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 62  , 0x80, 62  , 0x80, 63  ,
	52  , 53  , 54  , 55  , 56  , 57  , 58  , 59  , 60  , 61  , 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0   , 1   , 2   , 3   , 4   , 5   , 6   , 7   , 8   , 9   , 10  , 11  , 12  , 13  , 14  ,
	15  , 16  , 17  , 18  , 19  , 20  , 21  , 22  , 23  , 24  , 25  , 0x80, 0x80, 0x80, 0x80, 63  ,
	0x80, 26  , 27  , 28  , 29  , 30  , 31  , 32  , 33  , 34  , 35  , 36  , 37  , 38  , 39  , 40  ,
	41  , 42  , 43  , 44  , 45  , 46  , 47  , 48  , 49  , 50  , 51  , 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
};

char *b64decode_mod(const unsigned char *table, const void* data, const size_t len) {
	unsigned char* p = (unsigned char*)data;
	int pad = len > 0 && (len % 4 || p[len - 1] == '=');
	const size_t L = ((len + 3) / 4 - pad) * 4;
	char *str = (char *)malloc(sizeof(char) * 3*((len+3)/4));

	int j = 0;
	for (size_t i = 0; i < L; i += 4) {
		int n = table[p[i]] << 18 | table[p[i + 1]] << 12 | table[p[i + 2]] << 6 | table[p[i + 3]];
		str[j++] = n >> 16;
		str[j++] = n >> 8 & 0xFF;
		str[j++] = n & 0xFF;
	}
	if (pad) {
		int n = table[p[L]] << 18 | table[p[L + 1]] << 12;
		str[j++] = n >> 16;

		if (len > L + 2 && p[L + 2] != '=')	{
			n |= table[p[L + 2]] << 6;
			str[j++] = n >> 8 & 0xFF;
		}
	}

	str[j] = '\0';
	return str;
}

static char hexconvtab[] = "0123456789abcdef";

int bin2hex(char *ret, const unsigned char *old, const size_t oldlen) {
    size_t i, j;

    for (i = j = 0; i < oldlen; i++) {
        ret[j++] = hexconvtab[old[i] >> 4];
        ret[j++] = hexconvtab[old[i] & 15];
    }
    ret[j] = '\0';
    return 0;
}

typedef struct node {
   unsigned long l;
   struct node *next;
} node;

typedef struct set{
    node **nodes;
    size_t cap;
} set;

set *new_set(size_t cap) {
    set *s = malloc(sizeof(set));

    s->nodes = malloc(sizeof(node) * cap);
    for (int i = 0; i < cap; i++) {
        s->nodes[i] = NULL;
    }
    s->cap = cap;

    return s;
}

size_t set_get_index(set *s, unsigned long l) {
    return l % s->cap;
}

node *new_node(unsigned long l) {
    node *n = malloc(sizeof(node));
    n->l = l;
    n->next = NULL;

    return n;
}

int set_add(set *s, unsigned long l) {
    size_t i = set_get_index(s, l);

    if (s->nodes[i] == NULL) {
        s->nodes[i] = new_node(l);
        return 0;
    }

    node *curr = s->nodes[i];
    if (curr->l == l) {
        return 1;
    }
    while (curr->next != NULL) {
        curr = curr->next;
        if (curr->l == l) {
            return 1;
        }
    }
    curr->next = new_node(l);

    return 0;
}

int free_set(set *s) {
    for (size_t i = 0; i < s->cap; i++) {
        node *n = s->nodes[i];
        while (n != NULL) {
            node *n2 = n;
            n = n->next;
            free(n2);
        }
    }

    free(s);
    return 0;
}

char *c_get_bid2s(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, unsigned char *is_null, unsigned char *error) {
    char *bid2s = (char *)malloc(sizeof(char) * (int)ceil((float)args->lengths[0]/B64U_LEN*HEX_LEN));
    char *bs = args->args[0];
    size_t len = args->lengths[0];
    size_t j = 0;
    size_t i = 0;

    if (len<B64U_LEN) {
        *length = 0;
        return "";
    }

    bool found = false;
    char *hex_bid2 = (char *)malloc(sizeof(char) * HEX_LEN+1);

    set *s = new_set(len/(B64U_LEN+1)+1);

    while (i < args->lengths[0]) {
        char b = bs[i];

        if (b == '0' &&
            (i == 0 || !isalnum(bs[i-1])) &&
            i+1+HEX_LEN < len && bs[i+1] == 'x' && is_hex(bs+i+2, HEX_LEN) &&
            (i+1+HEX_LEN+1 >= len || !isalnum(bs[i+1+HEX_LEN+1]))) {

            i += 2;
            strncpy(hex_bid2, bs+i, HEX_LEN);
            hex_bid2[HEX_LEN] = '\0';
            i += HEX_LEN;

            found = true;
        } else if (is_b64u_char(b) &&
            (i == 0 || !is_b64u_char(bs[i-1])) &&
            i+B64U_LEN-1 < len && is_b64u(bs+i, B64U_LEN) &&
            (i+B64U_LEN >= len || !is_b64u_char(bs[i+B64U_LEN]))) {

            char *bytes = b64decode_mod(base64_dtable, bs+i, B64U_LEN);
            bin2hex(hex_bid2, bytes, 8);
            free(bytes);
            i += B64U_LEN;

            found = true;
        }

        if (found) {
            unsigned long l = strtoul(hex_bid2, NULL, 16);
            if (!set_add(s, l)) {
                for (char *t = hex_bid2; *t != '\0'; t++) {
                    bid2s[j++] = *t;
                }
                bid2s[j++] = ' ';;
            }
            found = false;
        }

        i++;
    }

    free_set(s);

    if (j) {
        *length = j-1;
    } else {
        *length = 0;
    }
	return bid2s;
}
