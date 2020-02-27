#include <string.h>
#include <ctype.h>
#include "mysql.h"

#ifndef __cplusplus
#include <stdbool.h>
#endif

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

#define HEX_LEN 16
#define B64U_LEN 11

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
	char *str = malloc(sizeof(char) * 3*((len+3)/4));

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

static char* php_bin2hex(const unsigned char *old, const size_t oldlen) {
    char *result = (char*) malloc(oldlen * 2 + 1);
    size_t i, j;

    for (i = j = 0; i < oldlen; i++) {
        result[j++] = hexconvtab[old[i] >> 4];
        result[j++] = hexconvtab[old[i] & 15];
    }
    result[j] = '\0';
    return result;
}

/*
 * The memmem() function finds the start of the first occurrence of the
 * substring 'needle' of length 'nlen' in the memory area 'haystack' of
 * length 'hlen'.
 *
 * The return value is a pointer to the beginning of the sub-string, or
 * NULL if the substring is not found.
 */
// void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
// {
//     int needle_first;
//     const void *p = haystack;
//     size_t plen = hlen;

//     if (!nlen)
//         return NULL;

//     needle_first = *(unsigned char *)needle;

//     while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
//     {
//         if (!memcmp(p, needle, nlen))
//             return (void *)p;

//         p++;
//         plen = hlen - (p - haystack);
//     }

//     return NULL;
// }

char *c_get_bid2s(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, unsigned char *is_null, unsigned char *error) {
    char *bid2s = malloc(sizeof(char) * args->lengths[0]);
    char *bs = args->args[0];
    size_t len = args->lengths[0];
    size_t j = 0;
    size_t i = 0;

    while (i < args->lengths[0]) {
        char b = bs[i];

        if (b == '0' &&
            (i == 0 || !isalnum(bs[i-1])) &&
            i+1+HEX_LEN < len && bs[i+1] == 'x' && is_hex(bs+i+2, HEX_LEN) &&
            (i+1+HEX_LEN+1 >= len || !isalnum(bs[i+1+HEX_LEN+1]))) {

            i += 2;
            // if (memmem(bid2s, j, bs+i, HEX_LEN) == NULL) {
            for (int k = 0; k < HEX_LEN; k++) {
                bid2s[j++] = tolower(bs[i++]);
            }
            bid2s[j++] = ' ';
            // } else {
            //     i += HEX_LEN;
            // }
        } else if (is_b64u_char(b) &&
            (i == 0 || !is_b64u_char(bs[i-1])) &&
            i+B64U_LEN-1 < len && is_b64u(bs+i, B64U_LEN) &&
            (i+B64U_LEN >= len || !is_b64u_char(bs[i+B64U_LEN]))) {

            char *hex = php_bin2hex(b64decode_mod(base64_dtable, bs+i, B64U_LEN), 8);
            // if (memmem(bid2s, j, hex, HEX_LEN) == NULL) {
            for (char *t = hex; *t != '\0'; t++) {
                bid2s[j++] = *t;
            }
            bid2s[j++] = ' ';
            // }
            i += B64U_LEN;
        }

        i++;
    }

    if (j) {
        *length = j-1;
    } else {
        *length = 0;
    }
	return bid2s;
}
