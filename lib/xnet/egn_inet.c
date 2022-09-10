#include "egn_inet.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#if defined (WIN32)
int inet_pton_v4(const char* src, void* dst) {
    const int kIpv4AddressSize = 4;
    int found = 0;
    const char* src_pos = src;
    unsigned char result[kIpv4AddressSize];
    memset(result,0,sizeof(result));
    while (*src_pos != '\0') {
        // strtol won't treat whitespace characters in the begining as an error,
        // so check to ensure this is started with digit before passing to strtol.
        if (!isdigit(*src_pos)) {
            return 0;
        }
        char* end_pos;
        long value = strtol(src_pos, &end_pos, 10);
        if (value < 0 || value > 255 || src_pos == end_pos) {
            return 0;
        }
        ++found;
        if (found > kIpv4AddressSize) {
            return 0;
        }
        result[found - 1] =(value);
        src_pos = end_pos;
        if (*src_pos == '.') {
            // There's more.
            ++src_pos;
        } else if (*src_pos != '\0') {
            // If it's neither '.' nor '\0' then return fail.
            return 0;
        }
    }
    if (found != kIpv4AddressSize) {
        return 0;
    }
    memcpy(dst, result, sizeof(result));
    return 1;
}
const char* inet_ntop_v4(const void* src, char* dst, socklen_t size) {
    if (size < INET_ADDRSTRLEN) {
        return NULL;
    }
    const struct in_addr* as_in_addr =src;
    snprintf(dst, size, "%d.%d.%d.%d",
             as_in_addr->S_un.S_un_b.s_b1,
             as_in_addr->S_un.S_un_b.s_b2,
             as_in_addr->S_un.S_un_b.s_b3,
             as_in_addr->S_un.S_un_b.s_b4);
    return dst;
}

// Implementation of inet_ntop (create a printable representation of an
// ip address). XP doesn't have its own inet_ntop, and
// WSAAddressToString requires both IPv6 to be  installed and for Winsock
// to be initialized.

const char* inet_ntop(int af, const void *src,
                      char* dst, socklen_t size) {
    if (!src || !dst) {
        return NULL;
    }
    switch (af) {
        case AF_INET: {
            return inet_ntop_v4(src, dst, size);
        }
    }
    return NULL;
}

// As above, but for inet_pton. Implements inet_pton for v4 and v6.
// Note that our inet_ntop will output normal 'dotted' v4 addresses only.
int inet_pton(int af, const char* src, void* dst) {
    if (!src || !dst) {
        return 0;
    }
    if (af == AF_INET) {
        return inet_pton_v4(src, dst);
    }
    return -1;
}
#endif
