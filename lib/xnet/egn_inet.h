#ifndef XNET_EGN_INET_H
#define XNET_EGN_INET_H

#pragma once
#if defined (WIN32)

#include <winsock2.h>
#include<Ws2tcpip.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

int inet_pton(int af, const char *src, void *dst);

#else
#include <netinet/in.h>
#include<arpa/inet.h>
#endif

#endif //XNET_EGN_INET_H