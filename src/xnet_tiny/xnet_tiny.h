#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>

#define  XNET_CFG_PACKET_MAX_SIZE 1516 // 收发数据包的最大大小

typedef struct _xnet_packet_t {
    uint16_t size;                              // 数据包有效数据的大小
    uint8_t* data;                              // 数据包数据的起始地址
    uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];  // 负载数组
} xnet_packet_t;

xnet_packet_t* xnet_alloc_for_send(uint16_t size);
xnet_packet_t* xnet_alloc_for_read(uint16_t size);

void xnet_init(void);
void xnet_poll(void);

#endif // XNET_TINY_H