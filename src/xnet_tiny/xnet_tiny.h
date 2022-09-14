#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>
#include <string.h>

#define XNET_CFG_NETIF_IP       {192,168,56,2}

#define XNET_CFG_PACKET_MAX_SIZE 1514 // 最大数据包字节数
#define XNET_IPV4_ADDR_SIZE      4    // IP地址长度
#define XNET_MAC_ADDR_SIZE       6    // MAC地址长度

/**
 * 禁用编译器字节填充
 */
#pragma pack(1)

/**
 * 以太网数据帧格式: RFC894
 */
typedef struct _xeth_head_t {
    uint8_t dst[XNET_MAC_ADDR_SIZE]; // 目标mac地址
    uint8_t src[XNET_MAC_ADDR_SIZE]; // 源mac地址
    uint16_t type;                   // 协议类型
} xeth_head_t;

#define XARP_HW_ETH     0x1
#define XARP_REQUEST    0x1
#define XARP_REPLY      0x2

/**
 * ARP报文
 */
typedef struct _xarp_packet_t {
    uint16_t hw_type, pt_type;
    uint8_t hw_size, pt_size;
    uint16_t opcode;
    uint8_t sender_mac[XNET_MAC_ADDR_SIZE];
    uint8_t sender_ip[XNET_IPV4_ADDR_SIZE];
    uint8_t target_mac[XNET_MAC_ADDR_SIZE];
    uint8_t target_ip[XNET_IPV4_ADDR_SIZE];
} xarp_packet_t;

#pragma pack(0)

/**
 * 以太网协议类型枚举
 */
typedef enum _xeth_type_t {
    XETH_TYPE_ARP = 0x0806,
    XETH_TYPE_IP = 0x0800,
} xeth_type_t;

/**
 * 错误码
 */
typedef enum _xnet_err_t {
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1
} xnet_err_t;

/**
 * 数据包定义
 */
typedef struct _xnet_packet_t {
    uint16_t size;                              // 数据包有效数据的大小
    uint8_t* data;                              // 数据包数据的起始地址
    uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];  // 负载数组
} xnet_packet_t;

xnet_packet_t* xnet_alloc_for_send(uint16_t size);
xnet_packet_t* xnet_alloc_for_read(uint16_t size);

void xnet_init(void);
void xnet_poll(void);

/**
 * ip地址
 */
typedef union _xip_addr_t {
    uint8_t array[XNET_IPV4_ADDR_SIZE];
    uint32_t addr;
} xip_addr_t;

#define XARP_ENTRY_FREE 0
#define XARP_ENTRY_OK 0

/**
 * arp结构体
 */
typedef struct _xarp_entry_t {
    xip_addr_t ip_addr;
    uint8_t mac_addr[XNET_MAC_ADDR_SIZE];
    uint8_t state;
    uint16_t ttl;
    uint8_t retry_cnt;
} xarp_entry_t;

void xarp_init(void);
int xarp_make_request(const xip_addr_t* ip_addr);
void xarp_in(xnet_packet_t* packet);

xnet_err_t xnet_driver_open(uint8_t* mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t* packet);
xnet_err_t xnet_driver_read(xnet_packet_t** packet);

#endif // XNET_TINY_H