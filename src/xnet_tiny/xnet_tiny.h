#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>
#include <string.h>

#define XNET_CFG_NETIF_IP       {192,168,56,2}

#define XNET_CFG_PACKET_MAX_SIZE 1514 // 最大数据包字节数
#define XNET_IPV4_ADDR_SIZE      4    // IP地址长度
#define XNET_MAC_ADDR_SIZE       6    // MAC地址长度

#define XARP_CFG_ENTRY_OK_TTL         5    // ARP注册表过期时间
#define XARP_CFG_ENTRY_PENDING_TTL    5    // ARP查询超时时间
#define XARP_CFG_MAX_RETRIES          3    // ARP查询重试次数

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
 * 协议类型枚举
 */
typedef enum _xnet_protocol_t {
    XNET_PROTOCOL_ARP = 0x0806,     // ARP协议
    XNET_PROTOCOL_IP = 0x0800,      // IP协议
    XNET_PROTOCOL_ICMP = 1,         // ICMP协议
    XNET_PROTOCOL_UDP = 17,         // UDP协议
    XNET_PROTOCOL_TCP = 6,          // TCP协议
} xnet_protocol_t;

/**
 * 错误码
 */
typedef enum _xnet_err_t {
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1,
    XNET_ERR_NONE = -2,
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

#define XARP_ENTRY_FREE     0
#define XARP_ENTRY_OK       1
#define XARP_ENTRY_PENDING  2
#define XARP_TIMER_PERIOD   1

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

typedef uint32_t xnet_time_t;
const xnet_time_t xsys_cur_time(void);

#define XNET_VERSION_IPV4   4

/**
 * 禁用编译器字节填充
 */
#pragma pack(1)
/**
 * IP协议包
 */
typedef struct _xip_packet_t {
    uint8_t head_len : 4;                   // 首部长,冒号后面为位域,占用4字节,同时单位为4字节,即真实长度=head_len*4
    uint8_t version : 4;                    // 版本号
    uint8_t service_type;                   // 服务类型
    uint16_t total_len;                     // 总长度
    uint16_t id;                            // 包ID
    uint16_t flags_fragment;                // 标志位
    uint8_t ttl;                            // 生存时间
    uint8_t protocol;                       // 上层协议类型
    uint16_t head_checksum;                 // 校验和
    uint8_t src_ip[XNET_IPV4_ADDR_SIZE];    // 源ip地址
    uint8_t dst_ip[XNET_IPV4_ADDR_SIZE];    // 目标ip地址
} xip_packet_t;
#pragma pack(0)

/**
 * IP协议相关
 */
#define XNET_IP_DEFAULT_TTL 64
void xip_init(void);
void xip_in(xnet_packet_t* packet);
xnet_err_t xip_out(xnet_protocol_t protocol, xip_addr_t* dst_ip, xnet_packet_t* packet);

/**
 * ARP协议相关函数
 */
void xarp_init(void);
int xarp_make_request(const xip_addr_t* ip_addr);
void xarp_in(xnet_packet_t* packet);
void xarp_poll(void);
xnet_err_t xarp_resolve(const xip_addr_t* xip_addr, uint8_t** mac_addr);

/**
 * 禁用编译器字节填充
 */
#pragma pack(1)
/**
 * ICMP协议包
 */
typedef struct _xicmp_packet_t {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} xicmp_packet_t;
#pragma pack(0)

#define XICMP_CODE_ECHO_REQUEST 8
#define XICMP_CODE_ECHO_REPLY   0

void xicmp_init();
void xicmp_in(xip_addr_t* src_ip, xnet_packet_t* packet);

xnet_err_t xnet_driver_open(uint8_t* mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t* packet);
xnet_err_t xnet_driver_read(xnet_packet_t** packet);

#endif // XNET_TINY_H