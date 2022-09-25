#include "xnet_tiny.h"

#define min(a, b) ((a) > (b) ? (b) : (a))
#define swap_order16(v) (((v) & 0xFF) << 8 | ((v) >> 8) & 0xFF)
#define xip_addr_equal_buf(addr, buf) (memcmp((addr)->array, (buf), XNET_IPV4_ADDR_SIZE) == 0)
#define xip_addr_equal(addr1, addr2) ((addr1)->addr == (addr2)->addr)
#define xip_addr_from_buf(dst, buf)          ((dst)->addr = *(uint32_t *)(buf))

static const xip_addr_t netif_ip = XNET_CFG_NETIF_IP;
static const uint8_t eth_broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];
static xnet_packet_t tx_packet, rx_packet;
static xarp_entry_t xarp_entry;
static xnet_time_t xarp_timer;

xnet_packet_t* xnet_alloc_for_send(uint16_t size) {
    tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - size;
    tx_packet.size = size;
    return &tx_packet;
}

xnet_packet_t* xnet_alloc_for_read(uint16_t size) {
    rx_packet.data = rx_packet.payload;
    rx_packet.size = size;
    return &rx_packet;
}

/**
 * 添加packet头部
 * @param packet
 * @param size
 */
static void add_header(xnet_packet_t* packet, uint16_t size) {
    packet->data -= size;
    packet->size += size;
}

/**
 * 移除packet头部
 * @param packet
 * @param size
 */
static void remove_header(xnet_packet_t* packet, uint16_t size) {
    packet->data += size;
    packet->size -= size;
}

/**
 * 截断packet
 * @param packet
 * @param size
 */
static void truncate_packet(xnet_packet_t* packet, uint16_t size) {
    packet->size = min(packet->size, size);
}

/**
 * 以太网初始化
 * @return
 */
static xnet_err_t eth_init(void) {
    xnet_err_t err = xnet_driver_open(netif_mac);
    if (err < 0) return err;
    return xarp_make_request(&netif_ip);
}

/**
 * 以太网给指定mac地址发送数据
 * @param p
 * @param mac_addr
 * @param packet
 * @return
 */
static xnet_err_t eth_out_mac(xnet_protocol_t type, const uint8_t* mac_addr, xnet_packet_t* packet) {
    xeth_head_t* eth_head;
    add_header(packet, sizeof(xeth_head_t));
    eth_head = (xeth_head_t*) packet->data;
    memcpy(eth_head->dst, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(eth_head->src, netif_mac, XNET_MAC_ADDR_SIZE);
    eth_head->type = swap_order16(type);
    return xnet_driver_send(packet);
}

/**
 * 以太网给指定IP地址发送数据
 * @param dst_ip
 * @param packet
 * @return
 */
static xnet_err_t eth_out_ip(xip_addr_t* dst_ip, xnet_packet_t* packet) {
    xnet_err_t err;
    uint8_t* mac_addr;
    if ((err = xarp_resolve(dst_ip, &mac_addr)) == XNET_ERR_OK) {
        return eth_out_mac(XNET_PROTOCOL_IP, mac_addr, packet);
    }
    return err;
}

/**
 * 以太网接收数据
 * @param packet
 */
static void eth_in(xnet_packet_t* packet) {
    xeth_head_t* eth_head;
    if (packet->size <= sizeof(xeth_head_t)) return;
    eth_head = (xeth_head_t*) packet->data;
    switch (swap_order16(eth_head->type)) {
        case XNET_PROTOCOL_ARP:
            remove_header(packet, sizeof(xeth_head_t));
            xarp_in(packet);
            break;
        case XNET_PROTOCOL_IP:
            remove_header(packet, sizeof(xeth_head_t));
            xip_in(packet);
            break;
    }
}

/**
 * 从以太网获取数据
 */
static void eth_poll(void) {
    xnet_packet_t* packet;
    if (xnet_driver_read(&packet) == XNET_ERR_OK) {
        eth_in(packet);
    }
}

/**
 * 初始化
 */
void xnet_init(void) {
    eth_init();
    xarp_init();
    xip_init();
    xicmp_init();
}

/**
 * 拉取数据
 */
void xnet_poll(void) {
    eth_poll();
    xarp_poll();
}

int xarp_check_state(xnet_time_t* time, uint32_t timeout) {
    xnet_time_t now = xsys_cur_time();
    if (timeout == 0) {
        *time = now;
        return 0;
    } else if (now - *time >= timeout) {
        *time = now;
        return 1;
    }
    return 0;
}

/**
 * arp注册表初始化
 */
void xarp_init(void) {
    xarp_entry.state = XARP_ENTRY_FREE;
    xarp_check_state(&xarp_timer, 0);
}

/**
 * 无回报ARP包
 * @param ip_addr
 * @return
 */
int xarp_make_request(const xip_addr_t* ip_addr) {
    xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* arp_packet = (xarp_packet_t*)packet->data;

    arp_packet->hw_type = swap_order16(XARP_HW_ETH);
    arp_packet->pt_type = swap_order16(XNET_PROTOCOL_IP);
    arp_packet->hw_size = XNET_MAC_ADDR_SIZE;
    arp_packet->pt_size = XNET_IPV4_ADDR_SIZE;
    arp_packet->opcode = swap_order16(XARP_REQUEST);
    memcpy(arp_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->sender_ip, netif_ip.array, XNET_IPV4_ADDR_SIZE);
    memset(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->target_ip, ip_addr->array, XNET_IPV4_ADDR_SIZE);
    return eth_out_mac(XNET_PROTOCOL_ARP, eth_broadcast, packet);
}

/**
 * 解析IP地址对应的MAC地址
 * @param xip_addr
 * @param mac_addr TODO 视频中mac_addr使用的是二级指针，需要后续调试确认
 * @return
 */
xnet_err_t xarp_resolve(const xip_addr_t* xip_addr, uint8_t** mac_addr) {
    if (xarp_entry.state == XARP_ENTRY_OK && xip_addr_equal(xip_addr, &xarp_entry.ip_addr)) {
        *mac_addr = xarp_entry.mac_addr;
        return XNET_ERR_OK;
    }
    xarp_make_request(xip_addr);
    return XNET_ERR_NONE;
}

/**
 * ARP响应包
 * @param arp_packet
 * @return
 */
xnet_err_t xarp_make_response(xarp_packet_t* xarp_packet) {
    xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* response_packet = (xarp_packet_t*)packet->data;

    response_packet->hw_type = swap_order16(XARP_HW_ETH);
    response_packet->pt_type = swap_order16(XNET_PROTOCOL_IP);
    response_packet->hw_size = XNET_MAC_ADDR_SIZE;
    response_packet->pt_size = XNET_IPV4_ADDR_SIZE;
    response_packet->opcode = swap_order16(XARP_REPLY);
    memcpy(response_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->sender_ip, netif_ip.array, XNET_IPV4_ADDR_SIZE);
    memcpy(response_packet->target_mac, xarp_packet->sender_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->target_ip, xarp_packet->sender_ip, XNET_IPV4_ADDR_SIZE);
    return eth_out_mac(XNET_PROTOCOL_ARP, xarp_packet->sender_mac, packet);
}

/**
 * 更新ARP注册表
 * @param src_ip
 * @param src_mac
 */
static void update_arp_entry(uint8_t* src_ip, uint8_t* src_mac) {
    memcpy(xarp_entry.ip_addr.array, src_ip, XNET_IPV4_ADDR_SIZE);
    memcpy(xarp_entry.mac_addr, src_mac, XNET_MAC_ADDR_SIZE);
    xarp_entry.state = XARP_ENTRY_OK;
    xarp_entry.ttl = XARP_CFG_ENTRY_OK_TTL;
    xarp_entry.retry_cnt = XARP_CFG_MAX_RETRIES;
}

/**
 * ARP协议输入
 * @param packet
 */
void xarp_in(xnet_packet_t *packet) {
    if (packet->size < sizeof(xarp_packet_t)) {
        return;
    }
    xarp_packet_t* xarp_packet = (xarp_packet_t*) packet->data;
    uint16_t opcode = swap_order16(xarp_packet->opcode);
    if (swap_order16(xarp_packet->hw_type) != XARP_HW_ETH ||
        xarp_packet->hw_size != XNET_MAC_ADDR_SIZE ||
        swap_order16(xarp_packet->pt_type) != XNET_PROTOCOL_IP ||
        xarp_packet->pt_size != XNET_IPV4_ADDR_SIZE ||
            (opcode != XARP_REQUEST && opcode != XARP_REPLY)) {
        return;
    }
    if (!xip_addr_equal_buf(&netif_ip, xarp_packet->target_ip)) {
        return;
    }
    switch (opcode) {
        case XARP_REQUEST:
            xarp_make_response(xarp_packet);
            update_arp_entry(xarp_packet->sender_ip, xarp_packet->sender_mac);
            break;
        case XARP_REPLY:
            update_arp_entry(xarp_packet->sender_ip, xarp_packet->sender_mac);
            break;
    }
}

/**
 * 查询ARP注册表
 */
void xarp_poll(void) {
    if (xarp_check_state(&xarp_timer, XARP_TIMER_PERIOD)) {
        switch (xarp_entry.state) {
            case XARP_ENTRY_OK:
                if (--xarp_entry.ttl == 0) {
                    xarp_make_request(&xarp_entry.ip_addr);
                    xarp_entry.state = XARP_ENTRY_PENDING;
                    xarp_entry.ttl = XARP_CFG_ENTRY_PENDING_TTL;
                }
                break;
            case XARP_ENTRY_PENDING:
                if (--xarp_entry.ttl == 0) {
                    if (xarp_entry.retry_cnt-- == 0) {
                        xarp_entry.state = XARP_ENTRY_FREE;
                    } else {
                        xarp_make_request(&xarp_entry.ip_addr);
                        xarp_entry.state = XARP_ENTRY_PENDING;
                        xarp_entry.ttl = XARP_CFG_ENTRY_PENDING_TTL;
                    }
                }
                break;
        }
    }
}

/**
 * 校验和计算
 * @param buf 校验数据区的起始地址
 * @param len 数据区的长度，以字节为单位
 * @param pre_sum 累加的之前的值，用于多次调用checksum对不同的的数据区计算出一个校验和
 * @param complement 是否对累加和的结果进行取反
 * @return 校验和结果
 */
static uint16_t checksum16(uint16_t* buf, uint16_t len, uint16_t pre_sum, int complement) {
    uint32_t checksum = pre_sum;
    uint16_t high;

    while (len > 1) {
        checksum += *buf++;
        len -= 2;
    }
    if (len > 0) {
        checksum += *(uint8_t *)buf;
    }

    // 注意，这里要不断累加。不然结果在某些情况下计算不正确
    while ((high = checksum >> 16) != 0) {
        checksum = high + (checksum & 0xffff);
    }
    return complement ? (uint16_t)~checksum : (uint16_t)checksum;
}

/**
 * IP协议初始化
 */
void xip_init(void) {

}

/**
 * IP协议输入处理
 * @param packet
 */
void xip_in(xnet_packet_t* packet) {
    xip_packet_t* xip_packet = (xip_packet_t*) packet->data;
    if (xip_packet->version != XNET_VERSION_IPV4) {
        return;
    }
    uint16_t head_size = xip_packet->head_len * 4;
    uint16_t total_size = swap_order16(xip_packet->total_len);
    if (head_size < sizeof(xip_packet) || total_size < head_size) {
        return;
    }
    uint16_t pre_checksum = xip_packet->head_checksum;
    xip_packet->head_checksum = 0;
    if (pre_checksum != checksum16((uint16_t *) xip_packet, head_size, 0, 1)) {
        return;
    }
    if (!xip_addr_equal_buf(&netif_ip, xip_packet->dst_ip)) {
        return;
    }

    xip_addr_t src_ip;
    xip_addr_from_buf(&src_ip, xip_packet->src_ip);
    switch (xip_packet->protocol) {
        case XNET_PROTOCOL_ICMP:
            remove_header(packet, head_size);
            xicmp_in(&src_ip, packet);
            break;
        default:
            break;
    }
}

/**
 * IP协议输出处理
 * @param protocol
 * @param dst_ip
 * @param packet
 * @return
 */
xnet_err_t xip_out(xnet_protocol_t protocol, xip_addr_t* dst_ip, xnet_packet_t* packet) {
    static uint32_t xip_packet_id = 0;
    add_header(packet, sizeof(xip_packet_t));
    xip_packet_t* xip_packet = (xip_packet_t*) packet->data;
    xip_packet->version = XNET_VERSION_IPV4;
    xip_packet->head_len = sizeof(xip_packet_t) / 4;
    xip_packet->service_type = 0;
    xip_packet->total_len = swap_order16(packet->size);
    xip_packet->id = swap_order16(xip_packet_id);
    xip_packet_id++;
    xip_packet->flags_fragment = 0;
    xip_packet->ttl = XNET_IP_DEFAULT_TTL;
    xip_packet->protocol = protocol;
    memcpy(xip_packet->src_ip, &netif_ip.array, XNET_IPV4_ADDR_SIZE);
    memcpy(xip_packet->dst_ip, dst_ip->array, XNET_IPV4_ADDR_SIZE);
    xip_packet->head_checksum = 0;
    xip_packet->head_checksum = checksum16((uint16_t *) xip_packet, sizeof(xip_packet_t), 0, 1);
    return eth_out_ip(dst_ip, packet);
}

/**
 * ICMP协议初始化
 */
void xicmp_init() {

}

/**
 * 回复ICMP请求
 * @param xicmp_packet
 * @param src_ip
 * @param packet
 * @return
 */
static xnet_err_t reply_icmp_request(xicmp_packet_t* xicmp_packet, xip_addr_t* src_ip, xnet_packet_t* packet) {
    xnet_packet_t* tx = xnet_alloc_for_send(packet->size);
    xicmp_packet_t* xicmp_reply_packet = (xicmp_packet_t*)tx->data;
    xicmp_reply_packet->type = XICMP_CODE_ECHO_REPLY;
    xicmp_reply_packet->code = 0;
    xicmp_reply_packet->id = xicmp_packet->id;
    xicmp_reply_packet->seq = xicmp_packet->seq;
    xicmp_reply_packet->checksum = 0;
    memcpy((uint8_t*) xicmp_reply_packet + sizeof(xicmp_packet_t), (uint8_t*) xicmp_packet + sizeof(xicmp_packet_t),
           packet->size - sizeof(xicmp_packet_t));
    xicmp_reply_packet->checksum = checksum16((uint16_t*) xicmp_reply_packet, tx->size, 0, 1);
    return xip_out(XNET_PROTOCOL_ICMP, src_ip, tx);
}

/**
 * ICMP协议输入处理
 * @param src_ip
 * @param packet
 */
void xicmp_in(xip_addr_t* src_ip, xnet_packet_t *packet) {
    xicmp_packet_t* xicmp_packet = (xicmp_packet_t*)packet->data;
    if (packet->size >= sizeof(xicmp_packet_t) && xicmp_packet->type == XICMP_CODE_ECHO_REQUEST) {
        reply_icmp_request(xicmp_packet, src_ip, packet);
    }
}