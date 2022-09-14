#include "xnet_tiny.h"

#define min(a, b) ((a) > (b) ? (b) : (a))
#define swap_order16(v) (((v) & 0xFF) << 8 | ((v) >> 8) & 0xFF)
#define xip_addr_equal_buf(addr, buf) (memcmp((addr)->array, (buf), XNET_IPV4_ADDR_SIZE) == 0)

static const xip_addr_t netif_ip = XNET_CFG_NETIF_IP;
static const uint8_t eth_broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];
static xnet_packet_t tx_packet, rx_packet;
static xarp_entry_t xarp_entry;

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
static xnet_err_t eth_out(xeth_type_t type, const uint8_t* mac_addr, xnet_packet_t* packet) {
    xeth_head_t* eth_head;
    add_header(packet, sizeof(xeth_head_t));
    eth_head = (xeth_head_t*) packet->data;
    memcpy(eth_head->dst, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(eth_head->src, netif_mac, XNET_MAC_ADDR_SIZE);
    eth_head->type = swap_order16(type);
    return xnet_driver_send(packet);
}

/**
 * 以太网接收数据
 * @param packet
 */
static void eth_in(xnet_packet_t* packet) {
    xeth_head_t* eth_head;
    if (packet->size <= sizeof(xeth_head_t)) return;
    eth_head = packet->data;
    switch (swap_order16(eth_head->type)) {
        case XETH_TYPE_ARP:
            remove_header(packet, sizeof(xeth_head_t));
            xarp_in(packet);
            break;
        case XETH_TYPE_IP:
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
}

/**
 * 拉取数据
 */
void xnet_poll(void) {
    eth_poll();
}

/**
 * arp注册表初始化
 */
void xarp_init(void) {
    xarp_entry.state = XARP_ENTRY_FREE;
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
    arp_packet->pt_type = swap_order16(XETH_TYPE_IP);
    arp_packet->hw_size = XNET_MAC_ADDR_SIZE;
    arp_packet->pt_size = XNET_IPV4_ADDR_SIZE;
    arp_packet->opcode = swap_order16(XARP_REQUEST);
    memcpy(arp_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->sender_ip, netif_ip.array, XNET_IPV4_ADDR_SIZE);
    memset(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->target_ip, ip_addr->array, XNET_IPV4_ADDR_SIZE);
    return eth_out(XETH_TYPE_ARP, eth_broadcast, packet);
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
    response_packet->pt_type = swap_order16(XETH_TYPE_IP);
    response_packet->hw_size = XNET_MAC_ADDR_SIZE;
    response_packet->pt_size = XNET_IPV4_ADDR_SIZE;
    response_packet->opcode = swap_order16(XARP_REPLY);
    memcpy(response_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->sender_ip, netif_ip.array, XNET_IPV4_ADDR_SIZE);
    memcpy(response_packet->target_mac, xarp_packet->sender_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->target_ip, xarp_packet->sender_ip, XNET_IPV4_ADDR_SIZE);
    return eth_out(XETH_TYPE_ARP, xarp_packet->sender_mac, packet);
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
}

void xarp_in(xnet_packet_t *packet) {
    if (packet->size < sizeof(xarp_packet_t)) {
        return;
    }
    xarp_packet_t* xarp_packet = (xarp_packet_t*) packet->data;
    uint16_t opcode = swap_order16(xarp_packet->opcode);
    if (swap_order16(xarp_packet->hw_type) != XARP_HW_ETH ||
        xarp_packet->hw_size != XNET_MAC_ADDR_SIZE ||
        swap_order16(xarp_packet->pt_type) != XETH_TYPE_IP ||
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
            break;
    }
}
