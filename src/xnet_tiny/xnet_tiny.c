#include "xnet_tiny.h"

#define min(a, b) ((a) > (b) ? (b) : (a))
#define swap_order16(v) (((v) & 0xFF) << 8 | ((v) >> 8) & 0xFF)

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

int xarp_make_request(const xip_addr_t* ip_addr) {
    xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* arp_packet = (xnet_packet_t*)packet->data;

    arp_packet->hw_type = XARP_HW_ETH;
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