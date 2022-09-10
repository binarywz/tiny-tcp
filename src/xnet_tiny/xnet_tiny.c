#include "xnet_tiny.h"

#define min(a, b) ((a) > (b) ? (b) : (a))
static xnet_packet_t tx_packet, rx_packet;

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

void xnet_init(void) {

}

void xnet_poll(void) {

}

// 添加packet头部
static void add_header(xnet_packet_t* packet, uint16_t size) {
    packet->data -= size;
    packet->size += size;
}

// 移除packet头部
static void remove_header(xnet_packet_t* packet, uint16_t size) {
    packet->data += size;
    packet->size -= size;
}

// 截断packet
static void truncate_packet(xnet_packet_t* packet, uint16_t size) {
    packet->size = min(packet->size, size);
}