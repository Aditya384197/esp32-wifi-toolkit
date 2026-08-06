#include "pcapng.h"
#include <string.h>

size_t writePcapngGlobalHeader(uint8_t* buffer) {
    size_t off = 0;
    uint32_t shb_type = 0x0A0D0D0A, shb_len = 28, magic = 0x1A2B3C4D;
    uint16_t v_major = 1, v_minor = 0;
    int64_t section_len = -1;
    memcpy(buffer + off, &shb_type, 4); off += 4;
    memcpy(buffer + off, &shb_len, 4); off += 4;
    memcpy(buffer + off, &magic, 4); off += 4;
    memcpy(buffer + off, &v_major, 2); off += 2;
    memcpy(buffer + off, &v_minor, 2); off += 2;
    memcpy(buffer + off, &section_len, 8); off += 8;
    memcpy(buffer + off, &shb_len, 4); off += 4;

    uint32_t idb_type = 0x00000001, idb_len = 20, snaplen = 65535;
    uint16_t link_type = 127, reserved = 0;
    memcpy(buffer + off, &idb_type, 4); off += 4;
    memcpy(buffer + off, &idb_len, 4); off += 4;
    memcpy(buffer + off, &link_type, 2); off += 2;
    memcpy(buffer + off, &reserved, 2); off += 2;
    memcpy(buffer + off, &snaplen, 4); off += 4;
    memcpy(buffer + off, &idb_len, 4); off += 4;
    return off;
}

size_t writePcapngPacket(const uint8_t* payload, size_t payload_len,
                         int8_t rssi, uint8_t channel, uint64_t ts_usec,
                         uint8_t* buffer, size_t max_len) {
    uint16_t freq = (channel <= 14) ? (2407 + channel*5) : (5000 + channel*5);
    uint16_t chan_flags = (channel <= 14) ? 0x00A0 : 0x0140;
    uint8_t radiotap[14] = {0x00,0x00,0x0E,0x00,0x28,0x00,0x00,0x00,
                            (uint8_t)(freq&0xFF), (uint8_t)(freq>>8),
                            (uint8_t)(chan_flags&0xFF), (uint8_t)(chan_flags>>8),
                            (uint8_t)rssi, 0x00};
    uint32_t rt_len = 14;
    uint32_t cap_len = payload_len + rt_len;
    uint32_t aligned = (cap_len + 3) & ~3;
    uint32_t pad = aligned - cap_len;
    uint32_t block_len = 32 + aligned + 20;

    if (block_len > max_len) return 0;

    size_t off = 0;
    uint32_t epb_type = 0x00000006, iface_id = 0;
    uint32_t ts_high = ts_usec >> 32, ts_low = ts_usec & 0xFFFFFFFF;
    memcpy(buffer + off, &epb_type, 4); off += 4;
    memcpy(buffer + off, &block_len, 4); off += 4;
    memcpy(buffer + off, &iface_id, 4); off += 4;
    memcpy(buffer + off, &ts_high, 4); off += 4;
    memcpy(buffer + off, &ts_low, 4); off += 4;
    memcpy(buffer + off, &cap_len, 4); off += 4;
    memcpy(buffer + off, &cap_len, 4); off += 4;
    memcpy(buffer + off, radiotap, rt_len); off += rt_len;
    memcpy(buffer + off, payload, payload_len); off += payload_len;
    if (pad) { memset(buffer + off, 0, pad); off += pad; }

    uint16_t opt_code = 0x8001, opt_len = 1;
    memcpy(buffer + off, &opt_code, 2); off += 2;
    memcpy(buffer + off, &opt_len, 2); off += 2;
    buffer[off++] = (uint8_t)rssi;
    memset(buffer + off, 0, 3); off += 3;

    opt_code = 0x8002; opt_len = 1;
    memcpy(buffer + off, &opt_code, 2); off += 2;
    memcpy(buffer + off, &opt_len, 2); off += 2;
    buffer[off++] = channel;
    memset(buffer + off, 0, 3); off += 3;

    opt_code = 0x0000; opt_len = 0;
    memcpy(buffer + off, &opt_code, 2); off += 2;
    memcpy(buffer + off, &opt_len, 2); off += 2;

    memcpy(buffer + off, &block_len, 4); off += 4;
    return off;
}
