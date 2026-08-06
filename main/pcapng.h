#ifndef PCAPNG_H
#define PCAPNG_H

#include <stdint.h>
#include <stddef.h>

size_t writePcapngGlobalHeader(uint8_t* buffer);
size_t writePcapngPacket(const uint8_t* payload, size_t payload_len,
                         int8_t rssi, uint8_t channel, uint64_t ts_usec,
                         uint8_t* buffer, size_t max_len);

#endif // PCAPNG_H
