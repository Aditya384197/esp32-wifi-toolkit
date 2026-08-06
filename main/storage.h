#ifndef STORAGE_H
#define STORAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>      // 🔥 FILE के लिए – यह लाइन जोड़ी गई है
#include "pcapng.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    FILE* file;
    bool open;
} PcapngFileLogger;

bool pcapng_logger_open(PcapngFileLogger* logger, const char* path);
void pcapng_logger_write(PcapngFileLogger* logger, const uint8_t* data, size_t len,
                         int8_t rssi, uint8_t channel, uint64_t ts);
void pcapng_logger_close(PcapngFileLogger* logger);

#ifdef __cplusplus
}
#endif

#endif // STORAGE_H
