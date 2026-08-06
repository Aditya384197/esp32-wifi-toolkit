#include "storage.h"
#include <stdio.h>
#include <stdbool.h>

bool pcapng_logger_open(PcapngFileLogger* logger, const char* path) {
    if (logger->open) pcapng_logger_close(logger);
    FILE* f = fopen(path, "ab");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0) {
        uint8_t hdr[48];
        size_t n = writePcapngGlobalHeader(hdr);
        fwrite(hdr, 1, n, f);
    }
    logger->file = f;
    logger->open = true;
    return true;
}

void pcapng_logger_write(PcapngFileLogger* logger, const uint8_t* data, size_t len,
                         int8_t rssi, uint8_t channel, uint64_t ts) {
    if (!logger->open || !logger->file) return;
    uint8_t buf[2048];
    size_t n = writePcapngPacket(data, len, rssi, channel, ts, buf, sizeof(buf));
    if (n) {
        fwrite(buf, 1, n, logger->file);
        fflush(logger->file);
    }
}

void pcapng_logger_close(PcapngFileLogger* logger) {
    if (logger->open && logger->file) {
        fclose(logger->file);
        logger->file = NULL;
        logger->open = false;
    }
}
