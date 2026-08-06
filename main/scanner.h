#ifndef SCANNER_H
#define SCANNER_H

#include "utils.h"
#include "config.h"

#define TAG_SCAN "SCAN"

typedef struct {
    uint8_t bssid[6];
    char    ssid[33];
    uint8_t ssid_len;
    uint8_t channel;
    int8_t  rssi;
    uint8_t enc;
    bool    wps;
    bool    captured;
    uint8_t attempts;
} ApRecord;

int getApCount(void);
bool getAp(int idx, ApRecord* out);
int getBestApByScore(ApRecord* best);
void markApCaptured(const uint8_t* bssid);
void wifiScanner(void);

#endif // SCANNER_H
