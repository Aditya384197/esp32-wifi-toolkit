#include "beacon.h"
#include "utils.h"
#include "esp_rom_sys.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TAG_BEACON "BEACON"

static const char* const _fakeNames[20] = {
    "FBI_Surveillance_Van",  "NSA_PRISM_Node_7",
    "Not_Your_WiFi",         "Skynet_Alpha_Unit",
    "DEA_Surveillance_3",    "CIA_SpecialOps_AP",
    "VaultTec_Industries",   "PrettyFlyForAWiFi",
    "DefinitelyNotAHotspot", "HackTheGibson_3310",
    "TellMyWifiLoveHer",     "WinternetIsComing",
    "404_SSID_Not_Found",    "ThePromisedLAN",
    "GetYourOwnWiFi",        "PasswordIsPassword",
    "NotSkynet_v2",          "MomUseThisOne",
    "YourNeighboursWiFi",    "Linksys_Definitely"
};

static const uint8_t _ratesIE[]    = { 0x01,0x08, 0x82,0x84,0x8B,0x96,0x24,0x30,0x48,0x6C };
static const uint8_t _extRatesIE[] = { 0x32,0x04, 0x30,0x48,0x60,0x6C };
static const uint8_t _rsnIE[]      = {
    0x30,0x14, 0x01,0x00, 0x00,0x0F,0xAC,0x04,
    0x01,0x00, 0x00,0x0F,0xAC,0x04,
    0x01,0x00, 0x00,0x0F,0xAC,0x02,
    0x0C,0x00
};
static const uint8_t _wpaIE[] = {
    0xDD,0x18, 0x00,0x50,0xF2,0x01, 0x01,0x00,
    0x00,0x50,0xF2,0x02, 0x02,0x00,
    0x00,0x50,0xF2,0x04, 0x00,0x50,0xF2,0x02,
    0x01,0x00, 0x00,0x50,0xF2,0x02
};

#define _BA(src, n) \
    do { if ((size_t)(pos+(n)) > bufSize) { LOG_E(TAG_BEACON,"Frame buf overflow"); return 0; } \
         memcpy(buf+pos,(src),(n)); pos+=(n); } while(0)
#define _BB(b) \
    do { if ((size_t)(pos+1) > bufSize) { LOG_E(TAG_BEACON,"Frame buf overflow"); return 0; } \
         buf[pos++]=(uint8_t)(b); } while(0)

static int buildBeaconFrame(uint8_t* buf, size_t bufSize,
                             const char* ssid, const uint8_t* bssid,
                             uint8_t channel, uint16_t seqNum) {
    static const uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    static const uint8_t zero8[8] = {0};
    static const uint8_t tim[]    = {0x05,0x04,0x00,0x01,0x00,0x00};
    memset(buf, 0, bufSize);
    int pos = 0;

    _BB(0x80); _BB(0x00);
    _BB(0x00); _BB(0x00);
    _BA(bcast, 6);
    _BA(bssid, 6);
    _BA(bssid, 6);
    uint16_t sc = (seqNum & 0x0FFF) << 4;
    _BB(sc & 0xFF); _BB(sc >> 8);
    _BA(zero8, 8);
    _BB(CFG_BEACON_INTERVAL_TU & 0xFF); _BB(CFG_BEACON_INTERVAL_TU >> 8);
    _BB(0x31); _BB(0x04);

    uint8_t sLen = (uint8_t)strnlen(ssid, 32);
    _BB(0x00); _BB(sLen);
    if (sLen > 0) {
        if ((size_t)(pos + sLen) > bufSize) return 0;
        memcpy(buf + pos, ssid, sLen); pos += sLen;
    }

    _BA(_ratesIE,    sizeof(_ratesIE));
    _BA(_extRatesIE, sizeof(_extRatesIE));
    _BB(0x03); _BB(0x01); _BB(channel);
    _BA(tim, sizeof(tim));
    _BA(_rsnIE, sizeof(_rsnIE));
    _BA(_wpaIE, sizeof(_wpaIE));

    return pos;
}
#undef _BA
#undef _BB

typedef struct {
    int            ssidCount;
    char           prefix[33];
    bool           hasPrefix;
    volatile bool* stopFlag;
    volatile bool  finished;
} BeaconParams;

static BeaconParams _bp;

static void _beaconCore(BeaconParams* p) {
    char    ssids[CFG_BEACON_MAX_SSIDS][33];
    uint8_t bssids[CFG_BEACON_MAX_SSIDS][6];
    uint32_t txErr[CFG_BEACON_MAX_SSIDS] = {0};

    printf("\n┌────────────────────────────────────────────────────────────┐\n");
    printf("│  Fake SSIDs:                                               │\n");
    for (int i = 0; i < p->ssidCount; i++) {
        randomMac(bssids[i]);
        if (p->hasPrefix)
            snprintf(ssids[i], 33, "%s_%02X%02X", p->prefix, bssids[i][4], bssids[i][5]);
        else
            snprintf(ssids[i], 33, "%s_%02X", _fakeNames[i % 20], bssids[i][5]);
        char bStr[18]; macToStr(bssids[i], bStr);
        printf("│  [%2d] %-32s  %s   │\n", i+1, ssids[i], bStr);
    }
    printf("└────────────────────────────────────────────────────────────┘\n");
    LOG_I(TAG_BEACON, "Spamming. Send 's' to stop.");

    uint8_t  frameBuf[CFG_BEACON_MAX_FRAME_LEN];
    uint32_t totalSent = 0;
    uint32_t round     = 0;
    uint32_t lastPrint = millis();
    uint8_t  ch        = 1;
    uint16_t seq       = 0;

    while (!(*(p->stopFlag))) {
        for (int i = 0; i < p->ssidCount; i++) {
            if (*(p->stopFlag)) break;
            seq++;
            int fLen = buildBeaconFrame(frameBuf, sizeof(frameBuf),
                                        ssids[i], bssids[i], ch, seq);
            if (fLen > 0) {
                if (!wifi80211Tx(WIFI_IF_STA, frameBuf, fLen, false)) txErr[i]++;
                totalSent++;
            }
            esp_rom_delay_us(CFG_BEACON_INTER_US);
        }
        round++;
        if (round % CFG_BEACON_ROTATE_EVERY == 0) {
            ch = (uint8_t)((ch % CFG_CHANNEL_MAX) + 1);
            setChannel(ch);
        }
        if (millis() - lastPrint >= 1000) {
            LOG_I(TAG_BEACON, "Sent: %u  Ch: %u  Round: %u", totalSent, ch, round);
            lastPrint = millis();
        }
        vTaskDelay(CFG_WDT_YIELD_TICKS);
    }

    disablePromiscuous();
    printf("\n┌────────── Beacon Spammer Report ─────────┐\n");
    printf("│  Total beacons sent : %-6u              │\n", totalSent);
    for (int i = 0; i < p->ssidCount; i++)
        if (txErr[i] > 0)
            printf("│  [%2d] TX errors: %u%*s│\n", i+1, txErr[i], (int)(40 - snprintf(NULL,0,"%u",txErr[i])), "");
    printf("└────────────────────────────────────────────┘\n");
    LOG_I(TAG_BEACON, "Stopped.");
}

static void _beaconTaskFn(void* pv) {
    BeaconParams* p = (BeaconParams*)pv;
    _beaconCore(p);
    p->finished = true;
    vTaskDelete(NULL);
}

void beaconSpammer(int ssidCount, const char* prefix, volatile bool* stopFlag) {
    if (ssidCount < 1) ssidCount = 1;
    if (ssidCount > CFG_BEACON_MAX_SSIDS) ssidCount = CFG_BEACON_MAX_SSIDS;

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(80));
    setTxPower(CFG_TX_POWER);

    if (!enablePromiscuous(WIFI_PROMIS_FILTER_MASK_MGMT, NULL)) {
        LOG_E(TAG_BEACON, "Failed to enable promiscuous mode!");
        return;
    }
    setChannel(1);

    _bp.ssidCount = ssidCount;
    _bp.hasPrefix = (prefix && strlen(prefix) > 0);
    if (_bp.hasPrefix) strlcpy(_bp.prefix, prefix, sizeof(_bp.prefix));
    _bp.stopFlag = stopFlag;
    _bp.finished = false;

    TaskHandle_t h   = NULL;
    BaseType_t   res = xTaskCreatePinnedToCore(
        _beaconTaskFn, "beacon_t",
        CFG_TASK_STACK_BYTES, &_bp,
        CFG_TASK_PRIORITY, &h, 1
    );

    if (res != pdPASS) {
        LOG_E(TAG_BEACON, "Task creation failed!");
        disablePromiscuous();
        return;
    }

    while (!_bp.finished) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}
