#include "sniffer.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TAG_SNIFF "SNIFF"

#define FT_PROBE_REQ  0x04
#define FT_PROBE_RSP  0x05
#define FT_BEACON     0x08
#define FT_AUTH       0x0B
#define FT_DEAUTH     0x0C
#define FT_DISASSOC   0x0A
#define FT_ASSOC_REQ  0x00

typedef struct {
    uint8_t  mac[6];
    char     lastSSID[33];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint32_t probeCount;
    uint32_t wildcardCount;
} SniffedDevice;

static SniffedDevice _devTable[CFG_SNIFFER_MAX_DEVICES];
static int           _devCount = 0;

static int _findOrAddDevice(const uint8_t* mac, const char* ssid,
                             int8_t rssi, uint8_t ch, bool isWildcard) {
    for (int i = 0; i < _devCount; i++) {
        if (macEqual(_devTable[i].mac, mac)) {
            _devTable[i].rssi       = rssi;
            _devTable[i].channel    = ch;
            _devTable[i].lastSeen   = millis();
            _devTable[i].probeCount++;
            if (isWildcard)
                _devTable[i].wildcardCount++;
            else if (ssid && strlen(ssid) > 0)
                strlcpy(_devTable[i].lastSSID, ssid, sizeof(_devTable[i].lastSSID));
            return i;
        }
    }
    if (_devCount >= CFG_SNIFFER_MAX_DEVICES) return -1;
    int i = _devCount++;
    memcpy(_devTable[i].mac, mac, 6);
    strlcpy(_devTable[i].lastSSID, (ssid && !isWildcard) ? ssid : "", 33);
    _devTable[i].rssi          = rssi;
    _devTable[i].channel       = ch;
    _devTable[i].firstSeen     = millis();
    _devTable[i].lastSeen      = millis();
    _devTable[i].probeCount    = 1;
    _devTable[i].wildcardCount = isWildcard ? 1 : 0;
    return i;
}

static struct {
    uint32_t probeReqTargeted;
    uint32_t probeReqWildcard;
    uint32_t probeRsp;
    uint32_t beacon;
    uint32_t auth;
    uint32_t deauth;
    uint32_t other;
    uint32_t total;
    uint32_t ringDropped;
} _sniffStats;

RING_BUFFER_DECLARE(sniff, CFG_SNIFFER_RING_SIZE, CFG_SNIFFER_MAX_PKT_LEN)
static sniff_ring_t _sniffRing;

static void IRAM_ATTR _sniffISR(void* buf, wifi_promiscuous_pkt_type_t) {
    if (!buf) return;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < 10) return;
    if (!sniff_push(&_sniffRing, pkt->payload, pkt->rx_ctrl.sig_len,
                    pkt->rx_ctrl.rssi, (uint8_t)pkt->rx_ctrl.channel))
        _sniffStats.ringDropped++;
}

static void _processSniffEntry(const sniff_entry_t* e) {
    const uint8_t* pl  = e->data;
    uint16_t       len = e->len;
    int8_t         rssi = e->rssi;
    uint8_t        ch   = e->channel;

    if (len < 24) return;

    uint8_t fc0   = pl[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsub  = (fc0 >> 4) & 0x0F;

    _sniffStats.total++;
    if (ftype != 0) return;

    const uint8_t* sa = pl + 10;

    switch (fsub) {
        case FT_PROBE_REQ: {
            char ssid[33] = {0};
            bool isWild   = true;

            if (len > 26 && pl[24] == 0x00) {
                uint8_t slen = pl[25];
                if (slen > 0 && slen <= 32 && (uint32_t)(26 + slen) < len) {
                    memcpy(ssid, pl + 26, slen);
                    ssid[slen] = '\0';
                    isWild = false;
                }
            }

            if (isWild)
                _sniffStats.probeReqWildcard++;
            else
                _sniffStats.probeReqTargeted++;

            int  idx   = _findOrAddDevice(sa, ssid, rssi, ch, isWild);
            bool isNew = (idx >= 0 && _devTable[idx].probeCount == 1);

            char macStr[18]; macToStr(sa, macStr);
            if (!isWild) {
                LOG_I(TAG_SNIFF, "[PROBE] %s Ch:%2u RSSI:%4d → \"%s\"%s",
                      macStr, ch, rssi, ssid, isNew ? "  ★ NEW" : "");
            } else {
                if (isNew) {
                    LOG_I(TAG_SNIFF, "[PROBE] %s Ch:%2u RSSI:%4d → (wildcard)  ★ NEW",
                          macStr, ch, rssi);
                }
            }
            break;
        }

        case FT_DEAUTH:
        case FT_DISASSOC:
            _sniffStats.deauth++;
            if (len >= 26) {
                uint16_t reason = pl[24] | (pl[25] << 8);
                const uint8_t* da = pl + 4;
                char daStr[18], saStr[18];
                macToStr(da, daStr);
                macToStr(sa, saStr);
                LOG_I(TAG_SNIFF, "[%s] %s → %s Reason:%u",
                      (fsub == FT_DEAUTH) ? "DEAUTH" : "DISASSOC",
                      saStr, daStr, reason);
            }
            break;

        case FT_AUTH:
            _sniffStats.auth++;
            if (len >= 6) {
                uint16_t auth_alg = pl[0] | (pl[1] << 8);
                if (auth_alg == 3) {
                    char saStr[18];
                    macToStr(sa, saStr);
                    LOG_I(TAG_SNIFF, "[SAE] Auth from %s", saStr);
                }
            }
            break;

        default:
            _sniffStats.other++;
            break;
    }
}

static void _drainSniffRing(void) {
    sniff_entry_t e;
    while (sniff_pop(&_sniffRing, &e)) _processSniffEntry(&e);
}

static void _printSniffSummary(void) {
    uint32_t totalProbe = _sniffStats.probeReqTargeted + _sniffStats.probeReqWildcard;

    printf("\n╔═══════════════════════════ Sniffer Summary ════════════════════════╗\n");
    printf("│  Total packets captured : %-6u                                    │\n", _sniffStats.total);
    printf("│  Probe Requests (total) : %-6u  Targeted:%-6u  Wildcard:%-6u   │\n",
           totalProbe, _sniffStats.probeReqTargeted, _sniffStats.probeReqWildcard);
    printf("│  Probe Responses        : %-6u                                    │\n", _sniffStats.probeRsp);
    printf("│  Beacons                : %-6u                                    │\n", _sniffStats.beacon);
    printf("│  Deauth / Disassoc      : %-6u                                    │\n", _sniffStats.deauth);
    printf("│  Auth                   : %-6u                                    │\n", _sniffStats.auth);
    printf("│  Ring buffer dropped    : %-6u                                    │\n", _sniffStats.ringDropped);
    printf("│  Unique devices         : %-3d                                       │\n", _devCount);
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n");

    if (_devCount > 0) {
        printf("\n  MAC                SSID (last probed)             RSSI  Ch  Count\n");
        printf("  ───────────────────────────────────────────────────────────────\n");
        for (int i = 0; i < _devCount; i++) {
            char m[18]; macToStr(_devTable[i].mac, m);
            printf("  %s  %-32s  %4d  %2u  %u\n",
                   m,
                   _devTable[i].lastSSID[0] ? _devTable[i].lastSSID : "(wildcard)",
                   _devTable[i].rssi,
                   _devTable[i].channel,
                   _devTable[i].probeCount);
        }
    }
}

void probeSniffer(uint32_t durationSec, volatile bool* stopFlag) {
    memset(&_sniffStats, 0, sizeof(_sniffStats));
    memset(_devTable,    0, sizeof(_devTable));
    _devCount = 0;
    sniff_reset(&_sniffRing);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(80));
    setTxPower(CFG_TX_POWER);

    if (!enablePromiscuous(WIFI_PROMIS_FILTER_MASK_MGMT, _sniffISR)) {
        LOG_E(TAG_SNIFF, "Failed to enable promiscuous mode!");
        return;
    }

    LOG_I(TAG_SNIFF, "Probe Sniffer started. Hop interval: %u ms", CFG_SNIFFER_HOP_MS);
    if (durationSec > 0) LOG_I(TAG_SNIFF, "Auto-stop in %u s.", durationSec);

    uint32_t startMs   = millis();
    uint32_t lastPrint = millis();
    uint8_t  ch        = CFG_CHANNEL_MIN;

    while (!(*stopFlag)) {
        setChannel(ch);
        ch = (uint8_t)((ch % CFG_CHANNEL_MAX) + 1);

        _drainSniffRing();

        if (durationSec > 0 && (millis() - startMs) >= durationSec * 1000UL) break;

        if (millis() - lastPrint >= 5000UL) {
            LOG_I(TAG_SNIFF, "Probes: T=%u W=%u | Devices: %d | Deauth: %u | Dropped: %u",
                  _sniffStats.probeReqTargeted, _sniffStats.probeReqWildcard,
                  _devCount, _sniffStats.deauth, _sniffStats.ringDropped);
            lastPrint = millis();
        }

        vTaskDelay(pdMS_TO_TICKS(CFG_SNIFFER_HOP_MS));
    }

    _drainSniffRing();
    disablePromiscuous();
    _printSniffSummary();
    LOG_I(TAG_SNIFF, "Stopped.");
}
