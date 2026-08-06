#include "scanner.h"
#include "utils.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static ApRecord _apCache[CFG_SCAN_MAX_NETWORKS];
static int _apCount = 0;

static bool _scanDone = false;
static EventGroupHandle_t _scanEventGroup = NULL;
#define SCAN_DONE_BIT BIT0

static void _scan_event_handler(void* arg, esp_event_base_t base,
                                int32_t id, void* data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_SCAN_DONE) {
        _scanDone = true;
        if (_scanEventGroup) xEventGroupSetBits(_scanEventGroup, SCAN_DONE_BIT);
    }
}

static const char* signalBar(int rssi) {
    if (rssi >= -50) return "[████████] Excellent";
    if (rssi >= -60) return "[██████░░] Good";
    if (rssi >= -70) return "[████░░░░] Fair";
    if (rssi >= -80) return "[██░░░░░░] Weak";
    return             "[░░░░░░░░] Very Weak";
}

static const char* encryptionStr(uint8_t enc) {
    switch ((wifi_auth_mode_t)enc) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
        default: return "UNKNOWN";
    }
}

static int scoreAp(const ApRecord* ap) {
    int score = ap->rssi;
    if (ap->enc >= 3) score += 30;
    if (ap->wps) score += 20;
    if (ap->captured) score -= 10000;
    if (ap->attempts > 0) score -= (ap->attempts * 10);
    return score;
}

void wifiScanner(void) {
    LOG_I(TAG_SCAN, "Scanning...");

    // Register event handler for scan
    if (!_scanEventGroup) {
        _scanEventGroup = xEventGroupCreate();
        esp_event_handler_instance_t instance;
        esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE,
                                            &_scan_event_handler, NULL, &instance);
    }

    // Start scan
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = { .active = { .min = 100, .max = 300 } }
    };
    _scanDone = false;
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, false);
    if (err != ESP_OK) {
        LOG_E(TAG_SCAN, "Scan start failed: %s", esp_err_to_name(err));
        return;
    }

    // Wait for scan completion
    xEventGroupWaitBits(_scanEventGroup, SCAN_DONE_BIT, pdTRUE, pdFALSE, pdMS_TO_TICKS(5000));
    if (!_scanDone) {
        LOG_E(TAG_SCAN, "Scan timeout");
        return;
    }

    // Get results
    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    if (ap_num == 0) {
        LOG_I(TAG_SCAN, "No networks found.");
        _apCount = 0;
        return;
    }

    _apCount = (ap_num < CFG_SCAN_MAX_NETWORKS) ? ap_num : CFG_SCAN_MAX_NETWORKS;
    wifi_ap_record_t* records = malloc(sizeof(wifi_ap_record_t) * _apCount);
    if (!records) {
        LOG_E(TAG_SCAN, "Memory allocation failed");
        return;
    }
    esp_wifi_scan_get_ap_records(&_apCount, records);

    // Fill cache
    for (int i = 0; i < _apCount; i++) {
        ApRecord* ap = &_apCache[i];
        memcpy(ap->bssid, records[i].bssid, 6);
        strncpy(ap->ssid, (char*)records[i].ssid, 32);
        ap->ssid[32] = '\0';
        ap->ssid_len = strlen(ap->ssid);
        ap->channel = records[i].primary;
        ap->rssi = records[i].rssi;
        ap->enc = (uint8_t)records[i].authmode;
        ap->captured = false;
        ap->attempts = 0;

        // WPS detection
        ap->wps = false;
        if (records[i].ies_len > 0) {
            const uint8_t* ies = records[i].ies;
            for (int j = 0; j < records[i].ies_len - 5; j++) {
                if (ies[j] == 0xDD && ies[j+1] >= 4 &&
                    ies[j+2] == 0x00 && ies[j+3] == 0x50 &&
                    ies[j+4] == 0xF2 && ies[j+5] == 0x04) {
                    ap->wps = true;
                    break;
                }
            }
        }
    }

    free(records);

    // Print table
    printf("\n┌────┬──────────────────────────────┬─────┬──────┬────────────┬──────────────────┬────────────────────┐\n");
    printf("│ #  │ SSID                         │ Ch  │ RSSI │ Security   │ BSSID            │ Signal             │\n");
    printf("├────┼──────────────────────────────┼─────┼──────┼────────────┼──────────────────┼────────────────────┤\n");
    for (int i = 0; i < _apCount; i++) {
        ApRecord* ap = &_apCache[i];
        char bssidStr[18];
        macToStr(ap->bssid, bssidStr);
        printf("│ %2d │ %-28s │ %3d │ %4d │ %-10s │ %-17s │ %s\n",
               i,
               ap->ssid[0] ? ap->ssid : "(hidden)",
               ap->channel,
               ap->rssi,
               encryptionStr(ap->enc),
               bssidStr,
               signalBar(ap->rssi));
    }
    printf("└────┴──────────────────────────────┴─────┴──────┴────────────┴──────────────────┴────────────────────┘\n");

    LOG_I(TAG_SCAN, "Scan complete. %d APs cached.", _apCount);
}

int getApCount(void) { return _apCount; }

bool getAp(int idx, ApRecord* out) {
    if (idx < 0 || idx >= _apCount) return false;
    *out = _apCache[idx];
    return true;
}

int getBestApByScore(ApRecord* best) {
    int bestIdx = -1;
    int bestScore = INT16_MIN;
    for (int i = 0; i < _apCount; i++) {
        if (_apCache[i].enc < 2) continue;
        int s = scoreAp(&_apCache[i]);
        if (s > bestScore) {
            bestScore = s;
            bestIdx = i;
        }
    }
    if (bestIdx >= 0) *best = _apCache[bestIdx];
    return bestIdx;
}

void markApCaptured(const uint8_t* bssid) {
    for (int i = 0; i < _apCount; i++) {
        if (memcmp(_apCache[i].bssid, bssid, 6) == 0) {
            _apCache[i].captured = true;
            _apCache[i].attempts++;
            break;
        }
    }
}
