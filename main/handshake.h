#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "utils.h"
#include "config.h"
#include "scanner.h"
#include "pcapng.h"
#include "storage.h"

#define TAG_HS "HANDSHAKE"

#define CAP_PMKID  0x01
#define CAP_EAPOL  0x02

typedef struct {
    uint8_t  type;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  bssid[6];
    uint8_t  sta[6];
    char     ssid[33];
    uint8_t  ssid_len;
    uint8_t  enc;
    uint8_t  pmkid[16];
    uint8_t  anonce[32];
    uint8_t  snonce[32];
    uint8_t  mic[16];
    uint8_t  eapol_m2[256];
    uint8_t  eapol_m3[256];
    uint8_t  eapol_m4[256];
    uint16_t eapol_m2_len;
    uint16_t eapol_m3_len;
    uint16_t eapol_m4_len;
    bool     has_mic;
    bool     has_anonce;
    bool     has_snonce;
    bool     has_m3;
    bool     has_m4;
    bool     is_full;
    uint8_t  sae_seq;
} HandshakeRecord;

typedef void (*HandshakeCb)(const HandshakeRecord* rec);

void setHandshakeCallback(HandshakeCb cb);
void startHandshakeCapture(const uint8_t* bssid, uint8_t channel,
                            const char* ssid, bool withDeauth,
                            volatile bool* stopFlag);

#endif // HANDSHAKE_H
