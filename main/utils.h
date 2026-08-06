#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "config.h"

// ============================
// Logging Macros
// ============================
#define LOG_D(tag, fmt, ...)  ESP_LOGD(tag, fmt, ##__VA_ARGS__)
#define LOG_I(tag, fmt, ...)  ESP_LOGI(tag, fmt, ##__VA_ARGS__)
#define LOG_W(tag, fmt, ...)  ESP_LOGW(tag, fmt, ##__VA_ARGS__)
#define LOG_E(tag, fmt, ...)  ESP_LOGE(tag, fmt, ##__VA_ARGS__)

// ============================
// Time Helpers
// ============================
static inline uint32_t millis(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

// ============================
// MAC Helpers
// ============================
void macToStr(const uint8_t* mac, char* buf);
bool macEqual(const uint8_t* a, const uint8_t* b);
void randomMac(uint8_t* mac);

// ============================
// Wi-Fi Helpers
// ============================
bool setChannel(uint8_t ch);
bool enablePromiscuous(uint32_t filterMask, wifi_promiscuous_cb_t cb);   // 🔥 FIXED type
void disablePromiscuous(void);
void setTxPower(int8_t power);
bool wifi80211Tx(wifi_interface_t iface, const uint8_t* buf, int len, bool enSysBuf);
void wifi_init_basic(void);

// ============================
// NVS BSSID Cache
// ============================
typedef struct {
    uint8_t cache[128][6];
    size_t count;
    bool dirty;
    nvs_handle_t nvs_handle;
    bool initialized;
} nvs_bssid_cache_t;

void nvs_bssid_cache_init(nvs_bssid_cache_t* cache, const char* ns);
bool nvs_bssid_cache_add(nvs_bssid_cache_t* cache, const uint8_t* bssid);
bool nvs_bssid_cache_is_present(nvs_bssid_cache_t* cache, const uint8_t* bssid);
bool nvs_bssid_cache_flush(nvs_bssid_cache_t* cache);
size_t nvs_bssid_cache_count(nvs_bssid_cache_t* cache);

// ============================
// Ring Buffer Macro
// ============================
#define RING_BUFFER_DECLARE(name, depth, max_len) \
    typedef struct { \
        uint8_t data[max_len]; \
        uint16_t len; \
        int8_t rssi; \
        uint8_t channel; \
    } name##_entry_t; \
    typedef struct { \
        name##_entry_t buf[depth]; \
        volatile uint8_t head; \
        volatile uint8_t tail; \
    } name##_ring_t; \
    \
    static inline bool name##_push(name##_ring_t* ring, const uint8_t* data, uint16_t len, int8_t rssi, uint8_t ch) { \
        uint8_t h = ring->head; \
        uint8_t next = (uint8_t)((h + 1) % depth); \
        if (next == ring->tail) return false; \
        uint16_t copy = (len > max_len) ? max_len : len; \
        memcpy(ring->buf[h].data, data, copy); \
        ring->buf[h].len = copy; \
        ring->buf[h].rssi = rssi; \
        ring->buf[h].channel = ch; \
        ring->head = next; \
        return true; \
    } \
    \
    static inline bool name##_pop(name##_ring_t* ring, name##_entry_t* out) { \
        uint8_t t = ring->tail; \
        if (t == ring->head) return false; \
        *out = ring->buf[t]; \
        ring->tail = (uint8_t)((t + 1) % depth); \
        return true; \
    } \
    \
    static inline bool name##_empty(name##_ring_t* ring) { return ring->head == ring->tail; } \
    static inline void name##_reset(name##_ring_t* ring) { ring->head = 0; ring->tail = 0; }

// ============================
// Serial Input Helpers
// ============================
int readIntFromSerial(void);
int readCharFromSerial(void);
void serialFlush(void);

#endif // UTILS_H
