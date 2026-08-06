#include "utils.h"
#include "esp_rom_sys.h"

// ============================
// MAC Helpers
// ============================
void macToStr(const uint8_t* mac, char* buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool macEqual(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 6) == 0;
}

void randomMac(uint8_t* mac) {
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    mac[0] = (uint8_t)(((r1 >> 0) & 0xFE) | 0x02);
    mac[1] = (uint8_t)((r1 >> 8) & 0xFF);
    mac[2] = (uint8_t)((r1 >> 16) & 0xFF);
    mac[3] = (uint8_t)((r2 >> 0) & 0xFF);
    mac[4] = (uint8_t)((r2 >> 8) & 0xFF);
    mac[5] = (uint8_t)((r2 >> 16) & 0xFF);
}

// ============================
// Wi-Fi Helpers
// ============================
bool setChannel(uint8_t ch) {
    if (ch < CFG_CHANNEL_MIN || ch > CFG_CHANNEL_MAX) {
        LOG_W("CH", "Invalid channel %u", ch);
        return false;
    }
    esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        LOG_W("CH", "set_channel(%u) failed: %s", ch, esp_err_to_name(err));
        return false;
    }
    return true;
}

bool enablePromiscuous(uint32_t filterMask, esp_promiscuous_cb_t cb) {
    wifi_promiscuous_filter_t f = { .filter_mask = filterMask };
    esp_err_t e1 = esp_wifi_set_promiscuous_filter(&f);
    esp_err_t e2 = esp_wifi_set_promiscuous_rx_cb(cb);
    esp_err_t e3 = esp_wifi_set_promiscuous(true);
    if (e1 != ESP_OK || e2 != ESP_OK || e3 != ESP_OK) {
        LOG_E("PROMISC", "Enable failed");
        return false;
    }
    return true;
}

void disablePromiscuous(void) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
}

void setTxPower(int8_t power) {
    if (power < 0) power = 0;
    if (power > 84) power = 84;
    esp_err_t err = esp_wifi_set_max_tx_power(power);
    if (err != ESP_OK)
        LOG_W("TXPWR", "set_max_tx_power(%d) failed: %s", power, esp_err_to_name(err));
}

bool wifi80211Tx(wifi_interface_t iface, const uint8_t* buf, int len, bool enSysBuf) {
    esp_err_t err = ESP_FAIL;
    for (int attempt = 0; attempt < CFG_TX_RETRY_COUNT; attempt++) {
        err = esp_wifi_80211_tx(iface, buf, len, enSysBuf);
        if (err == ESP_OK) return true;
        if (err != ESP_ERR_WIFI_NOT_INIT && err != 0x3019) break;
        if (attempt < CFG_TX_RETRY_COUNT - 1)
            esp_rom_delay_us(CFG_TX_RETRY_DELAY_US);
    }
    LOG_W("TX", "esp_wifi_80211_tx failed after %d attempt(s)", CFG_TX_RETRY_COUNT);
    return false;
}

void wifi_init_basic(void) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
}

// ============================
// NVS BSSID Cache
// ============================
void nvs_bssid_cache_init(nvs_bssid_cache_t* cache, const char* ns) {
    memset(cache->cache, 0, sizeof(cache->cache));
    cache->count = 0;
    cache->dirty = false;
    cache->initialized = true;
    nvs_open(ns, NVS_READWRITE, &cache->nvs_handle);
    size_t bytes = 0;
    nvs_get_blob(cache->nvs_handle, "bssids", cache->cache, &bytes);
    cache->count = bytes / 6;
    if (cache->count > 128) cache->count = 128;
}

bool nvs_bssid_cache_add(nvs_bssid_cache_t* cache, const uint8_t* bssid) {
    if (!cache->initialized) return false;
    for (size_t i = 0; i < cache->count; i++) {
        if (memcmp(cache->cache[i], bssid, 6) == 0) return false;
    }
    if (cache->count >= 128) return false;
    memcpy(cache->cache[cache->count], bssid, 6);
    cache->count++;
    cache->dirty = true;
    return true;
}

bool nvs_bssid_cache_is_present(nvs_bssid_cache_t* cache, const uint8_t* bssid) {
    if (!cache->initialized) return false;
    for (size_t i = 0; i < cache->count; i++) {
        if (memcmp(cache->cache[i], bssid, 6) == 0) return true;
    }
    return false;
}

bool nvs_bssid_cache_flush(nvs_bssid_cache_t* cache) {
    if (!cache->initialized || !cache->dirty) return false;
    nvs_set_blob(cache->nvs_handle, "bssids", cache->cache, cache->count * 6);
    nvs_commit(cache->nvs_handle);
    cache->dirty = false;
    return true;
}

size_t nvs_bssid_cache_count(nvs_bssid_cache_t* cache) {
    return cache->count;
}

// ============================
// Serial Input Helpers
// ============================
int readIntFromSerial(void) {
    char buf[16] = {0};
    int i = 0;
    while (1) {
        char c = getchar();
        if (c == '\n' || c == '\r') break;
        if (i < 15 && c >= '0' && c <= '9') buf[i++] = c;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return atoi(buf);
}

char readCharFromSerial(void) {
    char c = getchar();
    return c;
}

void serialFlush(void) {
    while (getchar() != EOF) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
