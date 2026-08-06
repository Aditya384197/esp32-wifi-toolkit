#include "utils.h"
#include "scanner.h"
#include "deauth.h"
#include "beacon.h"
#include "sniffer.h"
#include "packet_analyzer.h"
#include "handshake.h"
#include "evil_twin.h"
#include "pcapng.h"
#include "storage.h"
#include "esp_spiffs.h"
#include "esp_system.h"

static const char *TAG = "MAIN";
static volatile bool g_stop = false;
static bool autoTargetEnabled = false;
static uint32_t lastAutoScan = 0;

// ============================
// Handshake Callback
// ============================
static void onHandshake(const HandshakeRecord* rec) {
    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║   ★★★  HANDSHAKE CAPTURED  ★★★                     ║\n");
    printf("║  SSID: %s\n", rec->ssid);
    char bssidStr[18], staStr[18];
    macToStr(rec->bssid, bssidStr);
    macToStr(rec->sta, staStr);
    printf("║  BSSID: %s\n", bssidStr);
    printf("║  STA: %s\n", staStr);
    printf("║  Type: %s\n", rec->type == CAP_PMKID ? "PMKID" : (rec->is_full ? "Full 4-Way" : "Crackable Pair"));
    if (rec->type == CAP_PMKID) {
        printf("║  PMKID: ");
        for (int i = 0; i < 16; i++) printf("%02x", rec->pmkid[i]);
        printf("\n");
    }
    printf("╚══════════════════════════════════════════════════════╝\n");
}

// ============================
// SPIFFS Init
// ============================
static void init_spiffs(void) {
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        LOG_E(TAG, "Failed to mount SPIFFS");
        return;
    }
    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret == ESP_OK) {
        LOG_I(TAG, "SPIFFS mounted. Total: %d, Used: %d", total, used);
    }
}

// ============================
// Print Menu
// ============================
static void printMenu(void) {
    printf("\n╔══════════════════════ MENU ════════════════════════╗\n");
    printf("║  [1] Scanner                                          ║\n");
    printf("║  [2] Deauth Attack (Unicast/Fuzzing)                ║\n");
    printf("║  [3] Beacon Spammer                                  ║\n");
    printf("║  [4] Probe Sniffer                                   ║\n");
    printf("║  [5] Packet Analyzer (PMKID/SAE/Enterprise)          ║\n");
    printf("║  [6] Handshake Capture (Full 4-Way, CSA)            ║\n");
    printf("║  [7] Evil Twin + Captive Portal                      ║\n");
    printf("║  [a] AutoTarget (Wardriving) Toggle                  ║\n");
    printf("║  [i] System Info                                     ║\n");
    printf("║  [s] STOP current operation                         ║\n");
    printf("║  [m] Menu                                           ║\n");
    printf("║  [r] Restart                                        ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
}

// ============================
// AutoTarget Loop
// ============================
static void autoTargetLoop(void) {
    if (!autoTargetEnabled) return;
    if (millis() - lastAutoScan < CFG_AUTO_TARGET_INTERVAL_MS) return;
    lastAutoScan = millis();

    ApRecord best;
    int idx = getBestApByScore(&best);
    if (idx >= 0) {
        LOG_I(TAG, "AutoTarget: Best AP: %s Ch:%d RSSI:%d", best.ssid, best.channel, best.rssi);
        g_stop = false;
        startHandshakeCapture(best.bssid, best.channel, best.ssid, true, &g_stop);
    }
}

// ============================
// app_main
// ============================
void app_main(void) {
    // 1. NVS init
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 2. Netif + Event Loop
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // 3. WiFi init (basic)
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    // 4. SPIFFS init
    init_spiffs();

    // 5. Handshake callback
    setHandshakeCallback(onHandshake);

    // 6. Set Tx power
    setTxPower(CFG_TX_POWER);

    // 7. Print welcome
    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║   ESP32 Wi-Fi Security Toolkit  v1.0 (ESP-IDF)      ║\n");
    printf("║   All-in-One Advanced Pentesting Tool                ║\n");
    printf("║   Features: Unicast Deauth, WPA3/SAE, CSA, PCAPNG   ║\n");
    printf("║   AutoTarget (Wardriving), System Info               ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    printMenu();
    LOG_I(TAG, "Ready. Press 'm' for menu.");

    // 8. Main loop
    while (1) {
        autoTargetLoop();

        if (getchar() != EOF) {
            char choice = readCharFromSerial();
            serialFlush();
            if (choice == '\n' || choice == '\r') continue;
            printf("%c\n", choice);

            switch (choice) {
                case '1': {
                    g_stop = false;
                    wifiScanner();
                    break;
                }
                case '2': {
                    wifiScanner();
                    printf("Target index: ");
                    int idx = readIntFromSerial();
                    if (idx < 0 || idx >= getApCount()) {
                        printf("Invalid index.\n");
                        break;
                    }
                    ApRecord ap;
                    getAp(idx, &ap);
                    printf("Client MAC (or 0 for broadcast): ");
                    char macStr[20] = {0};
                    scanf("%s", macStr);
                    uint8_t clientMac[6];
                    bool hasClient = false;
                    if (strlen(macStr) > 2 && strcmp(macStr, "0") != 0) {
                        sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                               &clientMac[0], &clientMac[1], &clientMac[2],
                               &clientMac[3], &clientMac[4], &clientMac[5]);
                        hasClient = true;
                    }
                    g_stop = false;
                    deauthAttack(ap.bssid, hasClient ? clientMac : NULL, ap.channel,
                                 CFG_DEAUTH_CONTINUOUS, &g_stop);
                    break;
                }
                case '3': {
                    printf("Number of fake SSIDs (1-20): ");
                    int cnt = readIntFromSerial();
                    printf("Prefix (or blank): ");
                    char prefix[33] = {0};
                    scanf("%s", prefix);
                    g_stop = false;
                    beaconSpammer(cnt, prefix[0] ? prefix : NULL, &g_stop);
                    break;
                }
                case '4': {
                    printf("Duration (0=infinite): ");
                    uint32_t dur = readIntFromSerial();
                    g_stop = false;
                    probeSniffer(dur, &g_stop);
                    break;
                }
                case '5': {
                    printf("Channel (1-13): ");
                    int ch = readIntFromSerial();
                    printf("Duration (0=infinite): ");
                    uint32_t dur = readIntFromSerial();
                    g_stop = false;
                    packetAnalyzer((uint8_t)ch, dur, &g_stop);
                    break;
                }
                case '6': {
                    wifiScanner();
                    printf("Target index: ");
                    int idx = readIntFromSerial();
                    if (idx < 0 || idx >= getApCount()) {
                        printf("Invalid index.\n");
                        break;
                    }
                    ApRecord ap;
                    getAp(idx, &ap);
                    printf("Use Deauth? (y/n): ");
                    char yn[2] = {0};
                    scanf("%s", yn);
                    bool useDeauth = (yn[0] == 'y' || yn[0] == 'Y');
                    g_stop = false;
                    startHandshakeCapture(ap.bssid, ap.channel, ap.ssid, useDeauth, &g_stop);
                    break;
                }
                case '7': {
                    wifiScanner();
                    printf("Target index: ");
                    int idx = readIntFromSerial();
                    if (idx < 0 || idx >= getApCount()) {
                        printf("Invalid index.\n");
                        break;
                    }
                    ApRecord ap;
                    getAp(idx, &ap);
                    g_stop = false;
                    evilTwin(ap.ssid, ap.channel, ap.bssid, &g_stop);
                    break;
                }
                case 'a':
                case 'A': {
                    autoTargetEnabled = !autoTargetEnabled;
                    printf("AutoTarget %s\n", autoTargetEnabled ? "ON" : "OFF");
                    if (autoTargetEnabled) lastAutoScan = 0;
                    break;
                }
                case 'i':
                case 'I': {
                    printf("Heap: %u bytes\n", esp_get_free_heap_size());
                    printf("Uptime: %lu s\n", millis()/1000);
                    printf("AutoTarget: %s\n", autoTargetEnabled ? "ON" : "OFF");
                    break;
                }
                case 's':
                case 'S':
                    g_stop = true;
                    printf("[STOP] Operation stopped.\n");
                    break;
                case 'm':
                case 'M':
                    printMenu();
                    break;
                case 'r':
                case 'R':
                    esp_restart();
                    break;
                default:
                    break;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
