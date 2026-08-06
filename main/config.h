#ifndef CONFIG_H
#define CONFIG_H

#define CFG_SERIAL_BAUD          115200
#define CFG_SERIAL_TIMEOUT_MS    15000

#define CFG_CHANNEL_MIN          1
#define CFG_CHANNEL_MAX          13
#define CFG_CHANNEL_HOP_DWELL_MS 500

#define CFG_SCAN_SHOW_HIDDEN     true
#define CFG_SCAN_MAX_NETWORKS    40

#define CFG_TX_POWER             72

#define CFG_TX_RETRY_COUNT       3
#define CFG_TX_RETRY_DELAY_US    150

#define CFG_TASK_STACK_BYTES     8192
#define CFG_TASK_PRIORITY        4

#define CFG_DEAUTH_REASON_AP     7
#define CFG_DISASSOC_REASON      8
#define CFG_DEAUTH_INTER_US      200
#define CFG_DEAUTH_PRINT_EVERY   1000
#define CFG_DEAUTH_CONTINUOUS    0xFFFF
#define CFG_DEAUTH_REASON_CYCLING true
#define CFG_DEAUTH_REASONS       {1,2,4,7,8,15}

#define CFG_BEACON_MAX_SSIDS     20
#define CFG_BEACON_INTER_US      300
#define CFG_BEACON_LOOP_DELAY_MS 5
#define CFG_BEACON_ROTATE_EVERY  10
#define CFG_BEACON_INTERVAL_TU   100
#define CFG_BEACON_MAX_FRAME_LEN 512

#define CFG_SNIFFER_MAX_DEVICES  50
#define CFG_SNIFFER_HOP_MS       200
#define CFG_SNIFFER_RING_SIZE    64
#define CFG_SNIFFER_MAX_PKT_LEN  512

#define CFG_PA_RING_SIZE         64
#define CFG_PA_MAX_PKT_LEN       400
#define CFG_PA_STATS_EVERY_MS    10000

#define CFG_ET_AP_IP             { 192, 168, 4, 1 }
#define CFG_ET_MAX_CREDS         30
#define CFG_ET_STATUS_EVERY_MS   10000
#define CFG_ET_DNS_PORT          53
#define CFG_ET_HTTP_PORT         80

#define CFG_HS_DEAUTH_INTERVAL_MS  300
#define CFG_HS_MAX_PCAP_SIZE       65536
#define CFG_HS_TIMEOUT_SEC         120
#define CFG_HS_AP_SSID            "Handshake_AP"
#define CFG_HS_AP_PASS            "capture123"
#define CFG_HS_AP_IP              { 192, 168, 4, 1 }
#define CFG_HS_HTTP_PORT          80

#define CFG_AUTO_TARGET_INTERVAL_MS 5000
#define CFG_AUTO_TARGET_MIN_SCORE  -500

#define CFG_WDT_YIELD_TICKS      pdMS_TO_TICKS(1)

#endif // CONFIG_H
