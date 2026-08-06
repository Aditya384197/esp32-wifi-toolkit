#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include "utils.h"
#include "config.h"
#include "esp_http_server.h"
#include "esp_netif.h"

#define TAG_ET "EVILTWIN"

void evilTwin(const char* ssid, uint8_t channel,
              const uint8_t* realBssid,
              volatile bool* stopFlag);

#endif // EVIL_TWIN_H
