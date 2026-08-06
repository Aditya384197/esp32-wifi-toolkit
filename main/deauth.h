#ifndef DEAUTH_H
#define DEAUTH_H

#include "utils.h"
#include "config.h"
#include "scanner.h"

#define TAG_DEAUTH "DEAUTH"

void deauthAttack(const uint8_t* bssid,
                  const uint8_t* staMac,
                  uint8_t channel,
                  uint16_t count,
                  volatile bool* stopFlag);

#endif // DEAUTH_H
