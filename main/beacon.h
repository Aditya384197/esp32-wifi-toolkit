#ifndef BEACON_H
#define BEACON_H

#include "utils.h"
#include "config.h"

#define TAG_BEACON "BEACON"

void beaconSpammer(int ssidCount, const char* prefix, volatile bool* stopFlag);

#endif // BEACON_H
