#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include "utils.h"
#include "config.h"

#define TAG_PA "PKTANAL"

void packetAnalyzer(uint8_t channel, uint32_t durationSec, volatile bool* stopFlag);

#endif // PACKET_ANALYZER_H
