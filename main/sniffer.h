#ifndef SNIFFER_H
#define SNIFFER_H

#include "utils.h"
#include "config.h"

#define TAG_SNIFF "SNIFF"

void probeSniffer(uint32_t durationSec, volatile bool* stopFlag);

#endif // SNIFFER_H
