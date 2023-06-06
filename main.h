#include <bits/stdc++.h>
#include <iostream>
#include "mac.h"
#include "dot11.h"
#include <pcap.h>

using namespace std;

typedef struct dot11_frame_info {
    int Beacons;
    int PWR;
    char ENC[10];
    char ESSID[10];
} dot11_frame_info_t;