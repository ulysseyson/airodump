#include "main.h"
using namespace std;

map <Mac, dot11_frame_info_t> cache;

void usage(){
    cout<<"syntax : airodump <interface>\n";
    cout<<"sample : airodump mon0\n";
}

void console_log(){
    system("clear");  
    cout << "BSSID              PWR  Beacons  ENC  ESSID\n";
    cout << "-------------------------------------------\n";
    for (auto it:cache){
        cout << string(it.first) << "  " << it.second.PWR << "  " << it.second.Beacons << "      " << it.second.ENC << "  " << it.second.ESSID << "\n";
    }
    cout << "\n";

}
void airodump(const u_char *packet, int length){
    radiotap_header_t *rt_header = (radiotap_header_t *)packet;
    beacon_frame_t *beacon = (beacon_frame_t *)(packet + rt_header->it_len);

    // check beacon frame
    if (beacon->frame_control[0] != 0x80) return;
    
    if (cache.find(beacon->bssid) == cache.end()){
        dot11_frame_info_t info;
        info.Beacons = 0;
        info.PWR = (int)(signed char)rt_header->dbm_antenna_signal;
        // return;
        int data_start_idx = rt_header->it_len + sizeof(beacon_frame_t) + FIXED_PARAM_SIZE;
        while(data_start_idx < length){
            int tag_num = packet[data_start_idx];
            int tag_len = packet[data_start_idx + 1];
            memcpy(info.ENC, "None     \0", 10);
            if (data_start_idx + tag_len + 2 >= length) break;
            if (tag_num == 0) {
                memcpy(info.ESSID, packet + data_start_idx + 2, tag_len);
                info.ESSID[tag_len] = '\0';
            }
            else if (tag_num == 0x30) {
                rsn_hdr_t *rsn = (rsn_hdr_t *)(packet + data_start_idx + 2);
                int wpa_version = packet[data_start_idx + 2 + sizeof(rsn_hdr_t) + 4 * rsn->pairwise_cipher_count + 5];
                if (wpa_version == 2) {
                    memcpy(info.ENC, "WPA2     \0", 10);
                }
                else {
                    memcpy(info.ENC, "WPA      \0", 10);
                }
            }
            
            data_start_idx += (tag_len + 2);
            // cout << "tag pass\n" << data_start_idx << " " << length << "\n";
        }
        cache[beacon->bssid] = info;
    }
    else {
        cache[beacon->bssid].Beacons++;
    }
    console_log();
}

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }

	char* dev = argv[1];
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        airodump(packet, header->caplen);
    }

}