#include "main.h"
using namespace std;

map <Mac, dot11_frame_info_t> cache;

void usage(){
    cout<<"syntax : airodump <interface>\n";
    cout<<"sample : airodump mon0\n";
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
        cout << "PWR: " << info.PWR << "\n";
        cout << "BSSID: " << string(beacon->bssid) << "\n";
        int data_start_idx = rt_header->it_len + sizeof(beacon) + FIXED_PARAM_SIZE;
        while(data_start_idx < length){
            int tag_num = packet[data_start_idx];
            int tag_len = packet[data_start_idx + 1];
            if (data_start_idx + tag_len + 2 >= length) break;
            if (tag_num == 0) {
                memcpy(info.ESSID, packet + data_start_idx + 2, tag_len);
                cout << "tag num: " << tag_num << "\n";
                cout << "tag len: " << tag_len << "\n";
                cout << "ESSID: " << *(packet + data_start_idx + 2) << "\n";
                info.ESSID[tag_len] = '\0';
                cout << "ESSID: " << info.ESSID << "\n";
            }
            else if (tag_num == 0x30) {
                cout << "tag num: " << tag_num << "\n";
                cout << "tag len: " << tag_len << "\n";
                rsn_hdr_t *rsn = (rsn_hdr_t *)(packet + data_start_idx + 2);
                int cipher_count = rsn->pairwise_cipher_count;
                int wpa_version = packet[data_start_idx + 2 + sizeof(rsn_hdr_t) + 4 * rsn->pairwise_cipher_count + 5];
                cout << "WPA v" << wpa_version << " \n";
            }
            
            data_start_idx += (tag_len);
            // cout << "tag pass\n" << data_start_idx << " " << length << "\n";
        }
    }
    else {
        cache[beacon->bssid].Beacons++;
    }
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