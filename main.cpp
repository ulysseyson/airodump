#include "dot11.h"

#include <bits/stdc++.h>
#include <iostream>

using namespace std;

void usage(){
    cout<<"syntax : airodump <interface>\n";
    cout<<"sample : airodump mon0\n";
}

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }

    string interface = argv[1];
}