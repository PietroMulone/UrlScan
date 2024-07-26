#!/bin/bash
wfuzz -t 20  -w ../BlindDiscovery.txt -u https://aliexpress.com/FUZZ  --hh 357 -f temp,raw
sleep 50
