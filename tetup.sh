#!/bin/bash
echo "What is your iport?"
read iport
echo "iport : $iport"

nft " add table ip HRP "

nft " add chain HRP prerouting { type filter hook prerouting priority -150 ; } "
nft " add rule HRP prerouting udp sport 5060 tproxy to :$iport meta mark set 1 accept "

nft " add chain HRP output { type route hook output priority 0 ; } "
nft " add rule HRP output udp sport 5060 meta mark set 1 "

ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
