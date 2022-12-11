#!/bin/bash
echo "What is your iport?"
read iport
echo "iport : $iport"
echo "What is your oport?"
read oport
echo "oport : $oport"

nft " add table ip HRP "

nft " add map HRP daddr_rec { type ipv4_addr : ipv4_addr ; } "
nft " add map HRP dport_rec { type ipv4_addr : inet_service ; } "

nft " add chain HRP output_not { type filter hook output priority -300 ; } "
nft " add rule HRP output_not udp sport $oport ip daddr set ip saddr map @daddr_rec "
nft " add rule HRP output_not udp sport $oport udp dport set ip saddr map @dport_rec notrack "

nft " add chain HRP output_redir { type nat hook output priority 0 ; } "
nft " add rule HRP output_redir udp sport 5060 update @daddr_rec { ip saddr : ip daddr } "
nft " add rule HRP output_redir udp sport 5060 update @dport_rec { ip saddr : udp dport } "
nft " add rule HRP output_redir udp sport 5060 redirect to :$iport "


nft " add chain HRP postrouting { type filter hook postrouting priority -300 ; } "
nft " add rule HRP postrouting udp sport $oport udp sport set 5060 notrack "
# SNAT packets as if they are from SIP softphone.