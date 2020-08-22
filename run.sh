#! /bin/bash

apt install libmnl-dev
apt install libnfnetlink-dev
apt install libnetfilter-queue-dev

iptables -F
iptables -A OUTPUT -j NFQUEUE
iptables -A INPUT -j NFQUEUE

exit 0
