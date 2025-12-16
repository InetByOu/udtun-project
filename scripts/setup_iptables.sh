#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j DNAT --to :5667
iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -j MASQUERADE
