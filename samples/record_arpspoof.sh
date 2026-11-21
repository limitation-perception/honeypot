#!/bin/sh
set -eu

cleanup() {
    ip netns del victim 2>/dev/null || true
    ip netns del attacker 2>/dev/null || true
    ip link del br0 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip link add br0 type bridge ageing_time 0
ip link set br0 address 02:00:00:00:00:01
ip addr add 10.0.0.1/24 dev br0
ip link set br0 up

add_host() {  # ім'я  IP  MAC
    ip netns add "$1"
    ip link add "v-$1" type veth peer name eth0 netns "$1"
    ip link set "v-$1" master br0 up
    ip -n "$1" link set eth0 address "$3"
    ip -n "$1" addr add "$2/24" dev eth0
    ip -n "$1" link set eth0 up
}
add_host victim   10.0.0.2  02:00:00:00:00:02
add_host attacker 10.0.0.66 02:00:00:00:00:66

tcpdump -i br0 -s 128 -U -w samples/arpspoof.pcap arp &
TCPDUMP=$!
sleep 1

ip netns exec victim   ping -c 2 10.0.0.1 >/dev/null
ip netns exec attacker ping -c 2 10.0.0.2 >/dev/null

ip netns exec attacker timeout 5 arpspoof -i eth0 -t 10.0.0.2 10.0.0.1 >/dev/null 2>&1 || true

sleep 1
kill -INT "$TCPDUMP"
wait "$TCPDUMP" || true
chown "${SUDO_USER:-root}" samples/arpspoof.pcap
echo "done: samples/arpspoof.pcap"