set -e

iptables -A INPUT -t mangle -j CONNMARK --restore-mark
iptables -A INPUT -t mangle -m mark ! --mark 0 -j ACCEPT
iptables -A INPUT -t mangle -p tcp --dport "${PORT}" -j MARK --set-mark 0x10000
iptables -A INPUT -t mangle -p tcp --dport "${PORT}" -j MARK --or-mark "${FILTER_QUEUE}"
iptables -A INPUT -t mangle -j CONNMARK --save-mark
iptables -A OUTPUT -t mangle -j CONNMARK --restore-mark

iptables -A INPUT -m mark --mark 0x10000/0xffff0000 -m mark --mark "${FILTER_QUEUE}/0xffff" -j NFQUEUE --queue-num "${FILTER_QUEUE}"
iptables -A OUTPUT -m mark --mark 0x10000/0xffff0000 -m mark --mark "${FILTER_QUEUE}/0xffff" -j NFQUEUE --queue-num "${FILTER_QUEUE}"

$@
