set -e

for CMD in iptables ip6tables; do
  command -v "${CMD}" > /dev/null 2>&1 || continue

  "${CMD}" -A INPUT -t mangle -j CONNMARK --restore-mark
  "${CMD}" -A INPUT -t mangle -m mark ! --mark 0 -j ACCEPT
  "${CMD}" -A INPUT -t mangle -p tcp --dport "${PORT}" -j MARK --set-mark 0x10000
  "${CMD}" -A INPUT -t mangle -p tcp --dport "${PORT}" -j MARK --or-mark "${FILTER_QUEUE}"
  "${CMD}" -A INPUT -t mangle -j CONNMARK --save-mark
  "${CMD}" -A INPUT -m mark --mark 0x10000/0xffff0000 -m mark --mark "${FILTER_QUEUE}/0xffff" -j NFQUEUE --queue-num "${FILTER_QUEUE}"

  "${CMD}" -A OUTPUT -t mangle -j CONNMARK --restore-mark
  "${CMD}" -A OUTPUT -m mark --mark 0x10000/0xffff0000 -m mark --mark "${FILTER_QUEUE}/0xffff" -j NFQUEUE --queue-num "${FILTER_QUEUE}"
done

exec "$@"