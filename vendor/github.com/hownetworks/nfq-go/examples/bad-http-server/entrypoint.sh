iptables -A OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0
iptables -A INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0

$@
