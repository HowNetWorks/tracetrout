iptables -A OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0
iptables -A INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0
iptables -A INPUT -p icmp --icmp-type time-exceeded -j NFQUEUE --queue-num 0

ip6tables -A OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0
ip6tables -A INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0
ip6tables -A INPUT -p icmpv6 --icmpv6-type time-exceeded -j NFQUEUE --queue-num 0

$@
