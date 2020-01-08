# First cleanup everything
iptables -t filter -F
iptables -t filter -X
ip6tables -t filter -F
ip6tables -t filter -X