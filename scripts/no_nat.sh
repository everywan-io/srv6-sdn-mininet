# First cleanup everything
iptables -t nat -F
iptables -t nat -X
ip6tables -t nat -F
ip6tables -t nat -X