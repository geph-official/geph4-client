    export PATH=$PATH:/usr/sbin/:/sbin/
    # mark the owner
    iptables -D OUTPUT -t mangle -m owner ! --uid-owner `id -u` -j MARK --set-mark 8964
    iptables -A OUTPUT -t mangle -m owner ! --uid-owner `id -u` -j MARK --set-mark 8964
    iptables -D OUTPUT -t mangle -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j MARK --set-mark 11111
    iptables -A OUTPUT -t mangle -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j MARK --set-mark 11111
    # set up routing tables
    ip route flush table 8964
    ip route add default dev tun-geph table 8964
    ip rule del fwmark 8964 table 8964
    ip rule add fwmark 8964 table 8964
    # mangle
    iptables -t nat -D POSTROUTING -o tun-geph -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tun-geph -j MASQUERADE
    # redirect DNS
    iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT -m owner ! --uid-owner `id -u` --to 1.1.1.1:53
    iptables -t nat -D OUTPUT -p tcp --dport 53 -j DNAT -m owner ! --uid-owner `id -u` --to 1.1.1.1:53
    iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT -m owner ! --uid-owner `id -u` --to 1.1.1.1:53
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT -m owner ! --uid-owner `id -u` --to 1.1.1.1:53
    # clamp MTU
    iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
    # block non-Geph ipv6 completely
    ip6tables -D OUTPUT -o lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -D OUTPUT -m owner ! --uid-owner `id -u` -j REJECT
    ip6tables -A OUTPUT -m owner ! --uid-owner `id -u` -j REJECT