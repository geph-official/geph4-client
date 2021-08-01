## the bridge

maintains a connection to each Geph exit server using an "exit manager". This exit manager authenticates with the exit server, from which it obtains a port and `sosistab` public key. It then configures `iptables` to route traffic from a randomly chosen port of the bridge to the given port of the exit. This way, the bridge directly forwards packets without processing them.