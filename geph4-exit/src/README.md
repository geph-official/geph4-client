## the exit

listens for control protocol connections from bridges and direct connections from clients while collecting statistics.
- Upon receiving a control protocol connection request, the exit first authenticates with the bridge and then finds a free port on which to listen for `sosistab` connection requests. It then sends over this port, along with a `sosistab` public key, to the requesting bridge and reports this new binding to the binder. Then, [the session handler](https://github.com/geph-official/geph4/blob/master/geph4-exit/src/listen/session.rs) takes care of each incoming `sosistab` session.
    - [The session handler](https://github.com/geph-official/geph4/blob/master/geph4-exit/src/listen/session.rs) first authenticates the session, rejecting the connection or applying a [speed limit](https://github.com/geph-official/geph4/blob/master/geph4-exit/src/ratelimit.rs) if the request is from a non-plus user. Then, it listens for proxy and VPN connection requests. 
        - Proxy requests are handled by the [proxy_loop](https://github.com/geph-official/geph4/blob/master/geph4-exit/src/connect.rs), which connects to a remote host and forwards traffic to/from it and a given client.
        - VPN packets are handled by [handle_vpn_session](https://github.com/geph-official/geph4/blob/master/geph4-exit/src/vpn.rs), which allots the client an internal IP address and forwards all packets associated with that IP address to/from the client. Network address translation is done by `iptables` (??).

- The exit also directly listens for `sosistab` connection requests as a sort of "self-bridge". Such requests are also handed off to [the session handler](https://github.com/geph-official/geph4/blob/master/geph4-exit/src/listen/session.rs).
