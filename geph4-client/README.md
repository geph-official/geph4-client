## The client

starts logging and executes one of 4 subcommands, depending on the command-line arguments:

1. [**Connect**](https://github.com/geph-official/geph4/blob/master/geph4-client/src/main_connect.rs) is the main subcommand. It opens a tunnel to a Geph exit server, optionally through bridges, through which client traffic can be proxied. It restarts automatically upon failure.

    - How: the main process starts an identical child process, redirecting its stderr to a log file. The child process listens on 3 ports:
        1) Stats: handles requests for the debug pack, proxy information, program termination, and general statistics.
        2) SOCKS5: handles connections from SOCKS5 clients (e.g., browsers) and establishes connections to the provided IPv4 destinations. Traffic is then forwarded between the local SOCKS5 connection and the destination. If the `exclude_prc` flag is set AND the destination address is in PRC, then the connection is directly established, bypassing Geph. Otherwise, the connection is established through Geph, using a [TunnelManager](https://github.com/geph-official/geph4/tree/master/geph4-client/src/tunman).

            -  To open a connection, the `TunnelManager` creates a channel and sends the sending end of the new channel, along with the destination address, to its background task. The background task then establishes a [sosistab](https://docs.rs/sosistab/0.1.1/sosistab/) session, with/without bridges, in TCP/UDP mode, in/not in VPN mode, etc., depending on the inputs:
                - If the client is in China, then we always use bridges. If not, we proceed according to the `use_bridges` flag.
                    - If bridges are used, we retrieve a list of bridges and race connection attempts to all of them. We choose the bridge that connects most quickly. 
                - If we are in [VPN mode](https://github.com/geph-official/geph4/blob/master/geph4-client/src/vpn.rs), then the whole client program is actually started as the child process of the VPN helper. Besides the stats and proxy connections, we establish a VPN session, which relays packets/messages between the sosistab session and stdin/stdout. The [VPN helper](https://github.com/geph-official/geph4/tree/master/geph4-vpn-helper) arranges to redirect all outgoing network packets to `geph4-client`'s stdin, while reading incoming network packets from `geph4-client`'s stdout and injecting them into the operating system. On Linux, this redirection is accomplished using iptables; on windows, WinDivert.

        3) HTTP: handles connections from HTTP proxy clients. Internally, this just forwards traffic to the SOCKS5 listening port using the `socks2http` crate.
        
        Should the child process exit on error, the main process restarts the child.

2. [**Sync**](https://github.com/geph-official/geph4/blob/master/geph4-client/src/main_sync.rs) retrieves user information from the binder and prints it to stdout. It is used by the graphical UI to display the username, expiration date, list of exits, etc.

    <!-- - How: takes in a SyncOpt (which includes information required to access the binder, authenticate the user, and a force-synchronization flag) and returns 3 pieces of information:
        1) user authentication token
        2) list of all exits
        3) list of free exits from the ClientCache.  -->

    - If the `force` flag is set, then all 3 pieces of information are retrieved afresh from the binder. Manually pressing refresh in the UI sets the `force` flag, for example. If any piece of cached information is too old, then it is also fetched from the binder and updated. 

3. [**BinderProxy**](https://github.com/geph-official/geph4/blob/master/geph4-client/src/main_binderproxy.rs) connects to the binder and handles requests involved in creating a new user.

4. [**BridgeTest**](https://github.com/geph-official/geph4/blob/master/geph4-client/src/main_bridgetest.rs) attempts to establish a UDP connection to every bridge in the Geph network and prints the amount of time taken for each bridge to stderr. This is used for testing.

<!-- 

CommonOpt: information required by all 4 subcommands. Includes the address of the binder and certain public keys.

AuthOpt: information needed for user authentication. 

SyncOpt: a CommonOpt, an AuthOpt, and a force-synchronization flag
 -->
