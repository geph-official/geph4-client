# geph4-client
Geph (迷霧通) is a modular Internet censorship circumvention system designed specifically to deal with national filtering. 

`geph4-client` is the command-line Geph client. 

To install `geph4-client`, you need to first [install Rust](https://www.rust-lang.org/tools/install), then run 

```shell!
cargo install geph4-client
``` 

in a terminal. To see a list of the subcommands and flags available, simply run 

```shell!
geph4-client -h
```

Below is how each subcommand works.

## 1. [`connect`](https://github.com/geph-official/geph4-client/blob/master/src/connect.rs)
Given user credentials and other optional inputs, `connect` establishes a network connection to a Geph exit server. If that exit server is blocked from the client, `connect` proxyies the connection through dynamical [bridge servers](https://github.com/geph-official/bridge-phalanx) that are not blocked in the region.

A typical `connect` command might look like:

```shell!
geph4-client connect --exit-server 2.mtl.ca.ngexits.geph.io auth-password --username public5 --password public5
```

Internally, `connect` 
1. makes a [`ClientTunnel`](https://github.com/geph-official/geph4-client/blob/master/src/connect/tunnel/mod.rs#L80) that manages a [`sosistab2`](https://github.com/geph-official/sosistab2) [`Multiplex`](https://github.com/geph-official/sosistab2/blob/master/src/multiplex/multiplex_struct.rs) session to the specified remote Geph server, and
2. enables `socks5` and `http` proxies through this `ClientTunnel`, as well as routing VPN packets.

### The `ClientTunnel`
A tunnel starts and keeps alive the best sosistab `Multiplex` session it can given the specified `connect` parameters. 

A sosistab2 `Multiplex` is *a single end-to-end connection between a client and a server.* This can be thought of as analogous to TcpStream, except all reads and writes are datagram-based and unreliable. For more on `Multiplex`, see [`sosistab2`](https://github.com/geph-official/sosistab2).

The `Multiplex` session consists of several routes to the exit server, both through different bridges and without bridges. (If the user is [in China](https://github.com/geph-official/geph4-client/blob/master/src/china/mod.rs#L51), then we only provide routes that use bridges, because all the exit servers are blocked by the Great Firewall.) The sositab protocol then monitors the routes and switches seamlessly to the best working route. Finally, The `ClientTunnel` [actively updates](https://github.com/geph-official/geph4-client/blob/master/src/connect/tunnel/getsess.rs#L142) the set of bridges used by its `Multiplex` to switch out servers that get blocked.

Finally, `ClientTunnel` exposes [channels](https://github.com/geph-official/geph4-client/blob/master/src/connect/tunnel/mod.rs#L85) to the `Multiplex` for handling proxy requests and packet forwarding for VPN mode.

### Proxies

`connect` sets up [two proxy servers](https://github.com/geph-official/geph4-client/blob/master/src/connect.rs#L112) on localhost. By default, the `socks5` server listens on `127.0.0.1:9909`, and `http` listens on `127.0.0.1:9910`. These ports can be changed with the `--socks5-listen` and `--http-listen` flags.  These localhost servers accept proxy connections and fulfills requests by forwarding them to the `ClientTunnel`, after which they are proxied through the exit server.

When the `socks5` server accepts a connection, it establishes a [`sosistab2` reliable stream](https://github.com/geph-official/sosistab2/blob/master/src/multiplex/stream/mod.rs#L33) along with a task to forward all traffic from the `socks5` connection to the `sosistab` stream.

The `http` server is the `socks5` server converted using an adaptation of the [`socks2http`](https://github.com/xVanTuring/socks2http-rs) repo.

### VPN
[VPN mode](https://github.com/geph-official/geph4-client/blob/master/src/connect/vpn.rs#L47) takes packets from the source specified by `--vpn-mode` and sends them over a UDP-like unreliable connection on the `ClientTunnel`. 

Starting `geph4-client` in VPN mode on Linux might look like:
```shell!
sudo $(which geph4-client) connect --vpn-mode tun-route --exit-server 2.mtl.ca.ngexits.geph.io auth-password --username public5 --password public5
```

Note that VPN mode requires us to run `geph4-client` with root privileges. We use `$(which geph4-client)` because `geph4-client` might not be in `root`'s path.

- On Linux, use `--vpn-mode tun-route`. [This](https://github.com/geph-official/geph4-client/blob/master/src/connect/vpn.rs#L171) starts `geph4-client` in VPN mode, starts a TUN device, and route all packets to it using [`iptables`](https://en.wikipedia.org/wiki/Iptables).
- On Windows, use `--vpn-mode windivert`. This routes packets to it using [`Windivert`](https://reqrypt.org/windivert.html).
- VPN mode is currently not support for MacOS. Contributions are welcome!


## 2. [`sync`](https://github.com/geph-official/geph4-client/blob/master/src/sync.rs)
`sync` takes in a user's credentials and obtains the latest information about the user's subscription status, as well as what exits there are. 

To bypass censorship, we connect to the binder using [domain fronting](https://en.wikipedia.org/wiki/Domain_fronting). To mitigate attacks in the case that an attacker compromises the central Geph binder, we verify the exit list given by the binder against a public record on the [Mel blockchain](https://melproject.org/en/). You can read more about Geph's use of the blockchain [here](https://medium.com/themelio/mel-geph-securing-a-production-vpn-app-with-mel-light-clients-9e910d83507).

`sync` is designed to be used by the [GUI interface](https://github.com/geph-official/gephgui) around `geph4-client`.


## 3. [`binder_proxy`](https://github.com/geph-official/geph4-client/blob/master/src/binderproxy.rs)
`binder_proxy` creates a `BinderClient` that is a `JSON-RPC` client to the Geph binder. This is used by `gephgui` for things like obtaining exit statistics and user registration and deletion.


## 4. [`debugpack`](https://github.com/geph-official/geph4-client/blob/master/src/debugpack.rs)
```shell!
geph4-client debugpack --export-to /your/preferred/path/
```

exports an [`SQLite`](https://www.sqlite.org/index.html) database containing Geph's debug logs to `/your/preferred/path/`. 


## 5. iOS support
`geph4-client` also supports compiling as a universal `C` library for calling on iOS (this is because you cannot start a new process on iOS; on other platforms we start `geph4-client` in a new process). One difference to note is that this version of `geph4-client` completely avoids using `stdin/out` for any communication, as doing so would crash the app on iOS. Most of the logic surrounding iOS support is in [`ios.rs`](https://github.com/geph-official/geph4-client/blob/master/src/ios.rs).
