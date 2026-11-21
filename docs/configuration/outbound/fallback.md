---
icon: material/new-box
---

!!! question "Since sing-box 1.15.0"

### Structure

```json
{
  "type": "fallback",
  "tag": "fallback",

  "outbounds": [
    "wireguard",
    "openvpn"
  ],
  "timeout": "",
  "interrupt_exist_connections": false
}
```

### Fields

#### outbounds

==Required==

List of outbound tags in order of preference.

The first connected outbound is selected. An outbound that is not connected yet holds the selection until it connects, fails or its `timeout` expires, so the outbounds after it are only considered once it has been waited for. The group switches back to an earlier outbound as soon as it is connected again. If no outbound is connected, the first one is selected.

The same outbound is selected for TCP and UDP.

#### timeout

How long to wait for an outbound to connect before falling back to the next one, and for a connected outbound to reconnect after losing its connection. `10s` will be used if empty.

WireGuard retransmits a handshake initiation 5 seconds after the previous one, plus up to 333 milliseconds, so the default allows one retransmission.

Outbounds that are not connected are waited for one after another, so with several of them the group may need a multiple of `timeout` to fall back. When a `fallback` group is used as an outbound of another one, give the outer group a `timeout` at least as long as the inner group needs to fall back.

An outbound that reports a terminal error is skipped without waiting.

While the device is paused or the network is unavailable, the group does not fall back, and outbounds that are not connected are waited for again afterwards.

#### interrupt_exist_connections

Interrupt existing connections of the previous outbound when switching back to an earlier outbound.

When the group switches away from an outbound that is not connected, its existing connections are always interrupted.

Only inbound connections are affected by this setting, internal connections will always be interrupted.

### Connection state

The group does not perform URL tests: it uses the connection state reported by each outbound itself.

| Type             | Connected when                                                                                   |
|------------------|--------------------------------------------------------------------------------------------------|
| `wireguard`      | Every peer with an `address` has an established session (a completed handshake that has not expired). A WireGuard endpoint without such a peer is always connected. |
| `openvpn-client` | The tunnel is established and configured. While it waits for an authentication challenge to be answered, it is not connected. A terminal error, such as an authentication failure with `auth_retry` set to `none`, is reported as failed. |
| `openconnect`    | The tunnel is established and configured. A terminal error is reported as failed.               |
| `fallback`       | Its selected outbound is connected. It is reported as failed when all of its outbounds failed.  |

Other outbounds, including `selector` and `urltest` groups, have no connection state and are always considered connected, so the outbounds after such an outbound are never used. Placed last, such an outbound (for example `direct`) carries the traffic whenever every outbound before it is down: do not add one if traffic must never leave the tunnels.

The group keeps the selected outbound and the outbounds before it connected, or all outbounds if none is connected. A WireGuard endpoint then initiates handshakes by itself, also when it carries no traffic, and forces a fresh handshake after a network change so that its state reflects the new network path. While the group waits to switch back to it, a WireGuard endpoint keeps retrying its handshake, as it already does when `persistent_keepalive_interval` is set. While an outbound is connected, the outbounds after it are not used, and their on-demand endpoints are suspended (see `on_demand` of [WireGuard](/configuration/endpoint/wireguard/#on_demand), [OpenVPN](/configuration/endpoint/openvpn-client/#on_demand) and [OpenConnect](/configuration/endpoint/openconnect/#on_demand)).

A `fallback` group used as an outbound of another group keeps its own first outbound connected, also while the other group has not selected it.

!!! note ""

    A WireGuard handshake that does not complete only means that no authenticated response was received: the server may be unreachable, UDP may be filtered, or the keys may not match.

!!! warning ""

    Without a network change, a WireGuard session that silently stops working is only detected when WireGuard expires it, up to 3 minutes after its last handshake.
