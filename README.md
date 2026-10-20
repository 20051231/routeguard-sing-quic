# sing-quic

RouteGuard's derivative of [SagerNet/sing-quic](https://github.com/SagerNet/sing-quic),
based on commit `497364e8ee3e0d4d181dca740269816a84029c24`. Upstream copyright and
[GPLv3 license](LICENSE) remain applicable. This fork adds credential-free Hysteria2
warm authentication and local session snapshots for the RouteGuard standby pool.
An active local QUIC context is distinct from fresh remote reachability evidence.

quic-go API wrapper and QUIC based protocol implementations.
