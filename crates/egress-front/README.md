# egress-front

A small library that fronts a smolvm machine's egress on the host: it takes the listener its service
manager hands it (socket activation) and relays each of the machine's connections to smolvm's
interceptor, which substitutes credentials. It is the only crate that depends on smolvm's
`smolvm-credentials` and `smolvm-protocol` (git dependencies at a fork `rev`, see `Cargo.toml`), and
it re-exports what its users need.

It is written to be lifted into smolvm, so it names nothing of its users. Each piece has an upstream home:

| Piece | Upstream home |
|---|---|
| relay | a "spawn on a given listener" interceptor constructor in `smolvm-credentials` |
| egress rules (planned) | `smolvm-network` egress checks |
| request matcher (planned) | `smolvm-protocol` |
