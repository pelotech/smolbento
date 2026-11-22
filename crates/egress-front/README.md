# egress-front

A small library that fronts a smolvm machine's egress on the host: it relays the machine's
connections, applies egress rules, and substitutes credentials. It is the only crate that depends on
smolvm's `smolvm-credentials` and `smolvm-protocol` (git dependencies at the tag in `smolvm.lock`),
and it re-exports what its users need.

It is written to be lifted into smolvm, so it names nothing of its users. Each piece has an upstream home:

| Piece | Upstream home |
|---|---|
| relay | a "spawn on a given listener" interceptor constructor in `smolvm-credentials` |
| egress rules | `smolvm-network` egress checks |
| request matcher | `smolvm-protocol` |
