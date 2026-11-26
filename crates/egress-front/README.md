# egress-front

A small library that fronts a smolvm machine's egress on the host: it takes the listener its service
manager hands it (socket activation) and relays each of the machine's connections to smolvm's
interceptor, which substitutes credentials. It is the only crate that depends on smolvm's
`smolvm-credentials` and `smolvm-protocol` (git dependencies at a tag on the smolvm fork made by
`just smolvm-fork`, see the comment in `Cargo.toml`), and it re-exports what its users need.

Each flow is decided by the caller's `Decide` hook twice: from smolvm's preamble (destination
address and port, no name), and again from the first bytes the machine sends, with the name they ask
for (TLS SNI, else an HTTP request's single `Host:`, after any empty lines), and what they are
(`Tls`, `Http` or `Other`; TLS or HTTP with no name is still `Tls` or `Http`). The first-bytes read
waits for the machine's first bytes as long as the handshake timeout, as the interceptor does, and an
HTTP request line it has begun may take the rest of that one deadline. It ends at a whole ClientHello,
the end of the HTTP headers (`\n` line ends with an optional `\r`), 16 KiB, or 200 ms with nothing more. A
machine that sends nothing in time is closed without the second decide. A destination deny answers
`ECONNREFUSED`; a name deny closes the flow and sends the interceptor nothing. An allowed flow to
smolvm's gateway (`100.96.0.1`) is dialled as `127.0.0.1`.

It is written to be lifted into smolvm, so it names nothing of its users. Each piece has an upstream home:

| Piece | Upstream home |
|---|---|
| relay | a "spawn on a given listener" interceptor constructor in `smolvm-credentials` |
| flow decisions (`Decide`) | `smolvm-network` egress checks |
| request rules (`Policy`) | `smolvm-protocol` |

`broad_ca(machine)` mints a machine CA with no name constraint, for a machine whose decrypted hosts
change while it runs. The interceptor still decrypts only its `terminate_hosts`.

## Request rules

`Policy` holds request rules for decrypted hosts: `terminate_hosts()` lists the hosts to decrypt,
`inspection(host, port)` says whether rules apply to a connection, and `request(..)` judges one
request. The doc comments in `src/rules/mod.rs` and `src/rules/path.rs` say how requests match.
