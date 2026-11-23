# egress-front

A small library that fronts a smolvm machine's egress on the host: it takes the listener its service
manager hands it (socket activation) and relays each of the machine's connections to smolvm's
interceptor, which substitutes credentials. It is the only crate that depends on smolvm's
`smolvm-credentials` and `smolvm-protocol` (git dependencies at a tag on the smolvm fork made by
`just smolvm-fork`, see the comment in `Cargo.toml`), and it re-exports what its users need.

Each flow is decided by the caller's `Decide` hook twice: from smolvm's preamble (destination address
and port, no name), and again from the first bytes the machine sends, with the name they ask for
(TLS SNI, else an HTTP request's `Host:`). The first-bytes read ends at a whole
ClientHello, the end of the HTTP headers, 16 KiB, or 200 ms with nothing more, so a flow whose server
speaks first (SSH) is decided without a name. A destination deny answers `ECONNREFUSED`; a name deny
closes the flow and sends the interceptor nothing. An allowed flow to smolvm's gateway (`100.96.0.1`)
is dialled as `127.0.0.1`.

It is written to be lifted into smolvm, so it names nothing of its users. Each piece has an upstream home:

| Piece | Upstream home |
|---|---|
| relay | a "spawn on a given listener" interceptor constructor in `smolvm-credentials` |
| flow decisions (`Decide`) | `smolvm-network` egress checks |
| request rules (`Policy`) | `smolvm-protocol` |

## Request rules

`Policy` holds rules over the HTTP requests on a decrypted host: hosts (exact, or subdomains one label
or any depth deep, never the apex), an optional port, methods, path globs and query matchers. Rules add
up and order never matters: a matching deny wins. A host with an allow refuses every request no allow
matches (`no rule allows METHOD PATH on HOST`); a refusal names only the denying rule's reason and id.

- `terminate_hosts()` lists the hosts to decrypt, in the interceptor's `*.domain` form.
- `inspection(host, port)` says whether rules apply to a connection, and what to do when it can't be read.
- `request(..)` judges one request.

The guest is taken to be adversarial. A deny fires if **any** reading of the request matches, and an
allow needs **every** reading to: the method plus any `X-HTTP-Method-Override`, `X-HTTP-Method` or
`X-Method-Override` value, the path with `;params` dropped and kept, and the query split on `&` and `;` or on `&` alone, with each repeated
parameter. Paths are judged by a canonical view (decoded once, empty segments merged, dots resolved), which never changes what is forwarded. A target with an encoded `/` or `\`, a `%` that
isn't one valid escape (double encoding, `%u`), invalid UTF-8 or a control character is refused as
`ambiguous request target` on a host the rules name. Path globs: `*` within a segment, `**` as a whole
segment for zero or more. Not covered: request bodies, a `_method` parameter, Unicode normalization.
