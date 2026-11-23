# Network policy and secrets

What a sandbox may reach, and how it uses your API keys without seeing them. Running agents is in [Usage](usage.md).

On this page: [Network policy](#network-policy) · [Secrets](#secrets)

## Network policy

Creating or starting a sandbox needs a network policy. The first time, `bento` asks which one to use
and saves the answer:

| Mode | Meaning |
|---|---|
| `allow-all` | Open network |
| `balanced` | Default deny, plus Docker Sandboxes' baseline of 195 rules (AI APIs, package registries, code hosts, container registries, cloud services, OS packages, certificate checks, Nix caches) |
| `deny-all` | Nothing, unless you allow it |

Without a terminal, `bento` fails rather than asking. In scripts and CI, run `bento policy init
balanced`.

```sh
# applies to running sandboxes at once
bento policy allow network api.example.com,*.example.org
bento policy deny network tracking.example.com
bento policy allow network internal.example.com --sandbox claude-myrepo
# one row per policy; --wide lists every rule and host
bento policy ls
# what applies to one sandbox
bento policy ls claude-myrepo
# exits 1 when denied, and says which rule decided
bento policy check network pypi.org
# requests sandboxes made that were blocked
bento policy log
# blocked hosts with no rule yet; answer with allow (a rule for that sandbox) or dismiss
bento policy approval ls
bento policy approval respond registry.example.com --option allow
bento policy rm network --resource api.example.com
# deny rules for this sandbox only
bento create claude . --deny-network evil.com,tracker.example
```

Rules take hosts (`api.x.com`), wildcards (`*.x.com`, `**.x.com`), IPs and CIDRs, comma-separated.
`**` allows everything. A sandbox's egress process enforces the rules as sbx does, ports included,
for every connection that names its host ([Hosted egress](#hosted-egress), the default). Where
smolvm enforces a rule more loosely than sbx (`network.egress=smolvm`, or a connection with no
name), see [sbx compatibility](sbx-compatibility.md).

`bento policy ls` prints what sbx does. Under `balanced` with one allow rule and one deny rule:

```
POLICY             SOURCE   APPLIES TO   SUMMARY
default-deny-all   local    all          network: deny when no rule decides
local-policy       local    all          network: 200 allow, 1 deny
```

The mode shows as the fallback policy: `default-deny-all` for `balanced` and `deny-all`,
`default-allow-all` for `allow-all`. `--wide` has a row per rule with its ID (for `policy rm
network --id`), `--json` the same rules as `{"rules": [...]}`, and `-q` only their IDs. `--decision`,
`--source`, `--created-via`, `--type` and `--protocol` filter the rules.

- `run` and `create --deny-network <HOST>` add a deny rule for the new sandbox only, as `bento policy
  deny network --sandbox <NAME> <HOST>` does. It applies only at create; on an existing sandbox
  `run` warns and changes nothing. If the create fails, its rules are removed.
- A sandbox's secret hosts, and their subdomains, are always reachable. `policy deny` of one is
  refused, naming the secret's service.
- Ports (`host.example.com:8080`) are enforced for hosted sandboxes, in allows and denies. smolvm
  can't filter by port, so with `network.egress=smolvm` an allow opens every port and a deny with a
  port isn't enforced: deny the host without a port. The exception is a deny with exactly the same
  text as an allow, which cancels that allow. `policy ls --wide` says in STATUS which rules smolvm
  doesn't fully enforce; `policy check` without a port checks 443. Details are in [sbx
  compatibility](sbx-compatibility.md).
- `balanced` allows its hosts on any port. sbx limits them to 443.
- `bento policy reset` stops running sandboxes, then removes the mode and every rule. The next create
  or start asks for a mode again.
- Policy changes reach only the sandboxes this setup (its data directory) created, even when another
  setup shares the same `smolvm.home`.
- Blocked requests come from smolvm's egress log. A connection a hosted sandbox's egress process
  denies (by port or name) is logged in its `egress.log` instead, and isn't in `policy log` or
  `policy approval`. `policy approval` lists hosts with no rule yet;
  the host is the approval ID. `--option dismiss` adds no rule and hides the host until it is
  blocked again.
- `policy check network` takes a URL too, as sbx does: `https://example.com/x` checks
  `example.com:443` (`http` is port 80; another scheme needs a port). The host's loopback
  (`localhost`, `127.0.0.1`, `::1`, `host.docker.internal`) is denied whatever the mode unless the
  sandbox has host access, which a `localhost` allow rule gives at create; the check says so.
- `policy check network --protocol udp HOST:PORT` checks a UDP destination. With
  `network.egress=smolvm`, smolvm admits UDP wherever its allow list admits TCP, except port 53: it
  answers DNS itself. A hosted sandbox sends no UDP but DNS ([Hosted egress](#hosted-egress)), and an
  allowed verdict says so.
- `--method`, `--path` and `--query` on `policy allow|deny` bound a rule to some requests. Hosted
  sandboxes enforce them per request: see [Request rules](#request-rules). `policy check` gives
  the connection's verdict; `policy ls --wide` shows the request rules.
- `policy rm network --resource HOST --method GET --path '/v1/**'` removes the host from the rule
  with those methods and that path only.

### Host services

A sandbox reaches your machine's localhost as `host.docker.internal` once a `localhost` rule allows
it:

```sh
# before the sandbox is created
bento policy allow network --sandbox claude-myrepo localhost
bento run --name claude-myrepo claude .
# inside: curl http://host.docker.internal:11434/
# closes it, live
bento policy rm network --sandbox claude-myrepo --resource localhost
# opens it again, live
bento policy allow network --sandbox claude-myrepo localhost
```

- Only your `localhost` rules (global, or `--sandbox NAME`) give host access, and only at create.
  For such a sandbox, later `localhost` rules open and close access live. Other sandboxes have
  loopback blocked for life; a rule added later prints `note: NAME were created without host access;
  recreate them to use it`.
- A hosted sandbox reaches only the rule's port: `localhost:11434` opens `11434` and nothing else,
  and the guest's `Host:` or SNI plays no part. smolvm can't open a single host port, so with
  `network.egress=smolvm` it opens every port on your `127.0.0.1`. `policy allow` warns about that
  (`warning: smolvm can't open a single host port yet; …`) for hosted sandboxes too. See
  [Security](SECURITY.md#host-services-localhost-rules).
- Kit rules never grant host access, and `_builder` never has it. An `allow-all` sandbox keeps host
  access until recreated.
- Each start adds `100.96.0.1 host.docker.internal` to `/etc/hosts`. The name resolves everywhere,
  but only sandboxes created with host access can connect.
- `127.0.0.1`, `::1` and `host.docker.internal` rules aren't host-services rules; the rule must say
  `localhost`. A blocked request gets connection refused (on a hosted sandbox, its connection is
  reset). sbx returns `403 Approval required` instead.

## Secrets

Agents never see your API keys. The variable holds a placeholder inside the sandbox, and the
sandbox's egress process (smolvm with `network.egress=smolvm`) swaps in the real value only on HTTPS
requests to that service's hosts. An agent whose kit takes
the key another way gets no variable: `claude` reads it through its `apiKeyHelper`.

```sh
# prompts (hidden input; an empty line cancels)
bento secret set anthropic
# 1Password, read at each start
bento secret set claude --ref op://Private/claude-sandbox/credential
# run at each start
bento secret set github --command 'gh auth token'
# one sandbox only
bento secret set openai --sandbox claude-myrepo -t sk-…
bento secret set-custom --host api.example.com --env EXAMPLE_TOKEN --command 'pass show example'
# keeps it out of argv
printf %s "$TOKEN" | bento secret set github --value-stdin
bento secret ls
bento secret rm github
```

- `--ref` takes an `op://…` reference or an AWS Secrets Manager ARN (its region is used). Typed or
  `-t` values go to your OS keychain ([Configuration](configuration.md#secret-values)).
- `set-custom` takes bare host names (no scheme, port, path or IP; repeat `--host`), or
  `*.example.com` for every subdomain. `*.com` is refused, as smolvm refuses it; `*.co.uk` is
  accepted, since smolvm has no public suffix list. It warns about a name that doesn't resolve, and
  the create fails while one doesn't resolve. Removing a custom service's last secret removes the
  service too.
- A `--command` source runs in a fresh temporary directory, so give helper scripts an absolute path
  or put them on `PATH`. `./get-token.sh` no longer works.
- Built-in services: `anthropic`, `claude` (Claude Code's `claude setup-token` token), `cursor`,
  `droid`, `github`, `google`, `groq`, `mistral`, `nebius`, `openai`, `openrouter`, `xai`.

When things take effect:

- A sandbox binds the services that have a secret when it's **created**, and can always reach their
  hosts.
- A new value for a bound service applies **at once** to running sandboxes (`secret set` says
  `Applied to … now`), from their next request, and to stopped ones at their **next start**.
  Removing a secret (`secret rm`) still waits for the next start, and so does a new value for a
  sandbox an earlier smolbento made, when a kit gave it the service's credential.
- A secret for a service the sandbox wasn't created with needs a **recreate** on a hosted sandbox
  (the default), and `secret set` tells you which. With `network.egress=smolvm` it's bound to a
  running sandbox at once, or from the next start of one that booted with no secrets.

### Hosted egress

Every new sandbox with a network gets hosted egress unless `network.egress=smolvm` is set before
create. bento runs one socket-activated `bento _serve egress` process per sandbox (a launchd job on
macOS, a `systemd --user` socket and service on Linux), and every byte the sandbox sends over TCP
goes through it. It enforces the network rules and swaps the sandbox's secrets. It resolves secrets
when it starts, and the guest sees placeholders as usual.

Each connection is decided twice, and smolvm's allow list still applies first:

- **By address and port**, when the guest connects. An IP or CIDR deny rule (`10.0.0.0/8`,
  `1.1.1.0/24:443`), or a host port no `localhost` rule opens, refuses the connection before the
  destination is dialled. Other address checks are smolvm's allow list's.
- **By name and port**, from the guest's first bytes: the TLS SNI, or the HTTP `Host:` header.
  Nothing is forwarded until they're read. A deny (a denied host, or a port its rules don't allow)
  closes the connection. A name deny inside an allowed wildcard (`**.github.com` allowed,
  `gist.github.com` denied) holds. A name no rule mentions still passes when an IP or CIDR allow rule
  matches the destination (`10.0.0.0/8` admits `gitlab.corp` at `10.1.2.3`, and a proxy's CONNECT),
  unless a deny matches the name or the address.

Either way the guest sees the connection open, then reset, not refused: smolvm accepts it before
asking the egress process. curl exits 35 or 56 (52 for plain HTTP), not 7.
- A client that sends no name (SSH, TLS without SNI), or sends nothing for 200 ms before its name
  is in, is judged by address and port only, so name rules don't apply to it. The name is whatever
  the guest sends, so name rules stop cooperative clients, not a hostile agent: see
  [Security](SECURITY.md#network-and-secrets) for the ways around them.
- The host's gateway (`host.docker.internal`, `100.96.0.1`) is judged strictly as `localhost:<port>`:
  only a `localhost` rule for that port opens it.

The egress process reads rule changes at the next connection, with no restart. smolvm's allow list
changes as for any sandbox: a switch between `allow-all` and a restricted mode reaches it at the
next start. A `policy.toml` that can't be read denies every connection until it can, with the
reason logged.

Caveats:

- **CDNs:** a name rule judges the name the guest sends, and many sites share a CDN's addresses. An
  address rule or smolvm's allow list (resolved at start) can admit or refuse a shared address for
  every name on it.
- **UDP:** smolvm drops every datagram from a hosted sandbox except DNS, even to allowed hosts. QUIC
  falls back to TCP; NTP and mosh fail. Use `network.egress=smolvm` for a sandbox that needs UDP.
- **Live secret bindings:** a hosted sandbox can't bind a new service while it exists: `secret set`
  says `<name> uses hosted egress; recreate it to bind <service>`. A new value or a removed one
  applies at once: `secret set` and `secret rm` restart the egress process, and open connections
  drop at that moment. A stopped sandbox's process is restarted before the machine starts, so
  boot-time connections use the new value. Live binding is planned.
- No flow limits apply, except to decrypted connections ([Request rules](#request-rules)).

A sandbox falls back to smolvm egress, with a warning at create, when there's no service manager
for its unit (launchd, or `systemd --user` with a private socket directory and a short enough socket
path), when it has install-only credentials, or when a kit gives it install-phase network rules
(both for a kit's install hooks). `_builder` is never hosted.

The egress process logs to `<data>/egress/<name>/egress.log`: startup errors, a secret that failed
to resolve (by name, never value), and each denied connection with its reason (`deny
gist.github.com:443: …`). Look there when a hosted sandbox's connections fail. `bento rm` removes
the log with the sandbox.

A fork of a hosted sandbox gets its own egress process on its own port, with a copy of its parent's
CA and token: the copied guest already trusts that CA and holds those placeholders. It keeps the
parent's sandbox rules, as every fork does.

The Linux systemd units are tested in CI, and the macOS launchd units by running `just e2e` on a Mac.

#### Request rules

A rule with `--method`, `--path` or `--query`, or a kit's `network-policy@2` entry with `methods` or
`paths`, is bounded: it applies to some requests to its hosts. A hosted sandbox enforces bounded rules per
request:

```sh
# GET and HEAD only, on every path
bento policy allow network --sandbox claude-myrepo registry.npmjs.org --method GET,HEAD
# no pushes over HTTPS
bento policy deny network --sandbox claude-myrepo github.com --method POST --path '/*/*/git-receive-pack'
```

- **Ruled hosts are decrypted.** The egress process decrypts each host a bounded rule names, and
  each secret's host, with the sandbox's own CA, which the guest trusts. Every other connection is
  passed through as before.
- **A refused request gets `403`.** The body names a deny rule (`… (rule r-1a2b3c4d)`), or on a host
  that only bounded allows admit, says `no rule allows POST /post on httpbin.org`. It never shows a
  rule's content.
- **What a bounded rule means** (sbx's meaning):
  - A bounded deny acts on the requests it names, never on the whole host: `deny H --method POST`
    refuses POSTs, and GETs and other ports pass. A deny wins over any allow.
  - A bounded allow makes its host reachable, and then only the requests it names pass.
  - An unbounded allow of the same host and port beats it, and so do `allow-all`, a secret's host,
    and a host the `balanced` preset admits: they leave every request admitted.
- **Matching.**
  - Methods are matched in any case. `X-HTTP-Method-Override`, `X-HTTP-Method` and
    `X-Method-Override` count as the method too: a deny fires if any of them matches, and an allow
    needs all of them to match.
  - Paths and queries follow sbx (any case) for `bento policy` rules, and the kit spec (exact case)
    for kit rules.
  - A path is judged with its dot segments resolved. One with `%2f` or `%5c`, double encoding, `%u`,
    `%00`, a control character or invalid UTF-8 is refused as `ambiguous request target`.
- **Named hosts only.** `policy allow|deny` refuses bounded rules on `*`, `**`, IPs and CIDRs, and a
  bounded allow on a host glob (`crl*.x.com`). A bounded deny on a glob widens to `*.x.com`. A
  bounded deny on `localhost` acts on the whole host port: host services aren't decrypted. A
  stored bounded rule egress can't map (edited by hand, say) denies its whole host, allow or deny.
- **Changes apply live.**
  - A change on a host that's already decrypted applies from the next request, on open connections
    too.
  - A new ruled host, or one no longer ruled, restarts the sandbox's egress process at its next
    connection. Open connections drop then, that connection among them. The next one starts the
    process again: at once with systemd, and within 10 s with launchd.

On a ruled host:

- **HTTP/1.1 only.** HTTP/2 and HTTP/3 aren't offered.
- **`Range` and `If-Range` are stripped,** so a resumed download starts over.
- **Replies are asked for uncompressed** (`Accept-Encoding: identity`). One compressed anyway is
  decoded if it's gzip or deflate, up to 64 MiB. A br or zstd reply, or a larger one, gets `502`.
- **WebSocket:** the upgrade request is judged. The frames after it pass unfiltered.
- **At most 256 decrypted connections at once** per sandbox.
- **Plain HTTP is refused** (a reset, logged as `plain HTTP to a host with request rules`). The
  egress process can't judge it per request yet: use HTTPS.
- **Other protocols pass** a host with only bounded denies, as in sbx: SSH to `github.com` still
  works under `deny github.com --method POST`. Deny the SSH port (`github.com:22`) to block pushes
  completely. Where a bounded allow names the host, a connection that can't be read is refused.
- **`_method` overrides** in a query or a form body aren't seen.
- **Upstream certificates** are checked against the public web roots only: a ruled host with a
  private CA fails.

Request rules stop cooperative clients, not a hostile agent. The egress process knows a connection's
host only from the name the guest sends, so a guest can get past them (closing these is planned):

- by sending another allowed name, in the TLS SNI or `Host:`, on a connection to a ruled host's
  address;
- by sending no name: TLS without SNI, or plain HTTP without `Host:`, to a ruled host's address is
  judged by address and port, and passes unfiltered when the address is allowed.

To keep a host out, deny the host.

### Registry credentials

A registry credential lets smolbento pull kits and images that need a login. It stays on your
machine; sandboxes never get it.

```sh
# Docker Hub token
bento secret set --registry dhi.io --username alice --password-stdin < token.txt
# token-only
gh auth token | bento secret set --registry ghcr.io --password-stdin
bento secret ls
bento secret rm --registry dhi.io
```

The token goes to your OS keychain; `secrets.toml` keeps the host and user name. Omit `--username`
for token-only registries such as ghcr.io. Docker Hub, `dhi.io` and Quay robots need it; an empty
`--username` counts as none. For a token server on another host, pass `--registry-auth-endpoint
https://…` with the exact URL. The login goes only over HTTPS (or plain HTTP to a localhost
registry), and only to the registry, `auth.docker.io` for Docker Hub, or that URL.

Used for:

- Pulling published kits from that registry. A stored login replaces anonymous pulls, so an expired
  token also breaks that registry's public kits. Remove it with `bento secret rm --registry HOST`.
- Local kit builds, in the `_builder` sandbox. It can reach every logged-in registry, and smolvm
  sets the `Authorization` header there. Before a build that names `HOST/<repo>` in its descriptor,
  smolbento gets a short-lived pull token and starts the builder with it, so a build must start
  pulling within a few minutes. Only `HOST/…` references count.
- A build that reaches a logged-in registry without naming it that way gets `502 credential
  unavailable` and fails, naming the registry. Write the image as `HOST/<repo>`, or remove the
  login.
- Local builds don't yet support Docker Hub logins (`FROM debian` gets no token) or non-default
  ports (`registry.corp:5000`). Registries that accept Basic auth only work for kit pulls, not
  builds.
- Concurrent builds that use a registry login restart the builder, so run them one at a time. Adding
  or removing a login recreates the builder and its cache at the next build.

Registry logins appear only in plain `bento secret ls`, not with `-g`, `--sandbox` or a service
filter. `--sandbox` and `--all-sandboxes` (a login for a sandbox's own `docker pull`) aren't
supported yet.

`bento rm` removes that sandbox's own secrets and per-sandbox policy. `bento reset` removes all secrets
too, unless you pass `--preserve-secrets`.
