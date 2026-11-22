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
`**` allows everything. Where smolvm enforces a rule more loosely than sbx, see [sbx
compatibility](sbx-compatibility.md).

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
- A deny with a port (`host.example.com:8080`) isn't enforced: smolvm can't filter by port. Deny the
  host without a port. The exception is a deny with exactly the same text as an allow, which cancels
  that allow. `policy ls --wide` says in STATUS which rules aren't fully enforced; `policy check` without a port
  checks 443. Details are in [sbx compatibility](sbx-compatibility.md).
- `balanced` allows its hosts on any port. sbx limits them to 443.
- `bento policy reset` stops running sandboxes, then removes the mode and every rule. The next create
  or start asks for a mode again.
- Blocked requests come from smolvm's egress log. `policy approval` lists hosts with no rule yet;
  the host is the approval ID. `--option dismiss` adds no rule and hides the host until it is
  blocked again.
- `policy check network` takes a URL too, as sbx does: `https://example.com/x` checks
  `example.com:443` (`http` is port 80; another scheme needs a port). The host's loopback
  (`localhost`, `127.0.0.1`, `::1`, `host.docker.internal`) is denied whatever the mode unless the
  sandbox has host access, which a `localhost` allow rule gives at create; the check says so.
- `policy check network --protocol udp HOST:PORT` checks a UDP destination. smolvm admits UDP
  wherever its allow list admits TCP, except port 53: it answers DNS itself.
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
- smolvm can't open a single host port yet, so `localhost:11434` opens every port on your
  `127.0.0.1` to those sandboxes, and `policy allow` warns (`warning: smolvm can't open a single
  host port yet; …`). See [Security](SECURITY.md#host-services-localhost-rules).
- Kit rules never grant host access, and `_builder` never has it. An `allow-all` sandbox keeps host
  access until recreated.
- Each start adds `100.96.0.1 host.docker.internal` to `/etc/hosts`. The name resolves everywhere,
  but only sandboxes created with host access can connect.
- `127.0.0.1`, `::1` and `host.docker.internal` rules aren't host-services rules; the rule must say
  `localhost`. A blocked request gets connection refused. sbx returns `403 Approval required`
  instead.

## Secrets

Agents never see your API keys. The variable holds a placeholder inside the sandbox, and smolvm
swaps in the real value only on HTTPS requests to that service's hosts. An agent whose kit takes
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
- A secret for a service the sandbox wasn't created with needs a **recreate**; `secret set` tells
  you which.

### Hosted egress

`network.egress=hosted` (experimental, set before create) makes bento run the credential
interceptor instead of smolvm: one socket-activated `bento _serve egress` process per sandbox
(a launchd job on macOS, a `systemd --user` socket and service on Linux). It resolves secrets
when it starts, and the guest sees placeholders as usual. A sandbox with no credentials gets
no egress process. It needs a service manager: create is refused without one (launchd, or
`systemd --user` with a private socket directory).

The egress process logs to `<data>/egress/<name>/egress.log`: startup errors, a secret that
failed to resolve (by name, never value) and dropped flows. Look there when a hosted sandbox's
connections fail. `bento rm` removes the log with the sandbox.

A fork of a hosted sandbox gets its own egress process on its own port, with a copy of its
parent's CA and token: the copied guest already trusts that CA and holds those placeholders.

Limits in this release:

- Install-only credentials (a kit's install hooks) are refused at create.
- `secret set` and `secret rm` restart the sandbox's egress process, so a new value applies at
  once and a removed one is gone at once; open connections drop at that moment. A stopped
  sandbox's process is restarted before the machine starts, so boot-time connections use the
  new value. Binding a *new* service needs a recreate
  (`<name> uses hosted egress; recreate it to bind <service>`); live binding is planned.
- The Linux systemd units are tested in CI only; the macOS launchd path is tested by hand.

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
