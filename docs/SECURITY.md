# Security

## What a sandbox isolates

Each sandbox is a separate microVM with its own kernel. The agent's processes, packages and Docker
engine stay off your machine. The agent reaches your machine only through:

- the workspace directories you mount, read-write or read-only (`:ro`);
- ports you publish with `-p`, on `127.0.0.1`;
- the network.

In every policy mode, sandboxes can't reach your machine's localhost (`127.0.0.1` or `::1`) unless
you add a `localhost` rule. Inside the VM:

- The agent runs with permission prompts disabled, so the VM is the only boundary.
- `bento exec --privileged` and the sandbox's Docker engine run as root inside the VM.
- smolbento refuses to run as root on the host, because smolvm doesn't map a root-owned workspace
  to the agent user.

### Host services (`localhost` rules)

A `localhost` rule ([Host services](network-and-secrets.md#host-services)) lets sandboxes reach
your localhost as `host.docker.internal`. A hosted sandbox (the default, see [Hosted
egress](network-and-secrets.md#hosted-egress)) reaches only the ports the rules name: its egress
process judges every connection to the gateway as `localhost:<port>`. smolvm can't open a single
host port yet, so for a sandbox created with `network.egress=smolvm` a rule opens more than it
names:

- The rule opens every port on your `127.0.0.1` (not `::1`) to the sandboxes it applies to.
  `policy allow` warns about this each time, for hosted sandboxes too.
- A sandbox gets host access only if a `localhost` allow rule applies to it at create. Any other
  sandbox keeps your loopback blocked for its life, and a later rule doesn't open it. `policy allow`
  names those sandboxes.
- Closing is best-effort. `policy rm` closes the port in a running sandbox at once. A sandbox
  created with host access can still reach your localhost by other routes: a broad allow CIDR, a
  DNS answer covering `100.96.0.1`, the always-allowed `127.0.0.0/8` in restricted allow lists, or
  a switch to `allow-all`. To remove host access for good, recreate the sandbox without the rule.
- `allow-all` is fixed at create. An `allow-all` sandbox created with host access reaches every
  host port for its life, rule or not. `policy rm` says so.
- Kits can't grant it. Only your own rules do.
- The kit builder never has it. `_builder` always has your loopback blocked, even under a global
  `localhost` rule.

Under `allow-all`, a sandbox can reach your LAN IP, so a service listening on `0.0.0.0` is
reachable. `balanced` and `deny-all` block that unless you allow the address.

## Workspaces, clones and forks

- Workspaces are mounted read-write by default. Anything the agent writes, including git hooks or
  config in a mounted repo, lands on your machine. With `--clone`, the agent can't write to your
  repo. Only commits come back, on `git fetch sandbox-<name>` (not tags). Review them before you
  merge, and check fetched objects with `git -c fetch.fsckObjects=true fetch`.
- smolvm maps only a mounted directory's owner and group to the agent. A subdirectory owned by
  another of your groups keeps that group, so the agent can't write it through the group.
- With `--clone`, the agent can read your repo's whole `.git`, including `.git/config`, as in sbx.
  A user name and token in an HTTPS remote URL are left out of the clone's own remotes, but they
  stay in that file, and so does any `http.extraHeader`. Keep credentials out of repo config. Use
  a credential helper or `bento secret`. `create --clone` warns about remote URLs with a token.
- Forkable sandboxes (clone and mountless, not forks) start branchable. On Linux this drops smolvm's
  no-ptrace hardening of the VM process, so other processes running as you can read its memory,
  including secret values. On every platform, smolvm stops returning their idle memory. Turn it off
  with `bento settings set fork.enabled false`, from each sandbox's next start.

## SSH

`ssh NAME.sbx` ([SSH into a sandbox](usage.md#ssh-into-a-sandbox)) runs `bento ssh proxy` as a child
of `ssh`, on a pipe: no listener, no key, no password. It accepts the `none` method only and nothing
else, so only the user who runs `ssh` reaches it, and it can do what `bento exec` does. It turns
down SFTP, agent forwarding, X11 and remote forwarding. `-L` forwards reach only the sandbox's own
loopback (`localhost`, `127.0.0.0/8`, `::1`), never the host or another address. The host key is new
for each connection and not checked, since nothing sits between `ssh` and its child. Session data is
not logged. A sandbox's processes can see what you send through a forward, as with any `exec`.

## Host service units, browser and clipboard

- While the sandbox runs ([Browser and clipboard](usage.md#browser-and-clipboard)), it can open
  `https://` URLs in your browser and overwrite your clipboard, but it can't read the clipboard. A
  malicious page opened this way runs in your real browser, with your logins. `browser.enabled
  false` turns off URL opening. Clipboard text may be crafted to run commands when pasted, so check
  it first.
- [Host service](usage.md#host-services) units: per sandbox with a bridge or a runtime SSH agent
  grant, smolbento writes a launchd user agent or `systemd --user` socket and service units. They
  run as you, never as root, listen on a `0600` socket and start `bento _serve KIND SANDBOX` for
  each connection, with the connection as stdin and stdout and stderr on `/dev/null`. `_serve` is
  the filter and bridge handler, and reads the grant from the sandbox's labels; the unit carries
  your `PATH`, `HOME`, `SMOLBENTO_*` variables and, on Linux, `SSH_AUTH_SOCK`, never secrets. Anyone
  who can write your unit files or your `PATH` can run commands as you, as with any launch agent.
  Names carry a hash of the data dir, so separate setups don't touch each other's units.
- The socket directory ([Files](configuration.md#files)) is checked at create and at each start: a
  real directory (not a symlink), owned by you, with mode 0700, created that way if missing. If the
  check fails, the sandbox gets no bridge for that start, with a warning. This stops another user
  from receiving what the sandbox sends by creating the directory first.
- Forks don't install bridge shims or get units, but they keep the parent's socket mount. While the
  parent is served, a process in a fork can open URLs, copy and use the SSH agent through the
  parent's sockets.
- OAuth callback ports. For an opened URL whose `redirect_uri` is `http://localhost:PORT` or
  `http://127.0.0.1:PORT`, smolbento listens on your `127.0.0.1:PORT` (never other interfaces) for
  10 minutes (or until the session ends, in attached-only serving). It opens at most 4 ports a
  session, and not if something already answers on `localhost:PORT`. It passes requests whose `Host`
  is `localhost:PORT` or `127.0.0.1:PORT` into the sandbox. Known gaps:
  - Other local programs can reach that port while it's open, as they could reach an agent's
    callback server on your machine.
  - The sandbox can claim that port before a service of yours starts on it.
  - Pages the sandbox serves there are on `localhost`, whose cookies aren't separated by port. They
    can read and set the cookies of your other `localhost` apps.
  - Each replay is cut off after 15 seconds or 1 MiB of response.
  - `browser.enabled false` also turns the relay off.

## SSH agent

Built-in agents, and kits that ask with `ssh-agent@1`, can use your SSH agent whenever the sandbox
runs ([SSH agent](usage.md#ssh-agent)), and during a kit's `install` grant. While the agent is
served, code in the sandbox can sign as you and log in wherever your keys work. Don't run untrusted
work with it.

- They can list your agent's public keys and have it sign with any of them. That covers git commit
  signatures and SSH logins to any server your keys open.
- A kit's `sign: [...]` list allows only signatures in those namespaces, not logins.
- An `authenticate: [...]` list allows logins only to those servers: smolbento verifies the session
  binding the client sends, and signs only when the binding's host key is one your
  `ssh.knownHostsFile` (default `~/.ssh/known_hosts`) lists for a named server; anything else is
  refused without reaching your agent. A server known only through a `@cert-authority` line, or by
  a wildcard or negated pattern, isn't trusted for this. A kit without `authenticate` can't log in
  at all.
- They can't add, remove or lock keys or do anything else; smolbento answers those requests itself
  with a failure. Your private keys never enter the sandbox.
- The socket directory gets the bridge's checks (above): no agent for a start while it isn't
  private, and a kit that requires an agent is refused at create.
- `ssh.agentForwardingEnabled false` turns it off: new connections are refused at once, and open
  ones stay. Running `bento` without `SSH_AUTH_SOCK` does too. For a dedicated agent that holds only
  the keys you want sandboxes to use, set `ssh.agentSocketPath` to its socket.

## Network and secrets

- Use `balanced` or `deny-all` for untrusted work. Sandboxes created before you chose a policy stay
  open until their next start.
- Secrets are placeholders inside the sandbox. A real value goes only to that service's hosts, and
  only over HTTPS. A secret's hosts and their subdomains are always reachable from sandboxes that
  bind it.
- A hosted sandbox enforces host rules and ports by the name each connection sends (see [Hosted
  egress](network-and-secrets.md#hosted-egress)), so they stop cooperative clients, not a hostile
  agent. It can escape them three ways:
  - send an allowed host's name (SNI or `Host:`) to any address smolvm admits (domain fronting, or
    a server that ignores SNI);
  - pipeline plain HTTP requests: only the first request's `Host:` is read;
  - under `allow-all`, reach a host it denies by sending no name (TLS without SNI), as every
    address is allowed.

  TLS without a readable SNI, and plain HTTP without exactly one `Host:`, pass only on an IP or
  CIDR allow rule (or `allow-all`). Protocols where the server speaks first (SMTP, FTP) don't work:
  smolvm's interceptor waits up to 10 s for the client's first bytes, then closes the connection.

  With `network.egress=smolvm`, host rules are looser than sbx's: `*.x.com` matches any depth,
  wildcards inside a label widen, and ports aren't enforced, and method, path and query rules
  aren't enforced. See [sbx compatibility](sbx-compatibility.md#network-and-secrets).

  Hosted sandboxes enforce method, path and query rules per request on the hosts they name, and the
  same name spoofing gets past them: see [Request rules](network-and-secrets.md#request-rules).

## Kits

Kits can install software as root, run steps on every start, and open network access, so load only
kits you trust.

- Published kits load only from `kit.allowedSources` prefixes, and local kits only while
  `kit.allowLocalKits` is `true`. Both checks run before anything is downloaded or built. A prefix
  without `/`, such as `ghcr.io`, matches only that host, never `ghcr.io.evil.com`. The default
  allows Docker Hub and `ghcr.io/pelotech/smolbento/` (smolbento's own kits). See
  [Kit sources](configuration.md#kit-sources).
- Signatures are checked only when `kit.requireSignature` is `true` (default `false`). Then a
  registry kit needs a signature from a `kit.trustedSigners` signer, and local kits are refused.
  The default signers are Docker identities (`@docker.com`) and smolbento's release workflow.
  `--offline` skips the check. See [Kit signatures](configuration.md#kit-signatures).
- Images a kit names (a workload kit's image, and the base its layers are added to) are pulled
  without a `kit.allowedSources` check, like a Dockerfile's `FROM`.
- Registry transport is HTTPS, except for loopback registries (`localhost`, `127.0.0.0/8`,
  `::1`), which use plain HTTP, as in Docker.
- Kit network rules apply to their sandbox only, even under `deny-all`. `policy ls --source kit`
  lists them. Deny rules always win, so a sandbox deny rule blocks a host a kit allows.
- Install-only rules apply while they're in the policy: from create (or `kit add`) through the
  install steps, then go, before the workload's entrypoint starts. `policy ls` lists them only then.
  A start removes any an interrupted create or `kit add` left, and `bento rm` or the next create of
  that name removes an interrupted create's. A CIDR deny made during install stays for the sandbox's
  life, because smolvm takes CIDR denies only at create.
- `kit add` asks before opening new network access on an existing sandbox
  ([Adding a kit](kits.md#adding-a-kit-to-a-sandbox)).
- Kit credentials are your secrets as placeholders. A value goes only to the hosts the kit names,
  or to the service's own hosts if it names none.
  - A **built-in** service's secret (`github`, `anthropic`, ...) goes only to that service's own
    hosts. Naming another host fails: "kit K wants to send your github secret to HOST, which github
    doesn't use; refusing". sbx asks you to approve the kit's hosts instead; smolbento adds this
    check because Docker Hub kits load by default.
  - A **custom** service's secret (`bento secret set-custom`) goes to any host the kit names.
    `create` and `kit add` print "kit K sends your SERVICE secret to HOSTS".
  - `bento kit inspect REF` lists each credential's service and hosts.
  - A credential's hosts are always reachable, and a deny rule can't block them while the kit's
    binding exists. That binding lasts the sandbox's life, because smolvm needs those hosts to send
    the secret. Recreate the sandbox without the kit to drop it.
  - An optional credential with no secret set is skipped, and requests go out without it. A
    credential needed only while installing is gone after install.
- Install steps run as root. Startup and v2 steps get the whole sandbox environment, including
  secret variables, which hold placeholders ([Kits](kits.md#kits) has each step's environment). A
  failing startup step is a warning with the startup log's last lines, and the sandbox starts
  anyway, as in sbx.
- A workload kit's agent runs as the image's `USER`, or as root if there is none, and can write
  your workspace.
- Kit host mounts (`host-mount@1`) are directories on your machine. Writes land on your disk,
  outside the VM. Every other sandbox of the same kit reads them, even after this sandbox is
  removed, and so do later versions of a published kit (keyed by repository). Don't share one
  between an untrusted sandbox and one you trust. With `--mount`, the sandbox reads and writes the
  directory you give it and everything below it.
- Kit arguments aren't secret. Their values can reach the sandbox's environment and smolvm's machine
  config. Put secrets in credentials, not `--kit-arg`.
- Local kit builds run in the [`_builder` sandbox](kits.md#the-builder-sandbox), a VM under your
  global network policy, not on your Docker. The builder never gets your secrets.
- Registry credentials (`bento secret set --registry`) stay on your machine and go only to their
  registry ([details](network-and-secrets.md#registry-credentials)). A local build gets a pull token
  instead, which the guest sees only as a placeholder. Every registry you stored a login for is
  reachable from the builder, even under `deny-all`, because sbx's host build isn't bound by policy
  either. A build step can use the token until it expires (a few minutes). Some registries
  (`dhi.io`) honour it for repositories outside its scope.

## Skills

The shared skills store is agent material. smolbento never runs it, and reads nothing in it beyond
directory names. What you share with a sandbox is what its agent follows.

- A `readwrite` sandbox can change the skills other sandboxes load. Its agent writes straight into
  your store, so a changed or added skill is linked into every later sandbox, `readonly` ones
  included. Use it only for work you trust.
- `readonly` doesn't isolate a sandbox from changes. The agent can't edit a stored skill, but it
  loads whatever the store holds at each start, including changes made by a `readwrite` sandbox or
  by you.
- Use `--skills off` for untrusted work. The sandbox gets no store and no skills directory.
- A kit can widen `readwrite` to links. With `--skills readwrite`, a kit that names a `readwrite`
  directory makes `/run/sbx/skills-shared` read-write. The agent can then
  change stored skills through every link. Check a kit's `agent-skills@1` modes before using it
  with `readwrite`.
- Prefer HTTPS or SSH for `skills add`. `http://` and `git://` URLs are accepted, as in sbx, but
  their content can change in transit.
- Linking runs as root in the guest. It creates the skills directory and links in it,
  and changes the owner of those alone. It refuses a skills directory whose path goes through a
  symlink anywhere, including a parent such as `~/.claude`, and checks before and after creating
  the directory so the agent can't redirect it. Image symlinks such as `/home -> /var/home` count
  too, so such a sandbox gets no skills links.
- Bundled kit skills are image content. An `agent-skill@1` skill comes from the kit's image, and
  smolbento only links it. The agent reads its instructions like any skill's, so trust the kit as
  you would for its install hooks.

## MCP servers

- `--static-mcp` allows each selected remote server's host for that sandbox (rule source `mcp`),
  and no other. The port isn't part of the rule. A server with a header secret is also allowed as
  a credential host, subdomains included. The rules go with the sandbox.
- A header secret (`mcp:<server>:<name>`) is bound to the server's host as a smolvm credential. The
  sandbox and its agent MCP config hold only a placeholder, and the real value goes only on HTTPS
  requests to that host. Anything in the sandbox can make such requests, so the secret's reach is
  whatever that server allows its holder.
- A header without `${...}` isn't a secret. It's written into the agent's config as given, and so
  is the URL. A URL with credentials in it is refused at `mcp add`.
- A kit can't ask for an `mcp:` secret as its own credential.
- A `--command` server runs inside the sandbox, with the agent's privileges and network policy. It
  never runs on your machine.
- Registered names, URLs and header values are quoted into the registration script. A header value
  is never executed in the guest.

## Environment files

- `bindings` add domains a credential may be sent to. As in sbx, they are global: once approved,
  every later sandbox may send your token to them too. They're listed in the plan, stored in your
  secrets file, and removed with `bento env rm --prune-bindings`.
- An `sbxenv.yaml` from a repository can run commands on your machine. A secret's `command:` source
  runs with your privileges, at `env create` (to check it) and at each start. `env create` and
  `env run` show every such command and ask `Approve this plan? (y/N)` first. `--force` skips the
  question. Use `--force` only on files you trust.
- An approval covers exactly the plan you saw and is remembered for that environment. A change to
  the files or to a resource asks again. A file that declares host commands (lifecycle commands, or
  `command:` sources of secrets and registries) asks on every `env create` and `env run`, unless
  you set `env.rememberHostCommands`.
- Lifecycle commands run on your machine with your privileges and `bento`'s environment. They get
  neither the file's `env` values nor any secret. `--skip-host-commands` skips them. A command with
  a `timeout` is killed, with everything it started, when time is up.
- `entrypoint` and `cmd` run inside the sandbox under `env run`, never on your machine.
- A `registries` login is resolved once at create, stored like other secret values, and kept for
  that sandbox only. `env rm` or `rm` removes it.
- The approval record (`<data dir>/env/<name>.toml`) holds what the plan shows. A literal secret
  appears there only as its SHA-256 digest, and the summary shows it as a hash. The value is never
  shown.
- Every secret `command:` source (here and in `bento secret set --command`) runs from a fresh
  temporary directory, so it can't pick up a script from the current directory
  ([details](network-and-secrets.md#secrets)).
- A failed `env create` leaves the secrets it stored. `env rm` with the same files removes them.

## Supply chain

- Agent images are Docker's `docker/sandbox-templates`, pinned to version tags. Renovate updates
  them after a 7-day waiting period.
- `cargo deny` checks dependencies for advisories and licences on every change. zizmor checks the
  GitHub workflows.
- Release binaries are signed with Sigstore (`cosign sign-blob`, keyless). The macOS binary also
  carries an ad-hoc code signature.

## Reporting a vulnerability

Report security issues privately with GitHub's **Report a vulnerability** button on the
[pelotech/smolbento](https://github.com/pelotech/smolbento/security) Security tab, not in a public
issue.
