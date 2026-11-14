# Security

## What a sandbox isolates today

Each sandbox is a separate microVM with its own kernel. The agent's processes, packages and Docker
engine stay off your machine. The agent reaches your machine only through:

- the workspace directories you mount, read-write or read-only (`:ro`);
- ports you publish with `-p`, on `127.0.0.1`;
- the network.

In every policy mode, sandboxes can't reach your machine's localhost (`127.0.0.1` or `::1`) unless
you add a `localhost` rule. Sandboxes created with smolbento 0.2.1 or earlier can. Recreate them
with `sbt rm`, then create them again.

### Host services (`localhost` rules)

`sbt policy allow network [--sandbox NAME] localhost[:PORT]` lets sandboxes reach your localhost as
`host.docker.internal`. smolvm can't open a single host port yet, so a rule opens more than it
names:

- The rule opens every port on your `127.0.0.1` (not `::1`) to the sandboxes it applies to.
  `policy allow` warns about this each time.
- A sandbox gets host access only if a `localhost` allow rule applies to it at create. Any other
  sandbox keeps your loopback blocked for its life, and a later rule doesn't open it. `policy allow`
  names those sandboxes. Sandboxes created before smolbento had host services keep the block until
  recreated.
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

## Network and secrets

- Use `balanced` or `deny-all` for untrusted work. Sandboxes created before you chose a policy stay
  open until their next start.
- Secrets are placeholders inside the sandbox. A real value goes only to that service's hosts, and
  only over HTTPS. A secret's hosts and their subdomains are always reachable from sandboxes that
  bind it.
- Host rules are looser than sbx's. `*.x.com` matches any depth, wildcards inside a label widen,
  and ports, methods and paths aren't enforced. See [sbx compatibility](sbx-compatibility.md).

## Kits

Kits can install software as root, run steps on every start, and open network access, so load only
kits you trust.

- Published kits load only from `kit.allowedSources` prefixes, and local kits only while
  `kit.allowLocalKits` is `true`. Both checks run before anything is downloaded or built. A prefix
  without `/`, such as `ghcr.io`, matches only that host, never `ghcr.io.evil.com`. See
  [Kit sources](configuration.md#kit-sources).
- Signatures are checked only when `kit.requireSignature` is `true` (default `false`). Then a
  registry kit needs a signature from a `kit.trustedSigners` signer, and local kits are refused.
  `--offline` skips the check. See [Kit signatures](configuration.md#kit-signatures).
- Images a kit names (a workload kit's image, and the base its layers are added to) are pulled
  without a `kit.allowedSources` check, like a Dockerfile's `FROM`.
- Registry transport is HTTPS, except for loopback registries (`localhost`, `127.0.0.0/8`,
  `::1`), which use plain HTTP, as in Docker.
- Kit network rules apply to their sandbox only, even under `deny-all`. `sbt policy ls --source kit`
  lists them, one `kit:NAME` row per sandbox. Deny rules always win: to block a host a kit allows,
  run `sbt policy deny network --sandbox NAME HOST`.
- Install-only rules aren't listed by `policy ls`, as in sbx. They apply from create through the
  first start's setup and install steps, then go, and later starts never use them. `sbt rm` removes
  leftovers from an interrupted create, as does the next create of that name. A CIDR deny made
  during install stays for the sandbox's life, because smolvm takes CIDR denies only at create.
- `kit add` asks before opening new network access on an existing sandbox. `-y` grants it. Without
  a terminal it fails.
- Kit credentials are your secrets as placeholders. A value goes only to the hosts the kit names,
  or to the service's own hosts if it names none.
  - A **built-in** service's secret (`github`, `anthropic`, ...) goes only to that service's own
    hosts. Naming another host fails: "kit K wants to send your github secret to HOST, which github
    doesn't use; refusing". sbx trusts the kit here; smolbento doesn't, because Docker Hub kits
    load by default.
  - A **custom** service's secret (`sbt secret set-custom`) goes to any host the kit names. `create`
    and `kit add` print "kit K sends your SERVICE secret to HOSTS".
  - `sbt kit inspect REF` lists each credential's service and hosts under `Credentials:`
    (`credentials` in `--format json`).
  - A credential's hosts are always reachable, and a deny rule can't block them while the kit's
    binding exists. That binding lasts the sandbox's life, because smolvm needs those hosts to send
    the secret. Recreate the sandbox without the kit to drop it.
  - A credential with no secret set doesn't stop create. It warns
    (`WARN: required credential not found for service SERVICE`), and requests go out without it
    until you set the secret and recreate the sandbox.
  - A credential needed only while installing is gone after install.
- Install steps run as root. A v3 install step gets a clean environment (`PATH`, `HOME`, `USER`,
  `TERM`, the proxy and CA variables, and the variables it declares). Startup and v2 steps get the
  whole sandbox environment, including secret variables, which hold placeholders. A failing startup
  step stops the sandbox from starting until it's fixed.
- A workload kit's agent runs as the image's `USER`, or as root if there is none, as sbx does.
  smolvm maps your workspace to that user so it can write it.
- Kit host mounts (`host-mount@1`) are directories on your machine. Writes land on your disk,
  outside the VM. Every other sandbox of the same kit reads them, even after this sandbox is
  removed, and so do later versions of a published kit (keyed by repository). Don't share one
  between an untrusted sandbox and one you trust. With `--mount`, the sandbox reads and writes the
  directory you give it and everything below it.
- Kit arguments aren't secret. Their values can reach the sandbox's environment and smolvm's machine
  config. Put secrets in credentials, not `--kit-arg`.
- Local kit builds run in the `_builder` sandbox, a VM under your global network policy, not on
  your Docker. The builder never gets your secrets.
- Registry credentials (`sbt secret set --registry`) stay on your machine. The login goes only over
  HTTPS (or plain HTTP to a localhost registry), and only to that registry, to `auth.docker.io` for
  Docker Hub, or to the exact `--registry-auth-endpoint`. For a local build, smolbento trades the
  login on the host for a pull token scoped to the repositories the kit's descriptor names. The
  token lasts a few minutes. smolvm sets it as the builder's `Authorization` header, so the guest
  sees only a placeholder. Every registry you stored a credential for is reachable from the
  builder, even under `deny-all`, because sbx's host build isn't bound by policy either. A build
  step can use the token until it expires. Some registries (`dhi.io`) honour it for repositories
  outside its scope.

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
  secrets file, and removed with `sbt env rm --prune-bindings`.
- An `sbxenv.yaml` from a repository can run commands on your machine. A secret's `command:` source
  runs with your privileges, at `env create` (to check it) and at each start. `env create` and
  `env run` show every such command and ask `Approve this plan? (y/N)` first. `--force` skips the
  question. Use `--force` only on files you trust.
- An approval covers exactly the plan you saw and is remembered for that environment. A change to
  the files or to a resource asks again. A file that declares host commands (lifecycle commands, or
  `command:` sources of secrets and registries) asks on every `env create` and `env run`, unless
  you set `env.rememberHostCommands`.
- Lifecycle commands run on your machine with your privileges and `sbt`'s environment. They get
  neither the file's `env` values nor any secret. `--skip-host-commands` skips them. A command with
  a `timeout` is killed, with everything it started, when time is up.
- `entrypoint` and `cmd` run inside the sandbox under `env run`, never on your machine.
- A `registries` login is resolved once at create, stored like other secret values, and kept for
  that sandbox only. `env rm` or `rm` removes it.
- The approval record (`<data dir>/env/<name>.toml`) holds what the plan shows. A literal secret
  appears there only as its SHA-256 digest, and the summary shows it as a hash. The value is never
  shown.
- Every secret `command:` source (here and in `sbt secret set --command`) runs from a fresh
  temporary directory, so it can't pick up a script from the current directory. Use an absolute
  path or `PATH`.
- A failed `env create` leaves the secrets it stored. `env rm` with the same files removes them.

## Other things to know

- The agent runs with permission prompts disabled, so the VM is the only boundary.
- Workspaces are mounted read-write by default. Anything the agent writes, including git hooks or
  config in a mounted repo, lands on your machine. With `--clone`, the agent can't write to your
  repo. Only commits come back, on `git fetch sandbox-<name>` (not tags). Review them before you
  merge, and check fetched objects with `git -c fetch.fsckObjects=true fetch`.
- With `--clone`, the agent can read your repo's whole `.git`, including `.git/config`, as in sbx.
  A user name and token in an HTTPS remote URL are left out of the clone's own remotes, but they
  stay in that file, and so does any `http.extraHeader`. Keep credentials out of repo config. Use
  a credential helper or `sbt secret`. `create --clone` warns about remote URLs with a token.
- `sbt exec --privileged` and the sandbox's Docker engine run as root inside the VM.
- Forkable sandboxes (clone and mountless, not forks) start branchable. On Linux this drops smolvm's
  no-ptrace hardening of the VM process, so other processes running as you can read its memory,
  including secret values. On every platform, smolvm stops returning their idle memory. Turn it off
  with `sbt settings set fork.enabled false`, from each sandbox's next start.
- smolbento refuses to run as root on the host, because smolvm doesn't map a root-owned workspace
  to the agent user.
- While you're attached (`sbt run`, `sbt exec -it`), the sandbox can open `https://` URLs in your
  browser and overwrite your clipboard, but it can't read the clipboard. A malicious page opened
  this way runs in your real browser, with your logins. Turn off URL opening with
  `sbt settings set browser.enabled false`. Clipboard text may be crafted to run commands when
  pasted, so check it first.
- The bridge socket lives in `/tmp/sbt-<uid>/` (mode 0700). At create and at each start, smolbento
  checks that it's a real directory (not a symlink), owned by you, with mode 0700, and creates it
  that way if missing. If the check fails, the sandbox gets no bridge for that start, with a
  warning. This stops another user from receiving what the sandbox sends by creating the directory
  first (macOS empties `/tmp` on reboot).
- Forks don't install bridge shims, but they keep the parent's socket mount. While the parent is
  attached, a process in a fork can open URLs and copy through the parent's bridge.
- OAuth callback ports. For an opened URL whose `redirect_uri` is `http://localhost:PORT` or
  `http://127.0.0.1:PORT`, smolbento listens on your `127.0.0.1:PORT` (never other interfaces) for
  10 minutes or until the session ends. It opens at most 4 ports a session, and not if something
  already answers on `localhost:PORT`. It passes requests whose `Host` is `localhost:PORT` or
  `127.0.0.1:PORT` into the sandbox. Known gaps:
  - Other local programs can reach that port while it's open, as they could reach an agent's
    callback server on your machine.
  - The sandbox can claim that port before a service of yours starts on it.
  - Pages the sandbox serves there are on `localhost`, whose cookies aren't separated by port. They
    can read and set the cookies of your other `localhost` apps.
  - Each replay is cut off after 15 seconds or 1 MiB of response.
  - `browser.enabled false` also turns the relay off.
- Built-in agents, and kits that ask with `ssh-agent@1`, can use your SSH agent while `sbt run`,
  `sbt exec -it` or `sbt exec` runs for them, and during a kit's `install` grant. They can list
  your agent's public keys and have it sign with any of them. That covers git commit signatures and
  SSH logins to any server your keys open. A kit's `sign: [...]` list allows only signatures in
  those namespaces, not logins. They can't add, remove or lock keys or do anything else;
  smolbento answers those requests itself with a failure. Your private keys never enter the
  sandbox.
  While the agent is served, code in the sandbox can sign as you and log in wherever your keys
  work. Don't run untrusted work with it. A fork keeps the parent's socket mount, so while the
  parent is served, a fork can use the agent with the parent's grant. The socket lives in
  `/tmp/sbt-<uid>/` and gets the bridge's checks: no agent for a start while that directory isn't
  private, and a kit that requires an agent is refused at create.
  To turn it off, run `sbt settings set ssh.agentForwardingEnabled false`. New connections are
  refused at once, and open ones stay. Or run `sbt` without `SSH_AUTH_SOCK`. For a dedicated agent
  that holds only the keys you want sandboxes to use, set `ssh.agentSocketPath` to its socket.

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
- A kit can widen `readwrite` to links. With `--skills readwrite`, a kit that bundles a skill and
  names a `readwrite` directory makes `/run/sbx/skills-shared` read-write. The agent can then
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
