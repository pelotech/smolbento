# Security

## What a sandbox isolates today

Each sandbox is a separate microVM with its own kernel, so the agent's processes, packages and
Docker engine are kept off your machine. The agent can reach your machine only through:

- the workspace directories you mount, which it can read and write as you (or only read, with
  `:ro`);
- ports you publish with `-p`, on `127.0.0.1`;
- the network.

Sandboxes can't reach services on your machine's localhost (`127.0.0.1` or `::1`), in any policy
mode, unless you add a `localhost` rule (below). Sandboxes created with smolbento 0.2.1 or earlier
can: remove them with `sbt rm` and create them again.

### Host services (`localhost` rules)

`sbt policy allow network [--sandbox NAME] localhost[:PORT]` lets sandboxes reach your machine's
localhost as `host.docker.internal`. What it really opens, until smolvm can open a single host
port:

- **Every port.** A `localhost` rule opens every port on your machine's `127.0.0.1` (not `::1`) to
  the sandboxes it applies to, whatever port it names. `policy allow` warns about this each time.
- **Only sandboxes created with host access.** A sandbox gets host access only if one of your own
  `localhost` allow rules applies to it when it's created. Every other sandbox is created with
  your machine's loopback blocked for its life; a later `localhost` rule doesn't open it (`policy
  allow` names those sandboxes) until you recreate them. Sandboxes created before smolbento had
  host services keep the block until they're recreated.
- **Closing it is best-effort.** `policy rm` of the rule closes the port in a running sandbox at
  once, but a sandbox created with host access can still reach your machine's localhost in other
  ways, for example a broad allow CIDR or a DNS answer covering `100.96.0.1`, the always-allowed
  `127.0.0.0/8` in restricted allow lists, or a switch to `allow-all`. To
  take host access away for good, recreate the sandbox without the rule.
- **`allow-all` is fixed at create.** An `allow-all` sandbox created with host access reaches every
  host port for its life, rule or not (`policy rm` says so).
- **Kits can't grant it.** A kit's `localhost` rules never give a sandbox host access, only yours
  do.
- **The kit builder never has it.** `_builder` is always created with your machine's loopback
  blocked, even under a global `localhost` rule.

Under `allow-all`, a sandbox can still reach your machine's LAN IP, so a service listening on all
interfaces (`0.0.0.0`) is reachable through it. `balanced` and `deny-all` block it unless you allow
that address.

## Network and secrets

- Choose a network policy (`balanced` or `deny-all` for untrusted work). Sandboxes created before
  you chose one stay open until their next start.
- Secrets are placeholders inside the sandbox; the real value only travels to that service's hosts,
  and only over HTTPS. A secret's hosts, and their subdomains, are always reachable from sandboxes
  that bound it.
- Host rules are enforced a little more loosely than in sbx: `*.x.com` matches any depth,
  wildcards inside a label widen, and ports, methods and paths in rules aren't enforced. See
  [sbx compatibility](sbx-compatibility.md).

## Kits

A kit can install software as root in the sandbox, run steps on every start and open network
access, so load only kits you trust.

- **Which kits load.** Published kits only from the prefixes in `kit.allowedSources` (default
  Docker Hub, `["docker.io/"]`), and local kits only while `kit.allowLocalKits` is `true` (the
  default). Both are checked before anything is downloaded or built. A prefix without `/`, such as
  `ghcr.io`, matches only that registry host, never a look-alike such as `ghcr.io.evil.com`.
  Signatures aren't checked yet. The images a kit names (a workload kit's image, the base image its
  layers are added to) are pulled without a `kit.allowedSources` check, like a Dockerfile's
  `FROM`. Registries are reached over HTTPS, except
  loopback ones (`localhost`, `127.0.0.0/8`, `::1`), which use plain HTTP, as in Docker.
- **Kit network rules.** A kit's allow rules are added for its sandbox only, even under
  `deny-all`, as in sbx. `sbt policy ls --source kit` lists them as one `kit:NAME` row per
  sandbox (`--source local` lists yours). Deny rules always win: to block a host a kit allows, run
  `sbt policy deny network --sandbox NAME HOST`. Rules a kit needs only while installing aren't
  listed by `policy ls`, as in sbx; they are in place from the sandbox's creation through its first
  start's setup and install steps, and removed when install finishes. Later starts never use them,
  even if a create was interrupted before it could remove them; `sbt rm` removes any left over,
  and so does the next create of that name. An install-phase deny of a CIDR stays for the
  sandbox's life: smolvm takes CIDR denies only at create.
- **`kit add`** asks before it opens new network access on an existing sandbox; `-y` grants it,
  and without a terminal it fails.
- **Kit credentials** use your secrets, as placeholders in the sandbox; the value only goes to the
  hosts the kit names (or the service's own hosts, if it names none). What a kit can do with them:
  - A kit may send a **built-in** service's secret (`github`, `anthropic`, …) only to that
    service's own hosts. Naming any other host fails: "kit K wants to send your github secret to
    HOST, which github doesn't use; refusing". sbx trusts the kit here; smolbento doesn't, because
    Docker Hub kits load by default.
  - A kit may send a **custom** service's secret (`sbt secret set-custom`) to any host it names.
    `create` and `kit add` print "kit K sends your SERVICE secret to HOSTS".
  - `sbt kit inspect REF` lists each credential's service and the hosts its secret is sent to,
    under `Credentials:`; `--format json` has them in `credentials`.
  - A credential's hosts are always reachable from the sandbox, and a deny rule can't block them
    while the kit's binding exists, which is for the sandbox's life (smolvm needs them to send the
    secret). To drop them, recreate the sandbox without the kit.
  - A credential whose secret isn't set doesn't stop the create, as in sbx: it warns
    (`WARN: required credential not found for service SERVICE`), and the kit's requests go out
    without the credential until you set the secret and recreate the sandbox.
  - A credential a kit needs only while installing is gone after install.
- **What kit steps see.** Install steps run as root. A v3 install step gets a clean environment:
  `PATH`, `HOME`, `USER`, `TERM`, the proxy and CA variables, and only the variables it declares.
  Startup steps and v2 steps get the sandbox's whole environment, including your secrets'
  variables, but those hold placeholders, not the values, as everywhere in the sandbox. A failing
  startup step stops the sandbox from starting until it's fixed.
- **A workload kit's agent** runs as the image's `USER`, or as root if the image sets none, as in
  sbx. A non-root user gets your uid so it can write the workspace, like the built-in agents'
  `agent` user.
- **Kit host mounts** (`host-mount@1`) are directories on your machine. What the sandbox writes
  there lands on your disk, outside the VM, and every other sandbox of the same kit reads it, now
  and after this one is removed (a published kit is keyed by its repository, so later versions of
  it too). Don't let an untrusted sandbox share a kit host mount with one you trust. With `--mount`
  the sandbox can read and write the directory you give it, and everything below it.
- **Kit arguments aren't secret.** Their values can end up in the sandbox's environment and in
  smolvm's machine config. Put secrets in credentials, not in `--kit-arg`.
- **Local kit builds** run in the `_builder` sandbox, a VM under your global network policy, not on
  your machine's Docker. The builder never gets your secrets.
- **Registry credentials** (`sbt secret set --registry`) stay on your machine: the login is sent
  only over HTTPS (or plain HTTP to a registry on localhost) to the registry, `auth.docker.io` for Docker Hub, or the exact
  `--registry-auth-endpoint`. For a local build, smolbento trades it on the host for a pull token
  scoped to the repositories the kit's descriptor names, valid for a few minutes, and smolvm sets
  it as the `Authorization` header on the builder's requests to that registry; the guest sees only
  a placeholder. Every registry you stored a credential for is reachable from the builder, even
  under `deny-all`, as sbx's host build isn't bound by the policy either. A build step can use the
  token for that registry until it expires, and some registries (`dhi.io`) honour it for
  repositories outside its scope.

## Environment files

- An `sbxenv.yaml` from a repository can run commands on your machine, outside the sandbox: a
  secret's `command:` source runs with your privileges (at `env create`, to check it, and at each
  start). `env create` and `env run` show every such command in their summary and ask
  `Apply? [y/N]` before running anything. Nothing is remembered, so they ask each time. `--force`
  skips the question; use it only on files you trust.
- Every secret `command:` source (here and in `sbt secret set --command`) runs from a fresh
  temporary directory, so a command can't pick up a script from the directory you are in. Use an
  absolute path or `PATH`.
- A failed `env create` leaves the secrets it stored; `env rm` with the same files removes them.
- The summary shows a literal secret as a hash, never the value.

## Other things to know

- The agent runs with its permission prompts disabled. The VM, not the agent, is the boundary.
- Workspaces are mounted read-write by default. Anything the agent writes, including git hooks or
  config in a mounted repo, lands on your machine. With `--clone` the repo is read-only to the
  agent and only commits come back, when you `git fetch sandbox-<name>` (not tags); review them
  before you merge. Fetched objects can be checked with `git -c fetch.fsckObjects=true fetch`.
- With `--clone` the agent can read your repo's whole `.git`, as in sbx, including `.git/config`.
  A user name and token in an HTTPS remote URL are left out of the clone's own remotes, but not out
  of that file, and neither is an `http.extraHeader`. Don't keep credentials in the repo config;
  use a credential helper or `sbt secret`. `create --clone` warns about remote URLs with a token.
- `sbt exec --privileged` and the sandbox's Docker engine run as root inside the VM.
- Sandboxes that can be forked (clone and mountless ones, not forks) are started branchable. On
  Linux that drops smolvm's no-ptrace hardening of the VM process, so other processes running as
  you can read its memory, including secret values; on every platform smolvm stops handing their
  idle memory back. Turn it off with `sbt settings set fork.enabled false` (from each sandbox's
  next start).
- smolbento refuses to run as root on the host, because the agent takes the caller's uid.
- While you're attached (`sbt run`, `sbt exec -it`), anything in the sandbox can open `https://`
  URLs in your browser and overwrite your clipboard (it can't read it). A malicious page opened
  this way runs in your real browser, with your logins. To stop URL opening, run
  `sbt settings set browser.enabled false`. Text the sandbox puts on your clipboard may be
  crafted to run commands when pasted into a terminal; check it before pasting it there. The
  bridge socket lives in `/tmp/sbt-<uid>/` (mode 0700). smolbento checks that directory when a
  sandbox is created and at every start: it must be a real directory (not a symlink) owned by you
  with mode 0700, and is created that way if missing. If it isn't, the sandbox gets no bridge for
  that start (the shims are removed), with a warning, so another user who creates the directory
  first (macOS empties `/tmp` on reboot) can't receive what the sandbox sends.
- Forks don't install the bridge shims, but keep the parent's socket mount: while the parent is
  attached, a process in a fork can open URLs and copy through the parent's bridge.
- When an opened URL's `redirect_uri` is `http://localhost:PORT` or `http://127.0.0.1:PORT`,
  smolbento listens on your machine's `127.0.0.1:PORT` (never other interfaces) for 10 minutes
  (or until the session ends), at most 4 ports a session, unless something already answers on
  `localhost:PORT`, and passes requests whose `Host` is `localhost:PORT` or `127.0.0.1:PORT` into the
  sandbox. Other local programs can reach that port too while it's open, as they could reach
  the callback server of an agent running on your machine. While it's open, the sandbox can
  claim that port before a service of yours starts on it. Pages the sandbox serves there are
  on `localhost`, whose cookies aren't separated by port: they can read and set the cookies of
  your other `localhost` apps. Each replay is cut off after 15 seconds or 1 MiB of response.
  `browser.enabled false` also turns the relay off.
- **Your SSH agent.** Sandboxes of the built-in agents, and kits that ask with `ssh-agent@1`, can
  use your SSH agent while `sbt run`, `sbt exec -it` or `sbt exec` runs for them (and a kit's
  `install` grant during the create's install steps). What they can do with it:
  - list your agent's public keys, and have it sign with any of them: git commit signatures, and
    SSH logins to any server your keys open (a kit's `sign: [...]` list allows only signatures in
    those namespaces, no logins);
  - not add, remove or lock keys, or anything else: smolbento answers every other request itself
    with a failure, without passing it on. Your private keys never enter the sandbox.

  While it's served, code in the sandbox can sign as you and log in where your keys work, so
  don't run untrusted work with it. A fork has no agent of its own but keeps the parent's socket
  mount: while the parent is being served, a process in a fork can use the agent with the
  parent's grant. The socket lives in `/tmp/sbt-<uid>/` and gets the same checks as the bridge's
  (a sandbox gets no agent for a start while that directory isn't private, or the create is
  refused for a kit that requires it). To turn it off, run
  `sbt settings set ssh.agentForwardingEnabled false` (new connections are refused at once; open
  ones stay) or run `sbt` without `SSH_AUTH_SOCK`; to use a dedicated agent with only the keys you
  want sandboxes to use, set `ssh.agentSocketPath` to its socket.

## Skills

The shared skills store is agent material that smolbento never runs or reads beyond directory
names. What you share with a sandbox is what its agent will follow:

- **A `readwrite` sandbox can change the skills other sandboxes load.** Its agent writes straight
  into your store, so a skill it changes or adds is linked into every later sandbox, `readonly`
  ones included. Use it only for work you trust.
- **`readonly` doesn't isolate a sandbox from changes.** The agent can't edit a stored skill, but
  it loads whatever the store holds at each start, including changes made by a `readwrite`
  sandbox or by you.
- **Use `--skills off` for untrusted work.** The sandbox gets no store and no skills directory.
- **A kit can widen `readwrite` to links.** With `--skills readwrite`, a kit that bundles a skill
  and names a `readwrite` directory makes `/run/sbx/skills-shared` read-write, so the agent can
  change stored skills through every link. Check a kit's `agent-skills@1` modes before using it
  with `readwrite`.
- **Prefer HTTPS or SSH for `skills add`.** `http://` and `git://` URLs are accepted, as in
  `sbx`, but their content can be changed in transit.
- **Linking runs as root in the guest**, as in `sbx`. It only creates the skills directory and
  links in it, and changes the owner of those alone. It refuses a skills directory whose path
  goes through a symlink anywhere (the directory itself or a parent such as `~/.claude`), checked
  before and after creating it, so the agent can't point it at another place. That includes
  image symlinks such as `/home -> /var/home`: such a sandbox gets no skills links.
- **Bundled kit skills are image content.** An `agent-skill@1` skill comes from the kit's image,
  and smolbento only links it. Its instructions reach the agent like any skill's, so trust the kit
  as you would for its install hooks.

## Supply chain

- Agent images are Docker's `docker/sandbox-templates`, pinned to version tags and updated by
  Renovate after a 7-day waiting period.
- `cargo deny` checks dependencies for advisories and licences on every change; zizmor checks the
  GitHub workflows.
- Release binaries are signed with Sigstore (`cosign sign-blob`, keyless). The macOS binary also
  carries an ad-hoc code signature.

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** button on the
[pelotech/smolbento](https://github.com/pelotech/smolbento/security) Security tab, not in a public
issue.
