# Security

## What a sandbox isolates today

Each sandbox is a separate microVM with its own kernel, so the agent's processes, packages and
Docker engine are kept off your machine. The agent can reach your machine only through:

- the workspace directories you mount, which it can read and write as you (or only read, with
  `:ro`);
- ports you publish with `-p`, on `127.0.0.1`;
- the network.

Sandboxes can't reach services on your machine's localhost (`127.0.0.1` or `::1`), in any policy
mode. Sandboxes created with smolbento 0.2.1 or earlier can: remove them with `sbt rm` and create
them again.

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

Other things to know:

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
