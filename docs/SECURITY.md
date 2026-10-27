# Security

## What a sandbox isolates today

Each sandbox is a separate microVM with its own kernel, so the agent's processes, packages and
Docker engine are kept off your machine. The agent can reach your machine only through:

- the workspace directories you mount, which it can read and write as you (or only read, with
  `:ro`);
- ports you publish with `-p`, on `127.0.0.1`;
- the network.

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
  agent and only commits come back, when you `git fetch sandbox-<name>`; review them before you
  merge. Fetched objects can be checked with `git -c fetch.fsckObjects=true fetch`.
- `sbt exec --privileged` and the sandbox's Docker engine run as root inside the VM.
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
