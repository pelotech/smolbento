# Security

## What a sandbox isolates today

Each sandbox is a separate microVM with its own kernel, so the agent's processes, packages and
Docker engine are kept off your machine. The agent can reach your machine only through:

- the workspace directories you mount, which it can read and write as you (or only read, with
  `:ro`);
- ports you publish with `-p`, on `127.0.0.1`;
- the network.

## What it does not isolate yet

!!! warning "Open network"
    Until the network policy phase lands, sandboxes have **unrestricted outbound network access**,
    and secrets are not proxied. An agent that can be steered by untrusted input (a malicious
    issue, dependency or web page) could send your workspace or any API key you pass with `-e`
    anywhere. Don't use smolbento for untrusted work yet; see
    [Development status](development-status.md).

Other things to know:

- The agent runs with its permission prompts disabled. The VM, not the agent, is the boundary.
- Workspaces are mounted read-write by default. Anything the agent writes, including git hooks or
  config in a mounted repo, lands on your machine. A safer clone mode (only commits come back) is
  planned.
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
