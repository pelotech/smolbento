# smolbento and Docker Sandboxes

smolbento is an independent project. It isn't affiliated with or endorsed by Docker. It exists
because Docker designed a good command line and published a
[kit spec](https://github.com/docker/sandbox-kit-spec) for running agents in sandboxes, and
smolbento follows both on top of [smolvm](https://github.com/smol-machines/smolvm).

Both run each agent in its own microVM, and neither needs Docker Engine on the host. smolbento
keeps sbx's commands and kits, so the agents and kits Docker publishes work in either.

## How they differ

| | smolbento | Docker Sandboxes (`sbx`) |
|---|---|---|
| Account | None. Agent kits pull from Docker Hub without a login | Docker sign-in (`sbx login`) |
| Source | Open source, Apache-2.0 | Distributed by Docker as binaries |
| Background process | None. Each command calls smolvm directly | A local daemon |
| MicroVM | [smolvm](https://github.com/smol-machines/smolvm) (libkrun: Hypervisor.framework on macOS, KVM on Linux) | Docker's hypervisor sandbox |
| Hosts | macOS on Apple Silicon; Linux x86_64 or arm64 with KVM | macOS 14+ on Apple Silicon, Windows 11, Ubuntu 24.04+ |
| Command line | sbx's commands and flags; `alias sbx=bento` makes it a drop-in | `sbx` |
| Cloud sandboxes | No | Yes |

## Which to use

Docker Sandboxes is the reference implementation, from the team that designed the command line
and the kit spec. It also runs on Windows, and offers cloud sandboxes and organization policy.
smolbento suits you when you want an open-source tool with no account and no background process, on
macOS or Linux.

Where a command, flag or kit behaves differently, [sbx compatibility](sbx-compatibility.md) lists
it.

## What we haven't verified

The sbx column is our reading of Docker's documentation and of the sbx versions named in
[sbx compatibility](sbx-compatibility.md), which also lists what is
[not measured yet](sbx-compatibility.md#not-measured-against-sbx-yet). Windows and Ubuntu host
support, cloud sandboxes and organization policy are from Docker's documentation, not tried by us.
We haven't checked how sbx is licensed. Docker's documentation is the authority and sbx changes
quickly, so a row can be out of date. If something here is wrong,
[open an issue](https://github.com/pelotech/smolbento/issues).
