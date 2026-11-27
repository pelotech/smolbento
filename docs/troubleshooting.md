# Troubleshooting

Error messages and symptoms, each with its cause and fix.

Start with `bento diagnose`. Add `-D` to any command to print the smolvm commands it runs and turn
on the log below at `info`, for example `bento -D run claude`. `bento diagnose --format github-issue`
prints the checks as Markdown to paste into an issue. It includes paths on your machine, so read it
first. Nothing is uploaded.

## Logs and timings

`SMOLBENTO_LOG` turns on smolbento's log, on stderr. It takes a level (`info`, `debug`, `trace`) or a
filter per crate (`smolbento=debug,smolvm_credentials=info`), and wins over `-D`'s `info`. Unset,
nothing is logged. Stdout, `--json` included, is unchanged. Each step logs its time when it ends:
every smolvm call (its arguments and exit code) and the phases of `create`, `start`, `run` and
`exec`: kit resolve and loads, the kit build, the start plan, the boot, setup, install and startup
steps, the Docker engine, and the host services.

```console
$ SMOLBENTO_LOG=info bento create shell . 2>bento.log
$ grep close bento.log
… INFO bento_create:kit_resolve{sandbox=shell-proj}: smolbento::cli::request: close time.busy=104s …
… INFO bento_create:provision{sandbox=shell-proj}:create:start{sandbox=shell-proj}:smolvm{cmd=machine start -n sbx-shell-proj --egress-interceptor 127.0.0.1:51558 code=0}: smolbento::smolvm: close time.busy=1.07s …
…
```

The log and `-D` show flags, variable names and hosts, never secret or environment values. `-e`
values, long arguments (scripts, labels) and a guest command's arguments are left out
(`-- gh (+3 args)`).

`SMOLBENTO_LOG` doesn't reach a hosted sandbox's egress process. That process logs startup errors
and denied connections to its `egress.log` (see [Network and secrets](network-and-secrets.md)).

## `downloading smolvm from … failed`

Cause: smolbento downloads its smolvm from GitHub the first time a command needs it, and couldn't
reach GitHub. Retry once online. To work offline later, run `bento smolvm --version` while online.
Behind a firewall that blocks GitHub, download the release named in the error yourself, unpack it,
and point smolbento at it:

```sh
bento settings set smolvm.path /path/to/smolvm-VERSION-PLATFORM/smolvm
```

## `smolvm download … failed its checksum`

Cause: the download doesn't match the checksum built into smolbento: a proxy changed it, or the
release was replaced. Don't work around it. Retry, and report it if it persists.

## `could not run …/smolvm`

Cause: `smolvm.path` points at a smolvm that isn't there. Unset it to use the downloaded one:

```sh
bento settings unset smolvm.path
```

## `smolvm.home … is too long for macOS sockets`

Cause: macOS limits socket paths to 103 bytes, and smolvm's deepest socket sits several folders
inside `smolvm.home`. Set a shorter path, or unset it to use `~/.smolbento`.

## `diagnose` says `libbz2.so.1 not found` (Linux)

Cause: smolvm needs the bzip2 library. Install it (`apt install libbz2-1.0`, `dnf install bzip2-libs`).

## `diagnose` says `mkfs.ext4 not found` (macOS)

Only sandboxes with a disk larger than 20 GiB need it: `brew install e2fsprogs`.

## `don't run bento as root`

Cause: smolvm can't map a root-owned workspace to the agent user.

Run `bento` as your normal user. On Linux, grant that user `/dev/kvm` access (see below) instead of
using `sudo`.

## `diagnose` says `FAIL /dev/kvm` (Linux)

Cause: KVM is missing or not accessible.

```sh
ls -l /dev/kvm
# or kvm_amd, if the device is missing
sudo modprobe kvm_intel
# if the device exists; then log out and back in
sudo usermod -aG kvm $USER
```

If the device is missing, first enable virtualization in the BIOS or firmware. In a VM, enable
nested virtualization instead.

## `diagnose` says the hypervisor entitlement is missing (macOS)

Cause: the smolvm binary lacks `com.apple.security.hypervisor`, usually because it was built unsigned.

If you set `smolvm.path`, sign your build or unset it. Otherwise delete `~/.smolbento/engine` so
the next command downloads smolvm again.

## `diagnose` says `FAIL config`

Cause: `~/.config/smolbento/config.toml` doesn't parse. The message shows the error.

```sh
# reset one setting, or fix the file by hand
bento settings unset KEY
```

## `Permission denied` writing the workspace

Cause: the workspace is owned by root, or the sandbox was made by an older smolbento. Change the
owner, or recreate the sandbox ([Install](install.md#upgrading)).

A custom `-t` image must have an `agent` user, or the sandbox won't start.

## The first run is slow

Cause: the first run of each agent pulls its image (a few hundred MB to a few GB). Later runs start in
seconds.

## `Cannot connect to the Docker daemon` inside a sandbox

Cause: the sandbox's Docker engine starts in the background and takes a few seconds. Sandboxes created
with `docker.enabled=false` have no Docker engine.

If the error persists, read the daemon log:

```sh
bento exec --privileged NAME cat /var/log/dockerd.log
```

## Sandbox name already used by another workspace

Cause: the default name, `<agent>-<directory name>`, belongs to another directory's sandbox (two
directories with the same name). The error suggests a name with the parent directory:

```console
$ bento run claude
error: sandbox name "claude-infrastructure" is already used by workspace "/src/work/infrastructure"; pass --name to choose a different name, such as --name claude-oss-infrastructure
```

Pass `--name`, or set `sandbox.autoName` to take the suggested name
([Usage](usage.md#run-an-agent)).

## `502` from a secret's or registry's host

Cause, on a hosted sandbox: a `--ref` or `--command` secret needs a variable from your shell, and
the egress process doesn't get it ([Hosted egress](network-and-secrets.md#hosted-egress)). The
egress process lists the secrets it couldn't resolve, and `bento create` and `start` warn about each
once the sandbox is up, if the process has got that far. Use a source that doesn't need the shell's
variables (a stored value, a command that reads a file), or create the sandbox with
`network.egress=smolvm`, where secrets resolve in the shell that starts it.

Cause, in a local kit build: `502 credential unavailable` means the build reached a logged-in
registry without naming it as `HOST/<repo>` in its descriptor. Write the image as `HOST/<repo>`, or
remove the login (`bento secret rm --registry HOST`).

## Connections reset

Cause: a hosted sandbox's egress process denied the connection. The guest sees it open, then reset,
not refused: curl exits 35 or 56 (52 for plain HTTP), not 7. Its `egress.log`
([Hosted egress](network-and-secrets.md#hosted-egress)) has each denied connection with its reason
(`deny gist.github.com:443: …`). Plain HTTP to a host with request rules is logged as `plain HTTP to
a host with request rules`: use HTTPS.

## `403` from a hosted sandbox

Cause: a [request rule](network-and-secrets.md#request-rules) refused the request. The body names
the deny rule (`… (rule r-1a2b3c4d)`; `bento policy ls --wide` shows rule IDs), or, on a host that
only bounded allows admit, says `no rule allows POST /post on httpbin.org`. A path the egress
process can't judge is refused as `ambiguous request target`.

## `recreate required`

Cause: `bento kit add` of a kit that changes what a sandbox fixes at create
([Kits](kits.md#adding-a-kit-to-a-sandbox)). Nothing was changed. Create a new sandbox with the kit.

## `needs an SSH agent, but SSH_AUTH_SOCK is unset`

The full message is `kit K: com.docker.sandbox/ssh-agent@1 needs an SSH agent, but SSH_AUTH_SOCK is
unset`. Cause: the kit requires your SSH agent and none was found. Run `bento` with `SSH_AUTH_SOCK`
set, or set `ssh.agentSocketPath` ([Usage](usage.md#ssh-agent)).

## `clone skills repository: exit status N`

Cause: `bento skills add` couldn't clone the repository with your host `git`, which never prompts.
For a private repository, set up a credential helper or SSH agent first.

## Bundled skill name already used

The full message is `failed to compose shared skills into the sandbox: bundled skills NAME cannot be
exposed in DIR: another skill already uses the name`. Cause: a kit's required bundled skill has the
name of a skill in your store ([Skills from kits](kits.md#skills-from-kits)). The create stops
before the sandbox is made.

## `failed to write host clipboard`

The full message is `<command>: failed to write host clipboard (copying may be off: …)`. Cause:
copying is off, or nothing serves the clipboard socket. Turn copying on with `bento settings set
clipboard.textCopy true`; see [Host services](usage.md#host-services) for when the socket is served.

## A sandbox won't go away, or `already exists`

Cause: a leftover sandbox or smolvm machine.

```sh
bento ls
bento rm -f NAME
# if it's still listed by `bento smolvm machine ls`
bento smolvm machine delete --name sbx-NAME -f
```

A sandbox whose first start fails is removed, so you can rerun the command. If the removal fails too,
run `bento rm -f NAME`.

## A storage error from smolvm

Cause: usually a full disk.

```sh
df -h ~
# remove stopped sandboxes
bento prune
# remove one sandbox
bento rm NAME
# remove a saved template
bento template rm NAME
```

## `Refusing without a terminal; pass -f`

Cause: `rm`, `prune` and `reset` ask for confirmation.

In scripts and CI, pass `-f`.
