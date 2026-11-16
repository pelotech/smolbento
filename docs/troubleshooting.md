# Troubleshooting

Start with `bento diagnose`. Add `-D` to any command to print the smolvm commands it runs, for example
`bento -D run claude`. `bento diagnose --format github-issue` prints the checks as Markdown to paste
into an issue. It includes paths on your machine, so read it first. Nothing is uploaded.

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

Cause: smolvm maps the workspace to the agent only for a normal user's workspace.

Run `bento` as your normal user. On Linux, grant that user `/dev/kvm` access instead of using `sudo`.

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

Cause: the sandbox was created by an older smolbento, or the workspace is owned by root.

- Recreate sandboxes made by an older smolbento (see [Install](install.md#upgrading)).
- Make sure the workspace isn't owned by root.

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
