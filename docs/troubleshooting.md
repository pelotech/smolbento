# Troubleshooting

Start with `sbt diagnose`. Add `-D` to any command to print the smolvm commands it runs, for example
`sbt -D run claude`.

## `smolvm 1.x is too old`

Cause: smolvm is older than 1.34.4.

```sh
brew upgrade smolvm
```

## `could not run smolvm`

Cause: smolvm isn't on your `PATH`.

```sh
brew install smol-machines/tap/smolvm
# or point smolbento at it
sbt settings set smolvm.path /path/to/smolvm
```

## `don't run sbt as root`

Cause: smolvm maps the workspace to the agent only for a normal user's workspace.

Run `sbt` as your normal user. On Linux, grant that user `/dev/kvm` access instead of using `sudo`.

## `diagnose` says `FAIL /dev/kvm` (Linux)

Cause: KVM is missing or not accessible.

```sh
ls -l /dev/kvm
sudo modprobe kvm_intel        # or kvm_amd, if the device is missing
sudo usermod -aG kvm $USER     # if the device exists; then log out and back in
```

If the device is missing, enable virtualization in the BIOS or firmware (in a VM, enable nested
virtualization) first.

## `diagnose` says the hypervisor entitlement is missing (macOS)

Cause: the smolvm binary lacks `com.apple.security.hypervisor`, usually because it was built unsigned.

Reinstall smolvm from Homebrew or its release tarball.

## `diagnose` says `FAIL config`

Cause: `~/.config/smolbento/config.toml` doesn't parse. The message shows the error.

```sh
sbt settings unset <key>       # reset one setting, or fix the file by hand
```

## `Permission denied` writing the workspace

Cause: the sandbox was created by an older smolbento, or the workspace is owned by root.

- Recreate sandboxes made by an older smolbento (see the next section).
- Make sure the workspace isn't owned by root.

A custom `-t` image must have an `agent` user, or the sandbox won't start.

## `was created by an older smolbento`

Cause: the sandbox predates workspace mapping (no `sbx.mapped` label), so it can't start.

```sh
sbt rm NAME
sbt create AGENT PATH --name NAME
```

`ls`, `inspect`, `rm`, `prune` and `reset` still work on it. To keep what's installed inside, save it
as a template first (see [Install](install.md#upgrading-sandboxes-from-an-older-smolbento)).

## The first run is slow

Cause: the first run of each agent pulls its image (a few hundred MB to a few GB). Later runs start in
seconds.

## `Cannot connect to the Docker daemon` inside a sandbox

Cause: the sandbox's Docker engine starts in the background and takes a few seconds. Sandboxes created
with `docker.enabled=false` have no Docker engine.

If the error persists, read the daemon log:

```sh
sbt exec --privileged <name> cat /var/log/dockerd.log
```

## A sandbox won't go away, or `already exists`

Cause: a leftover sandbox or smolvm machine.

```sh
sbt ls
sbt rm -f <name>
smolvm machine delete -n sbx-<name> -f   # if the sandbox is still listed in smolvm
```

A sandbox whose first start fails is removed, so you can rerun the command. If the removal fails too,
run `sbt rm -f <name>`.

## A storage error from smolvm

Cause: usually a full disk.

```sh
df -h ~
sbt prune                # remove stopped sandboxes
sbt rm NAME              # remove one sandbox
sbt template rm NAME     # remove a saved template
```

## `Refusing without a terminal; pass -f`

Cause: `rm`, `prune` and `reset` ask for confirmation.

In scripts and CI, pass `-f`.
