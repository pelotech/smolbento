# Troubleshooting

Start with:

```sh
sbt diagnose
```

and add `-D` to any command to print the smolvm commands it runs, for example `sbt -D run claude`.

## `smolvm 1.x is too old`

smolbento needs smolvm 1.34.4 or newer: `brew upgrade smolvm`.

## `could not run smolvm`

smolvm isn't on your `PATH`. Install it (`brew install smol-machines/tap/smolvm`) or point
smolbento at it: `sbt settings set smolvm.path /path/to/smolvm`.

## `don't run sbt as root`

smolvm maps your workspace to the sandbox's agent user only when it runs as a normal user and the
directory isn't owned by root, so the agent couldn't write it. Run `sbt` as your normal user. On Linux, give that user access to
`/dev/kvm` instead of using `sudo`.

## `diagnose` says `FAIL /dev/kvm` (Linux)

Check `ls -l /dev/kvm`. If it is missing, enable virtualization in the BIOS/firmware (in a VM,
nested virtualization) and load the module (`sudo modprobe kvm_intel` or `kvm_amd`). If it exists,
add your user to its group (`sudo usermod -aG kvm $USER`) and log out and back in.

## `diagnose` says the hypervisor entitlement is missing (macOS)

The smolvm binary isn't signed with `com.apple.security.hypervisor`. Reinstall smolvm from Homebrew
or its release tarball rather than building it unsigned.

## `diagnose` says `FAIL config`

`~/.config/smolbento/config.toml` doesn't parse. The message shows the error; fix the file, or
reset a setting with `sbt settings unset <key>`.

## `Permission denied` writing the workspace

smolvm shows your workspace as owned by the sandbox's workload user (`agent`). If you see this,
check that the sandbox was created by this smolbento version and that your workspace isn't owned
by root. A custom `-t` image must have an `agent` user, or the sandbox won't start.

## `was created by an older smolbento`

Sandboxes made before smolvm 1.34.4 idmapped mounts were set up differently and can't be started.
Recreate them: `sbt rm NAME`, then create it again. `ls`, `inspect`, `rm`, `prune` and `reset`
still work on them. Saved templates keep working.

## The first run is slow

The first run of each agent pulls its image (a few hundred MB to a few GB). Later runs start in
seconds.

## `Cannot connect to the Docker daemon` inside a sandbox

The sandbox's Docker engine starts in the background when the sandbox starts and takes a few
seconds. If it persists: `sbt exec --privileged <name> cat /var/log/dockerd.log`. Sandboxes created
with `docker.enabled=false` have no Docker engine.

## A sandbox won't go away, or `already exists`

```sh
sbt ls
sbt rm -f <name>
smolvm machine ls            # smolbento's machines are named sbx-<name>
smolvm machine delete -n sbx-<name> -f
```

A sandbox whose first start fails is removed, so the same command can be run again. If the removal
failed too (the error says so), `sbt rm -f <name>` cleans it up.

## A storage error from smolvm

Most often the disk is full: check `df -h ~`. `sbt prune` removes stopped sandboxes, `sbt rm NAME`
one sandbox and `sbt template rm` a saved template.

## `Refusing without a terminal; pass -f`

`rm`, `prune` and `reset` ask for confirmation. In scripts and CI, pass `-f`.
