# Troubleshooting

Start with:

```sh
sbt diagnose
```

and add `-D` to any command to print the smolvm commands it runs, for example `sbt -D run claude`.

## `smolvm 1.x is too old`

smolbento needs smolvm 1.32.2 or newer: `brew upgrade smolvm`.

## `could not run smolvm`

smolvm isn't on your `PATH`. Install it (`brew install smol-machines/tap/smolvm`) or point
smolbento at it: `sbt settings set smolvm.path /path/to/smolvm`.

## `don't run sbt as root`

Inside a sandbox, the `agent` user takes the uid of whoever runs `sbt`, so running as root would
make the agent root too. Run `sbt` as your normal user. On Linux, give that user access to
`/dev/kvm` instead of using `sudo`.

## `diagnose` says `FAIL /dev/kvm` (Linux)

Enable virtualization in the BIOS/firmware, load the KVM module, and add your user to the `kvm`
group (log out and back in afterwards). In a VM, nested virtualization must be enabled.

## `diagnose` says the hypervisor entitlement is missing (macOS)

The smolvm binary isn't signed with `com.apple.security.hypervisor`. Reinstall smolvm from Homebrew
or its release tarball rather than building it unsigned.

## `diagnose` says `FAIL config`

`~/.config/smolbento/config.toml` doesn't parse. The message shows the error; fix the file, or
reset a setting with `sbt settings unset <key>`.

## `Permission denied` writing the workspace

smolbento gives the sandbox's `agent` user your uid each time the sandbox starts. If you see this
with a custom `-t` image, check that the image has an `agent` user and the `usermod` command.

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

If creating a sandbox failed halfway, the machine may exist but not be started; `sbt rm -f <name>`
cleans it up.

## `Refusing without a terminal; pass -f`

`rm`, `prune` and `reset` ask for confirmation. In scripts and CI, pass `-f`.
