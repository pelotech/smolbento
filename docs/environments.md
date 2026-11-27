# Environment files

Declare a sandbox in an `sbxenv.yaml` file. Running agents is in [Usage](usage.md).

## Environments (sbxenv.yaml)

`bento env` reads the same `sbxenv.yaml` files as `sbx env` (schema `"1"`). They describe a sandbox's
agent, workspace, kits, ports, variables and secrets.

```yaml
schemaVersion: "1"
agent: claude
name: myrepo
workspace: .
args:
  region:
    default: eu-west-1
env:
  AWS_REGION: ${{ env.args.region }}
ports:
  - host: 8080
    sandbox: 8080
secrets:
  github:
    command: gh auth token
sandboxOptions:
  cpus: 4
  memory: 8g
```

```sh
# show what applying would do; changes nothing
bento env plan
# from ./sbxenv.yaml: plan, ask once, create (no attach)
bento env create
# create if missing, then attach; -f skips the question
bento env run -f ./team ./local.yaml
# run a command in the environment's sandbox
bento env exec -- make test
# remove the sandbox and the secrets scoped to it
bento env rm
```

- Each `PATH` is a file or a directory holding `sbxenv.yaml`. With none, `~/.sbxenv.yaml` (if
  present) then `./sbxenv.yaml` are read.
- Files merge: maps by key, lists concatenate, later values win; an empty `key:` keeps the earlier
  value. Relative paths are relative to the file naming them.
- `${{ env.projectDir }}` is the first `PATH`'s directory (the current directory with no `PATH`, even
  when `~/.sbxenv.yaml` is read). `${{ env.fileDir }}` is the declaring file's directory.
- Only `true` and `false` are booleans. Text fields take numbers and booleans as written: `PORT:
  8080` and `DEBUG: on` are the strings `8080` and `on`.
- `~/.sbxenv.yaml` applies to every environment and can be enough alone. `bento env run` then works in
  a directory with no `sbxenv.yaml`. It can't set `name`, and its `workspace` must be `${{
  env.projectDir }}` or below, as in `workspace: {path: ${{ env.projectDir }}, clone: true}`.
- Args are declared under `args:` and used as `${{ env.args.NAME }}`. Each needs exactly one of
  `default` or `required: true`, and may set `enum` or `pattern` (not both). Set values with
  `--env-arg NAME=VALUE` or `--env-args-file FILE`; `--env-arg` wins.
- The name comes from `name:` or `--name`, otherwise `<agent>-<workspace directory>`. Give every
  command the `--name` you created the sandbox with.
- `env plan` prints the changes and whether applying would ask. `+` adds, `~` changes, `-` removes,
  `>` is a host command that runs again, `!` is an unapproved item the plan doesn't add (a path on
  your machine, or a `preRemove` command). A change only a new sandbox picks up says `waits for the
  next create`; `env` values and `initialize` apply at once.
- `env create` and `env run` ask `Approve this plan? (y/N)`. A yes is remembered until the files or
  the plan change. `-f/--force` approves one invocation without remembering it. Without a terminal
  and without `--force`, an unapproved plan is refused. `env rm` asks `Remove? [y/N]` and forgets
  the approval. `env exec` never asks.
- Lifecycle commands and `command:` sources of secrets and registries run on your machine with your
  privileges, so a file that declares any asks on every `env create` and `env run`. `bento settings
  set env.rememberHostCommands true` keeps an approval until the commands change.
  `--skip-host-commands` (on `env create`, `run`, `rm` and `plan`) skips all three lifecycle phases
  without changing your approval.
- Lifecycle commands run through `sh -c`, in `initialize` (every create and run, before anything),
  `postCreate` (after a new sandbox is created) and `preRemove` (`env rm`, after you confirm). A
  phase stops at the first failure or timeout. A failing `initialize` stops before anything is
  created; a failing `postCreate` keeps the sandbox and says to `bento env rm`; a failing `preRemove`
  only warns and removal goes on. Commands get `bento`'s environment plus `SBX_LIFECYCLE_PHASE`,
  `SBX_ENV_FILE`, `SBX_ENV_FILES` (joined with `:`), `SBX_ENV_DIR`, `SBX_SANDBOX_NAME`, `SBX_AGENT`
  and `SBX_WORKSPACE`, but not the file's `env` or any secret. Make `initialize` safe to run twice.
- `env run` launches `entrypoint` and `cmd` in place of the agent. With only `cmd`, the agent's own
  command gets it as arguments. Plain `bento run NAME` is unaffected. The last file wins. Arguments
  after `--` (`bento env run . -- --base HEAD`) replace `cmd` for that run.
- To pick the agent per run (there is no `--agent` flag, as in sbx), declare an `agent` arg and set
  `agent: ${{ env.args.agent }}`: `bento env run --env-arg agent=opencode -- -c` runs `opencode -c`.
- Registry logins pull this sandbox's image and kits. They're resolved at create and stored for that
  sandbox only, ahead of a host-wide `bento secret set --registry` login. They're removed with the
  sandbox.
- Bindings add extra domains a service's credential may go to. They're global: they go into your
  secrets file at create, for every later sandbox. `env rm` leaves them; `env rm
  --prune-bindings` removes each declared service's whole binding.
- `mcp.servers` entries with a `url` are registered as `bento mcp add` would (they stay after `env
  rm`) and given to the agent as `--static-mcp` does, with the same limits. Entries with a `command`
  are refused.
- `env create` refuses an existing sandbox. On an existing sandbox, `env run` starts it if needed
  and attaches, passing the file's current `env` values; any other change (kits, ports, workspaces,
  secrets, options) needs `env rm`, then `env create`. Secrets are stored before the sandbox is
  made; a failed create leaves them, and `env rm` with the same files removes them.
- `env exec` takes the `bento exec` flags and the command after `--`. Without `--`, every argument is
  the command and files come from the current directory. A command with options needs `--` (`bento env
  exec -- ls -la`).
- `agent` names a built-in agent, or a workload kit from `kits:` (a local kit by directory name, a
  registry kit by the last part of its repository name). Other kits are added to it. A missing local
  path, a `.zip` or a `git+` source is refused before any secret is stored. An unpullable registry
  kit fails after that; `env rm` removes the secrets.
- `mounts:` maps a kit's [host mount](kits.md#kit-host-mounts) path to your directory, as `--mount` does.
  Relative paths are relative to the file naming them; later files win per path.

Lifecycle, as written in a file:

```yaml
lifecycle:
  initialize:            # every `env create` and `env run`, before anything else
    - name: deps         # optional label
      command: ./scripts/setup.sh
      workdir: ./tools   # optional; default: the project directory
      timeout: 90s       # optional; a duration such as 1.5s or 1m30s
  postCreate: [...]
  preRemove: [...]
```

A background command must redirect its output (`cmd >/dev/null 2>&1 &`), or it fails five seconds
after it exits. Ctrl-C ends the running command and what it started.

Registry logins and bindings:

```yaml
registries:
  ghcr.io:
    username: {value: me}
    secret: {command: gh auth token}
bindings:
  github:
    apiKey:
      domains: [uploads.github.com]
```

- `rootSize`, `dockerSize` and `clonedWorkspaceSize` take sizes such as `30g`, rounded up to whole
  GiB. `rootSize` sizes the disk for the root filesystem's changes; `dockerSize` and
  `clonedWorkspaceSize` the disk for Docker's data and a clone's workspace (the larger wins).
- `fuse` and `pullPolicy: missing|never` are accepted. Secret service names must be ones `bento
  secret set` knows.

Limits: fields smolbento doesn't support yet exit 2 and name the field. Which fields, and how the
others differ from sbx: [sbx compatibility](sbx-compatibility.md#environment-files).
