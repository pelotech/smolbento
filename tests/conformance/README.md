# Kit-spec conformance

`just conformance` runs Docker's [sandbox kit spec](https://github.com/docker/sandbox-kit-spec)
conformance suite at `SPEC_COMMIT` (`src/kits/mod.rs`) against smolbento, through the
`smolbento-adapter` in this directory.

## What is claimed

The adapter claims `ssh-agent@1`, `host-mount@1`, `lifecycle@1`, `network-policy@1`/`@2`,
`agent-context@1`/`@2`, `long-running@1`, `privileged@1`, `resources@1` and `sbx@1`, under the
`balanced` mode (sbx's default: under `allow-all` a kit's bounded allow bounds nothing, as the mode
already grants the host).

## Results

All 11 `ssh-agent@1` checks pass: a workload's first process starts only once the start's install
steps, files, agent context and startup hooks are done, and after the runtime agent's unit is up.
`agent-context@2/delivery`, `materialized` and `mixed-versions` pass; `selection-boundaries` needs
`volume@1`, not claimed, so it skips.

The failures left are:

- `lifecycle@1/hook-env-restricted`: install steps keep the proxy and CA variables, a difference
  recorded in [sbx compatibility](../../docs/sbx-compatibility.md#kits).
- `SPEC-v3 §7.1.1/validate-expanded-declarations`, `atomic-selection` and `§7.1.2/exact-version`:
  they use the suite's selection controls (`--reject-capability`, selection records) that smolbento
  doesn't have.
- The `sbx@1` workspace and identity environment checks (`environment-provided`, `-process`,
  `-internal`, `-hooks`, `-hooks-internal`, `identity-stable`, `identity-new-after-deletion`).
  They read the environment the workload's agent was launched with by `create` and `start`. Like
  sbx 0.54, smolbento starts an `sbx@1` workload's agent only on `run` (sbx 0.54 runs only
  `sleep infinity` for the suite's own probe kit), so these checks fail on both. `identity-stable`
  also needs a `recreate`, which smolbento doesn't have.

The adapter maps `--workspace-mode internal` to a sandbox without a workspace mount (its workspace
is the image's `WORKDIR`) and refuses `none`, `host` and `cloned`, so those scenario checks skip.

`resources@1/limit-applied` warns: the sandbox reports its memory limit as unknown. The limit is
applied, as the VM's size (`--mem`, which the spec allows), but the check reads only the cgroup's
`memory.max`, and a smolvm machine's workload sees the cgroup2 root, which has none. It needs smolvm
to give the workload its own cgroup with the VM's memory as `memory.max`, as it already does for pod
containers. No adapter verb is involved, so the adapter can't report it.

## Not claimed

Each of these has checks that fail:

- `dockerd@1`: the spec's `recreate` replaces the sandbox in place, keeping the engine store, and
  smolbento has no `recreate`.
- `volume@1`: it also needs volumes kept across delete and create, with commands to list and
  remove them. smolbento keeps volumes on the sandbox's disk (see
  [sbx compatibility](../../docs/sbx-compatibility.md#kits)).
- `git-identity@1`: `recreate` and selection records are missing. `git-identity@1/global-defaults`
  passes.
- `agent-skills@1` and `agent-skill@1`: selection records.
- `credential@1`: `inject-only-no-env` finds the CA variables that install steps keep, the
  recorded difference above. The rest that ran pass.

The adapter can still run these slices (`SMOLBENTO_TCK_CAPABILITIES`). It maps
`--skills-host-mode` to `--skills`, `--skills-host-store` to its isolated store and
`--git-identity-config` to the host git config bento reads. It binds the fixture's credential as a
`secret set-custom --command` that reads the suite's dummy value from a 0600 file in
`SMOLBENTO_TCK_HOME` at each start.

## Short `SMOLBENTO_TCK_HOME`

The suite's isolated setup needs the units' socket path under 104 bytes, so keep
`SMOLBENTO_TCK_HOME` short. A longer one falls back to attached-only serving and the boot-time
checks fail.
