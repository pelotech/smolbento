# Contributing

Thanks for helping. Set up the dev shell first: see [Development](development.md).

## Before you open a PR

```sh
just test
just lint
just e2e        # if you touched anything that talks to smolvm
```

On a Mac, run all three. CI only runs Linux by default.

## Conventions

- **Conventional commits** for commit messages and PR titles (`feat:`, `fix:`, `docs:`, `ci:`,
  `refactor:`, …). commitlint checks them, and release-please builds the changelog from them.
- **sbx compatibility first.** New flags and output should match the
  [sbx CLI reference](https://docs.docker.com/reference/cli/sbx/). If you have to differ, document it
  in [sbx compatibility](sbx-compatibility.md). smolbento-only commands must not reuse sbx command
  names.
- **Only `src/smolvm/` runs smolvm**, through the `Runner` trait. Parse `--json` output, never tables.
- **No sandbox state files.** Per-sandbox data goes in `sbx.*` machine labels.
- **Never pass smolvm `--docker-socket`**: it would hand the host's Docker to the agent.
- **Dependencies** go in with `cargo add`. Never add a `cargo deny` advisory ignore to get a build
  green; pick a maintained crate instead.

## Adding a command or flag

1. Add it to `src/cli/args.rs`, matching sbx's spelling.
2. If sbx has it, add a line to `tests/parity/sbx-commands.txt`.
3. Test the handler against the fake runner, asserting the smolvm command line.
4. Update the `--help` snapshots (`cargo insta review`) and the docs.
5. Update [Development status](development-status.md) if it moves a phase forward.

## Agent images

Agent presets live in `src/agents.rs` as pinned `docker/sandbox-templates` tags. Renovate proposes
updates; check a new tag with `sbt run <agent>` before merging.
