# git-signing kit

Signs the commits made in a sandbox with a key from your SSH agent, under any agent, and sets your
git name and email. The private key never enters the sandbox, and the sandbox can use the agent
for git signatures only.

```sh
bento create claude . --kit git-signing
bento create docker.io/sbx/antigravity:latest . --kit git-signing
# sign with one particular key: the public key itself, not a path to it
bento create claude . --kit git-signing --kit-arg "signingKey=$(cat ~/.ssh/id_ed25519.pub)"
```

It is built into `bento`, so nothing is downloaded.

## What it does

- **Identity:** `user.name` and `user.email` come from the host's `git config`, read in the
  directory you run `bento` from.
- **Which repositories:** those with a remote. A scratch `git init` commits unsigned.
- **Tags:** not signed unless you ask (`git tag -s`), so a plain `git tag v1` stays a lightweight
  tag. Set `tag.gpgSign` yourself to sign every tag.
- **Which key:** `signingKey` if you give one, otherwise the first key your agent lists. With
  several keys in the agent, give `signingKey`.
- **Verification:** the key is recorded as a trusted signer for your email
  (`~/.config/git-signing/allowed_signers`), so `git log --show-signature` works in the sandbox.
- **Failures:** a commit that can't be signed stops with a `git-signing:` message naming what is
  missing (no agent, no keys, agent not answering, pinned key not loaded) and what to run. git may
  print `user.signingKey needs to be set` after it; ignore that line.
- **Your config wins:** the settings go in the image's system git config, so your own
  `~/.gitconfig` in the sandbox, or a repository's config, override them.

## Argument

| Name | Default | Meaning |
|---|---|---|
| `signingKey` | empty | The public key to sign with, as `ssh-add -L` prints it (the comment is optional; git's `key::` prefix is accepted). A path to a key file or a GPG key id is refused at the first commit. Empty signs with the agent's first key |

## Limits

- The image needs `git` 2.36 or newer (with an older one nothing is signed), `ssh-add` and
  `ssh-keygen` (the OpenSSH client). The built-in agents' images have them.
- The SSH agent is attached when a sandbox is created. With none on the host, the sandbox is created
  without one: repositories with a remote then refuse to commit until you create it again with an
  agent. See [SSH agent](../../docs/usage.md#ssh-agent).
- The kit asks for git signatures only, so a workload kit's sandbox (such as Antigravity's) can't
  log in to servers over SSH with your keys. The built-in agents get your SSH agent without that
  limit anyway, and a kit can't narrow it.
- A signature says the commit was made in a sandbox with access to your agent, not that you reviewed
  it.
