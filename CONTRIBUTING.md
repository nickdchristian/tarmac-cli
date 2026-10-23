# Contributing

You need Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/nickdchristian/tarmac-cli.git
cd tarmac-cli
uv sync --locked
```

Before opening a pull request, run the checks in the README's [Development](README.md#development) section.
CI runs the same ones.

- **Pull request titles** must follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, `chore:` and so on). Pull requests are squash-merged, and
  release-please builds the version and changelog from those titles, so don't edit the version or
  `CHANGELOG.md` by hand. Mark breaking changes with `!` (for example `feat!:`).
- **Templates and SCPs** live only in `src/tarmac/templates/`. They ship in the package, and
  `tarmac init --with-templates` copies them out for local changes.
- **Tests never call AWS.** They don't see your credentials, so mock `AwsSessionManager` or the boto3 clients.
