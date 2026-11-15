# Contributing

Thanks for your interest in contributing to Signet.

## Getting started

Prerequisites: Rust (stable), Node.js ≥ 18 + pnpm, PostgreSQL ≥ 14.

```bash
cp .env.example .env          # configure SIGNET_DATABASE_URL, etc.
docker compose -f build/docker-compose.yml --profile dev up -d db   # optional: local Postgres
cargo run -p signet           # backend on :8443
cd dashboard && pnpm install && pnpm dev   # dashboard on :5173
```

See [docs/local-development.md](./docs/local-development.md) for the full setup.

## Workflow

1. Fork the repository and create a feature branch from `master`.
2. Make focused, self-contained changes.
3. Keep commits small and reviewable; one logical change per commit.
4. Open a pull request with a clear description of the "why".

## Commit messages

Write all commit messages in **English**, imperative mood, present tense:

```text
Add login trend chart to overview

Fix MFA disable flow when policy is enforced
```

Keep the subject under ~72 characters; add a body for the "why" when needed.
This is enforced as a project rule (see `.cursor/rules/git-commit-english.mdc`).

## Code style

### Rust

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

- Follow `rustfmt` and `clippy` (CI fails on warnings).
- Logging must follow [.cursor/rules/logging.mdc](./.cursor/rules/logging.mdc):
  static messages, structured key-value fields, errors in an `error` field.
  Never interpolate dynamic values into the log message.

### Dashboard (Vue 3)

```bash
cd dashboard
pnpm typecheck
pnpm build
```

- TypeScript strict; run `pnpm typecheck` before committing.
- Follow the existing component/style conventions (Tailwind CSS v4).

## Tests

- Backend tests connect via `SIGNET_DATABASE_URL`.
- Add or update tests for bug fixes and new behavior where practical.

## Documentation

- Update the relevant files under `docs/` when behavior changes.
- `docs/` is the English source of truth; `docs/zh-CN/` holds the Chinese
  translations. Keep both in sync.
- `README.md` is the English default; `README.zh-CN.md` is the Chinese
  translation. Keep both in sync.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](./LICENSE).
