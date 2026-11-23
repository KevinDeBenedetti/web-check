# Copilot instructions — web-check

Use Context7 for library, framework and API documentation (setup, configuration,
code generation) without being asked.

## Repository

| Path            | What it is                                                                 |
| --------------- | -------------------------------------------------------------------------- |
| `apps/api`      | FastAPI API: scans, scope, findings; SQLite through SQLAlchemy and Alembic |
| `apps/web`      | React + Vite UI, served by the API under `/ui`                             |
| `apps/cli`      | `web-check`, the command-line client of the API                            |
| `apps/my_check` | `my-check`, a standalone web and Kubernetes scanner                        |

Architecture: `docs/architecture.md`. Setup and workflow: `docs/development.md`.

## Verifying a change

`make check` runs the format check, lint, type check and tests of the three Python
packages; `make ui-check` does the same for `apps/web`. Each package keeps its tests
in `apps/<package>/tests`; add one with every behaviour change.

## Conventions

- **Trust boundary.** Targets reach a scanner only through
  `api.utils.security.validate_target` and `ALLOWED_DOMAINS`. Scanner output is
  untrusted input: read it through `docker_runner.run_process` /
  `load_json_output` (bounded) and store it as `Finding` text (sanitised).
- **Scanner commands** are argv lists.
- **Failures are visible.** A scanner that times out, exits non-zero or writes no
  usable output returns `status="error"` or `"timeout"`; an empty success means
  the tool ran and found nothing.
- **Language.** UI strings in `apps/web` are French; code, comments, docs and
  commit messages are English.
- **Commits** follow Conventional Commits: release-please builds the changelog
  and the version from them.
- **Docs** under `docs/` publish to `https://kevindebenedetti.github.io/web-check/`:
  each page starts with a `title:` frontmatter and a matching H1, and links to
  other pages with relative `.md` paths.
