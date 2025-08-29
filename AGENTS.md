# Repository Guidelines

## Project Structure & Module Organization
- `src/framework/`: Core code (auth, database, routes, monitoring, audit, email, middleware, config).
- `tests/`: Pytest suite (`test_*.py`).
- `docs/`: Deployment, security, API, monitoring, and development docs.
- `static/`: Assets (`css/`, `js/`, `favicon.ico`).
- Entrypoints: `dev.py`, `dev_no_reload.py` (dev servers) and `app.py` (production).

## Build, Test, and Development Commands
- Install deps: `uv sync` (uses `pyproject.toml` + `uv.lock`).
- Run (dev, reload): `uv run dev.py`.
- Run (dev, no reload): `uv run dev_no_reload.py`.
- Run (prod-like): `uv run app.py`.
- Tests (verbose): `uv run pytest` or `pytest -v`.
- Lint: `uv run ruff check .`.
- Format: `uv run black .`.
- Docker (dev): `docker-compose up --build`.
- Docker (prod image): `docker build -f Dockerfile -t py-framework:latest .`.

## Coding Style & Naming Conventions
- Python 3.13+, 4-space indents, max line length 88 (Black/Ruff).
- Names: `snake_case` for functions/vars, `PascalCase` for classes, `UPPER_CASE` for constants.
- Keep modules focused; place web routes in `src/framework/routes/` and shared logic under appropriate subpackages.

## Testing Guidelines
- Framework: Pytest (`pytest.ini` config). Test files `tests/test_*.py`; functions `test_*`.
- Common markers: `unit`, `integration`, `security`, `database`, `email`, `oauth`, `admin`, `performance`, `slow`.
- Select tests: `pytest -m "not slow"`, filter: `pytest -k login`.
- JUnit XML written to `.pytest_cache/junit.xml` (CI-friendly). Keep/raise coverage where practical and include negative-path tests for security-sensitive code.

## Commit & Pull Request Guidelines
- Commits: imperative mood, concise subject (<72 chars), useful body. Reference issues (`Closes #123`). Group related changes; keep diffs focused.
- Before opening a PR: run `ruff` and `black`, ensure `pytest` passes, and update docs if behavior changes.
- PR content: clear description, rationale, screenshots for UI-affecting changes, reproduction steps for bug fixes, and links to related issues/docs.

## Security & Configuration Tips
- Use `.env` (copy from `.env.example`). At minimum set `SECRET_KEY` and any OAuth/SMTP settings you use.
- Avoid committing secrets; prefer environment variables in local/dev and CI.
- Security-critical areas live in `security.py`, `csrf.py`, `auth/`, and `middleware.py`; add tests for all changes touching these modules.

