# Codebase Improvement Proposals

## Architecture & Maintainability
- Consolidate rate limiting: `RateLimiter` exists in `security.py` and `auth/auth.py`. Extract a single utility (e.g., `src/framework/utils/rate_limit.py`) and ensure consistent headers and telemetry. — DONE
- Async consistency: `SecurityMiddleware` is async, `MonitoringMiddleware` is sync. Convert monitoring to async to avoid blocking and align with FastHTML middleware usage. — DONE
- Dependency injection: Pass `Database`, auth, email, and monitoring services via constructors/factories instead of importing within functions to ease testing and configuration.
- Logging: Replace `print()` with structured logging (e.g., `logging` with JSON formatter) and route warnings/errors to monitoring alert rules.

## Security
- CSP hardening: Current policy allows `'unsafe-inline'`. Prefer per‑request nonces or hashes for scripts/styles and inject via templates; keep relaxed in dev via settings. — DONE
- CSRF storage: In‑memory token store is single‑process only. Back with DuckDB table (or Redis in prod), scope to session/user, and rotate/expire reliably. Make the decorator async‑aware.
- Cookies: Ensure session cookies set `Secure`, `HttpOnly`, `SameSite=Strict/Lax` centrally (likely in login/session creation flow).
- Secrets: Encourage explicit `SECRET_KEY` through `.env` (random default complicates restarts). Fail fast if missing in production.

## Database & Migrations
- Schema migrations: Replace try/except ad‑hoc migrations with a versioned migrations table (e.g., `schema_version`) and idempotent scripts. Provide a simple CLI (`uv run python -m tools.migrate`).
- Referential integrity: Add `ON DELETE CASCADE` where appropriate (e.g., `sessions`, `oauth_accounts`, `two_factor_*`) to simplify user deletion and prevent orphaned rows.
- Concurrency: Revisit DuckDB connection pooling—file‑backed concurrency is limited. Prefer a minimal pool with context manager wrappers and clear thread ownership; document safe usage.
- Query instrumentation: Integrate `QueryOptimizer` with DB methods to auto‑track slow/frequent queries and surface in `/monitoring`.

## Testing
- Coverage: Add `pytest-cov` and enforce threshold (e.g., `--cov=src/framework --cov-fail-under=90`).
- Security tests: Add property/fuzz tests for token generators (CSRF, TOTP, reset tokens) and timing‑safe comparisons.
- Rate limit tests: Verify headers (`X-RateLimit-*`) and 429 behavior under burst traffic.
- DB integration tests: Exercise user deletion paths with FK constraints and 2FA tables.

## Performance & Observability
- Cache integration: Wrap hot paths with `PerformanceCache` and monitor with `monitor_cache_operation` decorators; expose cache stats in monitoring dashboard.
- Async I/O: Audit blocking calls (DuckDB, email) and consider background tasks or async adapters to avoid event‑loop stalls.
- Metrics endpoint: Ensure a `/metrics` route exports counters/gauges (Prometheus‑compatible) and document scrape config.

## Developer Experience
- CI pipeline: GitHub Actions using `uv` to run `ruff`, `black --check`, `pytest -m "not slow"`, and coverage. Cache `.uv` directory.
- Pre-commit: Add hooks for `ruff`, `black`, trailing whitespace, and `pytest -q` on changed tests.
- Docs cleanup: Fix encoding artifacts in `README.md` and ensure the documented `templates/` tree matches the repo.

## Documentation & Configuration
- Centralize settings: Map security toggles (CSP strictness, HSTS, rate limit window) to `Settings` in `config.py` and read in middleware constructors.
- Examples: Provide minimal `.env.example` with required keys and clearly marked optional sections (OAuth/SMTP).
