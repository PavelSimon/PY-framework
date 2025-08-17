# Development Server Guide

## Quick Start

### Standard Development (with hot reloading)
```bash
uv run python dev.py
```

### Development without hot reloading
```bash
uv run python dev_no_reload.py
```

### Simple development server
```bash
uv run python dev_simple.py
```

## Development Server Features

### dev.py (Recommended for development)
- ✅ **Hot reloading enabled** - automatically restarts when code changes
- ✅ **Debug mode** - detailed error messages and debugging
- ✅ **Live reload** - CSS/HTML changes update without restart
- ✅ **File watching** - monitors `src/`, `static/`, `templates/` directories
- ✅ **Development routes** - includes `/dev/` testing endpoints

### dev_no_reload.py (For stable development)
- ✅ **No reloading** - stable for database operations
- ✅ **Debug mode** - detailed error messages
- ❌ **No hot reload** - manual restart required for changes

## Access Points

- **Application**: http://localhost:8000
- **Admin Login**: admin@admin.com / AdminPass123!
- **Pavel's Admin Account**: Pavel@pavel-simon.com / <your_password>
- **Audit Dashboard**: http://localhost:8000/admin/audit
- **Development Tools**: http://localhost:8000/dev/

## Available Admin Accounts

1. **Default Admin**: admin@admin.com / AdminPass123!
2. **Pavel (Admin)**: Pavel@pavel-simon.com / <your_password>

## Development Workflow

1. **Start development server**:
   ```bash
   uv run python dev.py
   ```

2. **Make code changes** - server will automatically restart

3. **Test your changes** at http://localhost:8000

4. **Use development tools**:
   - Email testing: http://localhost:8000/dev/test-email
   - Auth testing: http://localhost:8000/dev/test-auth
   - Database inspector: http://localhost:8000/dev/database

## Troubleshooting

### Database Lock Issues
If you get "database is locked" errors:
1. Stop all running development servers (Ctrl+C)
2. Wait a few seconds
3. Restart with `uv run python dev.py`

### Port Already in Use
If port 8000 is busy:
1. Stop other servers: Ctrl+C in all terminals
2. Or change port in dev.py: `port=8001`

### Hot Reload Not Working
1. Check that files are being saved in watched directories
2. Verify the server shows "Will watch for changes in these directories"
3. Check file permissions in src/, static/, templates/

## File Structure for Development

```
PY-framework/
├── dev.py                    # Main development server (with reload)
├── dev_no_reload.py         # Stable development server
├── dev_simple.py            # Simple server wrapper
├── app.py                   # Production server
├── src/framework/           # Framework source code
├── static/                  # CSS, JS, images
├── templates/               # HTML templates (if used)
└── tests/                   # Test files
```