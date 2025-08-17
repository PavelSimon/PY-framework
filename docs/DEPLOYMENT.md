# Deployment Guide

## 🚀 Production Deployment Guide

This guide covers deploying PY-Framework to production with security best practices, performance optimizations, and Docker containerization support.

**✅ LATEST UPDATE**: Enhanced monitoring system with Prometheus metrics, health checks, and intelligent alerting for production environments.

## Pre-Deployment Checklist

### Security Requirements ✅
- [ ] Strong `SECRET_KEY` generated (32+ characters)
- [ ] HTTPS/SSL certificates configured
- [ ] Environment variables secured (no secrets in code)
- [ ] Database access restricted
- [ ] Email service configured with app passwords
- [ ] Rate limiting configured appropriately
- [ ] Security headers enabled
- [ ] CSRF protection enabled

### Performance Requirements ✅
- [ ] Database optimized and indexed
- [ ] Performance optimization enabled
- [ ] Cache settings configured
- [ ] Connection pooling enabled
- [ ] Static files properly served
- [ ] Session cleanup scheduled
- [ ] Log rotation configured
- [ ] Monitoring setup

### Audit & Monitoring Requirements ✅ ENHANCED
- [ ] Audit logging enabled
- [ ] Performance monitoring configured
- [ ] Enhanced monitoring system operational ✅ LATEST
- [ ] Prometheus metrics endpoint configured
- [ ] Health check endpoints accessible
- [ ] Alerting system configured with notifications
- [ ] Admin dashboard access secured
- [ ] Log retention policy set
- [ ] Security event monitoring enabled
- [ ] External monitoring tools integrated (Grafana/Prometheus)

### Database Requirements ✅ LATEST
- [ ] Database constraints verified and functional
- [ ] Role-based access control working correctly
- [ ] Foreign key constraints resolved
- [ ] Database schema integrity validated
- [ ] Connection pooling configured

### Docker Requirements ✅ NEW
- [ ] Docker images built and tested
- [ ] Container security hardening applied
- [ ] Volume mounting for persistent data
- [ ] Health checks configured
- [ ] Resource limits set

## Environment Configuration

### Required Environment Variables

```bash
# Core Security
SECRET_KEY=your-32-char-minimum-secret-key-here
DEBUG=False
DATABASE_URL=production.db

# Email Configuration (Gmail example)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=True
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
FROM_EMAIL=your-email@gmail.com

# Security Settings
MAX_FAILED_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=30
SESSION_EXPIRE_HOURS=24

# OAuth (Optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Performance Optimization ✅ NEW
ENABLE_PERFORMANCE_OPTIMIZATION=true
CACHE_DEFAULT_TTL=300
CACHE_MAX_SIZE=1000
SESSION_CACHE_MAX_SESSIONS=1000
CONNECTION_POOL_MAX_CONNECTIONS=10
QUERY_SLOW_THRESHOLD_MS=100.0
ENABLE_QUERY_OPTIMIZATION=true
ENABLE_CONNECTION_POOLING=true

# Audit Logging ✅ NEW
ENABLE_AUDIT_LOGGING=true
AUDIT_LOG_RETENTION_DAYS=90
AUDIT_LOG_MAX_EVENTS=10000
```

### Secret Key Generation

Generate a strong secret key:
```bash
# Using Python
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Using OpenSSL
openssl rand -base64 32
```

## Deployment Options

### Option 1: Docker Deployment (Recommended) ✅ NEW

Docker provides the easiest and most reliable deployment method with built-in dependency management and security hardening.

**Quick Start:**
```bash
# Clone repository
git clone <your-repo-url>
cd PY-framework

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Deploy with Docker Compose
docker-compose up -d
```

**For detailed Docker deployment instructions, see [Docker Guide](DOCKER.md)**

### Option 2: Traditional Server Deployment

#### 1. Server Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.13+
sudo apt install python3.13 python3.13-pip

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### 2. Application Setup
```bash
# Clone repository
git clone <your-repo-url>
cd PY-framework

# Install dependencies
uv sync --frozen

# Set up environment
cp .env.example .env
# Edit .env with production values
```

#### 3. Process Manager (Systemd)
Create `/etc/systemd/system/py-framework.service`:
```ini
[Unit]
Description=PY-Framework Web Application
After=network.target

[Service]
Type=exec
User=www-data
Group=www-data
WorkingDirectory=/path/to/PY-framework
Environment=PATH=/path/to/PY-framework/.venv/bin
ExecStart=/path/to/PY-framework/.venv/bin/python app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable py-framework
sudo systemctl start py-framework
sudo systemctl status py-framework
```

#### 4. Reverse Proxy (Nginx)
Create `/etc/nginx/sites-available/py-framework`:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozTLS:10m;
    
    # Security Headers (additional to app headers)
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
    
    location /static/ {
        alias /path/to/PY-framework/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/py-framework /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Option 2: Docker Deployment

#### 1. Create Dockerfile
```dockerfile
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uv", "run", "app.py"]
```

#### 2. Docker Compose
Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  py-framework:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=False
      - DATABASE_URL=/app/data/production.db
      - SMTP_SERVER=${SMTP_SERVER}
      - SMTP_USERNAME=${SMTP_USERNAME}
      - SMTP_PASSWORD=${SMTP_PASSWORD}
    volumes:
      - ./data:/app/data
      - ./static:/app/static
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
      - ./static:/var/www/static
    depends_on:
      - py-framework
    restart: unless-stopped
```

### Option 3: Cloud Platform Deployment

#### Heroku
Create `Procfile`:
```
web: uv run app.py --host 0.0.0.0 --port $PORT
```

Deploy:
```bash
# Install Heroku CLI and login
heroku create your-app-name
heroku config:set SECRET_KEY=your-secret-key
heroku config:set DEBUG=False
# Set other environment variables
git push heroku main
```

#### DigitalOcean App Platform
Create `.do/app.yaml`:
```yaml
name: py-framework
services:
- name: web
  source_dir: /
  github:
    repo: your-username/PY-framework
    branch: main
  run_command: uv run app.py
  environment_slug: python
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: SECRET_KEY
    value: your-secret-key
    type: SECRET
  - key: DEBUG
    value: "False"
  http_port: 8000
```

## Database Management

### Backup Strategy
```bash
# Create backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
cp production.db "backups/backup_$DATE.db"

# Keep only last 30 days
find backups/ -name "backup_*.db" -mtime +30 -delete
```

### Database Migration
```bash
# Before deployment
python -c "
from src.framework.database import Database
db = Database('production.db')
# Database will auto-create tables on first run
"
```

### Database Constraint Issues ✅ RESOLVED
**Note**: Previous versions had foreign key constraint issues preventing role updates. This has been resolved in the latest version:
- Foreign key constraints on `users.role_id` have been fixed
- Role-based access control now works seamlessly
- All user data and relationships are preserved
- Database schema integrity is maintained

If upgrading from an earlier version, the framework will automatically handle schema migrations.

## Monitoring and Logging

### Application Monitoring
```python
# Add to app.py for production monitoring
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
```

### Health Monitoring
Set up monitoring for:
- `/health` endpoint availability
- Response times
- Error rates
- Database connection
- Email service status

### Log Rotation
Configure logrotate in `/etc/logrotate.d/py-framework`:
```
/path/to/app.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload py-framework
    endscript
}
```

## Security Hardening

### Server Security
```bash
# Firewall setup
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443

# Disable unnecessary services
sudo systemctl disable <unused-services>

# Regular updates
sudo apt update && sudo apt upgrade -y
```

### Application Security
- SSL certificates (Let's Encrypt recommended)
- Security headers (handled by framework)
- Regular dependency updates
- Database access restrictions
- Environment variable protection

## Maintenance Tasks

### Regular Tasks
```bash
# Weekly cleanup script
#!/bin/bash

# Clean expired sessions
python -c "
from src.framework.database import Database
db = Database('production.db')
db.cleanup_expired_sessions()
"

# Clean expired tokens
python -c "
from src.framework.database import Database
db = Database('production.db')
db.cleanup_expired_tokens()
"

# Database optimization
sqlite3 production.db "VACUUM;"
```

### Monitoring Script
```bash
#!/bin/bash

# Check application health
curl -f http://localhost:8000/health || echo "Health check failed"

# Check disk space
df -h | grep -E "(/$|/var)" | awk '{print $5}' | sed 's/%//' | while read output;
do
  if [ $output -gt 80 ]; then
    echo "Disk space warning: ${output}% full"
  fi
done

# Check memory usage
free -m | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }'
```

## Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check logs
journalctl -u py-framework -f

# Check permissions
ls -la /path/to/PY-framework

# Check environment variables
systemctl show py-framework -p Environment
```

#### Database Issues
```bash
# Check database file permissions
ls -la production.db

# Test database connection
python -c "
from src.framework.database import Database
try:
    db = Database('production.db')
    print('Database connection successful')
except Exception as e:
    print(f'Database error: {e}')
"
```

#### Email Issues
```bash
# Test email configuration
python -c "
from src.framework.email import EmailService
email = EmailService()
success, message = email.test_email_configuration()
print(f'Email test: {success} - {message}')
"
```

## Performance Optimization

### Database Performance
- Regular VACUUM operations
- Monitor query performance
- Optimize indexes if needed
- Archive old data

### Application Performance
- Enable static file caching
- Monitor memory usage
- Profile slow endpoints
- Implement connection pooling if needed

### Caching Strategy
Consider adding caching for:
- Static content (handled by nginx)
- Session data (Redis for scaling)
- Frequently accessed data

---

**This deployment guide covers production deployment. Adjust configurations based on your specific infrastructure and requirements.**