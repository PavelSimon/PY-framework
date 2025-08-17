# Docker Deployment Guide

## 🐳 Container Deployment for PY-Framework

This guide covers Docker-based deployment options for PY-Framework, including development, production, and orchestration scenarios.

**✅ LATEST UPDATE**: Enhanced with database constraint fixes, performance monitoring, and audit logging support.

## Quick Start

### Production Deployment

```bash
# Clone the repository
git clone <your-repo-url>
cd PY-framework

# Create environment file
cp .env.example .env
# Edit .env with your production settings

# Build and run with Docker Compose
docker-compose up -d
```

### Development with Hot Reload

```bash
# Run development container with hot reload
docker-compose --profile dev up -d pyframework-dev

# Or build and run development container directly
docker build -f Dockerfile.dev -t pyframework:dev .
docker run -p 8000:8000 -v $(pwd)/src:/app/src pyframework:dev
```

## Container Architecture

### Production Container Features
- **Multi-stage build** for optimized image size
- **Non-root user** for enhanced security
- **Health checks** for container monitoring
- **Volume mounts** for persistent data
- **Environment-based configuration**
- **Production-optimized** FastHTML settings
- **Database constraint fixes** ✅ LATEST
- **Performance monitoring** integration ✅ NEW
- **Audit logging** support ✅ NEW

### Development Container Features
- **Hot reload** enabled with uvicorn
- **Source code mounting** for live changes
- **Debug mode** activated
- **Development dependencies** included
- **File watching** for automatic restarts

## Environment Configuration

### Required Environment Variables

```bash
# Core Settings
SECRET_KEY=your-secret-key-32-chars-minimum
DEBUG=False
DATABASE_URL=/app/data/app.db

# Performance Optimization ✅
ENABLE_PERFORMANCE_OPTIMIZATION=true
CACHE_DEFAULT_TTL=300
CACHE_MAX_SIZE=1000
SESSION_CACHE_MAX_SESSIONS=1000
CONNECTION_POOL_MAX_CONNECTIONS=10

# Audit Logging ✅
ENABLE_AUDIT_LOGGING=true
AUDIT_LOG_RETENTION_DAYS=90
AUDIT_LOG_MAX_EVENTS=10000

# Database Configuration ✅ LATEST
# Note: Database constraint issues have been resolved
# Role-based access control now works seamlessly
ENABLE_CONNECTION_POOLING=true
```

### Optional Configuration

```bash
# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=True
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=your-email@gmail.com

# OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Security Settings
MAX_FAILED_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=30
SESSION_EXPIRE_HOURS=24
```

## Docker Compose Profiles

### Production Profile (Default)

```bash
# Start production containers
docker-compose up -d

# View logs
docker-compose logs -f

# Stop containers
docker-compose down
```

**Features:**
- Production-optimized Dockerfile
- Security hardening enabled
- Performance optimization active
- Health checks configured
- Persistent volumes for data and logs

### Development Profile

```bash
# Start development containers
docker-compose --profile dev up -d

# View development logs
docker-compose --profile dev logs -f pyframework-dev

# Stop development containers
docker-compose --profile dev down
```

**Features:**
- Hot reload enabled
- Source code volume mounting
- Debug mode active
- Development server (dev.py)
- Live code changes without rebuild

## Volume Management

### Persistent Volumes

```yaml
volumes:
  - ./data:/app/data          # Database files
  - ./logs:/app/logs          # Application logs
```

### Development Volumes

```yaml
volumes:
  - ./src:/app/src            # Source code (hot reload)
  - ./static:/app/static      # Static files
  - ./templates:/app/templates # HTML templates
```

### Volume Commands

```bash
# Create named volumes
docker volume create pyframework_data
docker volume create pyframework_logs

# Inspect volumes
docker volume inspect pyframework_data

# Backup database
docker run --rm -v pyframework_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/database-backup.tar.gz /data

# Restore database
docker run --rm -v pyframework_data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/database-backup.tar.gz -C /
```

## Production Deployment

### 1. Preparation

```bash
# Create production environment file
cp .env.example .env.production

# Generate secure secret key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Edit .env.production with production values
nano .env.production
```

### 2. Build and Deploy

```bash
# Build production image
docker build -t pyframework:latest .

# Run with production environment
docker run -d \
  --name pyframework-prod \
  --env-file .env.production \
  -p 80:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  --restart unless-stopped \
  pyframework:latest
```

### 3. With Docker Compose

```bash
# Production deployment
docker-compose -f docker-compose.yml up -d

# With custom environment file
docker-compose --env-file .env.production up -d
```

## Health Monitoring

### Health Check Endpoints

```bash
# Container health check
curl http://localhost:8000/health

# Docker health status
docker ps --format "table {{.Names}}\t{{.Status}}"

# Health check logs
docker inspect --format='{{json .State.Health}}' pyframework-app
```

### Monitoring Commands

```bash
# View container stats
docker stats pyframework-app

# View container logs
docker logs -f pyframework-app

# Execute commands in container
docker exec -it pyframework-app /bin/bash
```

## Security Considerations

### Container Security

- **Non-root user**: Application runs as `pyframework` user
- **Minimal base image**: Uses Python slim image
- **No unnecessary packages**: Production image excludes dev tools
- **Read-only filesystem**: Consider using `--read-only` flag
- **Security scanning**: Regularly scan images for vulnerabilities

### Network Security

```bash
# Create custom network
docker network create --driver bridge pyframework-secure

# Run with custom network
docker run --network pyframework-secure pyframework:latest
```

### Secret Management

```bash
# Use Docker secrets (Swarm mode)
echo "your-secret-key" | docker secret create pyframework_secret_key -

# Use external secret management
docker run --env SECRET_KEY_FILE=/run/secrets/secret_key pyframework:latest
```

## Scaling and Orchestration

### Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml pyframework-stack

# Scale services
docker service scale pyframework-stack_pyframework=3
```

### Kubernetes Deployment

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pyframework
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pyframework
  template:
    metadata:
      labels:
        app: pyframework
    spec:
      containers:
      - name: pyframework
        image: pyframework:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          value: "/app/data/app.db"
        volumeMounts:
        - name: data-volume
          mountPath: /app/data
        - name: logs-volume
          mountPath: /app/logs
      volumes:
      - name: data-volume
        persistentVolumeClaim:
          claimName: pyframework-data-pvc
      - name: logs-volume
        persistentVolumeClaim:
          claimName: pyframework-logs-pvc
```

## Performance Optimization

### Build Optimization

```dockerfile
# Use multi-stage builds
FROM python:3.13-slim as builder
# Build dependencies...

FROM python:3.13-slim as production
# Copy only what's needed...
```

### Runtime Optimization

```bash
# Optimize container resources
docker run \
  --memory=512m \
  --cpus=1.0 \
  --restart unless-stopped \
  pyframework:latest
```

### Image Optimization

```bash
# Reduce image size
docker build --squash -t pyframework:optimized .

# Multi-platform builds
docker buildx build --platform linux/amd64,linux/arm64 -t pyframework:multi .
```

## Troubleshooting

### Common Issues

**Container won't start:**
```bash
# Check logs
docker logs pyframework-app

# Check health
docker inspect pyframework-app | grep -A 10 "Health"

# Interactive debugging
docker run -it pyframework:latest /bin/bash
```

**Database issues:**
```bash
# Check volume mounts
docker inspect pyframework-app | grep -A 10 "Mounts"

# Verify database file
docker exec pyframework-app ls -la /app/data/

# Database permissions
docker exec pyframework-app chown -R pyframework:pyframework /app/data
```

**Performance issues:**
```bash
# Monitor resources
docker stats pyframework-app

# Check application logs
docker logs -f pyframework-app | grep -i "error\|warning"

# Verify environment variables
docker exec pyframework-app env | grep PY
```

### Debug Mode

```bash
# Run container in debug mode
docker run -it \
  -e DEBUG=True \
  -e PYTHONPATH=/app \
  pyframework:latest python dev.py
```

## Backup and Recovery

### Database Backup

```bash
# Automated backup script
#!/bin/bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
docker exec pyframework-app sqlite3 /app/data/app.db ".backup /app/data/backup_${TIMESTAMP}.db"
docker cp pyframework-app:/app/data/backup_${TIMESTAMP}.db ./backups/
```

### Full System Backup

```bash
# Backup all volumes
docker run --rm \
  -v pyframework_data:/data \
  -v pyframework_logs:/logs \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/full-backup-$(date +%Y%m%d).tar.gz /data /logs
```

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/docker.yml
name: Docker Build and Deploy

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker image
      run: docker build -t pyframework:${{ github.sha }} .
    
    - name: Run tests in container
      run: |
        docker run --rm pyframework:${{ github.sha }} \
          python -m pytest tests/
    
    - name: Push to registry
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker push pyframework:${{ github.sha }}
```

## Container Registry

### Docker Hub

```bash
# Tag and push
docker tag pyframework:latest username/pyframework:latest
docker push username/pyframework:latest
```

### Private Registry

```bash
# Tag for private registry
docker tag pyframework:latest registry.company.com/pyframework:latest
docker push registry.company.com/pyframework:latest
```

---

## Next Steps

1. **Test deployment** in your environment
2. **Configure monitoring** with Prometheus/Grafana
3. **Set up automated backups**
4. **Implement blue-green deployment**
5. **Configure log aggregation** with ELK stack

For additional deployment options and advanced configurations, refer to the [Deployment Guide](DEPLOYMENT.md).