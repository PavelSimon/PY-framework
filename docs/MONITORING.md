# Enhanced Monitoring Guide

## 🔍 Comprehensive Monitoring for PY-Framework

This guide covers the enhanced monitoring system that provides enterprise-grade observability, metrics collection, health monitoring, and intelligent alerting for production deployments.

**✅ LATEST FEATURE**: Complete monitoring stack with Prometheus metrics, health checks, intelligent alerting, and Grafana integration.

## Overview

The enhanced monitoring system includes:

- **📊 Metrics Collection** - Prometheus-compatible metrics with automatic collection
- **🏥 Health Monitoring** - Comprehensive health checks for all system components  
- **🚨 Intelligent Alerting** - Smart alerting with multiple notification channels
- **📈 Performance Insights** - AI-powered performance analysis and recommendations
- **🌐 Web Dashboard** - Real-time monitoring dashboard with professional UI
- **📊 Grafana Integration** - Pre-built Grafana dashboards for advanced visualization

## Architecture

### Core Components

```
Enhanced Monitoring System
├── MetricsCollector          # Prometheus metrics collection
├── HealthChecker            # System health monitoring  
├── AlertManager             # Intelligent alerting system
├── MonitoringDashboard      # Web-based dashboard
├── MonitoringMiddleware     # FastHTML integration
└── MonitoringRoutes         # API endpoints
```

### Integration Points

- **FastHTML Middleware** - Automatic request/response tracking
- **Database Operations** - Query performance monitoring
- **Cache Operations** - Hit/miss rate tracking
- **User Actions** - Authentication and audit event tracking
- **System Resources** - CPU, memory, disk monitoring

## Features

### 📊 Metrics Collection

#### Automatic Metrics
- **HTTP Requests** - Total count, duration, error rates
- **Database Queries** - Query performance, connection pooling
- **Cache Operations** - Hit rates, performance metrics
- **User Activity** - Login success/failure, active sessions
- **System Resources** - CPU, memory, disk usage
- **Application Health** - Response times, error rates

#### Custom Metrics
```python
from src.framework.monitoring import get_metrics_collector

metrics = get_metrics_collector()

# Counter metrics
metrics.increment_counter('custom_events_total', labels={'event_type': 'signup'})

# Gauge metrics  
metrics.set_gauge('active_connections', 42)

# Histogram metrics
metrics.record_histogram('operation_duration_seconds', 1.5)
```

#### Prometheus Integration
```bash
# Metrics endpoint
curl http://localhost:8000/api/metrics

# Sample output:
# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/",status="200"} 1523

# HELP memory_usage_bytes Memory usage in bytes
# TYPE memory_usage_bytes gauge
memory_usage_bytes 2147483648
```

### 🏥 Health Monitoring

#### Built-in Health Checks
- **Database Connectivity** - Connection tests and query performance
- **Memory Usage** - System memory monitoring with thresholds
- **Disk Space** - Available storage monitoring
- **CPU Usage** - System load monitoring
- **Application Responsiveness** - Response time testing
- **Cache Health** - Cache system performance
- **Session Management** - Session system health

#### Health Check API
```bash
# Overall health status
curl http://localhost:8000/api/health

# Individual health check
curl http://localhost:8000/api/health/database

# Run specific check immediately (admin only)
curl -X POST http://localhost:8000/api/health/database/run
```

#### Custom Health Checks
```python
from src.framework.monitoring import get_health_checker
from src.framework.monitoring.health_checker import HealthCheck, HealthStatus

def custom_service_check():
    try:
        # Your custom check logic here
        return HealthCheck(
            name="custom_service",
            status=HealthStatus.HEALTHY,
            message="Service is operational",
            details={"response_time": 0.05},
            timestamp=datetime.now(),
            duration_ms=50
        )
    except Exception as e:
        return HealthCheck(
            name="custom_service", 
            status=HealthStatus.CRITICAL,
            message=f"Service failed: {str(e)}",
            details={"error": str(e)},
            timestamp=datetime.now(),
            duration_ms=0
        )

health = get_health_checker()
health.register_check(
    "custom_service",
    "Custom service availability", 
    custom_service_check,
    interval_seconds=60
)
```

### 🚨 Intelligent Alerting

#### Default Alert Rules
- **High Error Rate** - >5% HTTP error rate
- **Slow Response Time** - >1 second average response time
- **High Memory Usage** - >85% memory utilization
- **Database Issues** - Connection failures or slow queries
- **Failed Login Spike** - High number of failed login attempts
- **Low Disk Space** - <15% available disk space

#### Alert Channels
- **Email Notifications** - SMTP-based email alerts
- **Console Logging** - Log-based notifications
- **Webhook Integration** - HTTP webhook notifications
- **Slack Integration** - (Extensible for future implementation)

#### Custom Alert Rules
```python
from src.framework.monitoring import get_alert_manager
from src.framework.monitoring.alerting import AlertSeverity

def custom_condition():
    # Your custom alert condition
    return some_condition_check()

alerts = get_alert_manager()
alerts.register_rule(
    "custom_alert",
    "Custom condition detected",
    custom_condition,
    AlertSeverity.WARNING,
    cooldown_minutes=10
)
```

#### Email Alert Configuration
```bash
# Environment variables for email alerts
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=your-email@gmail.com
```

### 📈 Performance Insights

#### AI-Powered Analysis
- **Automatic Issue Detection** - Pattern recognition for performance issues
- **Health Score Calculation** - Overall system health scoring
- **Performance Recommendations** - Actionable optimization suggestions
- **Trend Analysis** - Performance trend detection and alerting

#### Performance Metrics
```python
# Get performance insights
from src.framework.monitoring import get_metrics_collector

metrics = get_metrics_collector()
insights = metrics.get_performance_insights()

print(f"Health Score: {insights['health_score']}")
for alert in insights['alerts']:
    print(f"Alert: {alert['message']} (Severity: {alert['severity']})")
for rec in insights['recommendations']:
    print(f"Recommendation: {rec['message']} - {rec['action']}")
```

### 🌐 Web Dashboard

#### Dashboard Features
- **Real-time Metrics** - Live system metrics and performance data
- **Health Status Overview** - Visual health status with color coding
- **Active Alerts** - Current alerts with severity indicators
- **Performance Charts** - (Placeholder for Chart.js integration)
- **System Resources** - CPU, memory, disk usage visualization
- **Alert Statistics** - Alert trends and breakdowns

#### Dashboard Access
```bash
# Monitoring dashboard (admin only)
http://localhost:8000/admin/monitoring

# API endpoints
http://localhost:8000/api/metrics/summary
http://localhost:8000/api/alerts
http://localhost:8000/api/health
```

## Deployment Integration

### Docker Environment Variables
```bash
# Enable enhanced monitoring
ENABLE_MONITORING=true

# Alert configuration
ALERT_EMAIL_ENABLED=true
ALERT_CONSOLE_ENABLED=true

# Monitoring intervals
HEALTH_CHECK_INTERVAL=60
METRICS_COLLECTION_INTERVAL=30
ALERT_CHECK_INTERVAL=10
```

### Docker Compose
```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      - ENABLE_MONITORING=true
      - SMTP_SERVER=smtp.gmail.com
      - SMTP_USERNAME=${SMTP_USERNAME}
      - SMTP_PASSWORD=${SMTP_PASSWORD}
    ports:
      - "8000:8000"
      - "8001:8001"  # Metrics endpoint

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
```

### Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'py-framework'
    static_configs:
      - targets: ['app:8000']
    metrics_path: '/api/metrics'
    scrape_interval: 5s
```

### Grafana Dashboard Import
```bash
# Get Grafana dashboard configuration
curl http://localhost:8000/admin/monitoring/grafana > py-framework-dashboard.json

# Import into Grafana
# 1. Go to Grafana (http://localhost:3000)
# 2. Login with admin/admin
# 3. Import dashboard from py-framework-dashboard.json
```

## API Reference

### Metrics Endpoints

#### `GET /api/metrics`
**Description**: Prometheus metrics endpoint
**Authentication**: None
**Response**: Plain text (Prometheus format)

#### `GET /api/metrics/summary`
**Description**: JSON metrics summary
**Authentication**: Admin required
**Response**: JSON metrics data

#### `GET /api/metrics/performance`
**Description**: Performance insights and recommendations
**Authentication**: Admin required
**Response**: JSON performance analysis

### Health Endpoints

#### `GET /api/health`
**Description**: Overall system health
**Authentication**: None
**Response**: JSON health status
**Status Codes**: 200 (healthy), 503 (critical)

#### `GET /api/health/{check_name}`
**Description**: Individual health check
**Authentication**: None
**Response**: JSON health check result

#### `POST /api/health/{check_name}/run`
**Description**: Run health check immediately
**Authentication**: Admin required
**Response**: JSON health check result

### Alert Endpoints

#### `GET /api/alerts`
**Description**: Active alerts
**Authentication**: Admin required
**Response**: JSON active alerts list

#### `GET /api/alerts/history`
**Description**: Alert history
**Authentication**: Admin required
**Parameters**: `limit` (default: 100)
**Response**: JSON alert history

#### `GET /api/alerts/stats`
**Description**: Alert statistics
**Authentication**: Admin required
**Response**: JSON alert statistics

### Dashboard Endpoints

#### `GET /admin/monitoring`
**Description**: Web monitoring dashboard
**Authentication**: Admin required
**Response**: HTML dashboard

#### `GET /admin/monitoring/grafana`
**Description**: Grafana dashboard configuration
**Authentication**: Admin required
**Response**: JSON Grafana config

#### `GET /admin/monitoring/export`
**Description**: Export all monitoring data
**Authentication**: Admin required
**Response**: JSON data export

## Integration with Existing Code

### Middleware Integration
```python
# Automatic integration in dev.py and app.py
from src.framework.monitoring.middleware import add_monitoring_middleware

app = create_app()
app = add_monitoring_middleware(app)
```

### Decorator Integration
```python
from src.framework.monitoring.middleware import monitor_database_operation

@monitor_database_operation("user_login")
def authenticate_user(email, password):
    # Your authentication logic
    pass
```

### Manual Metric Tracking
```python
from src.framework.monitoring import get_metrics_collector

def my_function():
    metrics = get_metrics_collector()
    
    start_time = time.time()
    try:
        # Your code here
        result = do_something()
        
        duration = time.time() - start_time
        metrics.record_histogram('my_function_duration', duration)
        metrics.increment_counter('my_function_success_total')
        
        return result
    except Exception as e:
        metrics.increment_counter('my_function_error_total')
        raise
```

## Performance Impact

### Resource Usage
- **Memory Overhead**: ~5-10MB for monitoring components
- **CPU Impact**: <1% additional CPU usage
- **Storage**: Metrics stored in memory (configurable retention)
- **Network**: Minimal overhead for metric collection

### Optimization
- **Metric Retention**: Configurable time-based retention
- **Sampling**: Support for metric sampling in high-traffic scenarios
- **Background Processing**: Non-blocking metric collection
- **Efficient Storage**: Optimized data structures for performance

## Troubleshooting

### Common Issues

#### Metrics Not Appearing
```bash
# Check metrics collector initialization
curl http://localhost:8000/api/metrics/summary

# Verify middleware is loaded
grep "Monitoring middleware initialized" logs/

# Check for errors in metrics collection
tail -f logs/app.log | grep -i error
```

#### Health Checks Failing
```bash
# Run individual health check
curl http://localhost:8000/api/health/database

# Check database connectivity
curl -X POST http://localhost:8000/api/health/database/run

# View detailed health status
curl http://localhost:8000/api/health
```

#### Alerts Not Firing
```bash
# Check alert manager status
curl http://localhost:8000/api/alerts/stats

# Verify alert rules
curl http://localhost:8000/api/alerts

# Check email configuration
grep SMTP .env
```

### Performance Troubleshooting
```python
# Get performance insights
from src.framework.monitoring import get_metrics_collector

metrics = get_metrics_collector()
insights = metrics.get_performance_insights()

# Check for performance alerts
if insights['health_score'] < 80:
    print("Performance issues detected:")
    for alert in insights['alerts']:
        print(f"- {alert['message']}")
```

### Debug Mode
```bash
# Enable debug logging for monitoring
export MONITORING_DEBUG=true

# View monitoring component logs
tail -f logs/monitoring.log
```

## Best Practices

### Metric Naming
- Use descriptive metric names: `http_requests_total` vs `requests`
- Include units in names: `duration_seconds`, `size_bytes`
- Use consistent labeling: `{method="GET", status="200"}`

### Alert Configuration
- Set appropriate thresholds based on baseline measurements
- Use cooldown periods to prevent alert spam
- Configure multiple notification channels for redundancy
- Test alert rules with simulated conditions

### Health Check Design
- Keep checks lightweight and fast (<1 second)
- Use meaningful error messages
- Include relevant context in details
- Set appropriate check intervals

### Dashboard Usage
- Monitor key metrics regularly
- Set up automated reports for stakeholders
- Use alerts for proactive issue detection
- Export data for trend analysis

### Production Deployment
- Enable all monitoring components
- Configure proper alert channels
- Set up external monitoring (Prometheus/Grafana)
- Implement log aggregation
- Configure proper retention policies

## Security Considerations

### Access Control
- All admin monitoring endpoints require authentication
- Role-based access control for sensitive operations
- API rate limiting on monitoring endpoints
- Secure storage of alert credentials

### Data Privacy
- No sensitive data in metrics labels
- Secure transmission of alert notifications
- Configurable data retention policies
- Audit logging of monitoring access

### Network Security
- TLS encryption for external monitoring
- Firewall rules for monitoring ports
- Secure credential management
- Regular security updates

---

**The enhanced monitoring system provides enterprise-grade observability for PY-Framework applications. For questions or support, refer to the main documentation or create an issue in the repository.**

> Last updated: 2025-08-29
> Recent internal changes: DB connections (thread-local + auto-reconnect), audit logging stability, OAuth async mocking compatibility, session rotation/cleanup, simple test RateLimiter, and pytest asyncio config.
