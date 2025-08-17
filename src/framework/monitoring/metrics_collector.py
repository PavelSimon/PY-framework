"""
Prometheus Metrics Collector for PY-Framework
Collects and exposes comprehensive application metrics
"""

import time
import threading
import psutil
import duckdb
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque
from functools import wraps


@dataclass
class MetricValue:
    """Represents a metric value with timestamp"""
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class MetricSeries:
    """Time series of metric values"""
    name: str
    help_text: str
    metric_type: str  # counter, gauge, histogram, summary
    values: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    def add_value(self, value: float, labels: Dict[str, str] = None):
        """Add a new metric value"""
        self.values.append(MetricValue(
            value=value,
            timestamp=datetime.now(),
            labels=labels or {}
        ))


class MetricsCollector:
    """Central metrics collection and management system"""
    
    def __init__(self):
        self._metrics: Dict[str, MetricSeries] = {}
        self._lock = threading.RLock()
        self._request_durations = deque(maxlen=10000)
        self._error_counts = defaultdict(int)
        self._active_connections = 0
        self._database_queries = deque(maxlen=1000)
        
        # Initialize core metrics
        self._init_core_metrics()
        
        # Start background collection
        self._collection_thread = threading.Thread(target=self._collect_system_metrics, daemon=True)
        self._collection_thread.start()
    
    def _init_core_metrics(self):
        """Initialize core application metrics"""
        self.register_metric(
            'http_requests_total',
            'Total number of HTTP requests',
            'counter'
        )
        
        self.register_metric(
            'http_request_duration_seconds',
            'HTTP request duration in seconds',
            'histogram'
        )
        
        self.register_metric(
            'http_errors_total',
            'Total number of HTTP errors',
            'counter'
        )
        
        self.register_metric(
            'database_connections_active',
            'Number of active database connections',
            'gauge'
        )
        
        self.register_metric(
            'database_query_duration_seconds',
            'Database query duration in seconds',
            'histogram'
        )
        
        self.register_metric(
            'cache_hits_total',
            'Total number of cache hits',
            'counter'
        )
        
        self.register_metric(
            'cache_misses_total',
            'Total number of cache misses',
            'counter'
        )
        
        self.register_metric(
            'session_count',
            'Number of active sessions',
            'gauge'
        )
        
        self.register_metric(
            'memory_usage_bytes',
            'Memory usage in bytes',
            'gauge'
        )
        
        self.register_metric(
            'cpu_usage_percent',
            'CPU usage percentage',
            'gauge'
        )
        
        self.register_metric(
            'disk_usage_bytes',
            'Disk usage in bytes',
            'gauge'
        )
        
        self.register_metric(
            'user_logins_total',
            'Total number of user logins',
            'counter'
        )
        
        self.register_metric(
            'failed_logins_total',
            'Total number of failed login attempts',
            'counter'
        )
        
        self.register_metric(
            'active_users',
            'Number of currently active users',
            'gauge'
        )
        
        self.register_metric(
            'audit_events_total',
            'Total number of audit events',
            'counter'
        )
    
    def register_metric(self, name: str, help_text: str, metric_type: str):
        """Register a new metric"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = MetricSeries(
                    name=name,
                    help_text=help_text,
                    metric_type=metric_type
                )
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter metric"""
        with self._lock:
            if name in self._metrics:
                current_value = 0
                if self._metrics[name].values:
                    current_value = self._metrics[name].values[-1].value
                self._metrics[name].add_value(current_value + value, labels)
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric value"""
        with self._lock:
            if name in self._metrics:
                self._metrics[name].add_value(value, labels)
    
    def record_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a histogram metric value"""
        with self._lock:
            if name in self._metrics:
                self._metrics[name].add_value(value, labels)
    
    def track_request(self, method: str, path: str, status_code: int, duration: float):
        """Track HTTP request metrics"""
        labels = {
            'method': method,
            'path': path,
            'status': str(status_code)
        }
        
        self.increment_counter('http_requests_total', labels=labels)
        self.record_histogram('http_request_duration_seconds', duration, labels=labels)
        
        if status_code >= 400:
            self.increment_counter('http_errors_total', labels=labels)
    
    def track_database_query(self, query_type: str, duration: float, success: bool = True):
        """Track database query metrics"""
        labels = {
            'query_type': query_type,
            'success': str(success).lower()
        }
        
        self.record_histogram('database_query_duration_seconds', duration, labels=labels)
        
        # Store recent queries for analysis
        with self._lock:
            self._database_queries.append({
                'type': query_type,
                'duration': duration,
                'success': success,
                'timestamp': datetime.now()
            })
    
    def track_cache_operation(self, operation: str, hit: bool = True):
        """Track cache operation metrics"""
        if hit:
            self.increment_counter('cache_hits_total', labels={'operation': operation})
        else:
            self.increment_counter('cache_misses_total', labels={'operation': operation})
    
    def track_user_login(self, success: bool, user_id: Optional[int] = None):
        """Track user login metrics"""
        if success:
            self.increment_counter('user_logins_total')
        else:
            self.increment_counter('failed_logins_total')
    
    def track_audit_event(self, event_type: str):
        """Track audit event metrics"""
        self.increment_counter('audit_events_total', labels={'event_type': event_type})
    
    def update_active_connections(self, count: int):
        """Update active database connections count"""
        self.set_gauge('database_connections_active', count)
    
    def update_active_sessions(self, count: int):
        """Update active sessions count"""
        self.set_gauge('session_count', count)
    
    def update_active_users(self, count: int):
        """Update active users count"""
        self.set_gauge('active_users', count)
    
    def _collect_system_metrics(self):
        """Background thread to collect system metrics"""
        while True:
            try:
                # Memory usage
                memory = psutil.virtual_memory()
                self.set_gauge('memory_usage_bytes', memory.used)
                
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                self.set_gauge('cpu_usage_percent', cpu_percent)
                
                # Disk usage
                disk = psutil.disk_usage('.')
                self.set_gauge('disk_usage_bytes', disk.used)
                
                time.sleep(30)  # Collect every 30 seconds
                
            except Exception as e:
                print(f"Error collecting system metrics: {e}")
                time.sleep(60)  # Wait longer on error
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of all metrics"""
        with self._lock:
            summary = {}
            
            for name, series in self._metrics.items():
                if series.values:
                    latest = series.values[-1]
                    summary[name] = {
                        'value': latest.value,
                        'timestamp': latest.timestamp.isoformat(),
                        'labels': latest.labels,
                        'type': series.metric_type,
                        'help': series.help_text
                    }
            
            return summary
    
    def get_prometheus_format(self) -> str:
        """Export metrics in Prometheus format"""
        output = []
        
        with self._lock:
            for name, series in self._metrics.items():
                # Add help text
                output.append(f"# HELP {name} {series.help_text}")
                output.append(f"# TYPE {name} {series.metric_type}")
                
                # Add metric values
                if series.values:
                    latest = series.values[-1]
                    labels_str = ""
                    if latest.labels:
                        label_pairs = [f'{k}="{v}"' for k, v in latest.labels.items()]
                        labels_str = "{" + ",".join(label_pairs) + "}"
                    
                    output.append(f"{name}{labels_str} {latest.value}")
                
                output.append("")  # Empty line between metrics
        
        return "\n".join(output)
    
    def get_recent_requests(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent request metrics"""
        with self._lock:
            return list(self._request_durations)[-limit:]
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database performance statistics"""
        with self._lock:
            if not self._database_queries:
                return {}
            
            queries = list(self._database_queries)
            total_queries = len(queries)
            avg_duration = sum(q['duration'] for q in queries) / total_queries
            success_rate = sum(1 for q in queries if q['success']) / total_queries
            
            return {
                'total_queries': total_queries,
                'average_duration': avg_duration,
                'success_rate': success_rate,
                'slow_queries': [q for q in queries if q['duration'] > 0.1],  # > 100ms
                'recent_queries': queries[-10:]
            }
    
    def get_performance_insights(self) -> Dict[str, Any]:
        """Get performance insights and recommendations"""
        insights = {
            'alerts': [],
            'recommendations': [],
            'health_score': 100
        }
        
        # Analyze request performance
        if 'http_request_duration_seconds' in self._metrics:
            values = self._metrics['http_request_duration_seconds'].values
            if values:
                durations = [v.value for v in list(values)[-100:]]
                if durations:
                    avg_duration = sum(durations) / len(durations)
                    if avg_duration > 1.0:  # > 1 second
                        insights['alerts'].append({
                            'type': 'performance',
                            'message': f'High average request duration: {avg_duration:.2f}s',
                            'severity': 'warning'
                        })
                        insights['health_score'] -= 20
        
        # Analyze error rates
        if 'http_errors_total' in self._metrics and 'http_requests_total' in self._metrics:
            error_values = [v.value for v in list(self._metrics['http_errors_total'].values)[-100:]]
            request_values = [v.value for v in list(self._metrics['http_requests_total'].values)[-100:]]
            
            if error_values and request_values:
                error_rate = error_values[-1] / request_values[-1] if request_values[-1] > 0 else 0
                if error_rate > 0.05:  # > 5% error rate
                    insights['alerts'].append({
                        'type': 'error_rate',
                        'message': f'High error rate: {error_rate*100:.1f}%',
                        'severity': 'critical'
                    })
                    insights['health_score'] -= 30
        
        # Analyze memory usage
        if 'memory_usage_bytes' in self._metrics:
            memory_values = [v.value for v in list(self._metrics['memory_usage_bytes'].values)[-10:]]
            if memory_values:
                latest_memory = memory_values[-1]
                memory_gb = latest_memory / (1024**3)
                if memory_gb > 4:  # > 4GB
                    insights['recommendations'].append({
                        'type': 'memory',
                        'message': f'High memory usage: {memory_gb:.1f}GB',
                        'action': 'Consider optimizing cache settings or scaling up'
                    })
        
        return insights


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None
_collector_lock = threading.Lock()


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance"""
    global _metrics_collector
    
    if _metrics_collector is None:
        with _collector_lock:
            if _metrics_collector is None:
                _metrics_collector = MetricsCollector()
    
    return _metrics_collector


def metrics_decorator(metric_name: str, metric_type: str = 'histogram'):
    """Decorator to automatically track function execution metrics"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if metric_type == 'histogram':
                    collector.record_histogram(metric_name, duration)
                elif metric_type == 'counter':
                    collector.increment_counter(metric_name)
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                collector.increment_counter(f'{metric_name}_errors_total')
                raise
        
        return wrapper
    return decorator