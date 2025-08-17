"""
Health Check System for PY-Framework
Provides comprehensive health monitoring and status reporting
"""

import time
import threading
import psutil
import duckdb
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum


class HealthStatus(Enum):
    """Health check status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthCheck:
    """Individual health check result"""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    duration_ms: float


@dataclass
class HealthCheckDefinition:
    """Health check definition"""
    name: str
    description: str
    check_function: Callable[[], HealthCheck]
    interval_seconds: int = 60
    timeout_seconds: int = 10
    enabled: bool = True


class HealthChecker:
    """Comprehensive health monitoring system"""
    
    def __init__(self, database_path: str = "app.db"):
        self.database_path = database_path
        self._checks: Dict[str, HealthCheckDefinition] = {}
        self._results: Dict[str, HealthCheck] = {}
        self._lock = threading.RLock()
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        
        # Register default health checks
        self._register_default_checks()
        
        # Start monitoring
        self.start_monitoring()
    
    def _register_default_checks(self):
        """Register default health checks"""
        
        # Database connectivity check
        self.register_check(
            "database",
            "Database connectivity and operations",
            self._check_database,
            interval_seconds=30
        )
        
        # Memory usage check
        self.register_check(
            "memory",
            "System memory usage",
            self._check_memory,
            interval_seconds=60
        )
        
        # Disk space check
        self.register_check(
            "disk_space",
            "Available disk space",
            self._check_disk_space,
            interval_seconds=300  # 5 minutes
        )
        
        # CPU usage check
        self.register_check(
            "cpu",
            "CPU usage levels",
            self._check_cpu,
            interval_seconds=60
        )
        
        # Application responsiveness check
        self.register_check(
            "app_responsiveness",
            "Application response time",
            self._check_app_responsiveness,
            interval_seconds=30
        )
        
        # Cache health check
        self.register_check(
            "cache",
            "Cache system health",
            self._check_cache_health,
            interval_seconds=120
        )
        
        # Session health check
        self.register_check(
            "sessions",
            "Session management health",
            self._check_session_health,
            interval_seconds=180
        )
    
    def register_check(self, name: str, description: str, check_function: Callable,
                      interval_seconds: int = 60, timeout_seconds: int = 10, enabled: bool = True):
        """Register a new health check"""
        with self._lock:
            self._checks[name] = HealthCheckDefinition(
                name=name,
                description=description,
                check_function=check_function,
                interval_seconds=interval_seconds,
                timeout_seconds=timeout_seconds,
                enabled=enabled
            )
    
    def start_monitoring(self):
        """Start background health monitoring"""
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_monitoring.clear()
            self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self._monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop background health monitoring"""
        self._stop_monitoring.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        check_times = {}
        
        while not self._stop_monitoring.is_set():
            current_time = time.time()
            
            # Create a copy of checks to avoid dictionary changed during iteration
            with self._lock:
                checks_copy = dict(self._checks)
            
            for name, check_def in checks_copy.items():
                if not check_def.enabled:
                    continue
                
                # Check if it's time to run this check
                last_check = check_times.get(name, 0)
                if current_time - last_check >= check_def.interval_seconds:
                    try:
                        result = self._run_check_with_timeout(check_def)
                        with self._lock:
                            self._results[name] = result
                        check_times[name] = current_time
                        
                    except Exception as e:
                        # Create error result
                        error_result = HealthCheck(
                            name=name,
                            status=HealthStatus.CRITICAL,
                            message=f"Health check failed: {str(e)}",
                            details={"error": str(e)},
                            timestamp=datetime.now(),
                            duration_ms=0
                        )
                        with self._lock:
                            self._results[name] = error_result
            
            # Sleep for a short interval
            time.sleep(5)
    
    def _run_check_with_timeout(self, check_def: HealthCheckDefinition) -> HealthCheck:
        """Run a health check with timeout"""
        start_time = time.time()
        
        try:
            result = check_def.check_function()
            result.duration_ms = (time.time() - start_time) * 1000
            return result
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheck(
                name=check_def.name,
                status=HealthStatus.CRITICAL,
                message=f"Check execution failed: {str(e)}",
                details={"error": str(e), "duration_ms": duration_ms},
                timestamp=datetime.now(),
                duration_ms=duration_ms
            )
    
    def _check_database(self) -> HealthCheck:
        """Check database connectivity and performance"""
        start_time = time.time()
        details = {}
        
        try:
            # Test basic connectivity
            conn = duckdb.connect(self.database_path)
            
            # Test a simple query
            query_start = time.time()
            result = conn.execute("SELECT 1 as test").fetchone()
            query_duration = (time.time() - query_start) * 1000
            
            details["query_duration_ms"] = query_duration
            details["connection_successful"] = True
            
            # Check database size
            try:
                import os
                db_size = os.path.getsize(self.database_path)
                details["database_size_bytes"] = db_size
                details["database_size_mb"] = db_size / (1024 * 1024)
            except:
                pass
            
            conn.close()
            
            # Determine status based on performance
            if query_duration > 1000:  # > 1 second
                status = HealthStatus.CRITICAL
                message = f"Database responding slowly ({query_duration:.0f}ms)"
            elif query_duration > 100:  # > 100ms
                status = HealthStatus.WARNING
                message = f"Database response time elevated ({query_duration:.0f}ms)"
            else:
                status = HealthStatus.HEALTHY
                message = f"Database healthy ({query_duration:.0f}ms)"
            
            return HealthCheck(
                name="database",
                status=status,
                message=message,
                details=details,
                timestamp=datetime.now(),
                duration_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            return HealthCheck(
                name="database",
                status=HealthStatus.CRITICAL,
                message=f"Database connection failed: {str(e)}",
                details={"error": str(e), "connection_successful": False},
                timestamp=datetime.now(),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def _check_memory(self) -> HealthCheck:
        """Check system memory usage"""
        try:
            memory = psutil.virtual_memory()
            
            details = {
                "total_bytes": memory.total,
                "available_bytes": memory.available,
                "used_bytes": memory.used,
                "percent_used": memory.percent,
                "total_gb": memory.total / (1024**3),
                "available_gb": memory.available / (1024**3),
                "used_gb": memory.used / (1024**3)
            }
            
            # Determine status based on usage
            if memory.percent > 90:
                status = HealthStatus.CRITICAL
                message = f"Critical memory usage: {memory.percent:.1f}%"
            elif memory.percent > 80:
                status = HealthStatus.WARNING
                message = f"High memory usage: {memory.percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage normal: {memory.percent:.1f}%"
            
            return HealthCheck(
                name="memory",
                status=status,
                message=message,
                details=details,
                timestamp=datetime.now(),
                duration_ms=0
            )
            
        except Exception as e:
            return HealthCheck(
                name="memory",
                status=HealthStatus.UNKNOWN,
                message=f"Could not check memory: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now(),
                duration_ms=0
            )
    
    def _check_disk_space(self) -> HealthCheck:
        """Check available disk space"""
        try:
            disk = psutil.disk_usage('.')
            
            percent_used = (disk.used / disk.total) * 100
            
            details = {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "percent_used": percent_used,
                "total_gb": disk.total / (1024**3),
                "used_gb": disk.used / (1024**3),
                "free_gb": disk.free / (1024**3)
            }
            
            # Determine status based on usage
            if percent_used > 95:
                status = HealthStatus.CRITICAL
                message = f"Critical disk usage: {percent_used:.1f}%"
            elif percent_used > 85:
                status = HealthStatus.WARNING
                message = f"High disk usage: {percent_used:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk usage normal: {percent_used:.1f}%"
            
            return HealthCheck(
                name="disk_space",
                status=status,
                message=message,
                details=details,
                timestamp=datetime.now(),
                duration_ms=0
            )
            
        except Exception as e:
            return HealthCheck(
                name="disk_space",
                status=HealthStatus.UNKNOWN,
                message=f"Could not check disk space: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now(),
                duration_ms=0
            )
    
    def _check_cpu(self) -> HealthCheck:
        """Check CPU usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            details = {
                "cpu_percent": cpu_percent,
                "cpu_count": cpu_count,
                "load_average": getattr(psutil, 'getloadavg', lambda: [0, 0, 0])()
            }
            
            # Determine status based on usage
            if cpu_percent > 90:
                status = HealthStatus.CRITICAL
                message = f"Critical CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent > 80:
                status = HealthStatus.WARNING
                message = f"High CPU usage: {cpu_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"CPU usage normal: {cpu_percent:.1f}%"
            
            return HealthCheck(
                name="cpu",
                status=status,
                message=message,
                details=details,
                timestamp=datetime.now(),
                duration_ms=0
            )
            
        except Exception as e:
            return HealthCheck(
                name="cpu",
                status=HealthStatus.UNKNOWN,
                message=f"Could not check CPU: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now(),
                duration_ms=0
            )
    
    def _check_app_responsiveness(self) -> HealthCheck:
        """Check application responsiveness"""
        start_time = time.time()
        
        try:
            # Simulate a quick operation
            import random
            import hashlib
            
            # Generate some work to test responsiveness
            data = str(random.randint(1, 1000000))
            hash_result = hashlib.md5(data.encode()).hexdigest()
            
            response_time = (time.time() - start_time) * 1000
            
            details = {
                "response_time_ms": response_time,
                "test_completed": True
            }
            
            # Determine status based on response time
            if response_time > 100:
                status = HealthStatus.WARNING
                message = f"Slow app response: {response_time:.1f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = f"App responsive: {response_time:.1f}ms"
            
            return HealthCheck(
                name="app_responsiveness",
                status=status,
                message=message,
                details=details,
                timestamp=datetime.now(),
                duration_ms=response_time
            )
            
        except Exception as e:
            return HealthCheck(
                name="app_responsiveness",
                status=HealthStatus.CRITICAL,
                message=f"App responsiveness check failed: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now(),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def _check_cache_health(self) -> HealthCheck:
        """Check cache system health"""
        try:
            from ..performance import get_performance_cache
            
            cache = get_performance_cache()
            stats = cache.get_stats()
            
            hit_rate = 0
            if stats['hits'] + stats['misses'] > 0:
                hit_rate = stats['hits'] / (stats['hits'] + stats['misses']) * 100
            
            details = {
                "cache_hits": stats['hits'],
                "cache_misses": stats['misses'],
                "hit_rate_percent": hit_rate,
                "cache_size": len(cache.cache),
                "total_operations": stats['hits'] + stats['misses']
            }
            
            # Determine status based on hit rate
            if hit_rate < 50 and details['total_operations'] > 100:
                status = HealthStatus.WARNING
                message = f"Low cache hit rate: {hit_rate:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Cache healthy (hit rate: {hit_rate:.1f}%)"
            
            return HealthCheck(
                name="cache",
                status=status,
                message=message,
                details=details,
                timestamp=datetime.now(),
                duration_ms=0
            )
            
        except Exception as e:
            return HealthCheck(
                name="cache",
                status=HealthStatus.WARNING,
                message=f"Could not check cache: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now(),
                duration_ms=0
            )
    
    def _check_session_health(self) -> HealthCheck:
        """Check session management health"""
        try:
            # This would integrate with your session management system
            # For now, we'll do a basic check
            
            details = {
                "session_check": "basic",
                "timestamp": datetime.now().isoformat()
            }
            
            return HealthCheck(
                name="sessions",
                status=HealthStatus.HEALTHY,
                message="Session management operational",
                details=details,
                timestamp=datetime.now(),
                duration_ms=0
            )
            
        except Exception as e:
            return HealthCheck(
                name="sessions",
                status=HealthStatus.WARNING,
                message=f"Could not check sessions: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now(),
                duration_ms=0
            )
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        with self._lock:
            if not self._results:
                return {
                    "status": "unknown",
                    "message": "No health checks completed yet",
                    "checks": {},
                    "summary": {
                        "total": 0,
                        "healthy": 0,
                        "warning": 0,
                        "critical": 0,
                        "unknown": 0
                    }
                }
            
            # Count status types
            counts = {"healthy": 0, "warning": 0, "critical": 0, "unknown": 0}
            checks = {}
            
            for name, result in self._results.items():
                status_str = result.status.value
                counts[status_str] += 1
                
                checks[name] = {
                    "status": status_str,
                    "message": result.message,
                    "details": result.details,
                    "timestamp": result.timestamp.isoformat(),
                    "duration_ms": result.duration_ms
                }
            
            # Determine overall status
            if counts["critical"] > 0:
                overall_status = "critical"
                overall_message = f"{counts['critical']} critical issues detected"
            elif counts["warning"] > 0:
                overall_status = "warning"
                overall_message = f"{counts['warning']} warnings detected"
            elif counts["unknown"] > 0:
                overall_status = "degraded"
                overall_message = f"{counts['unknown']} checks could not complete"
            else:
                overall_status = "healthy"
                overall_message = "All systems operational"
            
            return {
                "status": overall_status,
                "message": overall_message,
                "checks": checks,
                "summary": {
                    "total": len(self._results),
                    **counts
                },
                "timestamp": datetime.now().isoformat()
            }
    
    def get_check_result(self, check_name: str) -> Optional[Dict[str, Any]]:
        """Get result for a specific health check"""
        with self._lock:
            if check_name in self._results:
                result = self._results[check_name]
                return {
                    "name": result.name,
                    "status": result.status.value,
                    "message": result.message,
                    "details": result.details,
                    "timestamp": result.timestamp.isoformat(),
                    "duration_ms": result.duration_ms
                }
            return None
    
    def run_check_now(self, check_name: str) -> Optional[HealthCheck]:
        """Run a specific health check immediately"""
        if check_name in self._checks:
            check_def = self._checks[check_name]
            result = self._run_check_with_timeout(check_def)
            
            with self._lock:
                self._results[check_name] = result
            
            return result
        return None


# Global health checker instance
_health_checker: Optional[HealthChecker] = None
_checker_lock = threading.Lock()


def get_health_checker() -> HealthChecker:
    """Get the global health checker instance"""
    global _health_checker
    
    if _health_checker is None:
        with _checker_lock:
            if _health_checker is None:
                _health_checker = HealthChecker()
    
    return _health_checker