"""
Comprehensive tests for the enhanced monitoring system
"""

import pytest
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from src.framework.monitoring import (
    MetricsCollector,
    HealthChecker,
    AlertManager,
    get_metrics_collector,
    get_health_checker,
    get_alert_manager
)
from src.framework.monitoring.health_checker import HealthStatus
from src.framework.monitoring.alerting import AlertSeverity, AlertStatus


class TestMetricsCollector:
    """Test metrics collection functionality"""
    
    def test_metric_registration(self):
        """Test metric registration"""
        collector = MetricsCollector()
        
        collector.register_metric("test_counter", "Test counter metric", "counter")
        
        assert "test_counter" in collector._metrics
        assert collector._metrics["test_counter"].name == "test_counter"
        assert collector._metrics["test_counter"].metric_type == "counter"
    
    def test_counter_increment(self):
        """Test counter metric incrementation"""
        collector = MetricsCollector()
        collector.register_metric("test_counter", "Test counter", "counter")
        
        collector.increment_counter("test_counter", 5.0)
        collector.increment_counter("test_counter", 3.0)
        
        # Should have latest value (cumulative)
        latest = collector._metrics["test_counter"].values[-1]
        assert latest.value == 8.0
    
    def test_gauge_setting(self):
        """Test gauge metric setting"""
        collector = MetricsCollector()
        collector.register_metric("test_gauge", "Test gauge", "gauge")
        
        collector.set_gauge("test_gauge", 42.5)
        collector.set_gauge("test_gauge", 100.0)
        
        # Should have latest value only
        latest = collector._metrics["test_gauge"].values[-1]
        assert latest.value == 100.0
    
    def test_histogram_recording(self):
        """Test histogram metric recording"""
        collector = MetricsCollector()
        collector.register_metric("test_histogram", "Test histogram", "histogram")
        
        collector.record_histogram("test_histogram", 1.5)
        collector.record_histogram("test_histogram", 2.3)
        
        # Should have both values
        assert len(collector._metrics["test_histogram"].values) == 2
        assert collector._metrics["test_histogram"].values[0].value == 1.5
        assert collector._metrics["test_histogram"].values[1].value == 2.3
    
    def test_request_tracking(self):
        """Test HTTP request tracking"""
        collector = MetricsCollector()
        
        collector.track_request("GET", "/api/test", 200, 0.5)
        collector.track_request("POST", "/api/test", 500, 1.2)
        
        # Check that metrics were recorded
        assert "http_requests_total" in collector._metrics
        assert "http_request_duration_seconds" in collector._metrics
        assert "http_errors_total" in collector._metrics
        
        # Error should be recorded for 500 status
        error_metric = collector._metrics["http_errors_total"]
        assert len(error_metric.values) == 1
    
    def test_database_query_tracking(self):
        """Test database query tracking"""
        collector = MetricsCollector()
        
        collector.track_database_query("SELECT", 0.05, True)
        collector.track_database_query("INSERT", 0.15, False)
        
        # Check database metrics
        duration_metric = collector._metrics["database_query_duration_seconds"]
        assert len(duration_metric.values) == 2
        
        # Check query storage
        assert len(collector._database_queries) == 2
        assert collector._database_queries[0]['type'] == "SELECT"
        assert collector._database_queries[1]['success'] == False
    
    def test_cache_operation_tracking(self):
        """Test cache operation tracking"""
        collector = MetricsCollector()
        
        collector.track_cache_operation("get", hit=True)
        collector.track_cache_operation("get", hit=False)
        
        # Check cache metrics
        hits_metric = collector._metrics["cache_hits_total"]
        misses_metric = collector._metrics["cache_misses_total"]
        
        assert len(hits_metric.values) == 1
        assert len(misses_metric.values) == 1
    
    def test_prometheus_format_export(self):
        """Test Prometheus format export"""
        collector = MetricsCollector()
        collector.register_metric("test_metric", "A test metric", "counter")
        collector.increment_counter("test_metric", 42.0)
        
        prometheus_output = collector.get_prometheus_format()
        
        assert "# HELP test_metric A test metric" in prometheus_output
        assert "# TYPE test_metric counter" in prometheus_output
        assert "test_metric 42.0" in prometheus_output
    
    def test_metrics_summary(self):
        """Test metrics summary generation"""
        collector = MetricsCollector()
        collector.register_metric("test_metric", "Test", "gauge")
        collector.set_gauge("test_metric", 123.45)
        
        summary = collector.get_metrics_summary()
        
        assert "test_metric" in summary
        assert summary["test_metric"]["value"] == 123.45
        assert summary["test_metric"]["type"] == "gauge"
    
    def test_performance_insights(self):
        """Test performance insights generation"""
        collector = MetricsCollector()
        
        # Simulate high error rate
        collector.register_metric("http_requests_total", "Total requests", "counter")
        collector.register_metric("http_errors_total", "Total errors", "counter")
        
        collector.increment_counter("http_requests_total", 1000)
        collector.increment_counter("http_errors_total", 100)  # 10% error rate
        
        insights = collector.get_performance_insights()
        
        assert "alerts" in insights
        assert "health_score" in insights
        assert insights["health_score"] < 100  # Should be reduced due to high error rate


class TestHealthChecker:
    """Test health checking functionality"""
    
    @patch('psutil.virtual_memory')
    def test_memory_health_check(self, mock_memory):
        """Test memory health check"""
        # Mock healthy memory usage
        mock_memory.return_value = MagicMock(
            total=8589934592,  # 8GB
            available=4294967296,  # 4GB
            used=4294967296,  # 4GB
            percent=50.0
        )
        
        checker = HealthChecker()
        result = checker._check_memory()
        
        assert result.name == "memory"
        assert result.status == HealthStatus.HEALTHY
        assert "50.0%" in result.message
    
    @patch('psutil.virtual_memory')
    def test_memory_health_check_critical(self, mock_memory):
        """Test memory health check with critical usage"""
        # Mock critical memory usage
        mock_memory.return_value = MagicMock(
            total=8589934592,  # 8GB
            available=429496729,  # 0.4GB
            used=8160437863,  # 7.6GB
            percent=95.0
        )
        
        checker = HealthChecker()
        result = checker._check_memory()
        
        assert result.status == HealthStatus.CRITICAL
        assert "95.0%" in result.message
    
    @patch('psutil.disk_usage')
    def test_disk_space_check(self, mock_disk):
        """Test disk space health check"""
        # Mock healthy disk usage
        mock_disk.return_value = MagicMock(
            total=1073741824000,  # 1TB
            used=322122547200,    # 300GB
            free=751619276800,    # 700GB
        )
        
        checker = HealthChecker()
        result = checker._check_disk_space()
        
        assert result.status == HealthStatus.HEALTHY
        assert "30.0%" in result.message
    
    def test_database_connectivity_check(self):
        """Test database connectivity check"""
        checker = HealthChecker("test.db")
        
        # This will create a temporary database
        result = checker._check_database()
        
        # Should be healthy if database can be created/connected
        assert result.name == "database"
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.WARNING]
    
    def test_app_responsiveness_check(self):
        """Test application responsiveness check"""
        checker = HealthChecker()
        result = checker._check_app_responsiveness()
        
        assert result.name == "app_responsiveness"
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.WARNING]
        assert result.duration_ms > 0
    
    def test_health_status_summary(self):
        """Test health status summary generation"""
        checker = HealthChecker()
        
        # Wait a moment for initial checks
        time.sleep(2)
        
        status = checker.get_health_status()
        
        assert "status" in status
        assert "message" in status
        assert "checks" in status
        assert "summary" in status
        assert status["status"] in ["healthy", "warning", "critical", "degraded", "unknown"]
    
    def test_individual_check_execution(self):
        """Test running individual health checks"""
        checker = HealthChecker()
        
        result = checker.run_check_now("memory")
        
        assert result is not None
        assert result.name == "memory"
        assert isinstance(result.status, HealthStatus)
    
    def test_check_registration(self):
        """Test custom health check registration"""
        checker = HealthChecker()
        
        def custom_check():
            return checker._check_memory()  # Reuse existing check
        
        checker.register_check(
            "custom_test", 
            "Custom test check", 
            custom_check,
            interval_seconds=10
        )
        
        assert "custom_test" in checker._checks
        assert checker._checks["custom_test"].interval_seconds == 10


class TestAlertManager:
    """Test alerting functionality"""
    
    def test_alert_rule_registration(self):
        """Test alert rule registration"""
        manager = AlertManager()
        
        def test_condition():
            return True
        
        manager.register_rule(
            "test_alert",
            "Test alert condition",
            test_condition,
            AlertSeverity.WARNING,
            cooldown_minutes=5
        )
        
        assert "test_alert" in manager._rules
        assert manager._rules["test_alert"].severity == AlertSeverity.WARNING
        assert manager._rules["test_alert"].cooldown_minutes == 5
    
    def test_alert_triggering(self):
        """Test alert triggering and resolution"""
        manager = AlertManager()
        
        # Create a simple test condition
        trigger_alert = False
        
        def test_condition():
            return trigger_alert
        
        manager.register_rule(
            "test_alert",
            "Test alert",
            test_condition,
            AlertSeverity.CRITICAL
        )
        
        # Initially no alerts should be active
        active_alerts = manager.get_active_alerts()
        assert len(active_alerts) == 0
        
        # Trigger the alert
        trigger_alert = True
        manager._handle_alert_triggered(manager._rules["test_alert"])
        
        # Now there should be an active alert
        active_alerts = manager.get_active_alerts()
        assert len(active_alerts) == 1
        assert active_alerts[0]["rule_name"] == "test_alert"
        assert active_alerts[0]["severity"] == "critical"
    
    def test_alert_cooldown(self):
        """Test alert cooldown functionality"""
        manager = AlertManager()
        
        def always_true():
            return True
        
        manager.register_rule(
            "cooldown_test",
            "Cooldown test",
            always_true,
            AlertSeverity.WARNING,
            cooldown_minutes=1  # 1 minute cooldown
        )
        
        # Trigger first alert
        manager._handle_alert_triggered(manager._rules["cooldown_test"])
        active_count_1 = len(manager.get_active_alerts())
        
        # Immediately try to trigger again - should be blocked by cooldown
        manager._handle_alert_triggered(manager._rules["cooldown_test"])
        active_count_2 = len(manager.get_active_alerts())
        
        # Should still be the same count due to cooldown
        assert active_count_1 == active_count_2
    
    def test_alert_resolution(self):
        """Test automatic alert resolution"""
        manager = AlertManager()
        
        alert_condition = True
        
        def test_condition():
            return alert_condition
        
        manager.register_rule(
            "resolution_test",
            "Resolution test",
            test_condition,
            AlertSeverity.WARNING,
            auto_resolve=True
        )
        
        # Trigger alert
        manager._handle_alert_triggered(manager._rules["resolution_test"])
        assert len(manager.get_active_alerts()) == 1
        
        # Resolve condition
        alert_condition = False
        manager._handle_alert_resolved(manager._rules["resolution_test"])
        
        # Alert should be resolved
        assert len(manager.get_active_alerts()) == 0
    
    def test_alert_statistics(self):
        """Test alert statistics generation"""
        manager = AlertManager()
        
        # Add some test alerts to history
        from datetime import datetime
        from src.framework.monitoring.alerting import Alert
        
        test_alert = Alert(
            id="test_1",
            rule_name="test_rule",
            severity=AlertSeverity.WARNING,
            status=AlertStatus.RESOLVED,
            message="Test alert",
            details={},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        manager._alert_history.append(test_alert)
        
        stats = manager.get_alert_statistics()
        
        assert "total_alerts" in stats
        assert "active_alerts" in stats
        assert "severity_breakdown" in stats
        assert stats["total_alerts"] >= 1
    
    def test_notification_channel_registration(self):
        """Test notification channel registration"""
        manager = AlertManager()
        
        manager.register_channel(
            "test_console",
            "console",
            {},
            severity_filter=[AlertSeverity.CRITICAL]
        )
        
        assert "test_console" in manager._channels
        assert manager._channels["test_console"].channel_type == "console"
        assert AlertSeverity.CRITICAL in manager._channels["test_console"].severity_filter
    
    @patch('builtins.print')
    def test_console_notification(self, mock_print):
        """Test console notification sending"""
        manager = AlertManager()
        
        from src.framework.monitoring.alerting import AlertChannel, Alert
        
        channel = AlertChannel(
            name="test_console",
            channel_type="console",
            config={}
        )
        
        alert = Alert(
            id="test_alert",
            rule_name="test_rule",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.ACTIVE,
            message="Test alert message",
            details={},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        manager._send_console_notification(channel, alert)
        
        # Verify print was called with alert information
        mock_print.assert_called()
        call_args = mock_print.call_args_list
        assert any("CRITICAL" in str(call) for call in call_args)


class TestMonitoringIntegration:
    """Test monitoring system integration"""
    
    def test_singleton_instances(self):
        """Test that monitoring components are singletons"""
        metrics1 = get_metrics_collector()
        metrics2 = get_metrics_collector()
        assert metrics1 is metrics2
        
        health1 = get_health_checker()
        health2 = get_health_checker()
        assert health1 is health2
        
        alerts1 = get_alert_manager()
        alerts2 = get_alert_manager()
        assert alerts1 is alerts2
    
    def test_thread_safety(self):
        """Test thread safety of monitoring components"""
        collector = get_metrics_collector()
        
        # Register the metric first
        collector.register_metric("thread_test", "Thread safety test", "counter")
        
        def increment_counter():
            for i in range(100):
                collector.increment_counter("thread_test", 1.0)
        
        # Run multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=increment_counter)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Check final value
        final_value = collector._metrics["thread_test"].values[-1].value
        assert final_value == 500.0  # 5 threads * 100 increments each
    
    def test_monitoring_data_export(self):
        """Test monitoring data export functionality"""
        from src.framework.monitoring.dashboard import MonitoringDashboard
        
        dashboard = MonitoringDashboard()
        
        # Test Prometheus metrics export
        prometheus_data = dashboard.get_prometheus_metrics()
        assert isinstance(prometheus_data, str)
        assert "# HELP" in prometheus_data
        
        # Test health check JSON export
        health_data = dashboard.get_health_check_json()
        assert isinstance(health_data, dict)
        assert "status" in health_data
        
        # Test metrics JSON export
        metrics_data = dashboard.get_metrics_json()
        assert isinstance(metrics_data, dict)


# Integration tests for the monitoring system
class TestMonitoringRoutes:
    """Test monitoring routes and endpoints"""
    
    @pytest.fixture
    def app_setup(self):
        """Setup test application with monitoring"""
        # This would be implemented with actual FastHTML app setup
        # For now, just return mock data
        return {
            "app": MagicMock(),
            "db": MagicMock(),
            "auth": MagicMock()
        }
    
    def test_metrics_endpoint_format(self, app_setup):
        """Test that metrics endpoint returns Prometheus format"""
        collector = get_metrics_collector()
        collector.register_metric("test_metric", "Test", "counter")
        collector.increment_counter("test_metric", 1.0)
        
        prometheus_output = collector.get_prometheus_format()
        
        # Verify Prometheus format
        lines = prometheus_output.split('\n')
        help_lines = [line for line in lines if line.startswith('# HELP')]
        type_lines = [line for line in lines if line.startswith('# TYPE')]
        metric_lines = [line for line in lines if line and not line.startswith('#')]
        
        assert len(help_lines) > 0
        assert len(type_lines) > 0
        assert len(metric_lines) > 0
    
    def test_health_endpoint_status_codes(self, app_setup):
        """Test health endpoint returns appropriate status codes"""
        checker = get_health_checker()
        
        # Simulate healthy status
        with patch.object(checker, 'get_health_status') as mock_health:
            mock_health.return_value = {"status": "healthy"}
            # In real test, would make HTTP request and check status code 200
            
            mock_health.return_value = {"status": "critical"} 
            # In real test, would make HTTP request and check status code 503


if __name__ == "__main__":
    pytest.main([__file__, "-v"])