"""
Monitoring Dashboard for PY-Framework
Provides web-based monitoring interface and Grafana integration
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fasthtml.common import *
from .metrics_collector import get_metrics_collector
from .health_checker import get_health_checker
from .alerting import get_alert_manager


class MonitoringDashboard:
    """Web-based monitoring dashboard"""
    
    def __init__(self):
        self.metrics = get_metrics_collector()
        self.health = get_health_checker()
        self.alerts = get_alert_manager()
    
    def render_dashboard(self) -> Div:
        """Render the main monitoring dashboard"""
        
        # Get current data
        health_status = self.health.get_health_status()
        active_alerts = self.alerts.get_active_alerts()
        metrics_summary = self.metrics.get_metrics_summary()
        alert_stats = self.alerts.get_alert_statistics()
        
        return Div(
            H1("🔍 System Monitoring Dashboard", cls="text-2xl font-bold mb-6"),
            
            # Health Status Overview
            self._render_health_overview(health_status),
            
            # Active Alerts
            self._render_active_alerts(active_alerts),
            
            # Key Metrics
            self._render_key_metrics(metrics_summary),
            
            # Performance Charts
            self._render_performance_charts(),
            
            # Alert Statistics
            self._render_alert_statistics(alert_stats),
            
            # System Resources
            self._render_system_resources(health_status),
            
            cls="monitoring-dashboard p-6"
        )
    
    def _render_health_overview(self, health_status: Dict[str, Any]) -> Div:
        """Render health status overview"""
        
        status = health_status['status']
        status_color = {
            'healthy': 'text-green-600 bg-green-100',
            'warning': 'text-yellow-600 bg-yellow-100', 
            'degraded': 'text-orange-600 bg-orange-100',
            'critical': 'text-red-600 bg-red-100'
        }.get(status, 'text-gray-600 bg-gray-100')
        
        return Div(
            H2("🏥 System Health", cls="text-xl font-semibold mb-4"),
            Div(
                Div(
                    Div(
                        Span("●", cls=f"text-2xl {status_color.split()[0]}"),
                        Span(status.upper(), cls=f"ml-2 px-3 py-1 rounded-full text-sm font-medium {status_color}"),
                        cls="flex items-center"
                    ),
                    P(health_status['message'], cls="text-gray-600 mt-2"),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                # Health check details
                Div(
                    H3("Health Checks", cls="font-medium mb-2"),
                    *[
                        Div(
                            Span(check_name.replace('_', ' ').title(), cls="font-medium"),
                            Span(
                                check_data['status'].upper(),
                                cls=f"ml-2 px-2 py-1 rounded text-xs {self._get_status_color(check_data['status'])}"
                            ),
                            P(check_data['message'], cls="text-sm text-gray-600 mt-1"),
                            cls="mb-2 p-2 border-l-4 border-gray-200"
                        )
                        for check_name, check_data in health_status['checks'].items()
                    ],
                    cls="bg-white p-4 rounded-lg shadow mt-4"
                ),
                
                cls="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6"
            )
        )
    
    def _render_active_alerts(self, active_alerts: List[Dict[str, Any]]) -> Div:
        """Render active alerts"""
        
        if not active_alerts:
            return Div(
                H2("🔔 Active Alerts", cls="text-xl font-semibold mb-4"),
                Div(
                    P("✅ No active alerts - all systems operational", cls="text-green-600 font-medium"),
                    cls="bg-green-50 border border-green-200 rounded-lg p-4"
                ),
                cls="mb-6"
            )
        
        return Div(
            H2("🔔 Active Alerts", cls="text-xl font-semibold mb-4"),
            Div(
                *[
                    Div(
                        Div(
                            Span(
                                alert['severity'].upper(),
                                cls=f"px-3 py-1 rounded-full text-xs font-medium {self._get_alert_color(alert['severity'])}"
                            ),
                            Span(alert['rule_name'].replace('_', ' ').title(), cls="ml-2 font-medium"),
                            cls="flex items-center mb-2"
                        ),
                        P(alert['message'], cls="text-gray-700"),
                        P(f"Created: {alert['created_at']}", cls="text-sm text-gray-500 mt-2"),
                        cls=f"bg-white border-l-4 {self._get_alert_border_color(alert['severity'])} p-4 rounded-lg shadow mb-3"
                    )
                    for alert in active_alerts
                ],
                cls="space-y-2"
            ),
            cls="mb-6"
        )
    
    def _render_key_metrics(self, metrics_summary: Dict[str, Any]) -> Div:
        """Render key metrics overview"""
        
        # Extract key metrics
        request_count = metrics_summary.get('http_requests_total', {}).get('value', 0)
        error_count = metrics_summary.get('http_errors_total', {}).get('value', 0)
        avg_response_time = metrics_summary.get('http_request_duration_seconds', {}).get('value', 0)
        active_sessions = metrics_summary.get('session_count', {}).get('value', 0)
        memory_usage = metrics_summary.get('memory_usage_bytes', {}).get('value', 0)
        cpu_usage = metrics_summary.get('cpu_usage_percent', {}).get('value', 0)
        
        # Calculate error rate
        error_rate = (error_count / request_count * 100) if request_count > 0 else 0
        
        return Div(
            H2("📊 Key Metrics", cls="text-xl font-semibold mb-4"),
            Div(
                # Requests
                Div(
                    Div("🌐", cls="text-2xl mb-2"),
                    Div(f"{request_count:,}", cls="text-2xl font-bold text-blue-600"),
                    P("Total Requests", cls="text-sm text-gray-600"),
                    cls="bg-white p-4 rounded-lg shadow text-center"
                ),
                
                # Error Rate
                Div(
                    Div("⚠️", cls="text-2xl mb-2"),
                    Div(f"{error_rate:.1f}%", cls="text-2xl font-bold text-red-600"),
                    P("Error Rate", cls="text-sm text-gray-600"),
                    cls="bg-white p-4 rounded-lg shadow text-center"
                ),
                
                # Response Time
                Div(
                    Div("⏱️", cls="text-2xl mb-2"),
                    Div(f"{avg_response_time:.2f}s", cls="text-2xl font-bold text-green-600"),
                    P("Avg Response Time", cls="text-sm text-gray-600"),
                    cls="bg-white p-4 rounded-lg shadow text-center"
                ),
                
                # Active Sessions
                Div(
                    Div("👥", cls="text-2xl mb-2"),
                    Div(f"{active_sessions:,}", cls="text-2xl font-bold text-purple-600"),
                    P("Active Sessions", cls="text-sm text-gray-600"),
                    cls="bg-white p-4 rounded-lg shadow text-center"
                ),
                
                # Memory Usage
                Div(
                    Div("💾", cls="text-2xl mb-2"),
                    Div(f"{memory_usage / (1024**3):.1f}GB", cls="text-2xl font-bold text-orange-600"),
                    P("Memory Usage", cls="text-sm text-gray-600"),
                    cls="bg-white p-4 rounded-lg shadow text-center"
                ),
                
                # CPU Usage
                Div(
                    Div("🖥️", cls="text-2xl mb-2"),
                    Div(f"{cpu_usage:.1f}%", cls="text-2xl font-bold text-indigo-600"),
                    P("CPU Usage", cls="text-sm text-gray-600"),
                    cls="bg-white p-4 rounded-lg shadow text-center"
                ),
                
                cls="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-6"
            )
        )
    
    def _render_performance_charts(self) -> Div:
        """Render performance charts placeholder"""
        
        return Div(
            H2("📈 Performance Trends", cls="text-xl font-semibold mb-4"),
            Div(
                Div(
                    H3("Request Volume", cls="font-medium mb-2"),
                    Div(
                        P("Real-time charts would be rendered here", cls="text-gray-500 text-center py-8"),
                        P("Integration with Chart.js or similar library", cls="text-sm text-gray-400 text-center"),
                        cls="bg-gray-50 rounded border-2 border-dashed border-gray-300"
                    ),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                Div(
                    H3("Response Times", cls="font-medium mb-2"),
                    Div(
                        P("Response time trends over time", cls="text-gray-500 text-center py-8"),
                        P("Histogram and percentile data", cls="text-sm text-gray-400 text-center"),
                        cls="bg-gray-50 rounded border-2 border-dashed border-gray-300"
                    ),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                cls="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6"
            )
        )
    
    def _render_alert_statistics(self, alert_stats: Dict[str, Any]) -> Div:
        """Render alert statistics"""
        
        return Div(
            H2("🚨 Alert Statistics", cls="text-xl font-semibold mb-4"),
            Div(
                Div(
                    H3("Overview", cls="font-medium mb-3"),
                    Div(
                        Div(
                            Span("Active Alerts:", cls="font-medium"),
                            Span(str(alert_stats['active_alerts']), cls="ml-2 text-red-600 font-bold"),
                            cls="flex justify-between"
                        ),
                        Div(
                            Span("Total Alerts (24h):", cls="font-medium"),
                            Span(str(alert_stats['recent_alerts_24h']), cls="ml-2 text-blue-600 font-bold"),
                            cls="flex justify-between"
                        ),
                        Div(
                            Span("Alert Rules:", cls="font-medium"),
                            Span(f"{alert_stats['rules_enabled']}/{alert_stats['rules_total']}", cls="ml-2 text-green-600 font-bold"),
                            cls="flex justify-between"
                        ),
                        cls="space-y-2"
                    ),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                Div(
                    H3("Severity Breakdown", cls="font-medium mb-3"),
                    Div(
                        *[
                            Div(
                                Span(severity.title() + ":", cls="font-medium"),
                                Span(
                                    str(count),
                                    cls=f"ml-2 font-bold {self._get_severity_text_color(severity)}"
                                ),
                                cls="flex justify-between"
                            )
                            for severity, count in alert_stats['severity_breakdown'].items()
                        ],
                        cls="space-y-2"
                    ),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                cls="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6"
            )
        )
    
    def _render_system_resources(self, health_status: Dict[str, Any]) -> Div:
        """Render system resources"""
        
        # Extract resource data from health checks
        memory_data = health_status['checks'].get('memory', {}).get('details', {})
        disk_data = health_status['checks'].get('disk_space', {}).get('details', {})
        cpu_data = health_status['checks'].get('cpu', {}).get('details', {})
        
        return Div(
            H2("🖥️ System Resources", cls="text-xl font-semibold mb-4"),
            Div(
                # Memory
                Div(
                    H3("Memory Usage", cls="font-medium mb-3"),
                    Div(
                        Div(
                            f"{memory_data.get('percent_used', 0):.1f}%",
                            cls="text-lg font-bold"
                        ),
                        Div(
                            f"Used: {memory_data.get('used_gb', 0):.1f}GB / {memory_data.get('total_gb', 0):.1f}GB",
                            cls="text-sm text-gray-600"
                        ),
                        cls="mb-2"
                    ),
                    Div(
                        Div(
                            style=f"width: {memory_data.get('percent_used', 0)}%",
                            cls="bg-blue-500 h-2 rounded"
                        ),
                        cls="w-full bg-gray-200 rounded h-2"
                    ),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                # Disk Space
                Div(
                    H3("Disk Usage", cls="font-medium mb-3"),
                    Div(
                        Div(
                            f"{disk_data.get('percent_used', 0):.1f}%",
                            cls="text-lg font-bold"
                        ),
                        Div(
                            f"Used: {disk_data.get('used_gb', 0):.1f}GB / {disk_data.get('total_gb', 0):.1f}GB",
                            cls="text-sm text-gray-600"
                        ),
                        cls="mb-2"
                    ),
                    Div(
                        Div(
                            style=f"width: {disk_data.get('percent_used', 0)}%",
                            cls="bg-green-500 h-2 rounded"
                        ),
                        cls="w-full bg-gray-200 rounded h-2"
                    ),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                # CPU Usage
                Div(
                    H3("CPU Usage", cls="font-medium mb-3"),
                    Div(
                        Div(
                            f"{cpu_data.get('cpu_percent', 0):.1f}%",
                            cls="text-lg font-bold"
                        ),
                        Div(
                            f"Cores: {cpu_data.get('cpu_count', 'N/A')}",
                            cls="text-sm text-gray-600"
                        ),
                        cls="mb-2"
                    ),
                    Div(
                        Div(
                            style=f"width: {cpu_data.get('cpu_percent', 0)}%",
                            cls="bg-red-500 h-2 rounded"
                        ),
                        cls="w-full bg-gray-200 rounded h-2"
                    ),
                    cls="bg-white p-4 rounded-lg shadow"
                ),
                
                cls="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6"
            )
        )
    
    def _get_status_color(self, status: str) -> str:
        """Get CSS classes for status color"""
        colors = {
            'healthy': 'bg-green-100 text-green-800',
            'warning': 'bg-yellow-100 text-yellow-800',
            'critical': 'bg-red-100 text-red-800',
            'unknown': 'bg-gray-100 text-gray-800'
        }
        return colors.get(status, 'bg-gray-100 text-gray-800')
    
    def _get_alert_color(self, severity: str) -> str:
        """Get CSS classes for alert severity color"""
        colors = {
            'info': 'bg-blue-100 text-blue-800',
            'warning': 'bg-yellow-100 text-yellow-800',
            'critical': 'bg-red-100 text-red-800'
        }
        return colors.get(severity, 'bg-gray-100 text-gray-800')
    
    def _get_alert_border_color(self, severity: str) -> str:
        """Get CSS classes for alert border color"""
        colors = {
            'info': 'border-blue-500',
            'warning': 'border-yellow-500',
            'critical': 'border-red-500'
        }
        return colors.get(severity, 'border-gray-500')
    
    def _get_severity_text_color(self, severity: str) -> str:
        """Get text color for severity"""
        colors = {
            'info': 'text-blue-600',
            'warning': 'text-yellow-600',
            'critical': 'text-red-600'
        }
        return colors.get(severity, 'text-gray-600')
    
    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format"""
        return self.metrics.get_prometheus_format()
    
    def get_health_check_json(self) -> Dict[str, Any]:
        """Get health status as JSON"""
        return self.health.get_health_status()
    
    def get_metrics_json(self) -> Dict[str, Any]:
        """Get metrics summary as JSON"""
        return self.metrics.get_metrics_summary()


def create_grafana_dashboard_config() -> Dict[str, Any]:
    """Create Grafana dashboard configuration"""
    
    return {
        "dashboard": {
            "id": None,
            "title": "PY-Framework Monitoring",
            "tags": ["py-framework", "monitoring"],
            "timezone": "browser",
            "panels": [
                {
                    "id": 1,
                    "title": "HTTP Requests Rate",
                    "type": "stat",
                    "targets": [
                        {
                            "expr": "rate(http_requests_total[5m])",
                            "legendFormat": "Requests/sec"
                        }
                    ],
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
                },
                {
                    "id": 2,
                    "title": "HTTP Error Rate",
                    "type": "stat",
                    "targets": [
                        {
                            "expr": "rate(http_errors_total[5m]) / rate(http_requests_total[5m])",
                            "legendFormat": "Error Rate"
                        }
                    ],
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
                },
                {
                    "id": 3,
                    "title": "Response Time",
                    "type": "graph",
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.95, http_request_duration_seconds_bucket)",
                            "legendFormat": "95th percentile"
                        },
                        {
                            "expr": "histogram_quantile(0.50, http_request_duration_seconds_bucket)",
                            "legendFormat": "Median"
                        }
                    ],
                    "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
                },
                {
                    "id": 4,
                    "title": "System Resources",
                    "type": "graph",
                    "targets": [
                        {
                            "expr": "memory_usage_bytes / 1024^3",
                            "legendFormat": "Memory (GB)"
                        },
                        {
                            "expr": "cpu_usage_percent",
                            "legendFormat": "CPU %"
                        }
                    ],
                    "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16}
                }
            ],
            "time": {
                "from": "now-1h",
                "to": "now"
            },
            "refresh": "5s"
        }
    }