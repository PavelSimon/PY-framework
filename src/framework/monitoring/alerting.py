"""
Alerting System for PY-Framework
Provides intelligent alerting based on metrics and health checks
"""

import time
import json
import threading
import smtplib
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
try:
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
except ImportError:
    # Fallback for systems where email modules might not be available
    MimeText = None
    MimeMultipart = None


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status"""
    ACTIVE = "active"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


@dataclass
class AlertRule:
    """Alert rule definition"""
    name: str
    description: str
    condition: Callable[[], bool]
    severity: AlertSeverity
    cooldown_minutes: int = 5
    auto_resolve: bool = True
    enabled: bool = True
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class Alert:
    """Alert instance"""
    id: str
    rule_name: str
    severity: AlertSeverity
    status: AlertStatus
    message: str
    details: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class AlertChannel:
    """Alert notification channel"""
    name: str
    channel_type: str  # email, webhook, slack
    config: Dict[str, Any]
    enabled: bool = True
    severity_filter: List[AlertSeverity] = field(default_factory=lambda: [AlertSeverity.WARNING, AlertSeverity.CRITICAL])


class AlertManager:
    """Comprehensive alerting and notification system"""
    
    def __init__(self):
        self._rules: Dict[str, AlertRule] = {}
        self._active_alerts: Dict[str, Alert] = {}
        self._alert_history: List[Alert] = []
        self._channels: Dict[str, AlertChannel] = {}
        self._lock = threading.RLock()
        self._alert_counter = 0
        
        # Monitoring thread
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        
        # Register default alert rules
        self._register_default_rules()
        
        # Register default notification channels
        self._register_default_channels()
        
        # Start monitoring
        self.start_monitoring()
    
    def _register_default_rules(self):
        """Register default alerting rules"""
        
        # High error rate alert
        self.register_rule(
            "high_error_rate",
            "High HTTP error rate detected",
            self._check_error_rate,
            AlertSeverity.CRITICAL,
            cooldown_minutes=5
        )
        
        # Slow response time alert
        self.register_rule(
            "slow_response_time",
            "Application response time is slow",
            self._check_response_time,
            AlertSeverity.WARNING,
            cooldown_minutes=10
        )
        
        # High memory usage alert
        self.register_rule(
            "high_memory_usage",
            "High memory usage detected",
            self._check_memory_usage,
            AlertSeverity.WARNING,
            cooldown_minutes=15
        )
        
        # Database connectivity alert
        self.register_rule(
            "database_connectivity",
            "Database connectivity issues",
            self._check_database_connectivity,
            AlertSeverity.CRITICAL,
            cooldown_minutes=2
        )
        
        # Failed login attempts alert
        self.register_rule(
            "failed_login_spike",
            "High number of failed login attempts",
            self._check_failed_logins,
            AlertSeverity.WARNING,
            cooldown_minutes=30
        )
        
        # Disk space alert
        self.register_rule(
            "low_disk_space",
            "Low disk space warning",
            self._check_disk_space,
            AlertSeverity.WARNING,
            cooldown_minutes=60
        )
    
    def _register_default_channels(self):
        """Register default notification channels"""
        
        # Email channel (if configured)
        import os
        smtp_server = os.getenv('SMTP_SERVER')
        smtp_username = os.getenv('SMTP_USERNAME')
        
        if smtp_server and smtp_username:
            self.register_channel(
                "email",
                "email",
                {
                    "smtp_server": smtp_server,
                    "smtp_port": int(os.getenv('SMTP_PORT', '587')),
                    "smtp_username": smtp_username,
                    "smtp_password": os.getenv('SMTP_PASSWORD', ''),
                    "from_email": os.getenv('FROM_EMAIL', smtp_username),
                    "to_emails": [smtp_username]  # Default to sending to self
                }
            )
        
        # Console/log channel
        self.register_channel(
            "console",
            "console",
            {},
            severity_filter=[AlertSeverity.WARNING, AlertSeverity.CRITICAL]
        )
    
    def register_rule(self, name: str, description: str, condition: Callable[[], bool],
                     severity: AlertSeverity, cooldown_minutes: int = 5, auto_resolve: bool = True,
                     enabled: bool = True, tags: Dict[str, str] = None):
        """Register a new alert rule"""
        with self._lock:
            self._rules[name] = AlertRule(
                name=name,
                description=description,
                condition=condition,
                severity=severity,
                cooldown_minutes=cooldown_minutes,
                auto_resolve=auto_resolve,
                enabled=enabled,
                tags=tags or {}
            )
    
    def register_channel(self, name: str, channel_type: str, config: Dict[str, Any],
                        enabled: bool = True, severity_filter: List[AlertSeverity] = None):
        """Register a new notification channel"""
        with self._lock:
            self._channels[name] = AlertChannel(
                name=name,
                channel_type=channel_type,
                config=config,
                enabled=enabled,
                severity_filter=severity_filter or [AlertSeverity.WARNING, AlertSeverity.CRITICAL]
            )
    
    def start_monitoring(self):
        """Start alert monitoring"""
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_monitoring.clear()
            self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self._monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop alert monitoring"""
        self._stop_monitoring.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
    
    def _monitoring_loop(self):
        """Main alert monitoring loop"""
        last_check_times = {}
        
        while not self._stop_monitoring.is_set():
            current_time = time.time()
            
            # Create a copy of rules to avoid dictionary changed during iteration
            with self._lock:
                rules_copy = dict(self._rules)
            
            for rule_name, rule in rules_copy.items():
                if not rule.enabled:
                    continue
                
                # Check cooldown
                last_check = last_check_times.get(rule_name, 0)
                if current_time - last_check < 30:  # Check every 30 seconds minimum
                    continue
                
                try:
                    # Check if rule condition is met
                    if rule.condition():
                        self._handle_alert_triggered(rule)
                    elif rule.auto_resolve:
                        self._handle_alert_resolved(rule)
                    
                    last_check_times[rule_name] = current_time
                    
                except Exception as e:
                    print(f"Error checking alert rule '{rule_name}': {e}")
            
            time.sleep(10)  # Check every 10 seconds
    
    def _handle_alert_triggered(self, rule: AlertRule):
        """Handle when an alert rule is triggered"""
        alert_id = f"{rule.name}_{int(time.time())}"
        
        # Check if we already have an active alert for this rule
        existing_alert = None
        for alert in self._active_alerts.values():
            if alert.rule_name == rule.name and alert.status == AlertStatus.ACTIVE:
                existing_alert = alert
                break
        
        if existing_alert:
            # Check cooldown
            time_since_last = (datetime.now() - existing_alert.updated_at).total_seconds()
            if time_since_last < rule.cooldown_minutes * 60:
                return  # Still in cooldown
            
            # Update existing alert
            existing_alert.updated_at = datetime.now()
        else:
            # Create new alert
            with self._lock:
                self._alert_counter += 1
                alert_id = f"{rule.name}_{self._alert_counter}"
                
                alert = Alert(
                    id=alert_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    status=AlertStatus.ACTIVE,
                    message=rule.description,
                    details=self._get_alert_details(rule),
                    created_at=datetime.now(),
                    updated_at=datetime.now(),
                    tags=rule.tags
                )
                
                self._active_alerts[alert_id] = alert
                self._alert_history.append(alert)
            
            # Send notifications
            self._send_notifications(alert)
    
    def _handle_alert_resolved(self, rule: AlertRule):
        """Handle when an alert rule is resolved"""
        # Find active alert for this rule
        alert_to_resolve = None
        for alert in self._active_alerts.values():
            if alert.rule_name == rule.name and alert.status == AlertStatus.ACTIVE:
                alert_to_resolve = alert
                break
        
        if alert_to_resolve:
            with self._lock:
                alert_to_resolve.status = AlertStatus.RESOLVED
                alert_to_resolve.resolved_at = datetime.now()
                alert_to_resolve.updated_at = datetime.now()
                
                # Remove from active alerts
                if alert_to_resolve.id in self._active_alerts:
                    del self._active_alerts[alert_to_resolve.id]
            
            # Send resolution notification
            self._send_resolution_notification(alert_to_resolve)
    
    def _get_alert_details(self, rule: AlertRule) -> Dict[str, Any]:
        """Get additional details for an alert"""
        details = {
            "rule_name": rule.name,
            "timestamp": datetime.now().isoformat(),
            "server_time": time.time()
        }
        
        # Add specific details based on rule type
        try:
            from .metrics_collector import get_metrics_collector
            from .health_checker import get_health_checker
            
            metrics = get_metrics_collector()
            health = get_health_checker()
            
            # Add relevant metrics
            if rule.name == "high_error_rate":
                summary = metrics.get_metrics_summary()
                if 'http_errors_total' in summary:
                    details['current_error_count'] = summary['http_errors_total']['value']
                if 'http_requests_total' in summary:
                    details['current_request_count'] = summary['http_requests_total']['value']
            
            elif rule.name == "slow_response_time":
                summary = metrics.get_metrics_summary()
                if 'http_request_duration_seconds' in summary:
                    details['current_avg_duration'] = summary['http_request_duration_seconds']['value']
            
            elif rule.name == "high_memory_usage":
                summary = metrics.get_metrics_summary()
                if 'memory_usage_bytes' in summary:
                    details['current_memory_bytes'] = summary['memory_usage_bytes']['value']
                    details['current_memory_gb'] = summary['memory_usage_bytes']['value'] / (1024**3)
            
            # Add health check status
            health_status = health.get_health_status()
            details['overall_health'] = health_status['status']
            
        except Exception as e:
            details['error_getting_details'] = str(e)
        
        return details
    
    def _send_notifications(self, alert: Alert):
        """Send alert notifications to configured channels"""
        for channel_name, channel in self._channels.items():
            if not channel.enabled:
                continue
            
            if alert.severity not in channel.severity_filter:
                continue
            
            try:
                if channel.channel_type == "email":
                    self._send_email_notification(channel, alert)
                elif channel.channel_type == "console":
                    self._send_console_notification(channel, alert)
                elif channel.channel_type == "webhook":
                    self._send_webhook_notification(channel, alert)
                
            except Exception as e:
                print(f"Error sending notification via {channel_name}: {e}")
    
    def _send_resolution_notification(self, alert: Alert):
        """Send alert resolution notifications"""
        for channel_name, channel in self._channels.items():
            if not channel.enabled:
                continue
            
            if alert.severity not in channel.severity_filter:
                continue
            
            try:
                if channel.channel_type == "email":
                    self._send_email_resolution(channel, alert)
                elif channel.channel_type == "console":
                    self._send_console_resolution(channel, alert)
                
            except Exception as e:
                print(f"Error sending resolution notification via {channel_name}: {e}")
    
    def _send_email_notification(self, channel: AlertChannel, alert: Alert):
        """Send email notification"""
        if MimeText is None or MimeMultipart is None:
            print(f"Email notification skipped - email modules not available")
            return
            
        config = channel.config
        
        msg = MimeMultipart()
        msg['From'] = config['from_email']
        msg['To'] = ', '.join(config['to_emails'])
        msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.message}"
        
        body = f"""
Alert Triggered: {alert.message}

Severity: {alert.severity.value.upper()}
Rule: {alert.rule_name}
Time: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}
Alert ID: {alert.id}

Details:
{json.dumps(alert.details, indent=2)}

This is an automated alert from PY-Framework monitoring system.
        """
        
        msg.attach(MimeText(body, 'plain'))
        
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['smtp_username'], config['smtp_password'])
        server.send_message(msg)
        server.quit()
    
    def _send_email_resolution(self, channel: AlertChannel, alert: Alert):
        """Send email resolution notification"""
        if MimeText is None or MimeMultipart is None:
            print(f"Email resolution notification skipped - email modules not available")
            return
            
        config = channel.config
        
        msg = MimeMultipart()
        msg['From'] = config['from_email']
        msg['To'] = ', '.join(config['to_emails'])
        msg['Subject'] = f"[RESOLVED] {alert.message}"
        
        duration = ""
        if alert.resolved_at and alert.created_at:
            duration_seconds = (alert.resolved_at - alert.created_at).total_seconds()
            duration = f"Duration: {duration_seconds:.0f} seconds"
        
        body = f"""
Alert Resolved: {alert.message}

Severity: {alert.severity.value.upper()}
Rule: {alert.rule_name}
Created: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}
Resolved: {alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if alert.resolved_at else 'N/A'}
{duration}
Alert ID: {alert.id}

This alert has been automatically resolved.
        """
        
        msg.attach(MimeText(body, 'plain'))
        
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['smtp_username'], config['smtp_password'])
        server.send_message(msg)
        server.quit()
    
    def _send_console_notification(self, channel: AlertChannel, alert: Alert):
        """Send console notification"""
        timestamp = alert.created_at.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[ALERT {alert.severity.value.upper()}] {timestamp} - {alert.message}")
        print(f"  Rule: {alert.rule_name}")
        print(f"  ID: {alert.id}")
    
    def _send_console_resolution(self, channel: AlertChannel, alert: Alert):
        """Send console resolution notification"""
        timestamp = alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if alert.resolved_at else 'N/A'
        print(f"[RESOLVED] {timestamp} - {alert.message}")
        print(f"  Rule: {alert.rule_name}")
        print(f"  ID: {alert.id}")
    
    def _send_webhook_notification(self, channel: AlertChannel, alert: Alert):
        """Send webhook notification"""
        # Implementation for webhook notifications
        pass
    
    # Alert rule condition functions
    def _check_error_rate(self) -> bool:
        """Check if error rate is too high"""
        try:
            from .metrics_collector import get_metrics_collector
            
            metrics = get_metrics_collector()
            summary = metrics.get_metrics_summary()
            
            if 'http_errors_total' in summary and 'http_requests_total' in summary:
                errors = summary['http_errors_total']['value']
                requests = summary['http_requests_total']['value']
                
                if requests > 100:  # Only alert if we have significant traffic
                    error_rate = errors / requests
                    return error_rate > 0.05  # 5% error rate
            
            return False
        except:
            return False
    
    def _check_response_time(self) -> bool:
        """Check if response time is too slow"""
        try:
            from .metrics_collector import get_metrics_collector
            
            metrics = get_metrics_collector()
            db_stats = metrics.get_database_stats()
            
            if 'average_duration' in db_stats:
                return db_stats['average_duration'] > 1.0  # 1 second
            
            return False
        except:
            return False
    
    def _check_memory_usage(self) -> bool:
        """Check if memory usage is too high"""
        try:
            from .health_checker import get_health_checker
            
            health = get_health_checker()
            memory_check = health.get_check_result('memory')
            
            if memory_check and memory_check['details']:
                return memory_check['details'].get('percent_used', 0) > 85
            
            return False
        except:
            return False
    
    def _check_database_connectivity(self) -> bool:
        """Check database connectivity"""
        try:
            from .health_checker import get_health_checker
            
            health = get_health_checker()
            db_check = health.get_check_result('database')
            
            if db_check:
                return db_check['status'] in ['critical', 'unknown']
            
            return False
        except:
            return False
    
    def _check_failed_logins(self) -> bool:
        """Check for high number of failed logins"""
        try:
            from .metrics_collector import get_metrics_collector
            
            metrics = get_metrics_collector()
            summary = metrics.get_metrics_summary()
            
            if 'failed_logins_total' in summary:
                # This is a simple check - in practice you'd want to check rate over time
                failed_logins = summary['failed_logins_total']['value']
                return failed_logins > 50  # More than 50 failed logins total
            
            return False
        except:
            return False
    
    def _check_disk_space(self) -> bool:
        """Check disk space"""
        try:
            from .health_checker import get_health_checker
            
            health = get_health_checker()
            disk_check = health.get_check_result('disk_space')
            
            if disk_check and disk_check['details']:
                return disk_check['details'].get('percent_used', 0) > 85
            
            return False
        except:
            return False
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts"""
        with self._lock:
            return [
                {
                    "id": alert.id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "message": alert.message,
                    "details": alert.details,
                    "created_at": alert.created_at.isoformat(),
                    "updated_at": alert.updated_at.isoformat(),
                    "tags": alert.tags
                }
                for alert in self._active_alerts.values()
            ]
    
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alert history"""
        with self._lock:
            recent_alerts = self._alert_history[-limit:]
            return [
                {
                    "id": alert.id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "message": alert.message,
                    "created_at": alert.created_at.isoformat(),
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
                    "tags": alert.tags
                }
                for alert in recent_alerts
            ]
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alerting statistics"""
        with self._lock:
            total_alerts = len(self._alert_history)
            active_alerts = len(self._active_alerts)
            
            # Count by severity
            severity_counts = {"info": 0, "warning": 0, "critical": 0}
            for alert in self._alert_history:
                severity_counts[alert.severity.value] += 1
            
            # Recent alert rate (last 24 hours)
            cutoff = datetime.now() - timedelta(hours=24)
            recent_alerts = [a for a in self._alert_history if a.created_at > cutoff]
            
            return {
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "recent_alerts_24h": len(recent_alerts),
                "severity_breakdown": severity_counts,
                "rules_enabled": sum(1 for rule in self._rules.values() if rule.enabled),
                "rules_total": len(self._rules),
                "channels_enabled": sum(1 for channel in self._channels.values() if channel.enabled),
                "channels_total": len(self._channels)
            }


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None
_manager_lock = threading.Lock()


def get_alert_manager() -> AlertManager:
    """Get the global alert manager instance"""
    global _alert_manager
    
    if _alert_manager is None:
        with _manager_lock:
            if _alert_manager is None:
                _alert_manager = AlertManager()
    
    return _alert_manager