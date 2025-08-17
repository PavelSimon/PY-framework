"""
Monitoring Routes for PY-Framework
Provides monitoring endpoints for metrics, health checks, and dashboards
"""

from fasthtml.common import *
from datetime import datetime
from ..monitoring import (
    get_metrics_collector,
    get_health_checker, 
    get_alert_manager,
    MonitoringDashboard
)
from ..session import get_current_user


def create_monitoring_routes(app, db, auth_service, csrf_protection):
    """Create monitoring-related routes"""
    
    # Initialize monitoring dashboard
    dashboard = MonitoringDashboard()
    
    @app.get("/admin/monitoring")
    def monitoring_dashboard(request):
        """Main monitoring dashboard"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return RedirectResponse("/auth/login")
        
        # Render dashboard
        dashboard_content = dashboard.render_dashboard()
        
        from ..layout import create_layout
        return create_layout(
            title="System Monitoring",
            content=dashboard_content,
            current_user=user,
            active_page="monitoring"
        )
    
    @app.get("/api/metrics")
    def metrics_endpoint():
        """Prometheus metrics endpoint"""
        metrics = get_metrics_collector()
        prometheus_data = metrics.get_prometheus_format()
        
        return Response(
            content=prometheus_data,
            media_type="text/plain",
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.get("/api/health")
    def health_endpoint():
        """Health check endpoint (JSON)"""
        health = get_health_checker()
        health_data = health.get_health_status()
        
        # Set appropriate status code based on health
        status_code = 200
        if health_data['status'] in ['critical', 'unknown']:
            status_code = 503  # Service Unavailable
        elif health_data['status'] == 'warning':
            status_code = 200  # OK but with warnings
        
        return Response(
            content=health_data,
            media_type="application/json",
            status_code=status_code,
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.get("/api/health/{check_name}")
    def individual_health_check(check_name: str):
        """Individual health check endpoint"""
        health = get_health_checker()
        check_result = health.get_check_result(check_name)
        
        if not check_result:
            return Response(
                content={"error": f"Health check '{check_name}' not found"},
                media_type="application/json",
                status_code=404
            )
        
        status_code = 200
        if check_result['status'] in ['critical', 'unknown']:
            status_code = 503
        
        return Response(
            content=check_result,
            media_type="application/json", 
            status_code=status_code,
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.post("/api/health/{check_name}/run")
    def run_health_check(check_name: str, request):
        """Run a specific health check immediately"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return Response("Access denied", status_code=403)
        
        health = get_health_checker()
        result = health.run_check_now(check_name)
        
        if not result:
            return Response(
                content={"error": f"Health check '{check_name}' not found"},
                media_type="application/json",
                status_code=404
            )
        
        return Response(
            content={
                "name": result.name,
                "status": result.status.value,
                "message": result.message,
                "details": result.details,
                "timestamp": result.timestamp.isoformat(),
                "duration_ms": result.duration_ms
            },
            media_type="application/json"
        )
    
    @app.get("/api/alerts")
    def alerts_endpoint(request):
        """Get active alerts"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return Response("Access denied", status_code=403)
        
        alerts = get_alert_manager()
        active_alerts = alerts.get_active_alerts()
        
        return Response(
            content={"alerts": active_alerts},
            media_type="application/json",
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.get("/api/alerts/history")
    def alerts_history(request, limit: int = 100):
        """Get alert history"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return Response("Access denied", status_code=403)
        
        alerts = get_alert_manager()
        alert_history = alerts.get_alert_history(limit)
        
        return Response(
            content={"alerts": alert_history},
            media_type="application/json",
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.get("/api/alerts/stats")
    def alerts_statistics(request):
        """Get alert statistics"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return Response("Access denied", status_code=403)
        
        alerts = get_alert_manager()
        stats = alerts.get_alert_statistics()
        
        return Response(
            content=stats,
            media_type="application/json",
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.get("/api/metrics/summary")
    def metrics_summary(request):
        """Get metrics summary"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return Response("Access denied", status_code=403)
        
        metrics = get_metrics_collector()
        summary = metrics.get_metrics_summary()
        
        return Response(
            content=summary,
            media_type="application/json",
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.get("/api/metrics/performance")
    def performance_insights(request):
        """Get performance insights and recommendations"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return Response("Access denied", status_code=403)
        
        metrics = get_metrics_collector()
        insights = metrics.get_performance_insights()
        
        return Response(
            content=insights,
            media_type="application/json",
            headers={"Cache-Control": "no-cache"}
        )
    
    @app.get("/admin/monitoring/grafana")
    def grafana_dashboard_config(request):
        """Get Grafana dashboard configuration"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return RedirectResponse("/auth/login")
        
        from ..monitoring.dashboard import create_grafana_dashboard_config
        config = create_grafana_dashboard_config()
        
        return Response(
            content=config,
            media_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=py-framework-dashboard.json",
                "Cache-Control": "no-cache"
            }
        )
    
    @app.get("/admin/monitoring/export")
    def export_monitoring_data(request):
        """Export monitoring data for analysis"""
        
        # Get current user using the standard pattern
        user = get_current_user(request, db, auth_service)
        
        if not user or user.get('role_id') != 0:
            return RedirectResponse("/auth/login")
        
        # Collect all monitoring data
        metrics = get_metrics_collector()
        health = get_health_checker()
        alerts = get_alert_manager()
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "metrics_summary": metrics.get_metrics_summary(),
            "performance_insights": metrics.get_performance_insights(),
            "health_status": health.get_health_status(), 
            "active_alerts": alerts.get_active_alerts(),
            "alert_history": alerts.get_alert_history(1000),
            "alert_statistics": alerts.get_alert_statistics()
        }
        
        import json
        json_data = json.dumps(export_data, indent=2, default=str)
        
        return Response(
            content=json_data,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=monitoring-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
                "Cache-Control": "no-cache"
            }
        )
    
    print("SUCCESS: Monitoring routes registered")
    print("  - /admin/monitoring - Main monitoring dashboard")  
    print("  - /api/metrics - Prometheus metrics endpoint")
    print("  - /api/health - Health check endpoint")
    print("  - /api/alerts - Active alerts API")
    print("  - /admin/monitoring/grafana - Grafana dashboard config")
    print("  - /admin/monitoring/export - Data export")