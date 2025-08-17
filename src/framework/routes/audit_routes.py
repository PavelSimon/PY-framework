from fasthtml.common import *
from typing import Optional
from ..layout import create_app_layout
from ..session import get_current_user
from ..audit import get_audit_service, AuditEventType
from ..database.database import Database


def create_audit_routes(app, db: Database, auth_service=None):
    """Create audit and monitoring routes"""
    
    def get_admin_sidebar_items():
        """Get sidebar items for admin users"""
        return [
            {"title": "Main", "items": [
                {"name": "Dashboard", "url": "/dashboard", "icon": "📊"},
                {"name": "Users", "url": "/users", "icon": "👥"},
                {"name": "Settings", "url": "/settings", "icon": "⚙️"},
            ]},
            {"title": "Administration", "items": [
                {"name": "Audit Dashboard", "url": "/admin/audit", "icon": "🔒"},
                {"name": "User Activity", "url": "/admin/audit/users", "icon": "👥"},
                {"name": "System Stats", "url": "/admin/audit/stats", "icon": "📊"},
            ]},
            {"title": "Development", "items": [
                {"name": "Test Email", "url": "/dev/test-email", "icon": "📧"},
                {"name": "Test Auth", "url": "/dev/test-auth", "icon": "🔐"},
                {"name": "Database", "url": "/dev/database", "icon": "🗄️"},
            ]}
        ]
    
    @app.get("/admin/audit")
    def audit_dashboard(request):
        """Admin audit dashboard with security monitoring"""
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            access_denied_content = Div(
                H1("Access Denied"),
                P("This page is only available to administrators."),
                cls="access-denied"
            )
            return create_app_layout(
                content=access_denied_content,
                title="Access Denied",
                user=user
            )
        
        try:
            audit_service = get_audit_service(db)
            
            # Get recent security events
            security_events = audit_service.get_security_events(hours=24, limit=20)
            
            # Get login statistics
            login_stats = audit_service.get_login_statistics(days=30)
            
            # Security events table
            security_rows = []
            for event in security_events:
                # Format timestamp properly - handle both string and datetime objects
                timestamp = event['timestamp']
                if timestamp:
                    if isinstance(timestamp, str):
                        formatted_timestamp = timestamp[:19]
                    else:
                        # Handle datetime object
                        formatted_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    formatted_timestamp = 'N/A'
                
                security_rows.append(
                    Tr(
                        Td(formatted_timestamp),
                        Td(event['event_type'].replace('_', ' ').title()),
                        Td(event['user_id'] if event['user_id'] else 'Anonymous'),
                        Td(event['ip_address'] if event['ip_address'] else 'N/A'),
                        Td(event['user_agent'][:50] + '...' if event.get('user_agent') and len(event['user_agent']) > 50 else event.get('user_agent', 'N/A'))
                    )
                )
            
            security_table = Table(
                Thead(
                    Tr(
                        Th("Timestamp"),
                        Th("Event Type"),
                        Th("User ID"),
                        Th("IP Address"),
                        Th("User Agent")
                    )
                ),
                Tbody(*security_rows) if security_rows else Tbody(Tr(Td("No security events in the last 24 hours", colspan="5"))),
                cls="table table-striped"
            )
            
            # Statistics cards
            stats_cards = Div(
                Div(
                    Div(
                        H4("Login Statistics (30 days)", cls="card-title"),
                        P(f"Successful Logins: {login_stats.get('successful_logins', 0)}", cls="card-text"),
                        P(f"Failed Logins: {login_stats.get('failed_logins', 0)}", cls="card-text"),
                        P(f"Unique Users: {login_stats.get('unique_users', 0)}", cls="card-text"),
                        P(f"OAuth Logins: {login_stats.get('oauth_logins', 0)}", cls="card-text"),
                        P(f"Success Rate: {login_stats.get('success_rate', 0):.1f}%", cls="card-text"),
                        cls="card-body"
                    ),
                    cls="card mb-4"
                ),
                cls="col-md-6"
            )
            
            dashboard_content = Div(
                H1("🔒 Security Audit Dashboard"),
                P("Monitor security events and system activity", cls="lead"),
                
                Div(
                    stats_cards,
                    cls="row mb-4"
                ),
                
                H3("🚨 Recent Security Events (24 hours)"),
                Div(security_table, cls="table-responsive"),
                
                H3("📊 Quick Actions"),
                Div(
                    A("View User Activity", href="/admin/audit/users", cls="btn btn-primary me-2"),
                    A("Export Audit Log", href="/admin/audit/export", cls="btn btn-secondary me-2"),
                    A("System Statistics", href="/admin/audit/stats", cls="btn btn-info"),
                    cls="mb-4"
                ),
                cls="audit-dashboard"
            )
            
            return create_app_layout(
                content=dashboard_content,
                title="Security Audit Dashboard",
                user=user,
                sidebar_items=get_admin_sidebar_items(),
                current_page="/admin/audit"
            )
            
        except Exception as e:
            error_content = Div(
                H1("Audit Dashboard Error"),
                P(f"Error loading audit dashboard: {str(e)}"),
                cls="error-page"
            )
            return create_app_layout(
                content=error_content,
                title="Error",
                user=user
            )
    
    @app.get("/admin/audit/users")
    def audit_users(request, user_id: Optional[int] = None, limit: int = 50):
        """User activity audit page"""
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            access_denied_content = Div(
                H1("Access Denied"),
                P("This page is only available to administrators."),
                cls="access-denied"
            )
            return create_app_layout(
                content=access_denied_content,
                title="Access Denied",
                user=user
            )
        
        try:
            audit_service = get_audit_service(db)
            
            # Get all users for dropdown
            all_users = db.get_all_users_with_roles()
            
            user_options = [Option("Select a user...", value="")]
            for db_user in all_users:
                selected = "selected" if user_id == db_user['id'] else ""
                user_options.append(
                    Option(f"{db_user['email']} (ID: {db_user['id']})", value=str(db_user['id']), selected=selected)
                )
            
            # User selection form
            user_form = Form(
                Div(
                    Label("Select User:", For="user_id"),
                    Select(*user_options, name="user_id", id="user_id", cls="form-select"),
                    cls="mb-3"
                ),
                Div(
                    Label("Limit:", For="limit"),
                    Input(value=str(limit), name="limit", type="number", min="10", max="500", cls="form-control"),
                    cls="mb-3"
                ),
                Button("View Activity", type="submit", cls="btn btn-primary"),
                method="get",
                action="/admin/audit/users"
            )
            
            content = [
                H1("👥 User Activity Audit"),
                P("Monitor user activity and authentication events", cls="lead"),
                user_form,
                Hr()
            ]
            
            if user_id:
                # Get user activity
                activity = audit_service.get_user_activity(user_id=user_id, limit=limit)
                
                if activity:
                    activity_rows = []
                    for event in activity:
                        # Format timestamp properly - handle both string and datetime objects
                        timestamp = event['timestamp']
                        if timestamp:
                            if isinstance(timestamp, str):
                                formatted_timestamp = timestamp[:19]
                            else:
                                # Handle datetime object
                                formatted_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            formatted_timestamp = 'N/A'
                        
                        activity_rows.append(
                            Tr(
                                Td(formatted_timestamp),
                                Td(event['event_type'].replace('_', ' ').title()),
                                Td("✅" if event['success'] else "❌"),
                                Td(event['ip_address'] if event['ip_address'] else 'N/A'),
                                Td(event['user_agent'][:50] + '...' if event.get('user_agent') and len(event['user_agent']) > 50 else event.get('user_agent', 'N/A'))
                            )
                        )
                    
                    activity_table = Table(
                        Thead(
                            Tr(
                                Th("Timestamp"),
                                Th("Event Type"),
                                Th("Success"),
                                Th("IP Address"),
                                Th("User Agent")
                            )
                        ),
                        Tbody(*activity_rows),
                        cls="table table-striped"
                    )
                    
                    content.append(H3(f"Activity for User ID {user_id}"))
                    content.append(Div(activity_table, cls="table-responsive"))
                else:
                    content.append(P("No activity found for this user."))
            
            main_content = Div(*content, cls="audit-users-page")
            return create_app_layout(
                content=main_content,
                title="User Activity Audit", 
                user=user, 
                sidebar_items=get_admin_sidebar_items(), 
                current_page="/admin/audit/users"
            )
            
        except Exception as e:
            error_content = Div(
                H1("User Audit Error"),
                P(f"Error loading user activity: {str(e)}"),
                cls="error-page"
            )
            return create_app_layout(
                content=error_content,
                title="Error",
                user=user
            )
    
    @app.get("/admin/audit/stats")
    def audit_statistics(request, days: int = 30):
        """System audit statistics"""
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            access_denied_content = Div(
                H1("Access Denied"),
                P("This page is only available to administrators."),
                cls="access-denied"
            )
            return create_app_layout(
                content=access_denied_content,
                title="Access Denied",
                user=user
            )
        
        try:
            audit_service = get_audit_service(db)
            
            # Period selection form
            period_form = Form(
                Div(
                    Label("Statistics Period (days):", For="days"),
                    Select(
                        Option("7 days", value="7", selected="selected" if days == 7 else ""),
                        Option("30 days", value="30", selected="selected" if days == 30 else ""),
                        Option("90 days", value="90", selected="selected" if days == 90 else ""),
                        name="days", id="days", cls="form-select"
                    ),
                    cls="mb-3 d-inline-block me-3"
                ),
                Button("Update", type="submit", cls="btn btn-primary"),
                method="get",
                action="/admin/audit/stats",
                cls="mb-4"
            )
            
            # Get statistics
            login_stats = audit_service.get_login_statistics(days=days)
            security_events = audit_service.get_security_events(hours=days*24, limit=1000)
            
            # Security event counts by type
            event_counts = {}
            for event in security_events:
                event_type = event['event_type']
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            # Statistics cards
            stats_grid = Div(
                Div(
                    Div(
                        H5("Authentication", cls="card-title"),
                        P(f"Successful Logins: {login_stats.get('successful_logins', 0)}"),
                        P(f"Failed Logins: {login_stats.get('failed_logins', 0)}"),
                        P(f"Success Rate: {login_stats.get('success_rate', 0):.1f}%"),
                        cls="card-body"
                    ),
                    cls="card"
                ),
                cls="col-md-4 mb-3"
            )
            
            stats_content = Div(
                H1("📊 System Statistics"),
                P(f"Security and activity statistics for the last {days} days", cls="lead"),
                period_form,
                
                Div(
                    stats_grid,
                    cls="row"
                ),
                
                H3("Security Event Summary"),
                Ul(*[Li(f"{event_type.replace('_', ' ').title()}: {count}") for event_type, count in event_counts.items()]) if event_counts else P("No security events recorded."),
                cls="audit-statistics"
            )
            
            return create_app_layout(
                content=stats_content,
                title="System Statistics",
                user=user,
                sidebar_items=get_admin_sidebar_items(),
                current_page="/admin/audit/stats"
            )
            
        except Exception as e:
            error_content = Div(
                H1("Statistics Error"),
                P(f"Error loading statistics: {str(e)}"),
                cls="error-page"
            )
            return create_app_layout(
                content=error_content,
                title="Error",
                user=user
            )
    
    @app.get("/admin/audit/export")
    def export_audit_log(request, days: int = 30, format: str = "csv"):
        """Export audit log data"""
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            return Response("Access denied", status_code=403)
        
        # For now, return a simple response indicating this feature is coming soon
        export_content = Div(
            H1("🔽 Export Audit Log"),
            P("Export functionality is coming soon.", cls="lead"),
            P("This feature will allow you to export audit logs in various formats (CSV, JSON) for external analysis."),
            A("Back to Audit Dashboard", href="/admin/audit", cls="btn btn-primary"),
            cls="audit-export"
        )
        
        return create_app_layout(
            content=export_content,
            title="Export Audit Log",
            user=user,
            sidebar_items=get_admin_sidebar_items(),
            current_page="/admin/audit/export"
        )