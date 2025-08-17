"""
Performance monitoring routes for PY-Framework
Provides performance metrics, optimization tools, and monitoring dashboard
"""

from fasthtml.common import *
from typing import Dict, Any, Optional
from datetime import datetime
from ..layout import create_app_layout
from ..session import get_current_user
from ..performance_config import get_performance_config
from ..performance import get_performance_stats
from ..database.optimized_database import OptimizedDatabase


def create_performance_routes(app, db, auth_service, csrf_protection=None):
    """Create performance monitoring routes"""
    
    @app.get("/admin/performance")
    def performance_dashboard(request):
        """Performance monitoring dashboard (admin only)"""
        user = get_current_user(request, db, auth_service)
        
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            return create_app_layout(
                H1("Access Denied"),
                P("This page is only available to administrators."),
                title="Access Denied",
                user=user
            )
        
        # Get performance statistics
        perf_config = get_performance_config()
        perf_stats = get_performance_stats()
        
        # Get database performance metrics if available
        db_metrics = {}
        if hasattr(db, 'get_performance_metrics'):
            db_metrics = db.get_performance_metrics()
        
        content = Div(
            H1("Performance Monitoring", cls="text-3xl font-bold mb-6"),
            
            # Performance Overview Cards
            Div(
                *_performance_overview_cards(perf_stats, db_metrics),
                cls="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
            ),
            
            # Performance Charts and Details
            Div(
                Div(
                    _cache_performance_panel(perf_stats.get('cache', {})),
                    cls="col-span-1"
                ),
                Div(
                    _query_performance_panel(perf_stats.get('queries', {}), db_metrics.get('slow_queries', [])),
                    cls="col-span-1"
                ),
                cls="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8"
            ),
            
            # Database Optimization Tools
            _optimization_tools_panel(),
            
            cls="max-w-7xl mx-auto px-4"
        )
        
        return create_app_layout(
            content=content,
            title="Performance Monitoring",
            user=user,
            current_page="/admin/performance"
        )
    
    @app.get("/admin/performance/api/stats")
    def performance_api_stats(request):
        """API endpoint for performance statistics"""
        user = get_current_user(request, db, auth_service)
        if not user:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            return JSONResponse({"error": "Access denied"}, status_code=403)
        
        perf_stats = get_performance_stats()
        
        # Get database metrics if available
        db_metrics = {}
        if hasattr(db, 'get_performance_metrics'):
            db_metrics = db.get_performance_metrics()
        
        return JSONResponse({
            "timestamp": datetime.now().isoformat(),
            "performance": perf_stats,
            "database": db_metrics
        })
    
    @app.post("/admin/performance/optimize")
    def optimize_database(request):
        """Run database optimization tasks"""
        user = get_current_user(request, db, auth_service)
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            return JSONResponse({"error": "Access denied"}, status_code=403)
        
        # Verify CSRF token
        if csrf_protection:
            csrf_protection.validate_token(request)
        
        result = {"success": False, "message": "Optimization not available"}
        
        if hasattr(db, 'optimize_database'):
            result = db.optimize_database()
        
        # Return JSON for AJAX requests
        if request.headers.get("content-type") == "application/json":
            return JSONResponse(result)
        
        # Redirect back to dashboard for form submissions
        return RedirectResponse("/admin/performance", status_code=303)
    
    @app.get("/admin/performance/clear-cache")
    def clear_performance_cache(request):
        """Clear performance cache"""
        user = get_current_user(request, db, auth_service)
        if not user:
            return RedirectResponse("/auth/login", status_code=302)
        
        # Check if user is admin
        if user.get('role_id') != 0:
            return JSONResponse({"error": "Access denied"}, status_code=403)
        
        try:
            from ..performance import get_performance_cache, get_session_cache
            
            perf_cache = get_performance_cache()
            session_cache = get_session_cache()
            
            cache_size_before = len(perf_cache.cache)
            session_size_before = len(session_cache.sessions)
            
            perf_cache.clear()
            session_cache.sessions.clear()
            session_cache.access_times.clear()
            
            message = f"Cleared {cache_size_before} cache entries and {session_size_before} session cache entries"
            
            # Return JSON for AJAX requests
            if request.headers.get("accept") == "application/json":
                return JSONResponse({"success": True, "message": message})
            
            return RedirectResponse("/admin/performance", status_code=303)
            
        except Exception as e:
            error_message = f"Cache clear failed: {str(e)}"
            
            if request.headers.get("accept") == "application/json":
                return JSONResponse({"success": False, "error": error_message})
            
            return RedirectResponse("/admin/performance", status_code=303)


def _performance_overview_cards(perf_stats: Dict[str, Any], db_metrics: Dict[str, Any]) -> List:
    """Create performance overview cards"""
    cache_stats = perf_stats.get('cache', {})
    query_stats = perf_stats.get('queries', {})
    session_stats = perf_stats.get('sessions', {})
    
    return [
        # Cache Performance Card
        Div(
            Div(
                H3("Cache Performance", cls="text-lg font-semibold text-gray-900"),
                P(f"{cache_stats.get('hit_rate_percent', 0):.1f}%", cls="text-3xl font-bold text-blue-600"),
                P("Hit Rate", cls="text-sm text-gray-500"),
                cls="p-6"
            ),
            Div(
                P(f"{cache_stats.get('size', 0)} entries", cls="text-sm text-gray-600"),
                P(f"{cache_stats.get('total_requests', 0)} total requests", cls="text-sm text-gray-600"),
                cls="px-6 pb-4"
            ),
            cls="bg-white rounded-lg shadow border"
        ),
        
        # Query Performance Card
        Div(
            Div(
                H3("Query Performance", cls="text-lg font-semibold text-gray-900"),
                P(f"{query_stats.get('avg_time_ms', 0):.1f}ms", cls="text-3xl font-bold text-green-600"),
                P("Avg Query Time", cls="text-sm text-gray-500"),
                cls="p-6"
            ),
            Div(
                P(f"{query_stats.get('total_queries', 0)} queries", cls="text-sm text-gray-600"),
                P(f"{query_stats.get('unique_query_patterns', 0)} patterns", cls="text-sm text-gray-600"),
                cls="px-6 pb-4"
            ),
            cls="bg-white rounded-lg shadow border"
        ),
        
        # Session Cache Card
        Div(
            Div(
                H3("Session Cache", cls="text-lg font-semibold text-gray-900"),
                P(f"{session_stats.get('utilization_percent', 0):.1f}%", cls="text-3xl font-bold text-purple-600"),
                P("Cache Utilization", cls="text-sm text-gray-500"),
                cls="p-6"
            ),
            Div(
                P(f"{session_stats.get('total_sessions', 0)} sessions", cls="text-sm text-gray-600"),
                P(f"Max: {session_stats.get('max_sessions', 0)}", cls="text-sm text-gray-600"),
                cls="px-6 pb-4"
            ),
            cls="bg-white rounded-lg shadow border"
        ),
        
        # System Health Card
        Div(
            Div(
                H3("System Health", cls="text-lg font-semibold text-gray-900"),
                P("Healthy" if _is_system_healthy(perf_stats) else "Warning", 
                  cls=f"text-3xl font-bold {'text-green-600' if _is_system_healthy(perf_stats) else 'text-yellow-600'}"),
                P("Status", cls="text-sm text-gray-500"),
                cls="p-6"
            ),
            Div(
                P(f"Memory: OK", cls="text-sm text-gray-600"),
                P(f"Performance: {'Good' if _is_system_healthy(perf_stats) else 'Fair'}", cls="text-sm text-gray-600"),
                cls="px-6 pb-4"
            ),
            cls="bg-white rounded-lg shadow border"
        )
    ]


def _cache_performance_panel(cache_stats: Dict[str, Any]) -> Any:
    """Create cache performance panel"""
    return Div(
        H2("Cache Performance", cls="text-xl font-semibold mb-4"),
        
        Div(
            Div(
                Div("Hit Rate", cls="font-medium text-gray-700"),
                Div(f"{cache_stats.get('hit_rate_percent', 0):.1f}%", cls="text-2xl font-bold text-blue-600"),
                cls="text-center p-4 bg-blue-50 rounded-lg"
            ),
            Div(
                Div("Cache Size", cls="font-medium text-gray-700"),
                Div(f"{cache_stats.get('size', 0)}", cls="text-2xl font-bold text-green-600"),
                cls="text-center p-4 bg-green-50 rounded-lg"
            ),
            cls="grid grid-cols-2 gap-4 mb-4"
        ),
        
        Div(
            H3("Cache Statistics", cls="font-semibold mb-2"),
            Ul(
                Li(f"Total Requests: {cache_stats.get('total_requests', 0)}"),
                Li(f"Cache Hits: {cache_stats.get('hits', 0)}"),
                Li(f"Cache Misses: {cache_stats.get('misses', 0)}"),
                Li(f"Cache Sets: {cache_stats.get('sets', 0)}"),
                Li(f"Evictions: {cache_stats.get('evictions', 0)}"),
                cls="space-y-1 text-sm text-gray-600"
            ),
            cls="mb-4"
        ),
        
        cls="bg-white rounded-lg shadow p-6 border"
    )


def _query_performance_panel(query_stats: Dict[str, Any], slow_queries: List[Dict[str, Any]]) -> Any:
    """Create query performance panel"""
    return Div(
        H2("Query Performance", cls="text-xl font-semibold mb-4"),
        
        Div(
            Div(
                Div("Avg Time", cls="font-medium text-gray-700"),
                Div(f"{query_stats.get('avg_time_ms', 0):.1f}ms", cls="text-2xl font-bold text-green-600"),
                cls="text-center p-4 bg-green-50 rounded-lg"
            ),
            Div(
                Div("Total Queries", cls="font-medium text-gray-700"),
                Div(f"{query_stats.get('total_queries', 0)}", cls="text-2xl font-bold text-blue-600"),
                cls="text-center p-4 bg-blue-50 rounded-lg"
            ),
            cls="grid grid-cols-2 gap-4 mb-4"
        ),
        
        Div(
            H3("Slow Queries (>100ms)", cls="font-semibold mb-2"),
            Div(
                [
                    Div(
                        Div(
                            Code(query.get('query', '')[:80] + '...', cls="text-xs"),
                            cls="mb-1"
                        ),
                        Div(
                            Span(f"{query.get('avg_time_ms', 0):.1f}ms avg", cls="text-sm text-red-600 mr-2"),
                            Span(f"{query.get('count', 0)} executions", cls="text-sm text-gray-500"),
                            cls="text-xs"
                        ),
                        cls="p-2 bg-red-50 rounded border-l-4 border-red-400 mb-2"
                    )
                    for query in slow_queries[:5]
                ] if slow_queries else [
                    Div("No slow queries detected", cls="text-sm text-gray-500 text-center py-4")
                ],
                cls="max-h-64 overflow-y-auto"
            ),
            cls="mb-4"
        ),
        
        cls="bg-white rounded-lg shadow p-6 border"
    )


def _optimization_tools_panel() -> Any:
    """Create optimization tools panel"""
    return Div(
        H2("Database Optimization", cls="text-xl font-semibold mb-4"),
        
        Div(
            P("Run optimization tasks to improve database performance and clean up expired data.", 
              cls="text-gray-600 mb-4"),
            
            Div(
                Button(
                    "🧹 Run Database Optimization",
                    hx_post="/admin/performance/optimize",
                    hx_target="#optimization-result",
                    hx_indicator="#optimization-spinner",
                    cls="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded mr-2"
                ),
                Button(
                    "🗑️ Clear Performance Cache",
                    hx_get="/admin/performance/clear-cache",
                    hx_target="#optimization-result",
                    hx_headers='{"Accept": "application/json"}',
                    cls="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded"
                ),
                cls="mb-4"
            ),
            
            Div(
                Div("Processing...", id="optimization-spinner", cls="hidden text-blue-600"),
                Div(id="optimization-result", cls="mt-4"),
                cls="min-h-16"
            ),
            
            cls="p-4 bg-gray-50 rounded-lg"
        ),
        
        cls="bg-white rounded-lg shadow p-6 border"
    )


def _is_system_healthy(perf_stats: Dict[str, Any]) -> bool:
    """Determine if system is healthy based on performance metrics"""
    cache_stats = perf_stats.get('cache', {})
    query_stats = perf_stats.get('queries', {})
    
    # Simple health check criteria
    cache_hit_rate = cache_stats.get('hit_rate_percent', 0)
    avg_query_time = query_stats.get('avg_time_ms', 0)
    
    return cache_hit_rate > 70 and avg_query_time < 50  # 70% hit rate, <50ms avg query time