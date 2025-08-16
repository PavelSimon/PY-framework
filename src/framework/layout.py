from fasthtml.common import *
from typing import Optional, List, Dict


def create_navbar(user: Optional[Dict] = None, current_page: str = "home"):
    """Create the top navigation bar"""
    
    # Left side - Brand and main menu
    nav_left = Div(
        # Brand with favicon
        A(
            Img(src="/static/favicon.ico", alt="Logo"),
            "PY-Framework",
            href="/",
            cls="nav-brand"
        ),
        # Main menu
        Ul(
            Li(A("1. stránka", href="/page1", 
                cls="active" if current_page == "page1" else "")),
            cls="nav-main-menu"
        ),
        cls="nav-left"
    )
    
    # Right side - Login status or persona menu
    if user:
        # Get user initials for persona icon
        first_initial = user.get('first_name', '')[0].upper() if user.get('first_name') else ''
        last_initial = user.get('last_name', '')[0].upper() if user.get('last_name') else ''
        initials = first_initial + last_initial or user.get('email', 'U')[0].upper()
        
        nav_right = Div(
            Div(
                Button(
                    Div(initials, cls="persona-icon"),
                    cls="persona-btn"
                ),
                Div(
                    A("👤 Edit Profile", href="/profile"),
                    Div(cls="divider"),
                    A("🚪 Logout", href="/auth/logout"),
                    cls="persona-dropdown"
                ),
                cls="persona-menu"
            ),
            cls="nav-right"
        )
    else:
        nav_right = Div(
            Div(
                A("Login", href="/auth/login", cls="btn btn-primary"),
                A("Register", href="/auth/register", cls="btn btn-secondary"),
                cls="nav-login-status"
            ),
            cls="nav-right"
        )
    
    return Nav(nav_left, nav_right, cls="top-navbar")


def create_sidebar(menu_items: List[Dict] = None, current_page: str = ""):
    """Create the left sidebar with app-specific menu"""
    
    if menu_items is None:
        # Default menu items for development
        menu_items = [
            {"title": "Main", "items": [
                {"name": "Dashboard", "url": "/dashboard", "icon": "📊"},
                {"name": "Users", "url": "/users", "icon": "👥"},
                {"name": "Settings", "url": "/settings", "icon": "⚙️"},
            ]},
            {"title": "Development", "items": [
                {"name": "Test Email", "url": "/dev/test-email", "icon": "📧"},
                {"name": "Test Auth", "url": "/dev/test-auth", "icon": "🔐"},
                {"name": "Database", "url": "/dev/database", "icon": "🗄️"},
            ]}
        ]
    
    sections = []
    for section in menu_items:
        menu_links = []
        for item in section["items"]:
            is_active = current_page == item["url"]
            menu_links.append(
                Li(A(
                    f"{item.get('icon', '•')} {item['name']}", 
                    href=item["url"],
                    cls="active" if is_active else ""
                ))
            )
        
        sections.append(
            Div(
                H3(section["title"], cls="sidebar-title"),
                Ul(*menu_links, cls="sidebar-menu"),
                cls="sidebar-section"
            )
        )
    
    return Div(*sections, cls="sidebar")


def create_app_layout(
    content, 
    title: str = "PY-Framework", 
    user: Optional[Dict] = None,
    current_page: str = "",
    sidebar_items: List[Dict] = None,
    show_sidebar: bool = True,
    page_title: str = None,
    page_subtitle: str = None
):
    """Create the main application layout with navbar and sidebar"""
    
    navbar = create_navbar(user, current_page)
    
    # Create page title section if provided
    title_section = None
    if page_title:
        title_section = Div(
            create_page_title(page_title, page_subtitle),
            cls="page-title-section"
        )
    
    if show_sidebar:
        sidebar = create_sidebar(sidebar_items, current_page)
        main_content = Div(
            sidebar,
            Div(content, cls="content-area"),
            cls="main-content"
        )
    else:
        main_content = Div(
            Div(content, cls="content-area"),
            cls="main-content"
        )
    
    # Build layout with optional title section
    layout_elements = [navbar]
    if title_section:
        layout_elements.append(title_section)
    layout_elements.append(main_content)
    
    return Div(*layout_elements, cls="app-layout")


def create_auth_layout(content, title: str = "PY-Framework", page_title: str = None, page_subtitle: str = None):
    """Create layout for authentication pages (no sidebar)"""
    
    navbar = create_navbar(user=None)
    
    # Create page title section if provided
    title_section = None
    if page_title:
        title_section = Div(
            create_page_title(page_title, page_subtitle),
            cls="page-title-section"
        )
    
    # Build layout with optional title section
    layout_elements = [navbar]
    if title_section:
        layout_elements.append(title_section)
    layout_elements.append(
        Div(
            Div(content, cls="container"),
            cls="auth-content"
        )
    )
    
    return Div(*layout_elements, cls="auth-layout")


def create_page_title(title: str, subtitle: str = None):
    """Create a standardized page title section"""
    elements = [H1(title)]
    if subtitle:
        elements.append(P(subtitle, cls="text-muted"))
    
    return Div(*elements, cls="page-header")


def create_breadcrumb(items: List[Dict]):
    """Create breadcrumb navigation"""
    breadcrumb_items = []
    
    for i, item in enumerate(items):
        if i < len(items) - 1:
            breadcrumb_items.append(A(item["name"], href=item["url"]))
            breadcrumb_items.append(Span(" / ", cls="breadcrumb-separator"))
        else:
            breadcrumb_items.append(Span(item["name"], cls="breadcrumb-current"))
    
    return Nav(*breadcrumb_items, cls="breadcrumb")


def create_success_message(message: str):
    """Create a success alert message"""
    return Div(message, cls="alert alert-success")


def create_error_message(message: str):
    """Create an error alert message"""
    return Div(message, cls="alert alert-danger")


def create_warning_message(message: str):
    """Create a warning alert message"""
    return Div(message, cls="alert alert-warning")


def create_info_message(message: str):
    """Create an info alert message"""
    return Div(message, cls="alert alert-info")