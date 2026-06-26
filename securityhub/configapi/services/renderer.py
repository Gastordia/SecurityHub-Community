"""
Renderer - Isolated Jinja2 rendering component with security and timeout support.
"""
import logging
import signal
from typing import Dict, Any, Optional
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import TemplateSyntaxError, UndefinedError
from .template_loader import DatabaseTemplateLoader

logger = logging.getLogger(__name__)


class TemplateRenderError(Exception):
    """Exception raised when template rendering fails."""
    pass


class RenderTimeoutError(Exception):
    """Exception raised when template rendering times out."""
    pass


class Renderer:
    """
    Isolated Jinja2 rendering component with security and timeout support.
    Handles template rendering with proper error handling, execution timeout,
    and template inheritance support.
    """
    
    def __init__(
        self,
        autoescape: bool = True,
        trim_blocks: bool = True,
        lstrip_blocks: bool = True,
        enable_loader: bool = True,
        render_timeout: int = 30,
        asset_helper=None
    ):
        """
        Initialize renderer with Jinja2 environment.

        Args:
            autoescape: Enable auto-escaping for security
            trim_blocks: Trim whitespace from blocks
            lstrip_blocks: Strip whitespace from block start
            enable_loader: Enable database template loader for inheritance
            render_timeout: Maximum render time in seconds (default 30)
            asset_helper: TemplateAssetHelper instance for asset resolution
        """
        # Create loader if enabled
        loader = None
        if enable_loader:
            loader = DatabaseTemplateLoader()
        
        from jinja2 import StrictUndefined
        
        self.env = SandboxedEnvironment(
            autoescape=autoescape,
            trim_blocks=trim_blocks,
            lstrip_blocks=lstrip_blocks,
            loader=loader,
            undefined=StrictUndefined  # Raise error on undefined variables
        )
        
        self.render_timeout = render_timeout
        
        # Register custom filters (can be extended)
        self._register_filters()
        
        # Register custom tests (can be extended)
        self._register_tests()
        
        # Restrict to safe filters/tests only
        self._restrict_filters()
    
    def render(self, content: str, context: Dict[str, Any], timeout: Optional[int] = None) -> str:
        """
        Render template content with context and execution timeout.
        
        Args:
            content: Template content (Jinja2 template string)
            context: Context data for rendering
            timeout: Override default render timeout
        
        Returns:
            Rendered template as string
        
        Raises:
            TemplateRenderError: If rendering fails
            RenderTimeoutError: If rendering times out
        """
        timeout = timeout or self.render_timeout
        
        def timeout_handler(signum, frame):
            raise RenderTimeoutError(f"Template rendering exceeded timeout of {timeout} seconds")
        
        try:
            # Set up timeout (Unix only - SIGALRM not available on Windows)
            # For Windows, consider using threading.Timer or multiprocessing with timeout
            use_timeout = hasattr(signal, 'SIGALRM')
            
            if use_timeout:
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout)
            
            try:
                template = self.env.from_string(content)
                result = template.render(**context)
                return result
            finally:
                # Cancel timeout
                if use_timeout:
                    signal.alarm(0)
                    
        except RenderTimeoutError:
            raise
        except TemplateSyntaxError as e:
            error_msg = f"Template syntax error: {str(e)}"
            if e.lineno:
                error_msg += f" (line {e.lineno})"
            logger.error(error_msg)
            raise TemplateRenderError(error_msg) from e
        except Exception as e:
            error_msg = f"Error rendering template: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise TemplateRenderError(error_msg) from e
    
    def _register_filters(self):
        """Register custom Jinja2 filters."""
        # Example filters (can be extended)
        def format_date(value, format_string='%Y-%m-%d'):
            """Format date value."""
            if hasattr(value, 'strftime'):
                return value.strftime(format_string)
            return str(value)
        
        def severity_color(severity):
            """Get color for severity level."""
            colors = {
                'Critical': '#FF491C',
                'High': '#F66E09',
                'Medium': '#FBBC02',
                'Low': '#20B803',
                'Info': '#3399FF'
            }
            return colors.get(severity, '#666666')
        
        def generate_chart(chart_type, data=None, config=None):
            return ''

        def asset_url(asset_name: str) -> str:
            return ''
        
        # Register filters using filters dict
        self.env.filters['format_date'] = format_date
        self.env.filters['severity_color'] = severity_color
        self.env.filters['chart'] = generate_chart
        self.env.filters['asset_url'] = asset_url
        self.env.filters['asset'] = asset_url  # Alias for convenience
        
        # Also register as global function for {% chart %} and {% asset %} tag usage
        self.env.globals['chart'] = generate_chart
        self.env.globals['asset'] = lambda name: asset_url(name)  # Global function
    
    def _register_tests(self):
        """Register custom Jinja2 tests."""
        # Example tests (can be extended)
        def is_critical(severity):
            """Test if severity is critical."""
            return str(severity).lower() == 'critical'
        
        def is_high(severity):
            """Test if severity is high."""
            return str(severity).lower() == 'high'
        
        # Register tests using tests dict
        self.env.tests['critical'] = is_critical
        self.env.tests['high'] = is_high
    
    def _restrict_filters(self):
        """
        Restrict available filters to safe list only.
        Prevents use of dangerous filters.
        
        SandboxedEnvironment already blocks most dangerous operations,
        but we explicitly remove potentially problematic filters for defense-in-depth.
        """
        # Unsafe filters to explicitly remove (if they exist)
        unsafe_filters = {
            'attr',  # Can be used to access __class__, __init__, etc.
        }
        
        # Remove unsafe filters from environment
        for filter_name in unsafe_filters:
            self.env.filters.pop(filter_name, None)
        
        logger.debug(
            f"Template renderer initialized with {len(self.env.filters)} safe filters"
        )

