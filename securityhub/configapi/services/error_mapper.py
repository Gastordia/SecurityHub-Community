"""
Error Mapper - Maps runtime template errors to specific template lines.
Provides detailed error information for debugging.
"""
import logging
import traceback
from typing import Dict, Any, Optional, List
from jinja2 import TemplateSyntaxError, UndefinedError, TemplateRuntimeError

logger = logging.getLogger(__name__)


class TemplateErrorInfo:
    """Detailed error information with line mapping."""
    
    def __init__(
        self,
        error_type: str,
        message: str,
        line: Optional[int] = None,
        column: Optional[int] = None,
        block: Optional[str] = None,
        variable: Optional[str] = None,
        template_snippet: Optional[str] = None
    ):
        self.error_type = error_type  # 'syntax', 'undefined', 'runtime', 'security'
        self.message = message
        self.line = line
        self.column = column
        self.block = block  # Block context (e.g., "{% for item in vuln %}")
        self.variable = variable
        self.template_snippet = template_snippet  # Code snippet around error
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'error_type': self.error_type,
            'message': self.message,
            'line': self.line,
            'column': self.column,
            'block': self.block,
            'variable': self.variable,
            'template_snippet': self.template_snippet
        }
    
    def to_user_message(self) -> str:
        """Format error as user-friendly message."""
        parts = []
        
        if self.line:
            parts.append(f"Line {self.line}")
        
        if self.block:
            parts.append(f"Block: {self.block}")
        
        if self.variable:
            parts.append(f"Variable: {self.variable}")
        
        message = f"[{self.error_type.upper()} Error]"
        if parts:
            message += f" {' | '.join(parts)}: {self.message}"
        else:
            message += f": {self.message}"
        
        return message


class ErrorMapper:
    """
    Maps runtime template errors to specific template lines.
    Uses Jinja2 debug info and template analysis.
    """
    
    def __init__(self, template_content: str):
        """
        Initialize error mapper with template content.
        
        Args:
            template_content: Template content for line mapping
        """
        self.template_content = template_content
        self.lines = template_content.split('\n')
    
    def map_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> TemplateErrorInfo:
        """
        Map exception to detailed error information.
        
        Args:
            error: Exception that occurred during rendering
            context: Optional rendering context
        
        Returns:
            TemplateErrorInfo with detailed error information
        """
        # Handle Jinja2-specific errors
        if isinstance(error, TemplateSyntaxError):
            return self._map_syntax_error(error)
        elif isinstance(error, UndefinedError):
            return self._map_undefined_error(error)
        elif isinstance(error, (TemplateRuntimeError, KeyError, AttributeError)):
            return self._map_runtime_error(error, context)
        else:
            return self._map_generic_error(error)
    
    def _map_syntax_error(self, error: TemplateSyntaxError) -> TemplateErrorInfo:
        """Map Jinja2 syntax error."""
        line = getattr(error, 'lineno', None)
        column = getattr(error, 'offset', None)
        
        snippet = None
        if line and line > 0 and line <= len(self.lines):
            snippet = self._get_line_snippet(line - 1)
        
        return TemplateErrorInfo(
            error_type='syntax',
            message=str(error),
            line=line,
            column=column,
            template_snippet=snippet
        )
    
    def _map_undefined_error(self, error: UndefinedError) -> TemplateErrorInfo:
        """Map undefined variable error."""
        # Try to extract variable name from error message
        message = str(error)
        variable = None
        
        # Common patterns: "UndefinedError: 'variable' is undefined"
        if "'" in message:
            parts = message.split("'")
            if len(parts) >= 2:
                variable = parts[1]
        
        # Try to find line number from traceback
        line = self._extract_line_from_traceback(error)
        block = self._find_block_context(line) if line else None
        snippet = self._get_line_snippet(line - 1) if line else None
        
        return TemplateErrorInfo(
            error_type='undefined',
            message=message,
            line=line,
            variable=variable,
            block=block,
            template_snippet=snippet
        )
    
    def _map_runtime_error(self, error: Exception, context: Optional[Dict[str, Any]]) -> TemplateErrorInfo:
        """Map runtime error (KeyError, AttributeError, etc.)."""
        error_type = 'runtime'
        variable = None
        message = str(error)
        
        # Extract variable/attribute from error
        if isinstance(error, KeyError):
            variable = str(error).strip("'\"")
            message = f"Unknown variable '{variable}'"
        elif isinstance(error, AttributeError):
            # Try to extract attribute name
            msg_parts = str(error).split("'")
            if len(msg_parts) >= 2:
                variable = msg_parts[1]
            message = f"Attribute error: {message}"
        
        # Try to find line from traceback
        line = self._extract_line_from_traceback(error)
        block = self._find_block_context(line) if line else None
        snippet = self._get_line_snippet(line - 1) if line else None
        
        return TemplateErrorInfo(
            error_type=error_type,
            message=message,
            line=line,
            variable=variable,
            block=block,
            template_snippet=snippet
        )
    
    def _map_generic_error(self, error: Exception) -> TemplateErrorInfo:
        """Map generic error."""
        return TemplateErrorInfo(
            error_type='runtime',
            message=str(error),
            template_snippet=None
        )
    
    def _extract_line_from_traceback(self, error: Exception) -> Optional[int]:
        """Extract line number from exception traceback."""
        try:
            tb = error.__traceback__
            while tb:
                # Check if this frame is in template rendering
                filename = tb.tb_frame.f_code.co_filename
                if 'template' in filename.lower() or 'jinja' in filename.lower():
                    lineno = tb.tb_lineno
                    # Try to map to template line
                    # This is approximate - Jinja2 doesn't always provide exact mapping
                    return lineno
                tb = tb.tb_next
        except Exception:
            pass
        
        return None
    
    def _find_block_context(self, line: Optional[int]) -> Optional[str]:
        """Find the block context (for loop, if statement, etc.) for a line."""
        if not line or line < 1:
            return None
        
        # Search backwards from line for block start
        for i in range(line - 1, -1, -1):
            if i >= len(self.lines):
                continue
            
            line_content = self.lines[i].strip()
            
            # Check for block starts
            if line_content.startswith('{% for'):
                return line_content
            elif line_content.startswith('{% if'):
                return line_content
            elif line_content.startswith('{% block'):
                return line_content
            elif line_content.startswith('{% macro'):
                return line_content
        
        return None
    
    def _get_line_snippet(self, line_index: int, context_lines: int = 3) -> Optional[str]:
        """Get code snippet around a line."""
        if line_index < 0 or line_index >= len(self.lines):
            return None
        
        start = max(0, line_index - context_lines)
        end = min(len(self.lines), line_index + context_lines + 1)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = '>>> ' if i == line_index else '    '
            snippet_lines.append(f"{prefix}{i + 1}: {self.lines[i]}")
        
        return '\n'.join(snippet_lines)

