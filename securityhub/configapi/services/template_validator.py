"""
Template Validator - Full AST-based validation for Jinja2 templates.
Validates syntax, variables, security, and schema consistency.
"""
import logging
from typing import List, Dict, Any, Set, Optional
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import TemplateSyntaxError
from jinja2.meta import find_undeclared_variables
from jinja2.nodes import (
    Node, Call, Getattr, Getitem, Name, For, If, Block, Extends, Include,
    Filter, Test, List as ListNode, Dict as DictNode, Const
)

logger = logging.getLogger(__name__)


class ValidationError:
    """Represents a validation error"""
    def __init__(self, type: str, message: str, line: int = None, column: int = None, variable: str = None):
        self.type = type  # 'syntax', 'variable', 'security', 'format', 'schema'
        self.message = message
        self.line = line
        self.column = column
        self.variable = variable
    
    def to_dict(self):
        return {
            'type': self.type,
            'message': self.message,
            'line': self.line,
            'column': self.column,
            'variable': self.variable
        }


class ValidationWarning:
    """Represents a validation warning"""
    def __init__(self, type: str, message: str, line: int = None, variable: str = None):
        self.type = type  # 'variable', 'format', 'performance'
        self.message = message
        self.line = line
        self.variable = variable
    
    def to_dict(self):
        return {
            'type': self.type,
            'message': self.message,
            'line': self.line,
            'variable': self.variable
        }


class ValidationResult:
    """Result of template validation"""
    def __init__(self, errors: List[ValidationError] = None, warnings: List[ValidationWarning] = None):
        self.errors = errors or []
        self.warnings = warnings or []
    
    @property
    def is_valid(self) -> bool:
        """Check if template is valid (no errors)"""
        return len(self.errors) == 0
    
    @property
    def has_warnings(self) -> bool:
        """Check if template has warnings"""
        return len(self.warnings) > 0
    
    def to_dict(self):
        return {
            'valid': self.is_valid,
            'errors': [e.to_dict() for e in self.errors],
            'warnings': [w.to_dict() for w in self.warnings],
            'error_count': len(self.errors),
            'warning_count': len(self.warnings)
        }


class ASTVisitor:
    """
    AST visitor for analyzing Jinja2 template nodes.
    Detects dangerous patterns, undefined variables, and security issues.
    """
    
    def __init__(self, variables_schema: Dict[str, Any] = None):
        self.variables_schema = variables_schema or {}
        self.errors: List[ValidationError] = []
        self.warnings: List[ValidationWarning] = []
        self.defined_variables: Set[str] = set()
        self.forbidden_nodes: List[Node] = []
        self.loop_depth = 0
        self.max_loop_depth = 3  # Maximum allowed nesting depth
        self.max_range_limit = 1000  # Maximum range() limit
    
    def visit(self, node: Node, line: int = None):
        """
        Visit a node and analyze it.
        
        Args:
            node: Jinja2 AST node
            line: Line number (if available)
        """
        node_line = getattr(node, 'lineno', line)
        
        # Check for forbidden nodes
        if isinstance(node, Call):
            self._check_call_node(node, node_line)
        elif isinstance(node, Getattr):
            self._check_getattr_node(node, node_line)
        elif isinstance(node, For):
            self._check_for_loop(node, node_line)
        elif isinstance(node, Filter):
            self._check_filter_node(node, node_line)
        elif isinstance(node, Test):
            self._check_test_node(node, node_line)
        elif isinstance(node, Extends):
            # Extends is allowed (for template inheritance)
            pass
        elif isinstance(node, Include):
            # Include is allowed (for components)
            pass
        elif isinstance(node, Block):
            # Blocks are allowed
            pass
        elif isinstance(node, Name):
            self._check_name_node(node, node_line)
        
        # Recursively visit child nodes
        for child in node.iter_child_nodes():
            self.visit(child, node_line)
    
    def _check_call_node(self, node: Call, line: int):
        """Check for dangerous function calls."""
        if hasattr(node, 'node') and isinstance(node.node, Name):
            func_name = node.node.name
            
            # Forbidden function calls
            forbidden = ['eval', 'exec', '__import__', 'open', 'file', 'input', 'raw_input']
            if func_name in forbidden:
                self.errors.append(ValidationError(
                    type='security',
                    message=f"Forbidden function call: {func_name}()",
                    line=line,
                    variable=func_name
                ))
            # Check for range() calls
            elif func_name == 'range':
                self._check_range_call(node, line)
    
    def _check_getattr_node(self, node: Getattr, line: int):
        """Check for dangerous attribute access."""
        if hasattr(node, 'attr'):
            attr = node.attr
            
            # Forbidden attributes
            forbidden = ['__class__', '__dict__', '__globals__', '__builtins__', '__subclasses__']
            if attr in forbidden:
                self.errors.append(ValidationError(
                    type='security',
                    message=f"Forbidden attribute access: {attr}",
                    line=line,
                    variable=attr
                ))
    
    def _check_for_loop(self, node: For, line: int):
        """Check for loop depth and dangerous patterns."""
        self.loop_depth += 1
        
        if self.loop_depth > self.max_loop_depth:
            self.errors.append(ValidationError(
                type='security',
                message=f"Loop nesting depth exceeds maximum ({self.max_loop_depth})",
                line=line
            ))
        
        # Check for infinite loops (range without limit)
        # This is checked in _check_range_node
        
        # Visit loop body
        if hasattr(node, 'body'):
            for child in node.body:
                self.visit(child, line)
        
        self.loop_depth -= 1
    
    def _check_range_call(self, node: Call, line: int):
        """Check for dangerous range() calls."""
        # Try to extract range limits from Call node arguments
        if hasattr(node, 'args') and len(node.args) > 0:
            try:
                # range() can have 1-3 arguments: range(stop) or range(start, stop) or range(start, stop, step)
                # We're most interested in the stop value
                stop_arg = node.args[-1] if len(node.args) >= 2 else node.args[0]
                
                # Check if it's a constant value
                if isinstance(stop_arg, Const):
                    stop_value = stop_arg.value
                    if isinstance(stop_value, (int, float)) and stop_value > self.max_range_limit:
                        self.errors.append(ValidationError(
                            type='security',
                            message=f"Range limit ({stop_value}) exceeds maximum ({self.max_range_limit})",
                            line=line
                        ))
                else:
                    # Can't determine range at parse time - this is a warning
                    self.warnings.append(ValidationWarning(
                        type='performance',
                        message="Range limit cannot be determined at parse time - may cause performance issues",
                        line=line
                    ))
            except (AttributeError, TypeError, IndexError):
                # Can't determine range at parse time - this is a warning
                self.warnings.append(ValidationWarning(
                    type='performance',
                    message="Range limit cannot be determined at parse time - may cause performance issues",
                    line=line
                ))
    
    def _check_filter_node(self, node: Filter, line: int):
        """Check for dangerous or unsupported filters."""
        if hasattr(node, 'name'):
            filter_name = node.name
            
            # Unsafe filters that bypass autoescaping
            unsafe_filters = ['safe', 'raw']
            if filter_name in unsafe_filters:
                self.warnings.append(ValidationWarning(
                    type='security',
                    message=f"Unsafe filter '{filter_name}' bypasses autoescaping",
                    line=line
                ))
    
    def _check_test_node(self, node: Test, line: int):
        """Check for dangerous or unsupported tests."""
        if hasattr(node, 'name'):
            test_name = node.name
            # Add custom test validation if needed
            pass
    
    def _check_name_node(self, node: Name, line: int):
        """Check for undefined variables."""
        if hasattr(node, 'name'):
            var_name = node.name
            
            # Skip Jinja2 built-ins
            built_ins = {
                'true', 'false', 'none', 'loop', 'namespace', 'dict', 'cycler', 'joiner',
                'self', 'super', 'varargs', 'kwargs'
            }
            
            if var_name in built_ins:
                return
            
            # Check if variable is in schema
            if self.variables_schema and var_name not in self.variables_schema:
                # Check if it's a loop variable (defined in For loop)
                # This is a simplified check - full implementation would track loop variables
                if not var_name.startswith('_'):
                    self.warnings.append(ValidationWarning(
                        type='variable',
                        message=f"Variable '{var_name}' not defined in variables_schema",
                        line=line,
                        variable=var_name
                    ))


class TemplateValidator:
    """
    Full AST-based template validator.
    Validates syntax, variables, security, and schema consistency.
    """
    
    def __init__(self):
        # Use SandboxedEnvironment for security
        self.env = SandboxedEnvironment(
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
    
    def validate(
        self,
        template_content: str,
        variables_schema: Dict[str, Any] = None,
        format: str = 'html'
    ) -> ValidationResult:
        """
        Comprehensive AST-based template validation.
        
        Args:
            template_content: The template content to validate
            variables_schema: Optional schema of available variables
            format: Template format (html, pdf, word, etc.)
        
        Returns:
            ValidationResult with errors and warnings
        """
        errors = []
        warnings = []
        
        # 1. Basic validation
        if not template_content or not template_content.strip():
            errors.append(ValidationError(
                type='syntax',
                message='Template content cannot be empty',
                line=1
            ))
            return ValidationResult(errors, warnings)
        
        # 2. Jinja2 syntax validation and AST parsing
        try:
            ast = self.env.parse(template_content)
        except TemplateSyntaxError as e:
            errors.append(ValidationError(
                type='syntax',
                message=f'Jinja2 syntax error: {str(e)}',
                line=e.lineno,
                column=getattr(e, 'offset', None)
            ))
            return ValidationResult(errors, warnings)
        except Exception as e:
            errors.append(ValidationError(
                type='syntax',
                message=f'Template parsing error: {str(e)}',
                line=1
            ))
            return ValidationResult(errors, warnings)
        
        # 3. AST-based validation
        visitor = ASTVisitor(variables_schema or {})
        visitor.visit(ast)
        errors.extend(visitor.errors)
        warnings.extend(visitor.warnings)
        
        # 4. Variable validation using Jinja2 meta
        var_errors, var_warnings = self._validate_variables_meta(ast, variables_schema or {})
        errors.extend(var_errors)
        warnings.extend(var_warnings)
        
        # 5. Schema consistency validation
        schema_errors, schema_warnings = self._validate_schema_consistency(
            ast, variables_schema or {}
        )
        errors.extend(schema_errors)
        warnings.extend(schema_warnings)
        
        # 6. Block structure validation
        block_errors = self._validate_block_structure(ast)
        errors.extend(block_errors)
        
        # 7. Format-specific validation
        format_warnings = self._validate_format(template_content, format)
        warnings.extend(format_warnings)
        
        return ValidationResult(errors, warnings)
    
    def _validate_variables_meta(
        self,
        ast: Node,
        variables_schema: Dict[str, Any]
    ) -> tuple[List[ValidationError], List[ValidationWarning]]:
        """Validate variables using Jinja2 meta functions."""
        errors = []
        warnings = []
        
        try:
            # Find undeclared variables
            undeclared = find_undeclared_variables(ast)
            
            # Extract all variables used in template
            all_variables = self._extract_all_variables(ast)
            
            # Check if variables are in schema
            if variables_schema:
                schema_vars = set(variables_schema.keys())
                
                for var in all_variables:
                    # Skip Jinja2 built-in variables
                    if var in {'loop', 'namespace', 'dict', 'cycler', 'joiner', 'self', 'super'}:
                        continue
                    
                    # Check if variable is in schema
                    if var not in schema_vars:
                        warnings.append(ValidationWarning(
                            type='variable',
                            message=f'Variable "{var}" is not defined in variables_schema',
                            variable=var
                        ))
                
                # Check for required variables in schema that aren't used
                for schema_var, schema_info in variables_schema.items():
                    if isinstance(schema_info, dict) and schema_info.get('required', False):
                        if schema_var not in all_variables:
                            warnings.append(ValidationWarning(
                                type='variable',
                                message=f'Required variable "{schema_var}" from schema is not used in template',
                                variable=schema_var
                            ))
        except Exception as e:
            logger.warning(f"Error validating variables: {str(e)}")
            warnings.append(ValidationWarning(
                type='variable',
                message=f'Could not validate variables: {str(e)}'
            ))
        
        return errors, warnings
    
    def _extract_all_variables(self, node: Node) -> Set[str]:
        """Extract all variable names from AST."""
        variables = set()
        
        def collect_vars(n: Node):
            if isinstance(n, Name):
                variables.add(n.name)
            for child in n.iter_child_nodes():
                collect_vars(child)
        
        collect_vars(node)
        return variables
    
    def _validate_schema_consistency(
        self,
        ast: Node,
        variables_schema: Dict[str, Any]
    ) -> tuple[List[ValidationError], List[ValidationWarning]]:
        """Validate that template usage matches schema types."""
        errors = []
        warnings = []
        
        if not variables_schema:
            return errors, warnings
        
        # This is a simplified check - full implementation would analyze
        # how variables are used (e.g., iterating over non-lists, accessing
        # attributes on non-objects, etc.)
        
        # For now, we rely on runtime errors, but we could add static analysis here
        
        return errors, warnings
    
    def _validate_block_structure(self, ast: Node) -> List[ValidationError]:
        """Validate block structure (extends, blocks, etc.)."""
        errors = []
        
        # Check for extends without blocks
        has_extends = False
        has_blocks = False
        
        def check_structure(n: Node):
            nonlocal has_extends, has_blocks
            if isinstance(n, Extends):
                has_extends = True
            elif isinstance(n, Block):
                has_blocks = True
            for child in n.iter_child_nodes():
                check_structure(child)
        
        check_structure(ast)
        
        if has_extends and not has_blocks:
            errors.append(ValidationError(
                type='syntax',
                message='Template uses {% extends %} but has no {% block %} definitions',
                line=1
            ))
        
        return errors
    
    def _validate_format(self, template_content: str, format: str) -> List[ValidationWarning]:
        """Format-specific validation."""
        warnings = []
        
        if format == 'html':
            # Check for basic HTML structure
            if '<html' not in template_content.lower() and '<body' not in template_content.lower():
                warnings.append(ValidationWarning(
                    type='format',
                    message='HTML template may be missing <html> or <body> tags',
                    line=1
                ))
            
            # Check for balanced tags (basic check)
            open_tags = template_content.count('<')
            close_tags = template_content.count('>')
            if open_tags != close_tags:
                warnings.append(ValidationWarning(
                    type='format',
                    message='Potential unclosed HTML tags detected',
                    line=1
                ))
        
        elif format in ['pdf', 'latex']:
            # LaTeX-specific checks could go here
            pass
        
        elif format in ['word', 'docx']:
            # Word-specific checks could go here
            pass
        
        return warnings
    
    def validate_template_object(self, template) -> ValidationResult:
        """
        Validate a ReportTemplate model instance.
        
        Args:
            template: ReportTemplate instance
        
        Returns:
            ValidationResult
        """
        return self.validate(
            template_content=template.content,
            variables_schema=template.variables_schema or {},
            format=template.format
        )
