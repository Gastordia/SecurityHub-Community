"""
Comprehensive SSTI (Server-Side Template Injection) Security Tests.

Tests verify that the template rendering system is properly sandboxed
and cannot execute arbitrary Python code.
"""

import pytest
import tempfile
from django.test import TestCase
from django.conf import settings


class SSTISecurityTestCase(TestCase):
    """Test SSTI protection in template rendering"""
    
    def test_ssti_protection_config_inspection(self):
        """
        CRITICAL: Verify templates cannot access configuration/__builtins__/__globals__
        
        This is the most common SSTI attack vector.
        """
        from configapi.services.renderer import Renderer
        
        renderer = Renderer()
        context = {'test_var': 'safe_value'}
        
        # Attempt to access config (should fail)
        malicious_templates = [
            "{{ config }}",
            "{{ self.__init__.__globals__ }}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "{{ lipsum.__globals__ }}",
            "{{ cycler.__init__.__globals__ }}",
        ]
        
        for template in malicious_templates:
            with self.assertRaises(Exception):
                result = renderer.render(template, context)
                # If it doesn't raise, result should NOT contain sensitive data
                self.assertNotIn('SECRET', result.upper())
                self.assertNotIn('PASSWORD', result.upper())
                self.assertNotIn('DATABASE', result.upper())
    
    def test_ssti_protection_file_read(self):
        """
        CRITICAL: Verify templates cannot read files from filesystem
        """
        from configapi.services.renderer import Renderer
        
        renderer = Renderer()
        context = {}
        
        # Attempt to read /etc/passwd (should fail)
        malicious_templates = [
            "{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /etc/passwd').read() }}",
            "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('/etc/passwd').read() }}{% endif %}{% endfor %}",
        ]
        
        for template in malicious_templates:
            with self.assertRaises(Exception) as cm:
                result = renderer.render(template, context)
                # If it doesn't raise, check result doesn't contain file contents
                self.assertNotIn('root:', result)
                self.assertNotIn('/bin/bash', result)
    
    def test_ssti_protection_code_execution(self):
        """
        CRITICAL: Verify templates cannot execute arbitrary Python code
        """
        from configapi.services.renderer import Renderer
        
        renderer = Renderer()
        context = {}
        
        # Attempt to execute code (should fail)
        malicious_templates = [
            "{{ __import__('os').popen('whoami').read() }}",
            "{{ self.__init__.__globals__['__builtins__']['__import__']('os').system('ls') }}",
            "{{ ''.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['subprocess'].check_output('id') }}",
        ]
        
        for template in malicious_templates:
            with self.assertRaises(Exception):
                result = renderer.render(template, context)
    
    def test_ssti_protection_attribute_access(self):
        """Verify templates cannot access object attributes unsafely"""
        from configapi.services.renderer import Renderer
        
        renderer = Renderer()
        context = {'user': type('User', (), {'password': 'secret123', 'email': 'test@example.com'})}
        
        # Normal attribute access should work
        result = renderer.render("{{ user.email }}", context)
        self.assertEqual(result, 'test@example.com')
        
        # But dangerous attribute access should be blocked
        malicious_templates = [
            "{{ user.__class__ }}",
            "{{ user.__dict__ }}",
            "{{ user.__init__ }}",
            "{{ user.__globals__ }}",
        ]
        
        for template in malicious_templates:
            with self.assertRaises(Exception):
                renderer.render(template, context)
    
    def test_sandboxed_environment_active(self):
        """Verify that SandboxedEnvironment is being used"""
        from configapi.services.renderer import Renderer
        from jinja2.sandbox import SandboxedEnvironment
        
        renderer = Renderer()
        
        # Check that environment is actually sandboxed
        self.assertIsInstance(renderer.env, SandboxedEnvironment)
        self.assertTrue(renderer.env.autoescape)
    
    def test_safe_filters_only(self):
        """Verify only safe filters are available"""
        from configapi.services.renderer import Renderer
        
        renderer = Renderer()
        
        # Safe filters should work
        safe_template = "{{ 'HELLO' | lower }}"
        result = renderer.render(safe_template, {})
        self.assertEqual(result, 'hello')
        
        # Upper filter should work
        safe_template2 = "{{ 'hello world' | upper }}"
        result2 = renderer.render(safe_template2, {})
        self.assertEqual(result2, 'HELLO WORLD')
        
        # Custom severity_color filter should work
        safe_template3 = "{{ 'Critical' | severity_color }}"
        result3 = renderer.render(safe_template3, {})
        self.assertEqual(result3, '#FF491C')
    
    def test_xss_protection_autoescape(self):
        """Verify XSS protection through auto-escaping"""
        from configapi.services.renderer import Renderer
        
        renderer = Renderer()
        context = {'user_input': '<script>alert("XSS")</script>'}
        
        # Auto-escaping should protect against XSS
        template = "{{ user_input }}"
        result = renderer.render(template, context)
        
        # Should be escaped
        self.assertIn('&lt;script&gt;', result)
        self.assertNotIn('<script>', result)
    
    def test_render_timeout_protection(self):
        """Verify rendering has timeout protection"""
        from configapi.services.renderer import Renderer, RenderTimeoutError
        
        renderer = Renderer(render_timeout=1)  # 1 second timeout
        context = {}
        
        # This template would cause infinite loop
        infinite_loop_template = "{% for i in range(999999999) %}{{ i }}{% endfor %}"
        
        # Should timeout (or sandbox should prevent range that large)
        with self.assertRaises(Exception):  # Could be timeout or sandbox restriction
            renderer.render(infinite_loop_template, context)
    
    def test_undefined_variable_strict(self):
        """Verify undefined variables cause errors (StrictUndefined)"""
        from configapi.services.renderer import Renderer, TemplateRenderError
        
        renderer = Renderer()
        context = {'defined_var': 'value'}
        
        # Undefined variable should raise error
        template = "{{ undefined_var }}"
        
        with self.assertRaises((TemplateRenderError, Exception)):
            renderer.render(template, context)


class SSTIIntegrationTestCase(TestCase):
    """Integration tests for SSTI protection in full template system"""
    
    def test_template_service_uses_sandboxed_environment(self):
        """Verify TemplateService uses sandboxed environment"""
        from configapi.services.template_service import TemplateService
        from jinja2.sandbox import SandboxedEnvironment
        
        service = TemplateService()
        
        # Check sandboxed environment is used
        self.assertIsInstance(service.jinja_env, SandboxedEnvironment)
    
    def test_template_validator_uses_sandboxed_environment(self):
        """Verify TemplateValidator uses sandboxed environment"""
        from configapi.services.template_validator import TemplateValidator
        from jinja2.sandbox import SandboxedEnvironment
        
        validator = TemplateValidator()
        
        # Check sandboxed environment is used
        self.assertIsInstance(validator.env, SandboxedEnvironment)


# Pytest-style tests
@pytest.mark.django_db
def test_ssti_critical_protection():
    """Pytest-style critical SSTI protection test"""
    from configapi.services.renderer import Renderer
    
    renderer = Renderer()
    context = {}
    
    # Most dangerous SSTI payload
    ssti_payload = "{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('whoami').read() }}"
    
    with pytest.raises(Exception):
        result = renderer.render(ssti_payload, context)


@pytest.mark.django_db
def test_ssti_config_access_blocked():
    """Verify Django settings cannot be accessed via templates"""
    from configapi.services.renderer import Renderer
    
    renderer = Renderer()
    context = {}
    
    # Try to access Django settings
    payloads = [
        "{{ settings.SECRET_KEY }}",
        "{{ config.SECRET_KEY }}",
        "{{ self.env.globals['settings'] }}",
    ]
    
    for payload in payloads:
        with pytest.raises(Exception):
            result = renderer.render(payload, context)


@pytest.mark.django_db
def test_ssti_safe_template_works():
    """Verify safe templates work correctly"""
    from configapi.services.renderer import Renderer
    
    renderer = Renderer()
    context = {
        'project_name': 'Test Project',
        'vulnerabilities': [
            {'name': 'SQL Injection', 'severity': 'Critical'},
            {'name': 'XSS', 'severity': 'High'},
        ]
    }
    
    # Safe template
    template = """
    <h1>{{ project_name }}</h1>
    <ul>
    {% for vuln in vulnerabilities %}
        <li>{{ vuln.name }} - {{ vuln.severity }}</li>
    {% endfor %}
    </ul>
    """
    
    result = renderer.render(template, context)
    
    assert 'Test Project' in result
    assert 'SQL Injection' in result
    assert 'Critical' in result


@pytest.mark.django_db
def test_ssti_regression_test():
    """
    REGRESSION TEST: This test must always pass.
    
    If it fails, SSTI protection has been removed or broken.
    This is a CRITICAL security vulnerability.
    """
    from configapi.services.renderer import Renderer
    from jinja2.sandbox import SandboxedEnvironment
    
    renderer = Renderer()
    
    # Verify sandboxed environment
    assert isinstance(renderer.env, SandboxedEnvironment), (
        "❌ CRITICAL SECURITY FAILURE! ❌\n\n"
        "Template renderer is NOT using SandboxedEnvironment!\n"
        "This allows Server-Side Template Injection (SSTI) attacks.\n\n"
        "Security Risks:\n"
        "- Arbitrary code execution\n"
        "- File system access\n"
        "- Database access\n"
        "- Environment variable exposure\n\n"
        "OWASP: A03:2021 - Injection\n"
        "CWE: CWE-94 - Improper Control of Generation of Code\n\n"
        "FIX: Ensure Renderer class uses jinja2.sandbox.SandboxedEnvironment"
    )
    
    # Verify auto-escaping
    assert renderer.env.autoescape, (
        "Auto-escaping is disabled! This allows XSS attacks."
    )

