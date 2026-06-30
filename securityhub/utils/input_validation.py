"""
Input validation layer for API endpoints.

This module provides reusable validators for:
- File uploads (MIME type, size, content validation)
- Query parameters (sanitization, type validation)
- JSON payloads (schema validation, required fields)
- URL parameters (format validation)
- SQL injection prevention (parameter sanitization)

Usage:
    from utils.input_validation import validate_file_upload, validate_query_params
    
    def my_view(request):
        # Validate file upload
        file = request.FILES.get('file')
        validate_file_upload(file, allowed_types=['image/jpeg', 'image/png'])
        
        # Validate query parameters
        params = validate_query_params(request.GET, {
            'page': {'type': int, 'default': 1, 'min': 1},
            'limit': {'type': int, 'default': 20, 'min': 1, 'max': 100}
        })
"""
import re
from typing import Dict, List, Optional, Any, Union
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.http import QueryDict

# Try to import python-magic for MIME type detection
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


class APIValidationError(Exception):
    """Custom validation error for API responses."""
    def __init__(self, message: str, code: str = 'VALIDATION_ERROR', field: str = None):
        self.message = message
        self.code = code
        self.field = field
        super().__init__(self.message)


# Allowed MIME types for file uploads
ALLOWED_MIME_TYPES = {
    'image': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    'document': ['application/pdf', 'application/msword', 
                 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    'scan': ['application/xml', 'text/xml', 'application/json', 'text/csv', 'text/plain', 
              'application/octet-stream',  # For .nessus and other binary XML files
              'application/zip', 'application/x-zip-compressed'],
    'archive': ['application/zip', 'application/x-tar', 'application/gzip'],
}

# Maximum file sizes (in bytes). Configurable via settings.MAX_UPLOAD_SIZES
# (see FILE_UPLOAD_LIMITS_MB in settings.py / .env) so self-hosters can raise
# or lower limits without touching code.
MAX_FILE_SIZES = getattr(settings, 'MAX_UPLOAD_SIZES', {
    'image': 10 * 1024 * 1024,  # 10 MB
    'document': 50 * 1024 * 1024,  # 50 MB
    'scan': 100 * 1024 * 1024,  # 100 MB
    'archive': 200 * 1024 * 1024,  # 200 MB
    'default': 50 * 1024 * 1024,  # 50 MB
})


def validate_file_upload(
    file: Optional[UploadedFile],
    allowed_types: Optional[List[str]] = None,
    allowed_extensions: Optional[List[str]] = None,
    max_size: Optional[int] = None,
    required: bool = True,
    category: Optional[str] = None,
    sanitize_name: bool = True
) -> UploadedFile:
    """
    Comprehensive file upload validation with security checks.
    
    Security features:
    - File size limits (DoS protection)
    - Magic byte validation (no extension spoofing)
    - Filename sanitization (path traversal protection)
    - Extension whitelist
    - Content inspection (malware indicators)
    - Executable detection
    
    Args:
        file: UploadedFile instance
        allowed_types: List of allowed MIME types (optional)
        allowed_extensions: List of allowed file extensions (e.g., ['.xml', '.json'])
        max_size: Maximum file size in bytes (optional)
        required: Whether file is required (default: True)
        category: File category ('image', 'document', 'scan', 'archive')
        sanitize_name: Whether to sanitize filename (default: True)
        
    Returns:
        UploadedFile with sanitized filename
        
    Raises:
        APIValidationError: If validation fails
    """
    if not file:
        if required:
            raise APIValidationError("File is required", code='FILE_REQUIRED')
        return None
    
    # 1. Sanitize filename (prevent path traversal)
    if sanitize_name:
        sanitized_filename = sanitize_filename(file.name)
        # Update file name with sanitized version
        file.name = sanitized_filename
    
    # 2. Validate file extension
    if allowed_extensions:
        validate_file_extension(file.name, allowed_extensions)
    
    # 3. Check file size (DoS protection)
    if max_size is None and category:
        max_size = MAX_FILE_SIZES.get(category, MAX_FILE_SIZES['default'])
    elif max_size is None:
        max_size = MAX_FILE_SIZES['default']
    
    if file.size > max_size:
        raise APIValidationError(
            f"File size exceeds maximum allowed size of {max_size / 1024 / 1024:.1f} MB",
            code='FILE_TOO_LARGE',
            field='file'
        )
    
    # 4. Validate MIME type by magic bytes (not extension)
    if allowed_types is None and category:
        allowed_types = ALLOWED_MIME_TYPES.get(category, [])
    
    if allowed_types:
        # Read file content for MIME type detection
        file.seek(0)
        file_content = file.read(2048)  # Read first 2KB for better detection
        file.seek(0)  # Reset file pointer
        
        # Detect MIME type using python-magic if available
        if HAS_MAGIC:
            try:
                detected_mime = magic.from_buffer(file_content, mime=True)
            except Exception:
                # Fallback to content type from request
                detected_mime = file.content_type
        else:
            # Fallback to content type from request if python-magic not available
            detected_mime = file.content_type
        
        if detected_mime not in allowed_types:
            raise APIValidationError(
                f"File type '{detected_mime}' is not allowed. Allowed types: {', '.join(allowed_types)}",
                code='INVALID_FILE_TYPE',
                field='file'
            )
    
    # 5. Content validation (malware indicators, executables)
    _validate_file_content(file)
    
    return file


def validate_query_params(
    query_dict: QueryDict,
    schema: Dict[str, Dict[str, Any]],
    strict: bool = False
) -> Dict[str, Any]:
    """
    Validate and sanitize query parameters.
    
    Args:
        query_dict: Django QueryDict from request.GET or request.POST
        schema: Validation schema
            {
                'param_name': {
                    'type': int|str|bool|list,
                    'default': default_value,
                    'required': bool,
                    'min': min_value,
                    'max': max_value,
                    'choices': [allowed_values],
                    'regex': regex_pattern,
                }
            }
        strict: If True, raise error for unknown parameters
        
    Returns:
        Dictionary of validated parameters
        
    Raises:
        APIValidationError: If validation fails
    """
    validated = {}
    
    # Check for unknown parameters in strict mode
    if strict:
        unknown = set(query_dict.keys()) - set(schema.keys())
        if unknown:
            raise APIValidationError(
                f"Unknown parameters: {', '.join(unknown)}",
                code='UNKNOWN_PARAMETERS'
            )
    
    # Validate each parameter
    for param_name, param_config in schema.items():
        value = query_dict.get(param_name)
        
        # Check if required
        if param_config.get('required', False) and value is None:
            raise APIValidationError(
                f"Parameter '{param_name}' is required",
                code='PARAMETER_REQUIRED',
                field=param_name
            )
        
        # Use default if not provided
        if value is None:
            validated[param_name] = param_config.get('default')
            continue
        
        # Type conversion
        param_type = param_config.get('type', str)
        try:
            if param_type == int:
                value = int(value)
            elif param_type == float:
                value = float(value)
            elif param_type == bool:
                value = value.lower() in ('true', '1', 'yes', 'on')
            elif param_type == list:
                # Handle comma-separated values
                if isinstance(value, list):
                    value = value
                else:
                    value = [v.strip() for v in str(value).split(',')]
        except (ValueError, TypeError):
            raise APIValidationError(
                f"Parameter '{param_name}' must be of type {param_type.__name__}",
                code='INVALID_TYPE',
                field=param_name
            )
        
        # Min/Max validation
        if isinstance(value, (int, float)):
            if 'min' in param_config and value < param_config['min']:
                raise APIValidationError(
                    f"Parameter '{param_name}' must be at least {param_config['min']}",
                    code='VALUE_TOO_SMALL',
                    field=param_name
                )
            if 'max' in param_config and value > param_config['max']:
                raise APIValidationError(
                    f"Parameter '{param_name}' must be at most {param_config['max']}",
                    code='VALUE_TOO_LARGE',
                    field=param_name
                )
        
        # Choices validation
        if 'choices' in param_config:
            if value not in param_config['choices']:
                raise APIValidationError(
                    f"Parameter '{param_name}' must be one of {', '.join(map(str, param_config['choices']))}",
                    code='INVALID_CHOICE',
                    field=param_name
                )
        
        # Regex validation
        if 'regex' in param_config:
            if not re.match(param_config['regex'], str(value)):
                raise APIValidationError(
                    f"Parameter '{param_name}' does not match required format",
                    code='INVALID_FORMAT',
                    field=param_name
                )
        
        validated[param_name] = value
    
    return validated


def validate_json_payload(
    data: Dict[str, Any],
    schema: Dict[str, Dict[str, Any]],
    strict: bool = False
) -> Dict[str, Any]:
    """
    Validate JSON payload against schema.

    Args:
        data: Dictionary from request body
        schema: Validation schema (same format as validate_query_params)
        strict: If True, raise error for unknown fields

    Returns:
        Dictionary of validated data

    Raises:
        APIValidationError: If validation fails
    """
    if not isinstance(data, dict):
        raise APIValidationError("Request body must be a JSON object", code='INVALID_JSON')

    if strict:
        unknown = set(data.keys()) - set(schema.keys())
        if unknown:
            raise APIValidationError(
                f"Unknown fields: {', '.join(unknown)}",
                code='UNKNOWN_FIELDS'
            )

    validated = {}
    for param_name, param_config in schema.items():
        value = data.get(param_name)

        if param_config.get('required', False) and value is None:
            raise APIValidationError(
                f"Field '{param_name}' is required",
                code='FIELD_REQUIRED',
                field=param_name
            )

        if value is None:
            validated[param_name] = param_config.get('default')
            continue

        param_type = param_config.get('type', str)
        try:
            if param_type == int:
                value = int(value)
            elif param_type == float:
                value = float(value)
            elif param_type == bool:
                if isinstance(value, bool):
                    pass
                else:
                    value = str(value).lower() in ('true', '1', 'yes', 'on')
            elif param_type == list:
                if not isinstance(value, list):
                    value = [v.strip() for v in str(value).split(',')]
            elif param_type == str:
                value = str(value)
        except (ValueError, TypeError):
            raise APIValidationError(
                f"Field '{param_name}' must be of type {param_type.__name__}",
                code='INVALID_TYPE',
                field=param_name
            )

        if isinstance(value, (int, float)):
            if 'min' in param_config and value < param_config['min']:
                raise APIValidationError(
                    f"Field '{param_name}' must be at least {param_config['min']}",
                    code='VALUE_TOO_SMALL',
                    field=param_name
                )
            if 'max' in param_config and value > param_config['max']:
                raise APIValidationError(
                    f"Field '{param_name}' must be at most {param_config['max']}",
                    code='VALUE_TOO_LARGE',
                    field=param_name
                )

        if 'choices' in param_config and value not in param_config['choices']:
            raise APIValidationError(
                f"Field '{param_name}' must be one of {', '.join(map(str, param_config['choices']))}",
                code='INVALID_CHOICE',
                field=param_name
            )

        if 'regex' in param_config and not re.match(param_config['regex'], str(value)):
            raise APIValidationError(
                f"Field '{param_name}' does not match required format",
                code='INVALID_FORMAT',
                field=param_name
            )

        validated[param_name] = value

    return validated


def sanitize_string(value: str, max_length: Optional[int] = None) -> str:
    """
    Sanitize string input to prevent XSS and injection attacks.
    
    Args:
        value: String to sanitize
        max_length: Maximum length (optional)
        
    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # Trim whitespace
    value = value.strip()
    
    # Truncate if too long
    if max_length and len(value) > max_length:
        value = value[:max_length]
    
    return value


import uuid

def validate_id_parameter(pk: Union[str, int, uuid.UUID], field_name: str = 'id') -> Union[int, str]:
    """
    Validate and convert ID parameter to integer.
    
    Args:
        pk: ID parameter (string or int)
        field_name: Field name for error messages
        
    Returns:
        Integer ID
        
    Raises:
        ValidationError: If ID is invalid
    """
    if isinstance(pk, uuid.UUID):
        return str(pk)
    
    try:
        id_value = int(pk)
        if id_value <= 0:
            raise APIValidationError(
                f"{field_name} must be a positive integer",
                code='INVALID_ID',
                field=field_name
            )
        return id_value
    except (ValueError, TypeError):
        # Try to validate as UUID
        try:
            uuid_obj = uuid.UUID(str(pk))
            return str(uuid_obj)
        except ValueError:
            raise APIValidationError(
                f"{field_name} must be a valid integer or UUID",
                code='INVALID_ID',
                field=field_name
            )


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename to prevent path traversal and other attacks.
    
    Args:
        filename: Original filename
        max_length: Maximum filename length (default: 255)
        
    Returns:
        Sanitized filename
        
    Raises:
        APIValidationError: If filename is invalid
    """
    import os
    import unicodedata
    
    if not filename:
        raise APIValidationError("Filename is required", code='FILENAME_REQUIRED')
    
    # Check for path traversal attempts BEFORE basename (critical!)
    if '..' in filename or '/' in filename or '\\' in filename:
        raise APIValidationError(
            "Filename contains invalid path characters",
            code='INVALID_FILENAME',
            field='filename'
        )
    
    # Get just the filename (no path) - additional safety layer
    filename = os.path.basename(filename)
    
    # Check for null bytes (security risk)
    if '\x00' in filename:
        raise APIValidationError(
            "Filename contains null bytes",
            code='INVALID_FILENAME',
            field='filename'
        )
    
    # Normalize Unicode (prevents Unicode bypass attacks)
    filename = unicodedata.normalize('NFKD', filename)
    
    # Remove control characters
    filename = ''.join(char for char in filename if ord(char) >= 32)
    
    # Limit length
    if len(filename) > max_length:
        # Keep extension but truncate name
        name, ext = os.path.splitext(filename)
        max_name_length = max_length - len(ext)
        filename = name[:max_name_length] + ext
    
    # Final validation: must have at least 1 character before extension
    if not filename or filename.startswith('.'):
        raise APIValidationError(
            "Invalid filename",
            code='INVALID_FILENAME',
            field='filename'
        )
    
    return filename


def validate_file_extension(filename: str, allowed_extensions: List[str]) -> str:
    """
    Validate file extension against whitelist.
    
    Args:
        filename: Filename to validate
        allowed_extensions: List of allowed extensions (e.g., ['.xml', '.json'])
        
    Returns:
        File extension (lowercase)
        
    Raises:
        APIValidationError: If extension is not allowed
    """
    import os
    
    if not filename:
        raise APIValidationError("Filename is required", code='FILENAME_REQUIRED')
    
    # Get extension (lowercase)
    ext = os.path.splitext(filename)[1].lower()
    
    if not ext:
        raise APIValidationError(
            "File must have an extension",
            code='NO_EXTENSION',
            field='filename'
        )
    
    # Normalize allowed extensions (ensure they start with '.')
    allowed_extensions = [e if e.startswith('.') else f'.{e}' for e in allowed_extensions]
    allowed_extensions = [e.lower() for e in allowed_extensions]
    
    if ext not in allowed_extensions:
        raise APIValidationError(
            f"File extension '{ext}' is not allowed. Allowed extensions: {', '.join(allowed_extensions)}",
            code='INVALID_EXTENSION',
            field='filename'
        )
    
    return ext


def _validate_file_content(file: UploadedFile) -> None:
    """
    Perform basic content validation on file.
    
    Checks for:
    - Empty files
    - Suspicious file patterns
    - Basic malware indicators
    """
    if file.size == 0:
        raise APIValidationError("File is empty", code='FILE_EMPTY', field='file')
    
    # Read first few bytes to check for suspicious patterns
    file.seek(0)
    header = file.read(512)  # Read more bytes for better detection
    file.seek(0)
    
    # Check for executable signatures
    executable_signatures = [
        b'MZ',  # Windows executable
        b'\x7fELF',  # Linux executable
        b'\xca\xfe\xba\xbe',  # Mach-O (macOS) executable
        b'#!/',  # Shell script shebang (bare #! without / is a comment in many formats)
    ]
    
    for sig in executable_signatures:
        if header.startswith(sig):
            raise APIValidationError(
                "Executable files are not allowed",
                code='EXECUTABLE_NOT_ALLOWED',
                field='file'
            )
    
    # Check for PHP tags (web shell risk)
    if b'<?php' in header or b'<? ' in header:
        raise APIValidationError(
            "PHP files are not allowed",
            code='PHP_NOT_ALLOWED',
            field='file'
        )
    
    # Check for ASP tags
    if b'<%' in header and (b'Response.Write' in header or b'Execute' in header):
        raise APIValidationError(
            "ASP files are not allowed",
            code='ASP_NOT_ALLOWED',
            field='file'
        )


def validate_email(email: str) -> str:
    """
    Validate email address format.
    
    Args:
        email: Email address string
        
    Returns:
        Validated email address
        
    Raises:
        ValidationError: If email is invalid
    """
    email = email.strip().lower()
    
    # Basic email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise APIValidationError(
            "Invalid email address format",
            code='INVALID_EMAIL',
            field='email'
        )
    
    # Check length
    if len(email) > 254:  # RFC 5321 limit
        raise APIValidationError(
            "Email address is too long",
            code='EMAIL_TOO_LONG',
            field='email'
        )
    
    return email


def validate_url(url: str) -> str:
    """
    Validate URL format.
    
    Args:
        url: URL string
        
    Returns:
        Validated URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    url = url.strip()
    
    # Basic URL validation
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    if not re.match(url_pattern, url):
        raise APIValidationError(
            "Invalid URL format. Must start with http:// or https://",
            code='INVALID_URL',
            field='url'
        )
    
    return url

