"""
Context Adapter 2.0 - Supports nested structures, arrays, and complex types.
Bridges domain data and template variables using advanced variables_schema.
"""
import logging
from typing import Dict, Any, Optional, List, Union

logger = logging.getLogger(__name__)


class ContextAdapter:
    """
    Advanced context adapter with Schema 2.0 support.
    Handles nested structures, arrays with item types, and recursive parsing.
    """
    
    def adapt(self, report_data: Dict[str, Any], schema: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Adapt report data to match template variable schema (Schema 2.0).
        
        Supports:
        - Nested structures (project.manager.email)
        - Arrays with item types (vuln: array of objects)
        - Required field validation
        - Type inference and conversion
        - Pre-processing hooks
        
        Args:
            report_data: Raw report data from domain services
            schema: Template variables_schema with Schema 2.0 format
        
        Returns:
            Adapted context dictionary for template rendering
        
        Example Schema 2.0:
        {
            "project_name": {
                "path": "project.name",
                "type": "string",
                "required": true
            },
            "vuln": {
                "path": "vuln",
                "type": "array",
                "items": {
                    "type": "object",
                    "schema": {
                        "title": {"type": "string", "required": true},
                        "severity": {"type": "string"},
                        "cvssscore": {"type": "number"}
                    }
                }
            }
        }
        """
        if not schema:
            # No schema provided, return data as-is
            return report_data
        
        result = {}
        
        for var_name, var_spec in schema.items():
            if isinstance(var_spec, dict):
                # Schema 2.0 entry
                path = var_spec.get('path', var_name)
                var_type = var_spec.get('type', 'string')
                default = var_spec.get('default', None)
                required = var_spec.get('required', False)
                preprocess = var_spec.get('preprocess', None)  # Hook for preprocessing
                
                # Extract value by path
                value = self._get_by_path(report_data, path)
                
                # Handle missing values
                if value is None:
                    if required and default is None:
                        logger.warning(
                            f"Required variable '{var_name}' (path: {path}) not found in report data"
                        )
                        value = None
                    else:
                        value = default
                
                # Pre-processing hook
                if value is not None and preprocess:
                    value = self._apply_preprocess(value, preprocess)
                
                # Type conversion and validation
                if value is not None:
                    if var_type == 'array':
                        # Handle array with item schema
                        value = self._process_array(value, var_spec.get('items', {}))
                    elif var_type == 'object':
                        # Handle object with nested schema
                        value = self._process_object(value, var_spec.get('schema', {}))
                    else:
                        # Simple type conversion
                        value = self._convert_type(value, var_type)
                
                result[var_name] = value
            else:
                # Simple schema entry (just variable name)
                value = self._get_by_path(report_data, var_name)
                result[var_name] = value if value is not None else var_spec
        
        return result
    
    def _process_array(self, value: Any, items_spec: Dict[str, Any]) -> List[Any]:
        """
        Process array value according to items schema.
        
        Args:
            value: Array value from report data
            items_spec: Schema for array items
        
        Returns:
            Processed array
        """
        if not isinstance(value, (list, tuple)):
            # Try to convert to list
            if hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
                value = list(value)
            else:
                return [value] if value is not None else []
        
        item_type = items_spec.get('type', 'string')
        item_schema = items_spec.get('schema', {})
        
        processed = []
        for item in value:
            if item_type == 'object' and item_schema:
                # Process object item with nested schema
                processed_item = self._process_object(item, item_schema)
            else:
                # Process simple item
                processed_item = self._convert_type(item, item_type)
            
            processed.append(processed_item)
        
        return processed
    
    def _process_object(self, value: Any, object_schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process object value according to nested schema.
        
        Args:
            value: Object value from report data
            object_schema: Schema for object fields
        
        Returns:
            Processed object dictionary
        """
        # Convert to dict if needed
        if isinstance(value, dict):
            obj_dict = value
        elif hasattr(value, '__dict__'):
            obj_dict = value.__dict__
        else:
            # Try to access as object attributes
            obj_dict = {}
            for key in object_schema.keys():
                if hasattr(value, key):
                    obj_dict[key] = getattr(value, key)
        
        # Process each field according to schema
        processed = {}
        for field_name, field_spec in object_schema.items():
            if isinstance(field_spec, dict):
                field_type = field_spec.get('type', 'string')
                field_default = field_spec.get('default', None)
                field_required = field_spec.get('required', False)
                
                # Get field value
                field_value = obj_dict.get(field_name, field_default)
                
                # Validate required fields
                if field_required and field_value is None:
                    logger.warning(
                        f"Required field '{field_name}' missing in object"
                    )
                
                # Convert type
                if field_value is not None:
                    field_value = self._convert_type(field_value, field_type)
                
                processed[field_name] = field_value
            else:
                # Simple field spec
                processed[field_name] = obj_dict.get(field_name, field_spec)
        
        return processed
    
    def _apply_preprocess(self, value: Any, preprocess: Union[str, callable]) -> Any:
        """
        Apply preprocessing hook to value.
        
        Args:
            value: Value to preprocess
            preprocess: Preprocessing function name or callable
        
        Returns:
            Preprocessed value
        """
        if callable(preprocess):
            return preprocess(value)
        elif isinstance(preprocess, str):
            # Built-in preprocessing functions
            preprocessors = {
                'uppercase': lambda v: str(v).upper() if v else v,
                'lowercase': lambda v: str(v).lower() if v else v,
                'title': lambda v: str(v).title() if v else v,
                'trim': lambda v: str(v).strip() if v else v,
                'abs': lambda v: abs(v) if isinstance(v, (int, float)) else v,
                'round': lambda v: round(v, 2) if isinstance(v, (int, float)) else v,
            }
            
            if preprocess in preprocessors:
                return preprocessors[preprocess](value)
            else:
                logger.warning(f"Unknown preprocess function: {preprocess}")
                return value
        else:
            return value
    
    def _get_by_path(self, data: Dict[str, Any], path: str) -> Any:
        """
        Get value from nested dictionary using dot-notation path.
        
        Args:
            data: Dictionary to traverse
            path: Dot-separated path (e.g., "project.manager.email")
        
        Returns:
            Value at path or None if not found
        
        Example:
            data = {"project": {"manager": {"email": "test@example.com"}}}
            _get_by_path(data, "project.manager.email") -> "test@example.com"
        """
        if not path:
            return None
        
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            elif hasattr(value, key):
                value = getattr(value, key)
            elif hasattr(value, '__getitem__'):
                try:
                    value = value[key]
                except (KeyError, TypeError, IndexError):
                    return None
            else:
                return None
            
            if value is None:
                return None
        
        return value
    
    def _convert_type(self, value: Any, target_type: str) -> Any:
        """
        Convert value to target type if needed.
        
        Args:
            value: Value to convert
            target_type: Target type (string, number, boolean, array, object)
        
        Returns:
            Converted value
        """
        if target_type == 'string':
            return str(value) if value is not None else ''
        elif target_type == 'number':
            try:
                return float(value) if '.' in str(value) else int(value)
            except (ValueError, TypeError):
                return 0
        elif target_type == 'boolean':
            return bool(value)
        elif target_type == 'array':
            if isinstance(value, list):
                return value
            elif isinstance(value, (str, tuple)):
                return list(value)
            else:
                return [value] if value is not None else []
        elif target_type == 'object':
            if isinstance(value, dict):
                return value
            elif hasattr(value, '__dict__'):
                return value.__dict__
            else:
                return {'value': value}
        else:
            return value
    
    def generate_sample_data(self, schema: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate sample data from Schema 2.0 for preview/testing.
        
        Args:
            schema: Template variables_schema (Schema 2.0 format)
        
        Returns:
            Dictionary with sample values
        """
        if not schema:
            return self._get_default_sample_data()
        
        sample = {}
        
        for var_name, var_spec in schema.items():
            if isinstance(var_spec, dict):
                var_type = var_spec.get('type', 'string')
                default = var_spec.get('default')
                
                if default is not None:
                    sample[var_name] = default
                elif var_type == 'array':
                    # Generate sample array
                    items_spec = var_spec.get('items', {})
                    item_type = items_spec.get('type', 'string')
                    
                    if item_type == 'object':
                        # Generate array of objects
                        item_schema = items_spec.get('schema', {})
                        sample[var_name] = [
                            self._generate_object_sample(item_schema)
                            for _ in range(3)  # Generate 3 sample items
                        ]
                    else:
                        # Generate array of simple types
                        sample[var_name] = [
                            self._get_default_for_type(item_type, f"{var_name}_item")
                            for _ in range(3)
                        ]
                elif var_type == 'object':
                    # Generate sample object
                    object_schema = var_spec.get('schema', {})
                    sample[var_name] = self._generate_object_sample(object_schema)
                else:
                    sample[var_name] = self._get_default_for_type(var_type, var_name)
            else:
                sample[var_name] = f'Sample {var_name}'
        
        return sample
    
    def _generate_object_sample(self, object_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate sample object from schema."""
        sample = {}
        for field_name, field_spec in object_schema.items():
            if isinstance(field_spec, dict):
                field_type = field_spec.get('type', 'string')
                field_default = field_spec.get('default')
                
                if field_default is not None:
                    sample[field_name] = field_default
                else:
                    sample[field_name] = self._get_default_for_type(field_type, field_name)
            else:
                sample[field_name] = f'Sample {field_name}'
        
        return sample
    
    def _get_default_for_type(self, var_type: str, var_name: str) -> Any:
        """Get default value for a type."""
        defaults = {
            'string': f'Sample {var_name}',
            'number': 0,
            'boolean': False,
            'array': [],
            'object': {}
        }
        return defaults.get(var_type, f'Sample {var_name}')
    
    def _get_default_sample_data(self) -> Dict[str, Any]:
        """Get default sample data when no schema is provided."""
        return {
            'project': {
                'name': 'Sample Security Assessment',
                'id': 1,
                'description': 'This is a sample project for template preview'
            },
            'totalvulnerability': 42,
            'ciritcal': 5,
            'high': 12,
            'medium': 15,
            'low': 8,
            'info': 2,
            'standard': 'NIST',
            'Report_type': 'Audit',
            'mycomany': 'Security Company',
            'projectscope': [],
            'totalretest': [],
            'vuln': [
                {
                    'title': 'SQL Injection Vulnerability',
                    'severity': 'Critical',
                    'description': 'Sample vulnerability description',
                    'cvssscore': 9.8
                }
            ],
            'instances': [],
            'projectmanagers': [],
            'customeruser': [],
            'pie_chart': '<svg>Sample Chart</svg>'
        }
