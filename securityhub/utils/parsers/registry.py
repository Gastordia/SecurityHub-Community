"""
Parser registry for managing all scanner parsers
"""

from typing import Dict, Type, Optional, List
from .base import BaseParser
from .models import ParserMetadata


class ParserRegistry:
    """Registry for managing all parser classes"""
    
    _parsers: Dict[str, Type[BaseParser]] = {}
    _metadata_cache: Dict[str, ParserMetadata] = {}
    
    @classmethod
    def register(cls, scanner_type: str, parser_class: Type[BaseParser]) -> None:
        """Register a parser class for a scanner type"""
        if not issubclass(parser_class, BaseParser):
            raise ValueError(f"Parser class must inherit from BaseParser: {parser_class}")
        
        cls._parsers[scanner_type.lower()] = parser_class
        # Clear metadata cache for this scanner type
        cls._metadata_cache.pop(scanner_type.lower(), None)
    
    @classmethod
    def get_parser(cls, scanner_type: str) -> Optional[Type[BaseParser]]:
        """Get parser class for scanner type"""
        return cls._parsers.get(scanner_type.lower())
    
    @classmethod
    def create_parser(cls, scanner_type: str) -> Optional[BaseParser]:
        """Create parser instance for scanner type"""
        parser_class = cls.get_parser(scanner_type)
        if parser_class:
            return parser_class()
        return None
    
    @classmethod
    def list_parsers(cls) -> List[str]:
        """Get list of registered scanner types"""
        return list(cls._parsers.keys())
    
    @classmethod
    def get_metadata(cls, scanner_type: str) -> Optional[ParserMetadata]:
        """Get parser metadata for scanner type"""
        scanner_type_lower = scanner_type.lower()
        
        # Check cache first
        if scanner_type_lower in cls._metadata_cache:
            return cls._metadata_cache[scanner_type_lower]
        
        # Get from parser instance
        parser = cls.create_parser(scanner_type)
        if parser:
            metadata = parser.get_metadata()
            cls._metadata_cache[scanner_type_lower] = metadata
            return metadata
        
        return None
    
    @classmethod
    def get_all_metadata(cls) -> Dict[str, ParserMetadata]:
        """Get metadata for all registered parsers"""
        metadata = {}
        for scanner_type in cls.list_parsers():
            parser_metadata = cls.get_metadata(scanner_type)
            if parser_metadata:
                metadata[scanner_type] = parser_metadata
        return metadata
    
    @classmethod
    def is_supported(cls, scanner_type: str) -> bool:
        """Check if scanner type is supported"""
        return scanner_type.lower() in cls._parsers
    
    @classmethod
    def get_supported_formats(cls, scanner_type: str) -> List[str]:
        """Get supported file formats for scanner type"""
        metadata = cls.get_metadata(scanner_type)
        if metadata:
            return metadata.supported_formats
        return []
    
    @classmethod
    def validate_file(cls, scanner_type: str, file_path: str) -> bool:
        """Validate file for scanner type"""
        parser = cls.create_parser(scanner_type)
        if parser:
            return parser.validate_file(file_path)
        return False
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear metadata cache"""
        cls._metadata_cache.clear()
    
    @classmethod
    def unregister(cls, scanner_type: str) -> None:
        """Unregister a parser"""
        scanner_type_lower = scanner_type.lower()
        cls._parsers.pop(scanner_type_lower, None)
        cls._metadata_cache.pop(scanner_type_lower, None)


