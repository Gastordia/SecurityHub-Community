"""
Template Cache - Simple abstraction over Django cache with registry support.
Supports pattern-based cache invalidation using Redis SET.
"""
import hashlib
import json
import logging
from typing import Optional, Any, List
from django.core.cache import cache

logger = logging.getLogger(__name__)


class TemplateCache:
    """
    Cache abstraction for template rendering results.
    Builds cache keys from template ID, context, format, and version.
    """
    
    def __init__(self, default_timeout: int = 3600):
        """
        Initialize cache.
        
        Args:
            default_timeout: Default cache timeout in seconds (default 1 hour)
        """
        self.default_timeout = default_timeout
    
    def build_key(
        self,
        template_id: int,
        context: dict,
        format: str = "html",
        version_id: Optional[int] = None
    ) -> str:
        """
        Build cache key from template parameters.
        Includes version in key to prevent stale cache.
        
        Args:
            template_id: Template ID
            context: Rendering context
            format: Output format
            version_id: Optional template version ID (required for cache consistency)
        
        Returns:
            Cache key string
        """
        # Create deterministic key from parameters
        # Version ID is critical for cache consistency
        key_data = {
            "tid": template_id,
            "vid": version_id or 0,  # Use 0 if not provided (will cause cache miss)
            "fmt": format,
            "ctx": context
        }
        
        # Serialize to JSON and hash
        key_json = json.dumps(key_data, sort_keys=True, default=str)
        key_hash = hashlib.sha256(key_json.encode()).hexdigest()[:16]
        
        # Include version in key: tpl:{template_id}:{version}:{format}:{hash}
        return f"tpl:{template_id}:{version_id or 0}:{format}:{key_hash}"
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value.
        
        Args:
            key: Cache key
        
        Returns:
            Cached value or None if not found
        """
        try:
            return cache.get(key)
        except Exception as e:
            logger.warning(f"Error getting cache key {key}: {str(e)}")
            return None
    
    def set(self, key: str, value: Any, timeout: Optional[int] = None):
        """
        Set cached value.
        
        Args:
            key: Cache key
            value: Value to cache
            timeout: Cache timeout in seconds (uses default if None)
        """
        try:
            cache.set(key, value, timeout or self.default_timeout)
        except Exception as e:
            logger.warning(f"Error setting cache key {key}: {str(e)}")
    
    def delete(self, key: str):
        """
        Delete cached value.
        
        Args:
            key: Cache key
        """
        try:
            cache.delete(key)
        except Exception as e:
            logger.warning(f"Error deleting cache key {key}: {str(e)}")
    
    def register_key(self, template_id: int, cache_key: str):
        """
        Register a cache key for a template (for pattern-based invalidation).
        Uses Redis SET to track all keys for each template.
        
        Args:
            template_id: Template ID
            cache_key: Cache key to register
        """
        try:
            registry_key = f"tpl:keys:{template_id}"
            
            # Add key to set (if using Redis)
            # For other backends, this might not work - fallback to versioning
            if hasattr(cache, 'client') and hasattr(cache.client, 'sadd'):
                # Redis backend
                cache.client.sadd(registry_key, cache_key)
                # Set expiry on registry (1 day)
                cache.client.expire(registry_key, 86400)
            else:
                # Non-Redis backend - use versioning instead
                # Keys already include version, so old versions won't be used
                pass
        except Exception as e:
            logger.warning(f"Error registering cache key: {str(e)}")
    
    def clear_template(self, template_id: int):
        """
        Clear all cache entries for a template using registry.
        
        Args:
            template_id: Template ID
        """
        try:
            registry_key = f"tpl:keys:{template_id}"
            
            # Get all keys from registry
            if hasattr(cache, 'client') and hasattr(cache.client, 'smembers'):
                # Redis backend
                keys = cache.client.smembers(registry_key)
                for key in keys:
                    cache.delete(key.decode() if isinstance(key, bytes) else key)
                
                # Clear registry
                cache.client.delete(registry_key)
                logger.info(f"Cleared {len(keys)} cache entries for template {template_id}")
            else:
                # Non-Redis backend - log that versioning handles this
                logger.info(f"Cache clear requested for template {template_id} (version-based invalidation)")
        except Exception as e:
            logger.warning(f"Error clearing cache for template {template_id}: {str(e)}")
    
    def get_registered_keys(self, template_id: int) -> List[str]:
        """
        Get all registered cache keys for a template.
        
        Args:
            template_id: Template ID
        
        Returns:
            List of cache keys
        """
        try:
            registry_key = f"tpl:keys:{template_id}"
            
            if hasattr(cache, 'client') and hasattr(cache.client, 'smembers'):
                keys = cache.client.smembers(registry_key)
                return [k.decode() if isinstance(k, bytes) else k for k in keys]
            else:
                return []
        except Exception as e:
            logger.warning(f"Error getting registered keys: {str(e)}")
            return []

