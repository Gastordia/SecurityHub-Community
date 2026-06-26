"""
Standardized API Response Utilities
Provides consistent response formats across all SecurityHub APIs
"""

from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from typing import Any, Dict, List, Optional, Union


class APIResponseBuilder:
    """
    Standardized API response builder for consistent response formats
    """
    
    @staticmethod
    def success(
        data: Any = None,
        message: str = "Operation completed successfully",
        meta: Optional[Dict[str, Any]] = None,
        status_code: int = status.HTTP_200_OK
    ) -> Response:
        """
        Create a standardized success response
        
        Args:
            data: The response data (can be dict, list, or any serializable object)
            message: Success message
            meta: Additional metadata (pagination, counts, etc.)
            status_code: HTTP status code
            
        Returns:
            Response: Standardized success response
        """
        response_data = {
            "success": True,
            "message": message,
            "data": data,
            "timestamp": timezone.now().isoformat()
        }
        
        if meta:
            response_data["meta"] = meta
            
        return Response(response_data, status=status_code)
    
    @staticmethod
    def error(
        message: str = "An error occurred",
        errors: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        status_code: int = status.HTTP_400_BAD_REQUEST
    ) -> Response:
        """
        Create a standardized error response
        
        Args:
            message: Error message
            errors: Detailed error information (validation errors, etc.)
            error_code: Application-specific error code
            status_code: HTTP status code
            
        Returns:
            Response: Standardized error response
        """
        response_data = {
            "success": False,
            "message": message,
            "timestamp": timezone.now().isoformat()
        }
        
        if errors:
            response_data["errors"] = errors
            
        if error_code:
            response_data["error_code"] = error_code
            
        return Response(response_data, status=status_code)
    
    @staticmethod
    def paginated(
        data: List[Any],
        page: int,
        per_page: int,
        total_count: int,
        message: str = "Data retrieved successfully"
    ) -> Response:
        """
        Create a standardized paginated response
        
        Args:
            data: The paginated data
            page: Current page number
            per_page: Items per page
            total_count: Total number of items
            message: Success message
            
        Returns:
            Response: Standardized paginated response
        """
        total_pages = (total_count + per_page - 1) // per_page
        has_next = page < total_pages
        has_previous = page > 1
        
        meta = {
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_previous": has_previous
            }
        }
        
        return APIResponseBuilder.success(
            data=data,
            message=message,
            meta=meta
        )
    
    @staticmethod
    def not_found(
        message: str = "Resource not found",
        resource_type: Optional[str] = None,
        resource_id: Optional[Union[str, int]] = None
    ) -> Response:
        """
        Create a standardized 404 response
        
        Args:
            message: Not found message
            resource_type: Type of resource that wasn't found
            resource_id: ID of the resource that wasn't found
            
        Returns:
            Response: Standardized 404 response
        """
        error_details = {}
        if resource_type:
            error_details["resource_type"] = resource_type
        if resource_id:
            error_details["resource_id"] = resource_id
            
        return APIResponseBuilder.error(
            message=message,
            errors=error_details if error_details else None,
            error_code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )
    
    @staticmethod
    def forbidden(
        message: str = "You do not have permission to access this resource",
        required_permission: Optional[str] = None
    ) -> Response:
        """
        Create a standardized 403 response
        
        Args:
            message: Forbidden message
            required_permission: The permission that was required
            
        Returns:
            Response: Standardized 403 response
        """
        error_details = {}
        if required_permission:
            error_details["required_permission"] = required_permission
            
        return APIResponseBuilder.error(
            message=message,
            errors=error_details if error_details else None,
            error_code="PERMISSION_DENIED",
            status_code=status.HTTP_403_FORBIDDEN
        )
    
    @staticmethod
    def validation_error(
        message: str = "Validation failed",
        validation_errors: Dict[str, Any] = None
    ) -> Response:
        """
        Create a standardized validation error response
        
        Args:
            message: Validation error message
            validation_errors: Field-specific validation errors
            
        Returns:
            Response: Standardized validation error response
        """
        return APIResponseBuilder.error(
            message=message,
            errors={"validation": validation_errors} if validation_errors else None,
            error_code="VALIDATION_ERROR",
            status_code=status.HTTP_400_BAD_REQUEST
        )


# Convenience functions for backward compatibility
def success_response(*args, **kwargs) -> Response:
    """Convenience function for success responses"""
    return APIResponseBuilder.success(*args, **kwargs)

def error_response(*args, **kwargs) -> Response:
    """Convenience function for error responses"""
    return APIResponseBuilder.error(*args, **kwargs)

def paginated_response(*args, **kwargs) -> Response:
    """Convenience function for paginated responses"""
    return APIResponseBuilder.paginated(*args, **kwargs)

def not_found_response(*args, **kwargs) -> Response:
    """Convenience function for not found responses"""
    return APIResponseBuilder.not_found(*args, **kwargs)

def forbidden_response(*args, **kwargs) -> Response:
    """Convenience function for forbidden responses"""
    return APIResponseBuilder.forbidden(*args, **kwargs)

def validation_error_response(*args, **kwargs) -> Response:
    """Convenience function for validation error responses"""
    return APIResponseBuilder.validation_error(*args, **kwargs)
