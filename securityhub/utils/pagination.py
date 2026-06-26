"""
Custom Pagination Classes

Standardized pagination for API endpoints.
Created for Issue #18 (Phase 3)
"""

from django.conf import settings
from rest_framework.pagination import PageNumberPagination, LimitOffsetPagination
from rest_framework.response import Response
from collections import OrderedDict


class StandardResultsSetPagination(PageNumberPagination):
    """
    Standard pagination for most list endpoints.
    
    Usage:
        class MyViewSet(viewsets.ModelViewSet):
            pagination_class = StandardResultsSetPagination
    
    Query Parameters:
        - page: Page number (default: 1)
        - page_size: Items per page (default: 25, max: 100)
    
    Example:
        GET /api/projects/?page=2&page_size=50
    
    Response Format:
        {
            "count": 250,
            "next": "http://api/projects/?page=3",
            "previous": "http://api/projects/?page=1",
            "results": [...]
        }
    """
    page_size = getattr(settings, 'PAGINATION_STANDARD_PAGE_SIZE', 25)
    page_size_query_param = 'page_size'
    max_page_size = getattr(settings, 'PAGINATION_STANDARD_MAX_PAGE_SIZE', 100)
    
    def get_paginated_response(self, data):
        return Response(OrderedDict([
            ('count', self.page.paginator.count),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('page_size', self.page_size),
            ('total_pages', self.page.paginator.num_pages),
            ('current_page', self.page.number),
            ('results', data)
        ]))


class LargeResultsSetPagination(PageNumberPagination):
    """
    Pagination for endpoints with large datasets.
    
    Larger page size for bulk operations.
    
    Usage:
        class MyViewSet(viewsets.ModelViewSet):
            pagination_class = LargeResultsSetPagination
    
    Query Parameters:
        - page: Page number (default: 1)
        - page_size: Items per page (default: 100, max: 500)
    
    Example:
        GET /api/vulnerabilities/?page=1&page_size=200
    """
    page_size = getattr(settings, 'PAGINATION_LARGE_PAGE_SIZE', 100)
    page_size_query_param = 'page_size'
    max_page_size = getattr(settings, 'PAGINATION_LARGE_MAX_PAGE_SIZE', 500)
    
    def get_paginated_response(self, data):
        return Response(OrderedDict([
            ('count', self.page.paginator.count),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('page_size', self.page_size),
            ('total_pages', self.page.paginator.num_pages),
            ('current_page', self.page.number),
            ('results', data)
        ]))


class SmallResultsSetPagination(PageNumberPagination):
    """
    Pagination for endpoints with small datasets or real-time updates.
    
    Smaller page size for UI components like dashboards.
    
    Usage:
        class MyViewSet(viewsets.ModelViewSet):
            pagination_class = SmallResultsSetPagination
    
    Query Parameters:
        - page: Page number (default: 1)
        - page_size: Items per page (default: 10, max: 50)
    
    Example:
        GET /api/recent-activities/?page=1&page_size=20
    """
    page_size = getattr(settings, 'PAGINATION_SMALL_PAGE_SIZE', 10)
    page_size_query_param = 'page_size'
    max_page_size = getattr(settings, 'PAGINATION_SMALL_MAX_PAGE_SIZE', 50)
    
    def get_paginated_response(self, data):
        return Response(OrderedDict([
            ('count', self.page.paginator.count),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('page_size', self.page_size),
            ('total_pages', self.page.paginator.num_pages),
            ('current_page', self.page.number),
            ('results', data)
        ]))


class CursorBasedPagination(LimitOffsetPagination):
    """
    Cursor-based pagination for efficient scrolling through large datasets.
    
    Best for:
    - Infinite scroll UI
    - Real-time data streams
    - Very large datasets (millions of records)
    
    Usage:
        class MyViewSet(viewsets.ModelViewSet):
            pagination_class = CursorBasedPagination
    
    Query Parameters:
        - limit: Number of items (default: 25, max: 100)
        - offset: Starting position (default: 0)
    
    Example:
        GET /api/logs/?limit=50&offset=100
    
    Response Format:
        {
            "count": 10000,
            "next": "http://api/logs/?limit=50&offset=150",
            "previous": "http://api/logs/?limit=50&offset=50",
            "results": [...]
        }
    """
    default_limit = getattr(settings, 'PAGINATION_CURSOR_DEFAULT_LIMIT', 25)
    max_limit = getattr(settings, 'PAGINATION_CURSOR_MAX_LIMIT', 100)
    
    def get_paginated_response(self, data):
        return Response(OrderedDict([
            ('count', self.count),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('limit', self.limit),
            ('offset', self.offset),
            ('results', data)
        ]))


class NoPagination(PageNumberPagination):
    """
    No pagination - returns all results.
    
    ⚠️ WARNING: Use only for small, bounded datasets!
    
    Usage:
        class MyViewSet(viewsets.ModelViewSet):
            pagination_class = NoPagination
    
    Example:
        GET /api/project-types/  # Returns all types (usually < 20 items)
    """
    page_size = None
    
    def paginate_queryset(self, queryset, request, view=None):
        # Don't paginate - return None to indicate no pagination
        return None
    
    def get_paginated_response(self, data):
        # This shouldn't be called, but just in case
        return Response(data)


