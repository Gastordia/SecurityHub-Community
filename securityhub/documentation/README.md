# API Reference Documentation

This folder contains comprehensive API documentation for frontend developers.

## Files

- **`api-reference.json`** - Complete API endpoint reference organized by sections and features

## Structure

The JSON file is organized into the following sections:

1. **Authentication** (`/api/auth`) - Login, tokens, users, groups, permissions, biometric auth
2. **Projects** (`/api/project`) - Project management, scopes, retests, vulnerabilities, parser integration
3. **Vulnerability Database** (`/api/vulndb`) - Vulnerability DB, CWE, intelligence features
4. **Customers** (`/api/customer`) - Companies, customers, analytics, dashboards
5. **Configuration** (`/api/config`) - Report standards, project types, health checks
6. **Assets** (`/api/assets`) - Asset discovery and management
7. **Audit** (`/api/audit`) - Audit log retrieval and statistics
8. **Documentation** (`/api`) - OpenAPI/Swagger endpoints

## Using the JSON File

### For Frontend Developers

```javascript
// Example: Fetch API reference
import apiReference from './documentation/api-reference.json';

// Get all authentication endpoints
const authEndpoints = apiReference.sections.authentication.endpoints;

// Find specific endpoint
const loginEndpoint = authEndpoints.find(ep => ep.path.includes('login'));

// Get all project endpoints
const projectEndpoints = apiReference.sections.projects.endpoints;
```

### Endpoint Structure

Each endpoint includes:
- **path**: Full API path
- **methods**: Array of supported HTTP methods
- **description**: What the endpoint does
- **authentication**: Boolean indicating if auth is required
- **capabilities**: Required RBAC capabilities (object with method keys)
- **pathParams**: Path parameters (if any)
- **queryParams**: Query parameters (if any)
- **requestBody**: Request body structure (if any)
- **response**: Response structure (if documented)

### Example Endpoint

```json
{
  "path": "/api/project/projects/{id}/",
  "methods": ["GET", "PATCH", "DELETE"],
  "description": "Get project detail (GET), update project (PATCH), or delete project (DELETE)",
  "authentication": true,
  "capabilities": {
    "GET": ["project:view_company", "project:view_own"],
    "PATCH": ["project:update"],
    "DELETE": ["project:delete"]
  },
  "pathParams": {
    "id": "integer (required)"
  }
}
```

## Common Patterns

### Collection Endpoints
- **GET** `/api/{section}/{resource}/` - List all resources
- **POST** `/api/{section}/{resource}/` - Create new resource

### Item Endpoints
- **GET** `/api/{section}/{resource}/{id}/` - Get resource detail
- **PATCH** `/api/{section}/{resource}/{id}/` - Update resource
- **DELETE** `/api/{section}/{resource}/{id}/` - Delete resource

### Nested Resources
- **GET** `/api/{section}/{resource}/{id}/{nested}/` - List nested resources
- **POST** `/api/{section}/{resource}/{id}/{nested}/` - Create nested resource

### Actions
- **POST** `/api/{section}/{resource}/{id}/{action}/` - Perform action on resource

## Authentication

All authenticated endpoints require:
```
Authorization: Bearer <jwt_token>
X-Org-Id: <organization_id>
```

Obtain token via:
```
POST /api/auth/login/
```

**Note**: The `X-Org-Id` header is required for all authenticated requests. It determines:
- Which organization's data you're accessing
- What capabilities are checked (user's role in that organization)
- What data is returned (filtered to that organization)

## Capabilities (RBAC)

Endpoints may require specific capabilities:
- Format: `resource:action`
- Examples: `project:view_company`, `vuln:create`, `user:update`

## Pagination

List endpoints support pagination:
```
GET /api/project/projects/?page=1&page_size=20
```

## Filtering

Many endpoints support filtering via query parameters:
```
GET /api/project/projects/filter/?status=active&search=keyword
```

## Error Handling

Errors return JSON with appropriate HTTP status codes:
```json
{
  "error": "Error message here"
}
```

Common status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

## Tenant Scoping & Organization Context

**⚠️ IMPORTANT: All authenticated requests MUST include the `X-Org-Id` header.**

The API uses multi-tenant RBAC with organization-based data filtering:

1. **Permission Check (Allow/Deny)**: The `HasCaps` permission class checks if the user has required capabilities for the requested organization
2. **Data Filtering**: After permission is granted, all querysets are automatically filtered to only return data belonging to the specified organization

### Required Headers

```http
Authorization: Bearer <jwt_token>
X-Org-Id: <organization_id>
```

### Example Request

```bash
curl -X GET "https://api.example.com/api/project/projects/" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..." \
  -H "X-Org-Id: 123"
```

### How It Works

1. **Middleware** (`TenantMiddleware`) reads `X-Org-Id` header and validates user membership
2. **Permission Check** (`HasCaps`) verifies user has required capabilities for that organization
3. **Data Filtering** (`TenantScopedAPIView.scoped()`) automatically filters querysets by organization ID
4. **Response** contains only data belonging to the specified organization

### Error Responses

- **403 Forbidden** - Missing `X-Org-Id` header or user not a member of the organization
- **403 Forbidden** - User lacks required capabilities for the requested operation

## Frontend Implementation

For detailed frontend RBAC implementation guide, see:
- **[Frontend RBAC Implementation Guide](./FRONTEND_RBAC_IMPLEMENTATION.md)** - Complete guide on implementing RBAC in frontend applications

## Last Updated

**Date**: 2024-11-07  
**Version**: 1.0.0  
**Status**: All endpoints standardized to RESTful conventions

## Interactive Documentation

For interactive API exploration, visit:
- **Swagger UI**: `/api/docs/`
- **ReDoc**: `/api/redoc/`
- **OpenAPI Schema**: `/api/schema/`

