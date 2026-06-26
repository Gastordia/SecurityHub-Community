// Embedded API Reference Data
window.API_REFERENCE_DATA = {
  "api": {
    "version": "1.0.0",
    "baseUrl": "/api",
    "authentication": {
      "type": "JWT",
      "headers": {
        "Authorization": "Bearer <token>",
        "X-Org-Id": "<organization_id> - Required for all authenticated requests"
      },
      "description": "All authenticated endpoints require both Authorization and X-Org-Id headers"
    },
    "dateUpdated": "2024-11-07",
    "standardization": "All endpoints follow RESTful conventions with kebab-case naming"
  },
  "sections": {
    "authentication": {
      "name": "Authentication & Authorization",
      "basePath": "/api/auth",
      "description": "User authentication, token management, and profile operations",
      "endpoints": [
        {
          "path": "/api/auth/login/",
          "methods": [
            "POST"
          ],
          "description": "User login - Obtain JWT access and refresh tokens",
          "authentication": false,
          "requestBody": {
            "username": "string (required)",
            "password": "string (required)"
          },
          "response": {
            "access": "string (JWT token)",
            "refresh": "string (refresh token)"
          }
        },
        {
          "path": "/api/auth/token/refresh/",
          "methods": [
            "POST"
          ],
          "description": "Refresh access token using refresh token",
          "authentication": false,
          "requestBody": {
            "refresh": "string (required)"
          }
        },
        {
          "path": "/api/auth/logout/",
          "methods": [
            "GET"
          ],
          "description": "User logout",
          "authentication": true
        },
        {
          "path": "/api/auth/password/change/",
          "methods": [
            "POST"
          ],
          "description": "Change user password",
          "authentication": true,
          "capabilities": [
            "user:view_own"
          ]
        },
        {
          "path": "/api/auth/users/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List all users (GET) or create new user (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "user:view_company"
            ],
            "POST": [
              "user:create"
            ]
          },
          "queryParams": {
            "GET": [
              "page",
              "page_size",
              "search",
              "ordering"
            ]
          }
        },
        {
          "path": "/api/auth/users/active/",
          "methods": [
            "GET"
          ],
          "description": "List active users",
          "authentication": true,
          "capabilities": [
            "user:view_company"
          ]
        },
        {
          "path": "/api/auth/users/filter/",
          "methods": [
            "GET"
          ],
          "description": "Filter and search users with pagination",
          "authentication": true,
          "capabilities": [
            "user:view_company"
          ]
        },
        {
          "path": "/api/auth/users/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get user detail (GET), update user (PATCH), or delete user (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "user:view_company",
              "user:view_own"
            ],
            "PATCH": [
              "user:update"
            ],
            "DELETE": [
              "user:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/auth/profile/",
          "methods": [
            "GET",
            "PATCH"
          ],
          "description": "Get own profile (GET) or update own profile (PATCH)",
          "authentication": true,
          "capabilities": [
            "user:view_own"
          ]
        },
        {
          "path": "/api/auth/groups/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List groups (GET) or create group (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "group:view_company"
            ],
            "POST": [
              "group:create"
            ]
          }
        },
        {
          "path": "/api/auth/groups/{id}/",
          "methods": [
            "PATCH",
            "DELETE"
          ],
          "description": "Update group (PATCH) or delete group (DELETE)",
          "authentication": true,
          "capabilities": {
            "PATCH": [
              "group:update"
            ],
            "DELETE": [
              "group:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/auth/permissions/",
          "methods": [
            "GET"
          ],
          "description": "List all permissions",
          "authentication": true,
          "capabilities": [
            "perm:view_company"
          ]
        },
        {
          "path": "/api/auth/token/validate/{token}/",
          "methods": [
            "GET"
          ],
          "description": "Validate invitation or password reset token",
          "authentication": false,
          "pathParams": {
            "token": "string (required)"
          }
        },
        {
          "path": "/api/auth/token/process/{token}/",
          "methods": [
            "POST"
          ],
          "description": "Process invitation or password reset token",
          "authentication": false,
          "pathParams": {
            "token": "string (required)"
          }
        },
        {
          "path": "/api/auth/token/reset/request/",
          "methods": [
            "POST"
          ],
          "description": "Request password reset token",
          "authentication": false
        },
        {
          "path": "/api/auth/biometric/register/options/",
          "methods": [
            "POST"
          ],
          "description": "Get WebAuthn registration options",
          "authentication": true
        },
        {
          "path": "/api/auth/biometric/register/",
          "methods": [
            "POST"
          ],
          "description": "Register biometric credential",
          "authentication": true
        },
        {
          "path": "/api/auth/biometric/authenticate/options/",
          "methods": [
            "POST"
          ],
          "description": "Get WebAuthn authentication options",
          "authentication": true
        },
        {
          "path": "/api/auth/biometric/authenticate/",
          "methods": [
            "POST"
          ],
          "description": "Authenticate with biometric credential",
          "authentication": true
        },
        {
          "path": "/api/auth/biometric/credentials/",
          "methods": [
            "GET"
          ],
          "description": "List user's biometric credentials",
          "authentication": true
        },
        {
          "path": "/api/auth/biometric/credentials/{id}/",
          "methods": [
            "DELETE"
          ],
          "description": "Delete biometric credential",
          "authentication": true,
          "pathParams": {
            "id": "integer (required)"
          }
        }
      ]
    },
    "projects": {
      "name": "Projects Management",
      "basePath": "/api/project",
      "description": "Project lifecycle management, scopes, retests, and vulnerabilities",
      "endpoints": [
        {
          "path": "/api/project/projects/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List all projects (GET) or create new project (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "project:view_company"
            ],
            "POST": [
              "project:create"
            ]
          },
          "queryParams": {
            "GET": [
              "page",
              "page_size",
              "search",
              "status",
              "ordering"
            ]
          }
        },
        {
          "path": "/api/project/projects/filter/",
          "methods": [
            "GET"
          ],
          "description": "Filter and search projects with advanced filtering",
          "authentication": true,
          "capabilities": [
            "project:view_company"
          ]
        },
        {
          "path": "/api/project/projects/mine/",
          "methods": [
            "GET"
          ],
          "description": "Get current user's projects",
          "authentication": true,
          "capabilities": [
            "project:view_own"
          ]
        },
        {
          "path": "/api/project/projects/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get project dashboard statistics",
          "authentication": true,
          "capabilities": [
            "project:view_company"
          ]
        },
        {
          "path": "/api/project/projects/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get project detail (GET), update project (PATCH), or delete project (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "project:view_company",
              "project:view_own"
            ],
            "PATCH": [
              "project:update"
            ],
            "DELETE": [
              "project:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/complete/",
          "methods": [
            "POST"
          ],
          "description": "Mark project as completed",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/reopen/",
          "methods": [
            "POST"
          ],
          "description": "Reopen a completed project",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/hold/",
          "methods": [
            "POST"
          ],
          "description": "Put project on hold",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/report/",
          "methods": [
            "GET"
          ],
          "description": "Generate project report",
          "authentication": true,
          "capabilities": [
            "project:view_company",
            "project:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          },
          "queryParams": {
            "format": "string (pdf|html|docx)",
            "report_type": "string"
          }
        },
        {
          "path": "/api/project/projects/{id}/owner/",
          "methods": [
            "PATCH"
          ],
          "description": "Update project owner",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/scopes/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List project scopes (GET) or add scope (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "project:view_company",
              "project:view_own"
            ],
            "POST": [
              "project:update"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/scopes/{scope_id}/",
          "methods": [
            "PATCH",
            "DELETE"
          ],
          "description": "Update scope (PATCH) or delete scope (DELETE)",
          "authentication": true,
          "capabilities": {
            "PATCH": [
              "project:update"
            ],
            "DELETE": [
              "project:update"
            ]
          },
          "pathParams": {
            "id": "integer (required)",
            "scope_id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/scopes/upload-nmap/",
          "methods": [
            "POST"
          ],
          "description": "Upload Nmap scan file to import scopes",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          },
          "requestBody": {
            "file": "file (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/retests/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List project retests (GET) or create retest (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "project:view_company",
              "project:view_own"
            ],
            "POST": [
              "project:update"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/retests/{retest_id}/",
          "methods": [
            "DELETE"
          ],
          "description": "Delete retest",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)",
            "retest_id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/retests/{retest_id}/complete/",
          "methods": [
            "POST"
          ],
          "description": "Mark retest as completed",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)",
            "retest_id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/retests/{retest_id}/hold/",
          "methods": [
            "POST"
          ],
          "description": "Put retest on hold",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)",
            "retest_id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/vulnerabilities/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List project vulnerabilities (GET) or create vulnerability (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company",
              "vuln:view_own"
            ],
            "POST": [
              "vuln:create"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/findings/",
          "methods": [
            "GET"
          ],
          "description": "List project findings",
          "authentication": true,
          "capabilities": [
            "vuln:view_company",
            "vuln:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/vulnerabilities/publish/",
          "methods": [
            "POST"
          ],
          "description": "Publish vulnerabilities for a project",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/vulnerabilities/statistics/",
          "methods": [
            "GET"
          ],
          "description": "Get vulnerability statistics for a project",
          "authentication": true,
          "capabilities": [
            "vuln:view_company",
            "vuln:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/vulnerabilities/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get vulnerability detail (GET), update vulnerability (PATCH), or delete vulnerability (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company",
              "vuln:view_own"
            ],
            "PATCH": [
              "vuln:update"
            ],
            "DELETE": [
              "vuln:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/vulnerabilities/{id}/status/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "Get vulnerability status (GET) or update status (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company",
              "vuln:view_own"
            ],
            "POST": [
              "vuln:update"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/vulnerabilities/{id}/instances/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List vulnerability instances (GET) or create instance (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company",
              "vuln:view_own"
            ],
            "POST": [
              "vuln:create"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/vulnerabilities/{id}/instances/filter/",
          "methods": [
            "GET"
          ],
          "description": "Filter vulnerability instances",
          "authentication": true,
          "capabilities": [
            "vuln:view_company",
            "vuln:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/vulnerabilities/{id}/instances/{instance_id}/",
          "methods": [
            "PATCH",
            "DELETE"
          ],
          "description": "Update instance (PATCH) or delete instance (DELETE)",
          "authentication": true,
          "capabilities": {
            "PATCH": [
              "vuln:update"
            ],
            "DELETE": [
              "vuln:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)",
            "instance_id": "integer (required)"
          }
        },
        {
          "path": "/api/project/vulnerabilities/{id}/instances/status/",
          "methods": [
            "POST"
          ],
          "description": "Bulk update instance statuses",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          },
          "requestBody": {
            "instance_ids": "array of integers (required)",
            "status": "string (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/parser/upload/",
          "methods": [
            "POST"
          ],
          "description": "Upload parser file for a project",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          },
          "requestBody": {
            "file": "file (required)",
            "scanner_type": "string"
          }
        },
        {
          "path": "/api/project/parser/upload/",
          "methods": [
            "POST"
          ],
          "description": "Universal parser file upload",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "requestBody": {
            "file": "file (required)",
            "project_id": "integer",
            "scanner_type": "string"
          }
        },
        {
          "path": "/api/project/parser/scanners/",
          "methods": [
            "GET"
          ],
          "description": "Get list of supported scanners",
          "authentication": true
        },
        {
          "path": "/api/project/projects/{id}/scan/asset-integrated/",
          "methods": [
            "POST"
          ],
          "description": "Upload asset-integrated scan file",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/scan/supported-scanners/",
          "methods": [
            "GET"
          ],
          "description": "Get supported scanners for asset-integrated scans",
          "authentication": true
        },
        {
          "path": "/api/project/projects/{id}/assets/summary/",
          "methods": [
            "GET"
          ],
          "description": "Get project asset summary",
          "authentication": true,
          "capabilities": [
            "project:view_company",
            "project:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/projects/{id}/assets/approve/",
          "methods": [
            "POST"
          ],
          "description": "Approve out-of-scope assets",
          "authentication": true,
          "capabilities": [
            "project:update"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/project/images/upload/",
          "methods": [
            "POST"
          ],
          "description": "Upload image file",
          "authentication": true,
          "requestBody": {
            "file": "file (required)",
            "title": "string",
            "description": "string"
          }
        },
        {
          "path": "/api/project/images/{id}/",
          "methods": [
            "GET"
          ],
          "description": "Get image by ID",
          "authentication": true,
          "pathParams": {
            "id": "integer (required)"
          }
        }
      ]
    },
    "vulnerabilityDatabase": {
      "name": "Vulnerability Database",
      "basePath": "/api/vulndb",
      "description": "Vulnerability database management, CWE, and intelligence features",
      "endpoints": [
        {
          "path": "/api/vulndb/vulnerabilities/database/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List vulnerabilities (GET) or add to database (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "POST": [
              "vuln:create"
            ]
          }
        },
        {
          "path": "/api/vulndb/vulnerabilities/database/filter/",
          "methods": [
            "GET"
          ],
          "description": "Filter and search vulnerabilities",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/vulnerabilities/database/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get vulnerability from DB (GET), update (PATCH), or delete (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "PATCH": [
              "vuln:update"
            ],
            "DELETE": [
              "vuln:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/vulndb/cwe/",
          "methods": [
            "GET"
          ],
          "description": "List CWE (Common Weakness Enumeration) entries",
          "authentication": true
        },
        {
          "path": "/api/vulndb/parser/upload/",
          "methods": [
            "POST"
          ],
          "description": "Upload parser file",
          "authentication": true,
          "capabilities": [
            "vuln:create"
          ],
          "requestBody": {
            "file": "file (required)",
            "scanner_type": "string"
          }
        },
        {
          "path": "/api/vulndb/parser/upload-with-profiling/",
          "methods": [
            "POST"
          ],
          "description": "Upload parser file with asset profiling",
          "authentication": true,
          "capabilities": [
            "vuln:create"
          ],
          "requestBody": {
            "file": "file (required)",
            "scanner_type": "string",
            "enable_profiling": "boolean"
          }
        },
        {
          "path": "/api/vulndb/parser/universal-upload/",
          "methods": [
            "POST"
          ],
          "description": "Universal parser upload supporting multiple formats",
          "authentication": true,
          "capabilities": [
            "vuln:create"
          ]
        },
        {
          "path": "/api/vulndb/parser/scanners/",
          "methods": [
            "GET"
          ],
          "description": "Get supported scanners",
          "authentication": true
        },
        {
          "path": "/api/vulndb/intelligence/assets/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get asset intelligence dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/assets/dashboard/{project_id}/",
          "methods": [
            "GET"
          ],
          "description": "Get project-specific asset intelligence dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "project_id": "integer (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/assets/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List assets (GET) or create/update asset (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "POST": [
              "vuln:create"
            ]
          }
        },
        {
          "path": "/api/vulndb/intelligence/assets/{id}/",
          "methods": [
            "GET",
            "DELETE"
          ],
          "description": "Get asset by ID (GET) or delete asset (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "DELETE": [
              "vuln:delete"
            ]
          },
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/assets/{id}/report/",
          "methods": [
            "GET"
          ],
          "description": "Get asset intelligence report",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/assets/{id}/vulnerability-analysis/",
          "methods": [
            "GET"
          ],
          "description": "Get asset vulnerability analysis",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/assets/correlate/",
          "methods": [
            "POST"
          ],
          "description": "Correlate assets with vulnerabilities",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/assets/bulk/",
          "methods": [
            "POST"
          ],
          "description": "Bulk asset operations",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/threats/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get threat intelligence dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/threats/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List threats (GET) or create/update threat (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "POST": [
              "vuln:create"
            ]
          }
        },
        {
          "path": "/api/vulndb/intelligence/threats/{id}/",
          "methods": [
            "GET",
            "DELETE"
          ],
          "description": "Get threat by ID (GET) or delete threat (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "DELETE": [
              "vuln:delete"
            ]
          },
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/threats/{id}/report/",
          "methods": [
            "GET"
          ],
          "description": "Get threat intelligence report",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/threats/search/",
          "methods": [
            "GET"
          ],
          "description": "Search threats",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/threats/correlate/",
          "methods": [
            "POST"
          ],
          "description": "Correlate threats with vulnerabilities",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/threats/analyze-patterns/",
          "methods": [
            "POST"
          ],
          "description": "Analyze threat patterns",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/threats/bulk/",
          "methods": [
            "POST"
          ],
          "description": "Bulk threat operations",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/indicators/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List indicators (GET) or create/update indicator (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "POST": [
              "vuln:create"
            ]
          }
        },
        {
          "path": "/api/vulndb/intelligence/indicators/{id}/",
          "methods": [
            "GET",
            "DELETE"
          ],
          "description": "Get indicator by ID (GET) or delete indicator (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "vuln:view_company"
            ],
            "DELETE": [
              "vuln:delete"
            ]
          },
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/correlation/analyze/",
          "methods": [
            "POST"
          ],
          "description": "Perform correlation analysis",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/correlation/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get correlation dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/correlation/report/{report_type}/",
          "methods": [
            "GET"
          ],
          "description": "Get correlation report",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "report_type": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/correlation/recommendations/",
          "methods": [
            "GET"
          ],
          "description": "Get correlation recommendations",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/correlation/export/",
          "methods": [
            "GET"
          ],
          "description": "Export correlation data",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/",
          "methods": [
            "POST"
          ],
          "description": "Create asset profile",
          "authentication": true,
          "capabilities": [
            "vuln:create"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/bulk/",
          "methods": [
            "POST"
          ],
          "description": "Bulk profile assets",
          "authentication": true,
          "capabilities": [
            "vuln:create"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/{asset_id}/summary/",
          "methods": [
            "GET"
          ],
          "description": "Get asset intelligence summary",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "asset_id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/{asset_id}/timeline/",
          "methods": [
            "GET"
          ],
          "description": "Get asset evolution timeline",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "asset_id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/{asset_id}/enrich/",
          "methods": [
            "POST"
          ],
          "description": "Enrich asset from vulnerabilities",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ],
          "pathParams": {
            "asset_id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/cleanup-stale/",
          "methods": [
            "POST"
          ],
          "description": "Cleanup stale profiles",
          "authentication": true,
          "capabilities": [
            "vuln:delete"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/profiling/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get dynamic profiling dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/{asset_id}/",
          "methods": [
            "PATCH"
          ],
          "description": "Update asset profile",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ],
          "pathParams": {
            "asset_id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/profiling/projects/{project_id}/assets/",
          "methods": [
            "GET"
          ],
          "description": "Get project asset profiles",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "project_id": "integer (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/profiling/assets/bulk-update/",
          "methods": [
            "POST"
          ],
          "description": "Bulk update asset profiles",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/fusion/fuse/",
          "methods": [
            "POST"
          ],
          "description": "Fuse intelligence data",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/fusion/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get fusion dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/fusion/dashboard/{project_id}/",
          "methods": [
            "GET"
          ],
          "description": "Get project fusion dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "project_id": "integer (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/fusion/metrics/",
          "methods": [
            "GET"
          ],
          "description": "Get fusion metrics",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/fusion/attack-scenarios/",
          "methods": [
            "POST"
          ],
          "description": "Generate attack scenarios",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/fusion/recommendations/",
          "methods": [
            "GET"
          ],
          "description": "Get prioritized recommendations",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/fusion/summary/",
          "methods": [
            "GET"
          ],
          "description": "Get fusion summary",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        },
        {
          "path": "/api/vulndb/intelligence/enhanced/cve/{cve_id}/",
          "methods": [
            "GET"
          ],
          "description": "Get comprehensive vulnerability intelligence for CVE",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "cve_id": "string (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/enhanced/vulnerabilities/{vuln_db_id}/enrich/",
          "methods": [
            "POST"
          ],
          "description": "Enrich vulnerability intelligence",
          "authentication": true,
          "capabilities": [
            "vuln:update"
          ],
          "pathParams": {
            "vuln_db_id": "integer (required)"
          }
        },
        {
          "path": "/api/vulndb/intelligence/enhanced/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get intelligence dashboard",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ]
        }
      ]
    },
    "customers": {
      "name": "Customers & Companies",
      "basePath": "/api/customer",
      "description": "Company and customer management, analytics, and dashboards",
      "endpoints": [
        {
          "path": "/api/customer/companies/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List companies (GET) or create company (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "customer:view_company"
            ],
            "POST": [
              "customer:create"
            ]
          }
        },
        {
          "path": "/api/customer/companies/filter/",
          "methods": [
            "GET"
          ],
          "description": "Filter and search companies",
          "authentication": true,
          "capabilities": [
            "customer:manage_company"
          ]
        },
        {
          "path": "/api/customer/companies/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get company detail (GET), update company (PATCH), or delete company (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "customer:view_company"
            ],
            "PATCH": [
              "customer:update"
            ],
            "DELETE": [
              "customer:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/companies/{id}/projects/status/",
          "methods": [
            "GET"
          ],
          "description": "Get project status details for company",
          "authentication": true,
          "capabilities": [
            "project:view_company",
            "project:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/companies/{id}/projects/last-findings/",
          "methods": [
            "GET"
          ],
          "description": "Get last ten vulnerabilities for company",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/companies/{id}/projects/vulnerability/trends/",
          "methods": [
            "GET"
          ],
          "description": "Get vulnerability dashboard stats for company",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/companies/{id}/projects/vulnerability/statistics/",
          "methods": [
            "GET"
          ],
          "description": "Get organization vulnerability statistics",
          "authentication": true,
          "capabilities": [
            "vuln:view_company"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/companies/{id}/projects/",
          "methods": [
            "GET"
          ],
          "description": "Get all projects for a company",
          "authentication": true,
          "capabilities": [
            "project:view_company",
            "project:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/companies/{id}/projects/completed/",
          "methods": [
            "GET"
          ],
          "description": "Get completed projects for company",
          "authentication": true,
          "capabilities": [
            "project:view_company",
            "project:view_own"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/customers/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List customers (GET) or create customer (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "customer:view_company"
            ],
            "POST": [
              "customer:create"
            ]
          }
        },
        {
          "path": "/api/customer/customers/filter/",
          "methods": [
            "GET"
          ],
          "description": "Filter and search customers",
          "authentication": true,
          "capabilities": [
            "customer:view_company"
          ]
        },
        {
          "path": "/api/customer/customers/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get customer detail (GET), update customer (PATCH), or delete customer (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "customer:view_company"
            ],
            "PATCH": [
              "customer:update"
            ],
            "DELETE": [
              "customer:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/customer/token/invitation/resend/{user_id}/",
          "methods": [
            "POST"
          ],
          "description": "Resend invitation email",
          "authentication": true,
          "capabilities": [
            "user:manage_company"
          ],
          "pathParams": {
            "user_id": "integer (required)"
          }
        }
      ]
    },
    "configuration": {
      "name": "Configuration",
      "basePath": "/api/config",
      "description": "System configuration: report standards, project types, and health checks",
      "endpoints": [
        {
          "path": "/api/config/report-standards/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List report standards (GET) or create standard (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "config:view_company"
            ],
            "POST": [
              "config:create"
            ]
          }
        },
        {
          "path": "/api/config/report-standards/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get standard (GET), update standard (PATCH), or delete standard (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "config:view_company"
            ],
            "PATCH": [
              "config:update"
            ],
            "DELETE": [
              "config:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/config/project-types/",
          "methods": [
            "GET",
            "POST"
          ],
          "description": "List project types (GET) or create type (POST)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "config:view_company"
            ],
            "POST": [
              "config:create"
            ]
          }
        },
        {
          "path": "/api/config/project-types/{id}/",
          "methods": [
            "GET",
            "PATCH",
            "DELETE"
          ],
          "description": "Get type (GET), update type (PATCH), or delete type (DELETE)",
          "authentication": true,
          "capabilities": {
            "GET": [
              "config:view_company"
            ],
            "PATCH": [
              "config:update"
            ],
            "DELETE": [
              "config:delete"
            ]
          },
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/config/ping/",
          "methods": [
            "GET"
          ],
          "description": "Health check endpoint",
          "authentication": false
        }
      ]
    },
    "assets": {
      "name": "Asset Management",
      "basePath": "/api/assets",
      "description": "Asset discovery, management, and tracking",
      "endpoints": [
        {
          "path": "/api/assets/assets/",
          "methods": [
            "GET"
          ],
          "description": "Search and list assets",
          "authentication": true,
          "capabilities": [
            "asset:view_company"
          ]
        },
        {
          "path": "/api/assets/assets/discover/",
          "methods": [
            "POST"
          ],
          "description": "Discover assets from scan",
          "authentication": true,
          "capabilities": [
            "asset:create"
          ]
        },
        {
          "path": "/api/assets/assets/dashboard/",
          "methods": [
            "GET"
          ],
          "description": "Get asset dashboard data",
          "authentication": true,
          "capabilities": [
            "asset:view_company"
          ]
        },
        {
          "path": "/api/assets/assets/{id}/",
          "methods": [
            "GET"
          ],
          "description": "Get asset details",
          "authentication": true,
          "capabilities": [
            "asset:view_company"
          ],
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/assets/assets/{id}/history/",
          "methods": [
            "GET"
          ],
          "description": "Get asset discovery history",
          "authentication": true,
          "capabilities": [
            "asset:view_company"
          ],
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/assets/assets/{id}/approve/",
          "methods": [
            "POST"
          ],
          "description": "Approve out-of-scope asset",
          "authentication": true,
          "capabilities": [
            "asset:update"
          ],
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/assets/assets/{id}/exclude/",
          "methods": [
            "POST"
          ],
          "description": "Exclude asset from project",
          "authentication": true,
          "capabilities": [
            "asset:update"
          ],
          "pathParams": {
            "id": "string (required)"
          }
        },
        {
          "path": "/api/assets/projects/{project_id}/assets/",
          "methods": [
            "GET"
          ],
          "description": "Get project assets",
          "authentication": true,
          "capabilities": [
            "asset:view_company"
          ],
          "pathParams": {
            "project_id": "integer (required)"
          }
        },
        {
          "path": "/api/assets/projects/{project_id}/assets/summary/",
          "methods": [
            "GET"
          ],
          "description": "Get project assets summary",
          "authentication": true,
          "capabilities": [
            "asset:view_company"
          ],
          "pathParams": {
            "project_id": "integer (required)"
          }
        }
      ]
    },
    "audit": {
      "name": "Audit Logs",
      "basePath": "/api/audit",
      "description": "Audit log retrieval and statistics",
      "endpoints": [
        {
          "path": "/api/audit/audit-logs/",
          "methods": [
            "GET"
          ],
          "description": "List audit logs with filtering and pagination",
          "authentication": true,
          "capabilities": [
            "audit:view_company"
          ],
          "queryParams": {
            "user_id": "integer",
            "action": "string",
            "resource_type": "string",
            "start_date": "datetime",
            "end_date": "datetime",
            "page": "integer",
            "page_size": "integer"
          }
        },
        {
          "path": "/api/audit/audit-logs/{id}/",
          "methods": [
            "GET"
          ],
          "description": "Get audit log detail",
          "authentication": true,
          "capabilities": [
            "audit:view_company"
          ],
          "pathParams": {
            "id": "integer (required)"
          }
        },
        {
          "path": "/api/audit/audit-logs/statistics/",
          "methods": [
            "GET"
          ],
          "description": "Get audit log statistics",
          "authentication": true,
          "capabilities": [
            "audit:view_company"
          ],
          "queryParams": {
            "start_date": "datetime",
            "end_date": "datetime"
          }
        }
      ]
    },
    "documentation": {
      "name": "API Documentation",
      "basePath": "/api",
      "description": "OpenAPI/Swagger documentation endpoints",
      "endpoints": [
        {
          "path": "/api/schema/",
          "methods": [
            "GET"
          ],
          "description": "Get OpenAPI schema",
          "authentication": false
        },
        {
          "path": "/api/docs/",
          "methods": [
            "GET"
          ],
          "description": "Swagger UI documentation",
          "authentication": false
        },
        {
          "path": "/api/redoc/",
          "methods": [
            "GET"
          ],
          "description": "ReDoc documentation",
          "authentication": false
        }
      ]
    }
  },
  "capabilities": {
    "description": "RBAC capabilities required for endpoints. Format: 'resource:action'",
    "common": {
      "view_company": "View all resources in organization",
      "view_own": "View own resources only",
      "create": "Create new resources",
      "update": "Update existing resources",
      "delete": "Delete resources",
      "manage_company": "Full management access"
    },
    "resources": [
      "user",
      "project",
      "vuln",
      "customer",
      "config",
      "asset",
      "audit",
      "group",
      "perm"
    ]
  },
  "commonPatterns": {
    "collection": {
      "pattern": "/api/{section}/{resource}/",
      "methods": [
        "GET",
        "POST"
      ],
      "description": "GET lists all, POST creates new"
    },
    "item": {
      "pattern": "/api/{section}/{resource}/{id}/",
      "methods": [
        "GET",
        "PATCH",
        "DELETE"
      ],
      "description": "GET retrieves, PATCH updates, DELETE removes"
    },
    "nested": {
      "pattern": "/api/{section}/{resource}/{id}/{nested}/",
      "methods": [
        "GET",
        "POST"
      ],
      "description": "Nested resources under parent"
    },
    "action": {
      "pattern": "/api/{section}/{resource}/{id}/{action}/",
      "methods": [
        "POST"
      ],
      "description": "Custom actions on resources"
    }
  },
    "notes": {
    "authentication": "Most endpoints require JWT authentication via Authorization header AND X-Org-Id header",
    "requiredHeaders": {
      "Authorization": "Bearer <jwt_token> - Required for authenticated endpoints",
      "X-Org-Id": "<organization_id> - Required for all authenticated requests. Determines organization context and data filtering."
    },
    "pagination": "List endpoints support ?page=1&page_size=20 query parameters",
    "filtering": "Many endpoints support filtering via query parameters",
    "standardization": "All endpoints follow RESTful conventions with consistent naming",
    "errorHandling": "Errors return JSON with 'error' or 'message' field and appropriate HTTP status codes",
    "tenantScoping": {
      "description": "RBAC system performs both permission checks AND data filtering",
      "permissionCheck": "HasCaps permission class checks if user has required capabilities for the organization",
      "dataFiltering": "TenantScopedAPIView automatically filters all querysets by organization ID",
      "requiredHeader": "X-Org-Id header is REQUIRED - without it, requests return 403 Forbidden",
      "example": "GET /api/project/projects/ with X-Org-Id: 123 returns only projects where organization_id=123"
    }
  }
};
