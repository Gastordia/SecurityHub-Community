// Auto-generated endpoint data
const ENDPOINT_DATA = [
  {
    "id": "core_1_1",
    "number": "1.1",
    "name": "Vulndbfilter",
    "type": "Class-based ViewSet (DRF)",
    "category": "core",
    "path": "",
    "method": "",
    "capability": "`vuln:view_company` OR `vuln:create`",
    "description": "Lists all vulnerabilities with search/filter capabilities Creates new vulnerability entries Uses DRF ViewSet pattern with search filtering",
    "howItWorks": [
      "Inherits from `TenantScopedModelViewSet` (automatic tenant scoping)",
      "Uses tenant-aware caching (`all_vuln_data:org={org_id}`)",
      "Filters by `scope` field (legacy tenant isolation using `organization.company.name`)",
      "Supports search by `vulnerabilityname` field",
      "Returns paginated results via DRF pagination"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB` (from `vulnerability.models`)"
      },
      {
        "type": "serializer",
        "name": "`VulnDBserializers`"
      },
      {
        "type": "filter",
        "name": "`VulnerableDBFilter` (from `utils.filters`)"
      },
      {
        "type": "cache",
        "name": "Django cache framework"
      },
      {
        "type": "base class",
        "name": "`TenantScopedModelViewSet` (provides tenant scoping)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Core models exist, serializer works, tenant scoping implemented \u26a0\ufe0f **ISSUE**: Uses legacy `scope` field instead of `organization` field for tenant isolation \u2705 Cache is tenant-aware (prevents cross-tenant data leakage) \u2705 Audit logging implemented \u2705 Input validation via base class",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Uses legacy `scope` field instead of `organization` field for tenant isolation"
      }
    ]
  },
  {
    "id": "core_1_2",
    "number": "1.2",
    "name": "Vulndbdata",
    "type": "Function-based view",
    "category": "core",
    "path": "/api/vulndb/database/?title=<vulnerability_name>",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Searches for a vulnerability by exact title/name match Returns single vulnerability entry or empty array",
    "howItWorks": [
      "Gets `title` from query parameter `?title=`",
      "Retrieves tenant-scoped queryset from cache (or builds it)",
      "Filters by `vulnerabilityname=title` and returns first match",
      "Uses `VulnDBfetchserializers` for serialization"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "serializer",
        "name": "`VulnDBfetchserializers`"
      },
      {
        "type": "cache",
        "name": "Tenant-aware cache key"
      },
      {
        "type": "service",
        "name": "None (direct model access)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Simple query endpoint, all dependencies exist \u2705 Tenant scoping implemented \u2705 Audit logging implemented \u26a0\ufe0f **LIMITATION**: Only exact name match, no fuzzy search",
    "issues": [
      {
        "type": "LIMITATION",
        "message": "\u26a0\ufe0f  Only exact name match, no fuzzy search"
      }
    ]
  },
  {
    "id": "core_1_3",
    "number": "1.3",
    "name": "getallVulndbdata",
    "type": "Function-based view",
    "category": "core",
    "path": "/api/vulndb/all-vulndb",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns ALL vulnerabilities for the tenant (no pagination) Uses cached queryset for performance",
    "howItWorks": [
      "Retrieves tenant-scoped queryset from cache",
      "If cache miss, builds queryset and filters by `scope` field",
      "Serializes all results (no pagination - could be memory intensive)",
      "Returns complete list"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "serializer",
        "name": "`VulnDBfetchserializers` (many=True)"
      },
      {
        "type": "cache",
        "name": "Tenant-aware cache"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **PERFORMANCE RISK** \u26a0\ufe0f **ISSUE**: No pagination - could return thousands of records \u26a0\ufe0f **ISSUE**: May cause memory issues with large datasets \u2705 Tenant scoping implemented \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No pagination - could return thousands of records"
      },
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  May cause memory issues with large datasets"
      }
    ]
  },
  {
    "id": "core_1_4",
    "number": "1.4",
    "name": "getallVulndbdata_filter",
    "type": "Function-based view",
    "category": "core",
    "path": "/api/vulndb/all-vulndb/filter?<filters>",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns filtered vulnerabilities with pagination Uses `VulnerableDBFilter` for advanced filtering Returns paginated results",
    "howItWorks": [
      "Gets tenant-scoped queryset from cache",
      "Applies `VulnerableDBFilter` with request.GET parameters",
      "Uses `paginate_queryset` utility for pagination",
      "Returns paginated response with metadata"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "filter",
        "name": "`VulnerableDBFilter` (from `utils.filters`)"
      },
      {
        "type": "pagination",
        "name": "`paginate_queryset` utility"
      },
      {
        "type": "serializer",
        "name": "`VulnDBfetchserializers`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Proper pagination, filtering, tenant scoping \u2705 Better than `getallVulndbdata` (has pagination) \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "core_1_5",
    "number": "1.5",
    "name": "getvulndb",
    "type": "Function-based view",
    "category": "core",
    "path": "/api/vulndb/<pk>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Retrieves a single vulnerability by primary key Returns detailed vulnerability information",
    "howItWorks": [
      "Validates `pk` parameter (must be positive integer)",
      "Applies tenant scoping before query (prevents IDOR)",
      "Filters by `scope` field matching organization",
      "Returns first match or 404"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "serializer",
        "name": "`VulnDBfetchserializers`"
      },
      {
        "type": "validation",
        "name": "`validate_id_parameter`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Simple detail endpoint \u2705 IDOR protection via tenant scoping \u2705 Input validation implemented \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "core_1_6",
    "number": "1.6",
    "name": "add_vulndb",
    "type": "Function-based view",
    "category": "core",
    "path": "/api/vulndb/add-vulndb",
    "method": "POST",
    "capability": "`vuln:create`",
    "description": "Creates a new vulnerability entry in VulnerabilityDB Sets scope field for tenant isolation",
    "howItWorks": [
      "Validates request data via serializer",
      "Creates `VulnerabilityDB` instance",
      "Sets `scope` field from `organization.company.name` (legacy tenant isolation)",
      "Clears tenant-aware cache",
      "Returns created vulnerability data"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "serializer",
        "name": "`VulnDBfetchserializers` (for validation)"
      },
      {
        "type": "cache",
        "name": "Clears tenant-aware cache on create"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Standard CRUD create operation \u26a0\ufe0f **ISSUE**: Uses legacy `scope` field instead of `organization` field \u2705 Audit logging implemented \u2705 Cache invalidation implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Uses legacy `scope` field instead of `organization` field"
      }
    ]
  },
  {
    "id": "core_1_7",
    "number": "1.7",
    "name": "edit_vulndb",
    "type": "Function-based view",
    "category": "core",
    "path": "/api/vulndb/edit-vulndb/<pk>/",
    "method": "POST",
    "capability": "`vuln:update`",
    "description": "Updates an existing vulnerability entry Validates tenant ownership before update",
    "howItWorks": [
      "Validates `pk` parameter",
      "Applies tenant scoping to queryset (prevents IDOR)",
      "Retrieves vulnerability if exists in tenant scope",
      "Updates fields from request data",
      "Clears tenant-aware cache",
      "Logs old/new values for audit"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "serializer",
        "name": "`VulnDBfetchserializers` (for validation)"
      },
      {
        "type": "validation",
        "name": "`validate_id_parameter`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Standard CRUD update operation \u2705 IDOR protection via tenant scoping \u2705 Audit logging with change tracking \u2705 Cache invalidation implemented",
    "issues": []
  },
  {
    "id": "core_1_8",
    "number": "1.8",
    "name": "delete_vulndb",
    "type": "Function-based view",
    "category": "core",
    "path": "/api/vulndb/delete-vulndb",
    "method": "DELETE",
    "capability": "`vuln:delete`",
    "description": "Deletes one or multiple vulnerabilities Accepts list of IDs in request body",
    "howItWorks": [
      "Validates request data contains IDs",
      "Validates each ID parameter",
      "Applies tenant scoping before deletion (prevents IDOR)",
      "Deletes only vulnerabilities in tenant scope",
      "Clears tenant-aware cache",
      "Returns count of deleted items"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "validation",
        "name": "`validate_id_parameter` (for each ID)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Standard bulk delete operation \u2705 IDOR protection via tenant scoping \u2705 Input validation for all IDs \u2705 Audit logging with deletion details \u2705 Cache invalidation implemented",
    "issues": []
  },
  {
    "id": "core_1_9",
    "number": "1.9",
    "name": "CWEListAPIView",
    "type": "Class-based APIView",
    "category": "core",
    "path": "/api/vulndb/cwe/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns list of CWE (Common Weakness Enumeration) data Reads from static JSON file",
    "howItWorks": [
      "Checks tenant-aware cache first",
      "If cache miss, reads `data/cwe.json` file",
      "Caches data for 30 days",
      "Returns JSON data"
    ],
    "dependencies": [
      {
        "type": "file",
        "name": "`settings.BASE_DIR/data/cwe.json` (static file)"
      },
      {
        "type": "cache",
        "name": "Tenant-aware cache (though CWE data is public)"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **DEPENDENCY**: Requires `data/cwe.json` file to exist \u26a0\ufe0f **ISSUE**: Returns 404 if file doesn't exist (no fallback) \u2705 Cache implemented (though not strictly necessary for public data) \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Returns 404 if file doesn't exist (no fallback)"
      }
    ]
  },
  {
    "id": "upload_2_1",
    "number": "2.1",
    "name": "upload_parser_file",
    "type": "Function-based view",
    "category": "upload",
    "path": "/api/vulndb/upload-parser/",
    "method": "POST",
    "capability": "`project:update` OR `vuln:create`",
    "description": "Uploads and parses scanner files (Nessus, OpenVAS, etc.) Optionally performs asset profiling if `project_id` provided Returns standardized findings",
    "howItWorks": [
      "Validates file upload (MIME type, size max 50MB)",
      "Validates `project_id` if provided",
      "Uses `ParserService` to:",
      "Optionally calls `parse_file_with_asset_profiling` if `project_id` provided",
      "Returns findings count, scanner type, and parsed data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`ParserService` (from `utils.services.parser_service`)"
      },
      {
        "type": "parser registry",
        "name": "`ParserRegistry` (dynamically discovers parsers)"
      },
      {
        "type": "file validation",
        "name": "`validate_file_upload` (checks MIME type, size)"
      },
      {
        "type": "models",
        "name": "None directly (parser returns data, doesn't save)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Core parsing works \u2705 File validation implemented \u2705 Auto-detection works \u26a0\ufe0f **DEPENDENCY**: Requires parser registry to have parsers registered \u26a0\ufe0f **DEPENDENCY**: Requires `MEDIA_ROOT/temp/` directory for temporary file storage \u2705 Asset profiling integration available (optional)",
    "issues": [
      {
        "type": "DEPENDENCY",
        "message": "\u26a0\ufe0f  Requires parser registry to have parsers registered"
      },
      {
        "type": "DEPENDENCY",
        "message": "\u26a0\ufe0f  Requires `MEDIA_ROOT/temp/` directory for temporary file storage"
      }
    ]
  },
  {
    "id": "upload_2_2",
    "number": "2.2",
    "name": "universal_upload",
    "type": "Function-based view",
    "category": "upload",
    "path": "/api/vulndb/universal-upload/",
    "method": "POST",
    "capability": "`project:update` OR `vuln:create`",
    "description": "Universal upload endpoint that: Parses scanner file Performs asset profiling Saves vulnerabilities to both `VulnerabilityDB` and project `Vulnerability` models Updates project scope with asset data",
    "howItWorks": [
      "Validates file upload",
      "Requires `project_id` (mandatory)",
      "Validates project exists and belongs to tenant",
      "Calls `ParserService.parse_file_with_asset_profiling()`",
      "For each finding:",
      "Returns comprehensive response with counts"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`ParserService`"
      },
      {
        "type": "model",
        "name": "`VulnerabilityDB` (global template)"
      },
      {
        "type": "model",
        "name": "`Vulnerability` (from `project.models`, project-specific)"
      },
      {
        "type": "model",
        "name": "`Project` (must exist and belong to tenant)"
      },
      {
        "type": "service",
        "name": "Asset profiling via `ParserService`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Complete workflow implemented \u2705 Tenant scoping on project lookup \u2705 Dual saving (template + project-specific) \u2705 Asset profiling integrated \u26a0\ufe0f **COMPLEXITY**: Multiple operations, error handling needed \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "upload_2_3",
    "number": "2.3",
    "name": "upload_parser_file_with_asset_profiling",
    "type": "Function-based view",
    "category": "upload",
    "path": "/api/vulndb/upload-parser-with-profiling/",
    "method": "POST",
    "capability": "`project:update`",
    "description": "Uploads and parses scanner file with mandatory asset profiling Requires `project_id` (unlike `upload_parser_file`)",
    "howItWorks": [
      "Validates file upload",
      "Requires `project_id` (mandatory)",
      "Validates `project_id`",
      "Calls `ParserService.parse_file_with_asset_profiling()`",
      "Returns findings with asset profiling data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`ParserService`"
      },
      {
        "type": "model",
        "name": "`Project` (for asset profiling context)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Similar to `universal_upload` but simpler \u26a0\ufe0f **REDUNDANCY**: Overlaps with `upload_parser_file` and `universal_upload` \u2705 Asset profiling mandatory (consistent behavior) \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "upload_2_4",
    "number": "2.4",
    "name": "get_supported_scanners",
    "type": "Function-based view",
    "category": "upload",
    "path": "/api/vulndb/supported-scanners/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns list of supported scanner types with metadata Used by frontend to show available scanner options",
    "howItWorks": [
      "Creates `ParserService` instance",
      "Calls `get_supported_scanners()` method",
      "Returns list of scanner types with metadata (name, description, file types, etc.)"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`ParserService`"
      },
      {
        "type": "parser registry",
        "name": "Must have parsers registered"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Simple endpoint \u26a0\ufe0f **DEPENDENCY**: Requires parser registry to be initialized \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "DEPENDENCY",
        "message": "\u26a0\ufe0f  Requires parser registry to be initialized"
      }
    ]
  },
  {
    "id": "asset_3_1",
    "number": "3.1",
    "name": "asset_intelligence_dashboard",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/dashboard/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns dashboard data for asset intelligence Shows asset statistics, criticality distribution, etc.",
    "howItWorks": [
      "Calls `asset_intelligence_service.get_asset_dashboard_data()`",
      "Returns aggregated dashboard statistics"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`asset_intelligence_service` (singleton instance)"
      },
      {
        "type": "model",
        "name": "`AssetIntelligence` (used by service)"
      },
      {
        "type": "model",
        "name": "`VulnerabilityDB` (for correlation)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "asset_3_2",
    "number": "3.2",
    "name": "project_asset_intelligence_dashboard",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/dashboard/<project_id>/",
    "method": "GET",
    "capability": "`project:view_company`",
    "description": "Returns project-scoped asset intelligence dashboard Shows assets, criticality, vulnerabilities for a specific project",
    "howItWorks": [
      "Validates `project_id` parameter",
      "Retrieves project with tenant scoping",
      "Extracts asset profiles from `project.standard['asset_profiles']` (JSON field)",
      "Calculates statistics:",
      "Calculates risk level based on critical assets and vulnerabilities",
      "Returns dashboard data"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`Project` (from `project.models`)"
      },
      {
        "type": "model",
        "name": "`VulnerabilityDB` (filtered by scope=project.name)"
      },
      {
        "type": "service",
        "name": "`DynamicAssetProfilingService` (imported but not used)"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **ARCHITECTURAL ISSUE** \u26a0\ufe0f **ISSUE**: Reads asset profiles from `project.standard` JSON field (not from `AssetIntelligence` model) \u26a0\ufe0f **ISSUE**: Uses project name for vulnerability filtering (legacy scope field) \u26a0\ufe0f **ISSUE**: Service imported but not used (unused import) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Tenant scoping implemented \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Reads asset profiles from `project.standard` JSON field (not from `AssetIntelligence` model)"
      },
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Uses project name for vulnerability filtering (legacy scope field)"
      },
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Service imported but not used (unused import)"
      }
    ]
  },
  {
    "id": "asset_3_3",
    "number": "3.3",
    "name": "asset_intelligence_report",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/<asset_id>/report/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns comprehensive intelligence report for a specific asset Includes vulnerability analysis, threat context, etc.",
    "howItWorks": [
      "Validates `asset_id` (can be string or integer)",
      "Calls `asset_intelligence_service.get_asset_intelligence_report(asset_id)`",
      "Returns detailed report or error if asset not found"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`asset_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`get_asset_intelligence_report()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "asset_3_4",
    "number": "3.4",
    "name": "create_or_update_asset",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/create/",
    "method": "POST",
    "capability": "`vuln:create`",
    "description": "Creates or updates an asset in `AssetIntelligence` model Handles both create and update in single endpoint",
    "howItWorks": [
      "Gets asset data from request body",
      "Calls `asset_intelligence_service.create_or_update_asset(asset_data)`",
      "Service uses `get_or_create()` pattern",
      "Returns serialized asset data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`asset_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`create_or_update_asset()` (verified exists)"
      },
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "serializer",
        "name": "`AssetIntelligenceSerializer`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Service method exists and works \u2705 Service handles create/update logic \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "asset_3_5",
    "number": "3.5",
    "name": "asset_vulnerability_analysis",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/<asset_id>/vulnerability-analysis/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns detailed vulnerability analysis for a specific asset Shows which vulnerabilities affect the asset",
    "howItWorks": [
      "Validates `asset_id`",
      "Calls `asset_intelligence_service.get_asset_vulnerability_analysis(asset_id)`",
      "Returns analysis or error if asset not found"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`asset_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`get_asset_vulnerability_analysis()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "model",
        "name": "`VulnerabilityDB` (for correlation)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend (but used in test file) \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "asset_3_6",
    "number": "3.6",
    "name": "get_all_assets",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/?<filters>",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns paginated list of all assets with optional filtering Supports filtering by: asset_type, business_criticality, status, cloud_platform",
    "howItWorks": [
      "Builds Django Q query from GET parameters",
      "Filters `AssetIntelligence.objects` by query",
      "Orders by `asset_intelligence_score` (descending)",
      "Paginates results (default 50 per page)",
      "Returns paginated response with metadata"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "pagination",
        "name": "Django `Paginator`"
      },
      {
        "type": "serializer",
        "name": "`AssetIntelligenceSerializer`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Standard list endpoint with filtering \u26a0\ufe0f **ISSUE**: No tenant scoping applied (global asset list) \u26a0\ufe0f **SECURITY ISSUE**: Assets may leak across tenants if not properly scoped \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping applied (global asset list)"
      }
    ]
  },
  {
    "id": "asset_3_7",
    "number": "3.7",
    "name": "get_asset_by_id",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/<asset_id>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Retrieves a single asset by asset_id (not database PK)",
    "howItWorks": [
      "Uses `AssetIntelligence.objects.get(asset_id=asset_id)`",
      "Returns serialized asset data or 404"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "serializer",
        "name": "`AssetIntelligenceSerializer`"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **SECURITY ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - can access any asset by ID (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can access any asset by ID (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "asset_3_8",
    "number": "3.8",
    "name": "delete_asset",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/<asset_id>/delete/",
    "method": "DELETE",
    "capability": "`vuln:delete`",
    "description": "Deletes an asset from AssetIntelligence model",
    "howItWorks": [
      "Gets asset by `asset_id`",
      "Deletes asset",
      "Returns success message"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **SECURITY ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - can delete any asset (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can delete any asset (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "asset_3_9",
    "number": "3.9",
    "name": "correlate_assets_with_vulnerabilities",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/correlate/",
    "method": "POST",
    "capability": "`vuln:view_company`",
    "description": "Correlates assets with vulnerabilities Updates asset intelligence scores based on vulnerabilities",
    "howItWorks": [
      "Calls `asset_intelligence_service.correlate_assets_with_vulnerabilities()`",
      "Service performs correlation analysis",
      "Returns correlation results"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`asset_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`correlate_assets_with_vulnerabilities()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "asset_3_10",
    "number": "3.10",
    "name": "bulk_asset_operations",
    "type": "Function-based view",
    "category": "asset",
    "path": "/api/vulndb/assets/bulk-operations/",
    "method": "POST",
    "capability": "`vuln:update`",
    "description": "Performs bulk operations on multiple assets Supported operations: `update_criticality`, `recalculate_scores`",
    "howItWorks": [
      "Gets `operation` and `asset_ids` from request",
      "For `update_criticality`:",
      "For `recalculate_scores`:",
      "Returns results with success/error for each asset"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "methods",
        "name": "`calculate_asset_intelligence_score()`, `update_vulnerability_counts()`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Bulk operations work \u26a0\ufe0f **ISSUE**: No tenant scoping - can operate on any assets (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can operate on any assets (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "threat_4_1",
    "number": "4.1",
    "name": "threat_intelligence_dashboard",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/dashboard/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns dashboard data for threat intelligence Shows threat statistics, trends, etc.",
    "howItWorks": [
      "Calls `threat_intelligence_service.get_threat_dashboard_data()`",
      "Returns aggregated dashboard statistics"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`threat_intelligence_service` (singleton instance)"
      },
      {
        "type": "method",
        "name": "`get_threat_dashboard_data()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "threat_4_2",
    "number": "4.2",
    "name": "threat_intelligence_report",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/<threat_id>/report/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns comprehensive intelligence report for a specific threat",
    "howItWorks": [
      "Validates `threat_id`",
      "Calls `threat_intelligence_service.get_threat_intelligence_report(threat_id)`",
      "Returns detailed report or error"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`threat_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`get_threat_intelligence_report()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "threat_4_3",
    "number": "4.3",
    "name": "create_or_update_threat",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/create/",
    "method": "POST",
    "capability": "`vuln:create`",
    "description": "Creates or updates a threat in `ThreatIntelligence` model",
    "howItWorks": [
      "Gets threat data from request",
      "Calls `threat_intelligence_service.create_or_update_threat(threat_data)`",
      "Service uses `get_or_create()` pattern",
      "Calculates threat score",
      "Returns serialized threat data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`threat_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`create_or_update_threat()` (verified exists)"
      },
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      },
      {
        "type": "serializer",
        "name": "`ThreatIntelligenceSerializer`"
      },
      {
        "type": "method",
        "name": "`calculate_threat_score()` (on model)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Service method exists and works \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "threat_4_4",
    "number": "4.4",
    "name": "create_or_update_indicator",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/indicators/create/",
    "method": "POST",
    "capability": "`vuln:create`",
    "description": "Creates or updates a threat indicator in `ThreatIndicator` model",
    "howItWorks": [
      "Gets indicator data from request",
      "Calls `threat_intelligence_service.create_or_update_indicator(indicator_data)`",
      "Returns serialized indicator data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`threat_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`create_or_update_indicator()` (verified exists)"
      },
      {
        "type": "model",
        "name": "`ThreatIndicator`"
      },
      {
        "type": "serializer",
        "name": "`ThreatIndicatorSerializer`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Service method exists \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "threat_4_5",
    "number": "4.5",
    "name": "search_threats",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/search/?q=<query>&<filters>",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Searches threats based on query and filters Supports multiple filter parameters",
    "howItWorks": [
      "Extracts query parameter `q`",
      "Builds filters dict from GET parameters",
      "Calls `threat_intelligence_service.search_threats(query, filters)`",
      "Returns search results"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`threat_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`search_threats()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "threat_4_6",
    "number": "4.6",
    "name": "get_all_threats",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/?<filters>",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns paginated list of all threats with optional filtering",
    "howItWorks": [
      "Builds Django Q query from GET parameters",
      "Filters `ThreatIntelligence.objects` by query",
      "Orders by `threat_score` (descending)",
      "Paginates results",
      "Returns paginated response"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      },
      {
        "type": "pagination",
        "name": "Django `Paginator`"
      },
      {
        "type": "serializer",
        "name": "`ThreatIntelligenceSummarySerializer`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Standard list endpoint \u26a0\ufe0f **ISSUE**: No tenant scoping applied (global threat list) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping applied (global threat list)"
      }
    ]
  },
  {
    "id": "threat_4_7",
    "number": "4.7",
    "name": "get_threat_by_id",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/<threat_id>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Retrieves a single threat by threat_id",
    "howItWorks": [
      "Uses `ThreatIntelligence.objects.get(threat_id=threat_id)`",
      "Returns serialized threat data or 404"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      },
      {
        "type": "serializer",
        "name": "`ThreatIntelligenceSerializer`"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **SECURITY ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - can access any threat (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can access any threat (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "threat_4_8",
    "number": "4.8",
    "name": "delete_threat",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/<threat_id>/delete/",
    "method": "DELETE",
    "capability": "`vuln:delete`",
    "description": "Deletes a threat from ThreatIntelligence model",
    "howItWorks": [
      "Gets threat by `threat_id`",
      "Deletes threat",
      "Returns success message"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **SECURITY ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - can delete any threat (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can delete any threat (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "threat_4_9",
    "number": "4.9",
    "name": "correlate_threats_with_vulnerabilities",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/correlate/",
    "method": "POST",
    "capability": "`vuln:view_company`",
    "description": "Correlates threats with vulnerabilities and assets",
    "howItWorks": [
      "Calls `threat_intelligence_service.correlate_threats_with_vulnerabilities()`",
      "Returns correlation results"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`threat_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`correlate_threats_with_vulnerabilities()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      },
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "threat_4_10",
    "number": "4.10",
    "name": "analyze_threat_patterns",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/analyze-patterns/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Analyzes threat patterns and trends",
    "howItWorks": [
      "Calls `threat_intelligence_service.analyze_threat_patterns()`",
      "Returns pattern analysis"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`threat_intelligence_service`"
      },
      {
        "type": "method",
        "name": "`analyze_threat_patterns()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": []
  },
  {
    "id": "threat_4_11",
    "number": "4.11",
    "name": "bulk_threat_operations",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/threats/bulk-operations/",
    "method": "POST",
    "capability": "`vuln:update`",
    "description": "Performs bulk operations on multiple threats Supported operations: `update_status`, `recalculate_scores`",
    "howItWorks": [
      "Gets `operation` and `threat_ids` from request",
      "For each threat:",
      "Returns results with success/error for each threat"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`ThreatIntelligence`"
      },
      {
        "type": "method",
        "name": "`calculate_threat_score()` (on model)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Bulk operations work \u26a0\ufe0f **ISSUE**: No tenant scoping - can operate on any threats (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can operate on any threats (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "threat_4_12",
    "number": "4.12",
    "name": "get_all_indicators",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/indicators/?<filters>",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns paginated list of threat indicators with optional filtering",
    "howItWorks": [
      "Builds Django Q query from GET parameters",
      "Filters `ThreatIndicator.objects` by query",
      "Orders by `observation_count` (descending)",
      "Paginates results",
      "Returns paginated response"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`ThreatIndicator`"
      },
      {
        "type": "pagination",
        "name": "Django `Paginator`"
      },
      {
        "type": "serializer",
        "name": "`ThreatIndicatorSerializer`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Standard list endpoint \u26a0\ufe0f **ISSUE**: No tenant scoping applied (global indicator list) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping applied (global indicator list)"
      }
    ]
  },
  {
    "id": "threat_4_13",
    "number": "4.13",
    "name": "get_indicator_by_id",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/indicators/<indicator_id>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Retrieves a single threat indicator by indicator_id",
    "howItWorks": [
      "Uses `ThreatIndicator.objects.get(indicator_id=indicator_id)`",
      "Returns serialized indicator data or 404"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`ThreatIndicator`"
      },
      {
        "type": "serializer",
        "name": "`ThreatIndicatorSerializer`"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **SECURITY ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - can access any indicator (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can access any indicator (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "threat_4_14",
    "number": "4.14",
    "name": "delete_indicator",
    "type": "Function-based view",
    "category": "threat",
    "path": "/api/vulndb/indicators/<indicator_id>/delete/",
    "method": "DELETE",
    "capability": "`vuln:delete`",
    "description": "Deletes a threat indicator",
    "howItWorks": [
      "Gets indicator by `indicator_id`",
      "Deletes indicator",
      "Returns success message"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`ThreatIndicator`"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **SECURITY ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - can delete any indicator (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Audit logging implemented",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can delete any indicator (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "correlation_5_1",
    "number": "5.1",
    "name": "perform_correlation_analysis",
    "type": "Function-based view",
    "category": "correlation",
    "path": "/api/vulndb/correlation/analyze/",
    "method": "POST",
    "capability": "`vuln:view_company`",
    "description": "Performs comprehensive multi-dimensional correlation analysis Correlates vulnerabilities, assets, and threats across multiple dimensions",
    "howItWorks": [
      "Gets optional parameters: `vulnerability_ids`, `asset_ids`, `threat_ids`",
      "Calls `correlation_engine.correlate_vulnerabilities_assets_threats()`",
      "Engine performs:",
      "Returns comprehensive correlation results"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`correlation_engine` (from `utils.services.correlation_engine`)"
      },
      {
        "type": "class",
        "name": "`MultiDimensionalCorrelationEngine`"
      },
      {
        "type": "method",
        "name": "`correlate_vulnerabilities_assets_threats()` (verified exists)"
      },
      {
        "type": "models",
        "name": "`VulnerabilityDB`, `AssetIntelligence`, `ThreatIntelligence`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Engine exists and method implemented \u26a0\ufe0f **COMPLEXITY**: Heavy computation - may be slow with large datasets \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u26a0\ufe0f **ISSUE**: No tenant scoping on input parameters (may correlate across tenants)",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping on input parameters (may correlate across tenants)"
      }
    ]
  },
  {
    "id": "correlation_5_2",
    "number": "5.2",
    "name": "get_correlation_dashboard",
    "type": "Function-based view",
    "category": "correlation",
    "path": "/api/vulndb/correlation/dashboard/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns correlation dashboard data Shows summary statistics and top risk clusters",
    "howItWorks": [
      "Calls `correlation_engine.correlate_vulnerabilities_assets_threats()` (full analysis)",
      "Extracts dashboard-specific data:",
      "Returns formatted dashboard data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`correlation_engine`"
      },
      {
        "type": "method",
        "name": "`correlate_vulnerabilities_assets_threats()`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Uses same correlation engine \u26a0\ufe0f **PERFORMANCE**: Runs full correlation analysis (may be slow) \u26a0\ufe0f **ISSUE**: No tenant scoping - may show data from all tenants \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - may show data from all tenants"
      }
    ]
  },
  {
    "id": "correlation_5_3",
    "number": "5.3",
    "name": "get_correlation_report",
    "type": "Function-based view",
    "category": "correlation",
    "path": "/api/vulndb/correlation/report/<report_type>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns specific correlation report by type Supported types: `technical`, `business`, `threat_intelligence`, `risk_clusters`, `attack_paths`",
    "howItWorks": [
      "Validates `report_type` parameter",
      "Calls `correlation_engine.correlate_vulnerabilities_assets_threats()` (full analysis)",
      "Extracts specific report type from results",
      "Returns formatted report"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`correlation_engine`"
      },
      {
        "type": "method",
        "name": "`correlate_vulnerabilities_assets_threats()`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Uses correlation engine \u26a0\ufe0f **PERFORMANCE**: Runs full correlation for each report type \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "correlation_5_4",
    "number": "5.4",
    "name": "get_correlation_recommendations",
    "type": "Function-based view",
    "category": "correlation",
    "path": "/api/vulndb/correlation/recommendations/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns prioritized recommendations based on correlation analysis",
    "howItWorks": [
      "Calls `correlation_engine.correlate_vulnerabilities_assets_threats()`",
      "Extracts recommendations from correlation results",
      "Returns prioritized list"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`correlation_engine`"
      },
      {
        "type": "method",
        "name": "`correlate_vulnerabilities_assets_threats()`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Uses correlation engine \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "correlation_5_5",
    "number": "5.5",
    "name": "export_correlation_data",
    "type": "Function-based view",
    "category": "correlation",
    "path": "/api/vulndb/correlation/export/",
    "method": "POST",
    "capability": "`vuln:view_company`",
    "description": "Exports correlation data in various formats Supports CSV, JSON export",
    "howItWorks": [
      "Gets export format from request",
      "Performs correlation analysis",
      "Formats data for export",
      "Returns export file or data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`correlation_engine`"
      },
      {
        "type": "export utilities",
        "name": "Not specified"
      }
    ],
    "status": "\u26a0\ufe0f **PARTIALLY FUNCTIONAL** - Export logic may be incomplete \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "profiling_6_1",
    "number": "6.1",
    "name": "create_asset_profile",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/dynamic-profiling/create-profile/",
    "method": "POST",
    "capability": "`vuln:create`",
    "description": "Creates or updates an asset profile within a project Uses DynamicAssetProfilingService",
    "howItWorks": [
      "Gets `project_id` and `asset_data` from request",
      "Calls `DynamicAssetProfilingService.create_or_update_asset_profile(project_id, asset_data)`",
      "Service:",
      "Returns created/updated profile"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`DynamicAssetProfilingService` (from `utils.services.dynamic_asset_profiling_service`)"
      },
      {
        "type": "method",
        "name": "`create_or_update_asset_profile()` (verified exists)"
      },
      {
        "type": "model",
        "name": "`Project` (stores profiles in JSON field)"
      },
      {
        "type": "service",
        "name": "`IntelligenceEngine` (used by profiling service)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Service exists and works \u2705 Uses project JSON field for storage (project-scoped) \u26a0\ufe0f **ARCHITECTURE**: Stores in JSON field, not in AssetIntelligence model \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": []
  },
  {
    "id": "profiling_6_2",
    "number": "6.2",
    "name": "bulk_profile_assets",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/dynamic-profiling/bulk-profile/",
    "method": "POST",
    "capability": "`vuln:create`",
    "description": "Bulk profiles multiple assets at once Uses `dynamic_asset_profiling` service (from `utils.services.dynamic_asset_profiling`)",
    "howItWorks": [
      "Gets `assets` array from request body",
      "Gets optional `source` parameter (defaults to 'api')",
      "Calls `dynamic_asset_profiling.bulk_profile_assets(assets_data, source)`",
      "Returns bulk processing results"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`dynamic_asset_profiling` (from `utils.services.dynamic_asset_profiling`)"
      },
      {
        "type": "method",
        "name": "`bulk_profile_assets()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`AssetIntelligence` (used by service)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u26a0\ufe0f **ISSUE**: Uses different service (`dynamic_asset_profiling`) than `update_asset_profile` (uses `DynamicAssetProfilingService`)",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Uses different service (`dynamic_asset_profiling`) than `update_asset_profile` (uses `DynamicAssetProfilingService`)"
      }
    ]
  },
  {
    "id": "profiling_6_3",
    "number": "6.3",
    "name": "get_asset_intelligence_summary",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/dynamic-profiling/summary/<asset_id>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns comprehensive intelligence summary for an asset Shows enriched data from vulnerabilities",
    "howItWorks": [
      "Gets asset by `asset_id` from `AssetIntelligence` model",
      "Calls `dynamic_asset_profiling.get_asset_intelligence_summary(asset)`",
      "Returns summary data"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "service",
        "name": "`dynamic_asset_profiling`"
      },
      {
        "type": "method",
        "name": "`get_asset_intelligence_summary()` (need to verify exists)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **ISSUE**: No tenant scoping - can access any asset (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - can access any asset (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "profiling_6_4",
    "number": "6.4",
    "name": "get_asset_evolution_timeline",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/dynamic-profiling/evolution/<asset_id>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns timeline of asset profile evolution Shows how asset profile has changed over time",
    "howItWorks": [
      "Gets asset by `asset_id`",
      "Calls `dynamic_asset_profiling.get_asset_evolution_timeline(asset)`",
      "Returns timeline data"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "service",
        "name": "`dynamic_asset_profiling`"
      },
      {
        "type": "method",
        "name": "`get_asset_evolution_timeline()` (need to verify exists)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **ISSUE**: No tenant scoping (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "profiling_6_5",
    "number": "6.5",
    "name": "enrich_asset_from_vulnerabilities",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/dynamic-profiling/enrich/<asset_id>/",
    "method": "POST",
    "capability": "`vuln:update`",
    "description": "Manually triggers asset enrichment from vulnerabilities Updates asset intelligence based on related vulnerabilities",
    "howItWorks": [
      "Gets asset by `asset_id`",
      "Calls `dynamic_asset_profiling.enrich_asset_from_vulnerabilities(asset)`",
      "Returns enrichment results"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      },
      {
        "type": "model",
        "name": "`VulnerabilityDB` (for correlation)"
      },
      {
        "type": "service",
        "name": "`dynamic_asset_profiling`"
      },
      {
        "type": "method",
        "name": "`enrich_asset_from_vulnerabilities()` (need to verify exists)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **ISSUE**: No tenant scoping (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "profiling_6_6",
    "number": "6.6",
    "name": "cleanup_stale_profiles",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/dynamic-profiling/cleanup/",
    "method": "POST",
    "capability": "`vuln:delete`",
    "description": "Cleans up stale asset profiles Removes profiles that haven't been updated in specified days",
    "howItWorks": [
      "Gets `days_old` parameter from request (defaults to 90)",
      "Calls `dynamic_asset_profiling.cleanup_stale_profiles(days_old)`",
      "Returns cleanup results"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`dynamic_asset_profiling`"
      },
      {
        "type": "method",
        "name": "`cleanup_stale_profiles()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u26a0\ufe0f **ISSUE**: No tenant scoping - may clean up assets from other tenants",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - may clean up assets from other tenants"
      }
    ]
  },
  {
    "id": "profiling_6_7",
    "number": "6.7",
    "name": "get_dynamic_profiling_dashboard",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/dynamic-profiling/dashboard/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns dashboard data for dynamic asset profiling system Shows asset statistics, recent updates, source diversity",
    "howItWorks": [
      "Queries `AssetIntelligence` model directly:",
      "Calculates stale assets count",
      "Returns dashboard data"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`AssetIntelligence`"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **ARCHITECTURAL ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - shows global asset statistics \u26a0\ufe0f **ISSUE**: Direct model access (bypasses service layer) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - shows global asset statistics"
      },
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Direct model access (bypasses service layer)"
      }
    ]
  },
  {
    "id": "profiling_6_8",
    "number": "6.8",
    "name": "update_asset_profile",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/asset-profiling/update/",
    "method": "POST",
    "capability": "`vuln:update`",
    "description": "Updates asset profile with new data from scanner/parser Uses `DynamicAssetProfilingService` (project-scoped)",
    "howItWorks": [
      "Requires `project_id` and `asset_data` from request",
      "Creates `DynamicAssetProfilingService()` instance",
      "Calls `create_or_update_asset_profile(project_id, asset_data)`",
      "Service stores profile in `project.standard['asset_profiles']` JSON field",
      "Returns updated profile"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`DynamicAssetProfilingService` (from `utils.services.dynamic_asset_profiling_service`)"
      },
      {
        "type": "method",
        "name": "`create_or_update_asset_profile()` (verified exists)"
      },
      {
        "type": "model",
        "name": "`Project` (stores profiles in JSON field)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Service exists and works \u2705 Project-scoped (tenant isolation via project) \u26a0\ufe0f **ARCHITECTURE**: Different from `create_asset_profile` (uses different service) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": []
  },
  {
    "id": "profiling_6_9",
    "number": "6.9",
    "name": "get_project_asset_profiles",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/asset-profiling/project/?project_id=<id>",
    "method": "GET",
    "capability": "`project:view_company`",
    "description": "Returns all asset profiles for a specific project",
    "howItWorks": [
      "Gets `project_id` from query parameter",
      "Creates `DynamicAssetProfilingService()` instance",
      "Calls `get_project_asset_profiles(project_id)`",
      "Returns list of asset profiles"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`DynamicAssetProfilingService`"
      },
      {
        "type": "method",
        "name": "`get_project_asset_profiles()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`Project` (reads from JSON field)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Project-scoped (tenant isolation via project)",
    "issues": []
  },
  {
    "id": "profiling_6_10",
    "number": "6.10",
    "name": "get_asset_evolution_timeline",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/asset-profiling/evolution/?project_id=<id>&asset_id=<id>",
    "method": "GET",
    "capability": "`project:view_company`",
    "description": "Returns asset evolution timeline for a project-scoped asset",
    "howItWorks": [
      "Gets `project_id` and `asset_id` from query parameters",
      "Creates `DynamicAssetProfilingService()` instance",
      "Calls `get_asset_evolution_timeline(project_id, asset_id)`",
      "Returns timeline data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`DynamicAssetProfilingService`"
      },
      {
        "type": "method",
        "name": "`get_asset_evolution_timeline()` (need to verify exists)"
      },
      {
        "type": "model",
        "name": "`Project` (reads from JSON field)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused \u2705 Project-scoped",
    "issues": []
  },
  {
    "id": "profiling_6_11",
    "number": "6.11",
    "name": "bulk_update_asset_profiles",
    "type": "Function-based view",
    "category": "profiling",
    "path": "/api/vulndb/asset-profiling/bulk-update/",
    "method": "POST",
    "capability": "`project:update`",
    "description": "Bulk updates multiple asset profiles for a project",
    "howItWorks": [
      "Requires `project_id` and `asset_data_list` from request",
      "Creates `DynamicAssetProfilingService()` instance",
      "Loops through each asset data",
      "Calls `create_or_update_asset_profile()` for each",
      "Returns results with success/error for each asset"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`DynamicAssetProfilingService`"
      },
      {
        "type": "method",
        "name": "`create_or_update_asset_profile()` (verified exists)"
      },
      {
        "type": "model",
        "name": "`Project`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Bulk operations work \u2705 Project-scoped \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": []
  },
  {
    "id": "fusion_7_1",
    "number": "7.1",
    "name": "fuse_intelligence_data",
    "type": "Function-based view",
    "category": "fusion",
    "path": "/api/vulndb/fusion/fuse/",
    "method": "POST",
    "capability": "`vuln:view_company`",
    "description": "Fuses intelligence data from all three engines (vulnerability, asset, threat) Combines data to provide unified risk assessments",
    "howItWorks": [
      "Creates `IntelligenceFusionEngine()` instance",
      "Gets optional parameters: `vulnerability_ids`, `asset_ids`, `threat_ids`, `scope`, `project_id`",
      "Validates `scope` parameter (must be: 'all', 'critical', 'high', 'medium', 'low')",
      "Calls `fusion_engine.fuse_intelligence_data()` with parameters",
      "Returns comprehensive fusion results including:"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`IntelligenceFusionEngine` (from `utils.services.intelligence_fusion_engine`)"
      },
      {
        "type": "method",
        "name": "`fuse_intelligence_data()` (verified exists)"
      },
      {
        "type": "models",
        "name": "`VulnerabilityDB`, `AssetIntelligence`, `ThreatIntelligence`"
      },
      {
        "type": "services",
        "name": "Uses `universal_intelligence_engine`, `AssetIntelligenceService`, `ThreatIntelligenceService`, `MultiDimensionalCorrelationEngine`"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Engine exists and method implemented \u26a0\ufe0f **COMPLEXITY**: Heavy computation - combines multiple engines \u26a0\ufe0f **ISSUE**: No tenant scoping on input parameters (may fuse across tenants) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping on input parameters (may fuse across tenants)"
      }
    ]
  },
  {
    "id": "fusion_7_2",
    "number": "7.2",
    "name": "get_fusion_dashboard_data",
    "type": "Function-based view",
    "category": "fusion",
    "path": "/api/vulndb/fusion/dashboard/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns dashboard data for intelligence fusion",
    "howItWorks": [
      "Creates `IntelligenceFusionEngine()` instance",
      "Calls `fusion_engine.get_fusion_dashboard_data()`",
      "Returns dashboard data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`IntelligenceFusionEngine`"
      },
      {
        "type": "method",
        "name": "`get_fusion_dashboard_data()` (need to verify exists)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "fusion_7_3",
    "number": "7.3",
    "name": "get_project_fusion_dashboard_data",
    "type": "Function-based view",
    "category": "fusion",
    "path": "/api/vulndb/fusion/dashboard/<project_id>/",
    "method": "GET",
    "capability": "`project:view_company`",
    "description": "Returns project-scoped fusion dashboard data",
    "howItWorks": [
      "Retrieves project by `project_id` (no tenant scoping - IDOR risk!)",
      "Creates `IntelligenceFusionEngine()` instance",
      "Calls `fusion_engine.get_fusion_dashboard_data(project_id=project_id)`",
      "Adds project metadata to response"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`Project` (from `project.models`)"
      },
      {
        "type": "service",
        "name": "`IntelligenceFusionEngine`"
      },
      {
        "type": "method",
        "name": "`get_fusion_dashboard_data()` with project_id parameter"
      }
    ],
    "status": "\u26a0\ufe0f **SECURITY ISSUE**: No tenant scoping on project lookup (IDOR vulnerability) \u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: Method with project_id parameter \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": []
  },
  {
    "id": "fusion_7_4",
    "number": "7.4",
    "name": "get_fusion_metrics",
    "type": "Function-based view",
    "category": "fusion",
    "path": "/api/vulndb/fusion/metrics/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns fusion metrics and statistics",
    "howItWorks": [
      "Creates `IntelligenceFusionEngine()` instance",
      "Calls `fusion_engine.get_fusion_metrics()`",
      "Returns metrics data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`IntelligenceFusionEngine`"
      },
      {
        "type": "method",
        "name": "`get_fusion_metrics()` (need to verify exists)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "fusion_7_5",
    "number": "7.5",
    "name": "generate_attack_scenarios",
    "type": "Function-based view",
    "category": "fusion",
    "path": "/api/vulndb/fusion/attack-scenarios/",
    "method": "POST",
    "capability": "`vuln:view_company`",
    "description": "Generates attack scenarios from current intelligence data",
    "howItWorks": [
      "Creates `IntelligenceFusionEngine()` instance",
      "Gets `scope` and `max_scenarios` parameters from request",
      "Calls `fusion_engine.fuse_intelligence_data(scope=scope)`",
      "Extracts `attack_scenarios` from fusion results",
      "Limits scenarios to `max_scenarios` if specified",
      "Returns attack scenarios"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`IntelligenceFusionEngine`"
      },
      {
        "type": "method",
        "name": "`fuse_intelligence_data()` (verified exists)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Uses fusion engine \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "fusion_7_6",
    "number": "7.6",
    "name": "get_prioritized_recommendations",
    "type": "Function-based view",
    "category": "fusion",
    "path": "/api/vulndb/fusion/recommendations/",
    "method": "POST",
    "capability": "`vuln:view_company`",
    "description": "Returns prioritized recommendations from fusion analysis",
    "howItWorks": [
      "Creates `IntelligenceFusionEngine()` instance",
      "Gets `scope`, `max_recommendations`, and optional `priority_filter` from request",
      "Calls `fusion_engine.fuse_intelligence_data(scope=scope)`",
      "Extracts `recommendations` from fusion results",
      "Filters by priority if specified",
      "Limits to `max_recommendations` if specified",
      "Returns prioritized recommendations"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`IntelligenceFusionEngine`"
      },
      {
        "type": "method",
        "name": "`fuse_intelligence_data()` (verified exists)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Uses fusion engine \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "fusion_7_7",
    "number": "7.7",
    "name": "get_fusion_summary",
    "type": "Function-based view",
    "category": "fusion",
    "path": "/api/vulndb/fusion/summary/?scope=<scope>",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns fusion summary for current intelligence state",
    "howItWorks": [
      "Creates `IntelligenceFusionEngine()` instance",
      "Gets `scope` from query parameter (defaults to 'all')",
      "Calls `fusion_engine.fuse_intelligence_data(scope=scope)`",
      "Extracts `fusion_summary` from results",
      "Returns summary data"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`IntelligenceFusionEngine`"
      },
      {
        "type": "method",
        "name": "`fuse_intelligence_data()` (verified exists)"
      }
    ],
    "status": "\u2705 **FULLY FUNCTIONAL** - Uses fusion engine \u26a0\ufe0f **ISSUE**: No tenant scoping \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping"
      }
    ]
  },
  {
    "id": "intelligence_8_1",
    "number": "8.1",
    "name": "get_comprehensive_vulnerability_intelligence",
    "type": "Function-based view",
    "category": "intelligence",
    "path": "/api/vulndb/intelligence/<cve_id>/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns comprehensive intelligence for a specific CVE Uses enhanced intelligence engine with KEVin API integration",
    "howItWorks": [
      "Gets `cve_id` from URL parameter",
      "Calls `enhanced_intelligence_engine.get_comprehensive_vulnerability_intelligence(cve_id)`",
      "Returns intelligence data including:"
    ],
    "dependencies": [
      {
        "type": "service",
        "name": "`enhanced_intelligence_engine` (from `utils.services.intelligence_engine`)"
      },
      {
        "type": "method",
        "name": "`get_comprehensive_vulnerability_intelligence()` (need to verify exists)"
      },
      {
        "type": "external apis",
        "name": "CISA KEV, EPSS, NVD, Exploit DB"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **DEPENDENCY**: Requires external API access (KEVin, EPSS, NVD) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "DEPENDENCY",
        "message": "\u26a0\ufe0f  Requires external API access (KEVin, EPSS, NVD)"
      }
    ]
  },
  {
    "id": "intelligence_8_2",
    "number": "8.2",
    "name": "enrich_vulnerability_intelligence",
    "type": "Function-based view",
    "category": "intelligence",
    "path": "/api/vulndb/intelligence/enrich/<vuln_db_id>/",
    "method": "POST",
    "capability": "`vuln:update`",
    "description": "Triggers intelligence enrichment for a specific vulnerability Queues background job for enrichment",
    "howItWorks": [
      "Validates vulnerability exists in `VulnerabilityDB`",
      "Checks if vulnerability has CVE associated",
      "Calls `IntelligenceJobManager.enrich_single_vulnerability(vuln_db_id)`",
      "Returns task ID for tracking"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "service",
        "name": "`IntelligenceJobManager` (from `utils.services.intelligence_background_jobs`)"
      },
      {
        "type": "method",
        "name": "`enrich_single_vulnerability()` (need to verify exists)"
      },
      {
        "type": "background tasks",
        "name": "Celery (assumed)"
      }
    ],
    "status": "\u26a0\ufe0f **DEPENDENCY CHECK NEEDED**: \u26a0\ufe0f **ISSUE**: No tenant scoping on vulnerability lookup (IDOR vulnerability) \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping on vulnerability lookup (IDOR vulnerability)"
      }
    ]
  },
  {
    "id": "intelligence_8_3",
    "number": "8.3",
    "name": "get_intelligence_dashboard",
    "type": "Function-based view",
    "category": "intelligence",
    "path": "/api/vulndb/intelligence/dashboard/",
    "method": "GET",
    "capability": "`vuln:view_company`",
    "description": "Returns intelligence dashboard with comprehensive statistics Shows enrichment status, KEV vulnerabilities, risk scores",
    "howItWorks": [
      "Calls `IntelligenceJobManager.generate_report()` (queues background job)",
      "Queries `VulnerabilityDB` directly for statistics:",
      "Gets top 10 risk vulnerabilities (ordered by `final_intelligence_score`)",
      "Returns dashboard data with overview, threat intelligence stats, and top risk list",
      "Includes `report_task_id` for tracking background report generation"
    ],
    "dependencies": [
      {
        "type": "model",
        "name": "`VulnerabilityDB`"
      },
      {
        "type": "service",
        "name": "`IntelligenceJobManager` (from `utils.services.intelligence_background_jobs`)"
      },
      {
        "type": "method",
        "name": "`generate_report()` (need to verify exists)"
      },
      {
        "type": "background tasks",
        "name": "Celery (assumed)"
      }
    ],
    "status": "\u2705 **FUNCTIONAL** but \u26a0\ufe0f **ARCHITECTURAL ISSUE** \u26a0\ufe0f **ISSUE**: No tenant scoping - shows global vulnerability statistics \u26a0\ufe0f **ISSUE**: Direct model access (bypasses service layer) \u26a0\ufe0f **ISSUE**: References fields that may not exist on `VulnerabilityDB` model: \u26a0\ufe0f **DEPENDENCY**: Requires `IntelligenceJobManager` service \u26a0\ufe0f **USAGE**: Not found in frontend - may be unused",
    "issues": [
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  No tenant scoping - shows global vulnerability statistics"
      },
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  Direct model access (bypasses service layer)"
      },
      {
        "type": "ISSUE",
        "message": "\u26a0\ufe0f  References fields that may not exist on `VulnerabilityDB` model:"
      },
      {
        "type": "DEPENDENCY",
        "message": "\u26a0\ufe0f  Requires `IntelligenceJobManager` service"
      }
    ]
  }
];
