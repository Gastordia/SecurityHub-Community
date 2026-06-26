from __future__ import annotations

from pathlib import Path
from typing import Any

from django.conf import settings


BUNDLED_DOCX_TEMPLATES: dict[int, dict[str, Any]] = {
    900000001: {
        "id": 900000001,
        "name": "Tests d'intrusion Externes 2026",
        "description": "Template DOCX style INEOS pour rapports de tests d'intrusion externes.",
        "format": "docx",
        "category": "technical",
        "filename": "Template_Tests-d'intrusion_Externe_2026.docx",
        "variant": "external",
    },
    900000002: {
        "id": 900000002,
        "name": "Tests d'intrusion Internes 2026",
        "description": "Template DOCX style INEOS pour rapports de tests d'intrusion internes.",
        "format": "docx",
        "category": "technical",
        "filename": "Template_Tests-d'intrusion_Interne_2026.docx",
        "variant": "internal",
    },
}


def get_bundled_docx_template(template_id: int | None) -> dict[str, Any] | None:
    if template_id is None:
        return None
    template = BUNDLED_DOCX_TEMPLATES.get(int(template_id))
    if not template:
        return None

    path = Path(settings.BASE_DIR) / "templates" / "bundled_docx" / template["filename"]
    if not path.is_file():
        return None

    return {
        **template,
        "path": str(path),
    }


def list_bundled_docx_templates(
    *,
    format_filter: str | None = None,
    category_filter: str | None = None,
    is_public_filter: bool | None = None,
    search_query: str | None = None,
) -> list[dict[str, Any]]:
    if format_filter and format_filter not in {"docx", "word"}:
        return []
    if category_filter and category_filter != "technical":
        return []
    if is_public_filter is False:
        return []

    results: list[dict[str, Any]] = []
    search = (search_query or "").strip().lower()

    for template_id in sorted(BUNDLED_DOCX_TEMPLATES):
        template = get_bundled_docx_template(template_id)
        if not template:
            continue
        haystack = f"{template['name']} {template['description']}".lower()
        if search and search not in haystack:
            continue
        results.append(serialize_bundled_docx_template(template))

    return results


def serialize_bundled_docx_template(template: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": template["id"],
        "name": template["name"],
        "description": template["description"],
        "format": "docx",
        "category": template["category"],
        "tags": ["bundled", "docx", template["variant"]],
        "content": "",
        "variables_schema": {},
        "settings": {"bundled_docx": True, "variant": template["variant"]},
        "current_version": 1,
        "is_active": True,
        "is_public": True,
        "is_system_template": True,
        "created_by": 0,
        "created_by_email": "system@bundled.local",
        "organization": None,
        "organization_name": None,
        "created_at": None,
        "updated_at": None,
        "last_used_at": None,
        "usage_count": 0,
        "thumbnail_path": None,
        "rating": 0.0,
        "rating_count": 0,
    }
