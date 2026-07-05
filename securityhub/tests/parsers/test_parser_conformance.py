"""
Parser conformance suite.

Every registered parser must pass this suite against a real (synthetic, non-sensitive)
sample file checked into tests/fixtures/scans/<scanner_type>/. This is the safety net
described in docs/writing-a-parser.md - it exists to catch the exact bug class found
during a manual audit: Markdown/HTML leaking into stored descriptions (nothing in the
app renders either), and evidence/PoC fields carrying the wrong data.

Adding a new parser? Add tests/fixtures/scans/<type>/sample.<ext> and an entry in
FIXTURES below - this suite runs automatically for it.
"""
import re
from pathlib import Path

import pytest

from utils.parsers.models import StandardizedFinding, SeverityLevel
from utils.parsers.registry import ParserRegistry
from utils.parsers.register_parsers import register_all_parsers

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "scans"

# scanner_type -> sample file, relative to FIXTURES_DIR
FIXTURES = {
    "nmap": "nmap/sample.xml",
    "nessus": "nessus/sample.nessus",
    "openvas": "openvas/sample.xml",
    "burp": "burp/sample.xml",
    "zap": "zap/sample.xml",
    "nuclei": "nuclei/sample.json",
    "acunetix": "acunetix/sample.json",
    "nexpose": "nexpose/sample.xml",
    "appspider": "appspider/sample.xml",
    "qualys": "qualys/sample.xml",
    "sarif": "sarif/sample.sarif",
    "trivy": "trivy/sample.json",
}

# Nothing in this app renders Markdown or HTML (frontend prints descriptions as
# plain whitespace-pre-wrap text; the docx/PDF exporter only strips HTML, not
# Markdown) - parsers must produce clean plain text.
_MARKDOWN_PATTERNS = [
    re.compile(r"```"),
    re.compile(r"^#{1,6}\s", re.MULTILINE),
    re.compile(r"\*\*\S"),
]
_HTML_TAG_PATTERN = re.compile(r"<[a-zA-Z][^>]*>")

register_all_parsers()


def _text_fields(finding: StandardizedFinding):
    for name in ("description", "evidence", "solution"):
        value = getattr(finding, name)
        if value:
            yield name, value


def test_every_registered_parser_has_a_fixture():
    registered = set(ParserRegistry.list_parsers())
    missing = registered - set(FIXTURES)
    assert not missing, (
        f"Parser(s) {sorted(missing)} are registered but have no sample fixture + "
        f"FIXTURES entry in this file. Add tests/fixtures/scans/<type>/sample.<ext> "
        f"(see docs/writing-a-parser.md)."
    )


@pytest.mark.parametrize("scanner_type,relative_path", sorted(FIXTURES.items()))
def test_parser_conformance(scanner_type, relative_path):
    fixture_path = FIXTURES_DIR / relative_path
    assert fixture_path.exists(), f"Missing fixture: {fixture_path}"

    parser = ParserRegistry.create_parser(scanner_type)
    assert parser is not None, f"No parser registered for {scanner_type!r}"

    metadata = parser.get_metadata()
    assert metadata.name, "get_metadata().name must be non-empty"
    assert metadata.version, "get_metadata().version must be non-empty"
    assert metadata.supported_formats, "get_metadata().supported_formats must be non-empty"

    assert parser.validate_file(str(fixture_path)) is True, (
        f"{scanner_type} parser's validate_file() rejected its own sample fixture"
    )

    findings = parser.parse_findings(str(fixture_path))
    assert findings, f"{scanner_type} parser returned zero findings for its sample fixture"

    for finding in findings:
        assert isinstance(finding, StandardizedFinding)
        assert finding.title and finding.title.strip(), "finding.title must be non-empty"
        assert isinstance(finding.severity, SeverityLevel), "finding.severity must be a SeverityLevel"

        for field_name, value in _text_fields(finding):
            for pattern in _MARKDOWN_PATTERNS:
                assert not pattern.search(value), (
                    f"{scanner_type} finding.{field_name} contains Markdown syntax "
                    f"({pattern.pattern!r}) - the app has no Markdown renderer, write "
                    f"plain text instead. See docs/writing-a-parser.md."
                )
            assert not _HTML_TAG_PATTERN.search(value), (
                f"{scanner_type} finding.{field_name} contains an unstripped HTML tag - "
                f"run it through self.clean_html_text() first."
            )


@pytest.mark.parametrize(
    "scanner_type,fixture_key",
    [(a, b) for a in FIXTURES for b in FIXTURES if a != b],
)
def test_parser_does_not_misdetect_other_formats(scanner_type, fixture_key):
    """A parser's validate_file() should not claim another scanner's sample file.

    ParserService.auto_detect_scanner_type() tries every registered parser in
    registration order and returns the first match, so a loose validate_file()
    on one parser can silently steal uploads meant for another.
    """
    parser = ParserRegistry.create_parser(scanner_type)
    other_fixture = FIXTURES_DIR / FIXTURES[fixture_key]

    assert parser.validate_file(str(other_fixture)) is False, (
        f"{scanner_type} parser's validate_file() incorrectly accepted the "
        f"{fixture_key!r} sample file - tighten its detection logic "
        f"(see docs/writing-a-parser.md)."
    )
