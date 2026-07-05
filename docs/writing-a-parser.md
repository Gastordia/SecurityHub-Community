# Writing a scanner parser

SecurityHub turns uploaded scan reports into `Vulnerability` records via a small,
self-contained parser per scanner. This doc is the contract a parser must follow,
written after a manual audit found the same class of bug in six different parsers
(Markdown/HTML leaking into stored text, and evidence fields carrying the wrong
data) — read the "Common pitfalls" section even if you skip the rest.

## Where parsers live

Each scanner is one package under `securityhub/utils/parsers/<scanner_type>/`,
containing at least a `parser.py` with a class that inherits from `BaseParser`
(`securityhub/utils/parsers/base.py`). Existing parsers (`nmap`, `nessus`,
`openvas`, `burp`, `zap`, `nuclei`, `acunetix`, `nexpose`, `appspider`, `qualys`,
`sarif`, `trivy`) are the best reference implementations — skim two or three of
them before starting, especially one that parses the same file format
(XML/CSV/JSON) as your target scanner.

## The interface

`BaseParser` requires three methods:

```python
class YourScannerParser(BaseParser):
    def get_metadata(self) -> ParserMetadata:
        """Name, version, description, supported file extensions."""

    def validate_file(self, file_path: str) -> bool:
        """Return True only if this file is unambiguously YOUR format."""

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse the file and return one StandardizedFinding per vulnerability."""
```

`BaseParser` also gives you helpers you should prefer over rolling your own:
`clean_html_text()` (HTML → plain text, Markdown emphasis already disabled),
`extract_cve_ids()` / `extract_cwe_ids()` (regex extraction), and
`validate_file_extension()`.

### `validate_file()` must not be generic

Uploads are auto-detected by trying every registered parser's `validate_file()`
in registration order and using the **first** one that returns `True`
(`ParserService.auto_detect_scanner_type()`). A loose check — e.g. "root tag
contains the word 'report'" — will silently steal uploads meant for a different
scanner that happens to be registered later. Anchor on something specific to
your scanner (a distinctive field name, a fixed root tag, a required JSON key
combination), not a generic word that other formats also use.

The conformance suite (below) checks this automatically against every other
parser's sample file — if your `validate_file()` is too loose, the test tells
you exactly which other scanner's sample it collided with.

## The `StandardizedFinding` fields that matter most

```python
StandardizedFinding(
    title: str,               # required, non-empty
    description: str,         # what the vulnerability IS - the write-up
    severity: SeverityLevel,  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    evidence: Optional[str],  # proof-of-concept ONLY - not a general description
    solution: Optional[str],
    affected_asset: Optional[str],
    cvss_score, cvss_vector, cwe_ids, cve_ids (in raw_data), references, tags,
    raw_data: dict,           # anything else - never read back into the DB
)
```

**`description` vs `evidence` — this is the distinction that caused real bugs:**
put the general "what is this vulnerability and why does it matter" write-up in
`description`. Put scanner-specific proof (an attack payload, an HTTP
request/response snippet, a matched string, a URL) in `evidence` — it gets saved
to `Vulnerability.POC`. Don't swap them, and don't leave real proof data sitting
only in `raw_data` where the upload view can't reach it — `raw_data` is not read
back into any database field.

## Plain text only — no Markdown, no HTML

**Nothing in this application renders Markdown or HTML.** The frontend prints
`description`/`solution`/`POC` as raw `whitespace-pre-wrap` text, and the
Word/PDF report exporter (`project/report.py`) only strips HTML tags via
`bleach` — it does not interpret Markdown. If your parser emits `### Header`,
`**bold**`, or `` ```code fences``` ``, users will see those literal characters
in the UI and in exported reports.

- If the source data is HTML (common for web scanners like Burp/ZAP/Acunetix/
  AppSpider), run it through `self.clean_html_text(...)` — do **not** call
  `html2text` directly, since the shared helper has Markdown emphasis disabled.
- Build multi-field text as plain labeled lines (`"Product: nginx"`), not
  headers or bold markers.
- Don't wrap output in code fences.

## Registering your parser

Add one line to `register_all_parsers()` in
`securityhub/utils/parsers/register_parsers.py`:

```python
ParserRegistry.register("yourscanner", YourScannerParser)
```

## Required: a sample fixture + conformance test entry

Every registered parser must have a sample file under
`securityhub/tests/fixtures/scans/<scanner_type>/sample.<ext>` and a matching
entry in the `FIXTURES` dict in
`securityhub/tests/parsers/test_parser_conformance.py`. Use synthetic/anonymized
data — no real customer findings, hostnames, or credentials.

That one file gets you, for free:

- a check that `validate_file()` accepts your own sample
- a check that `parse_findings()` returns well-formed findings with a title and
  a valid severity
- a check that no Markdown/HTML survives in `description`/`evidence`/`solution`
- a check that your `validate_file()` doesn't misdetect every *other* scanner's
  sample file (and vice versa)

Run it locally before opening a PR:

```bash
cd securityhub
SECRET_KEY=x DEBUG=True python3 -m pytest tests/parsers/test_parser_conformance.py -v
```

If you're testing something more specific to your parser (a duplicate-merging
rule, a quirky severity mapping), add a small dedicated test next to it, e.g.
`securityhub/tests/test_parser_regressions.py` has several short examples.

## Common pitfalls (found via a real audit — don't repeat these)

- **Markdown/HTML in `description`** — see above. Found in nmap, nessus, sarif,
  burp, appspider, acunetix, nexpose.
- **`evidence` reused for the wrong data** — one parser put a CVSS vector string
  (already stored properly in `cvss_vector`) into `evidence`, so it showed up as
  a nonsense "proof of concept". Only put real PoC data in `evidence`, or leave
  it `None`.
- **Cleaning some HTML fields but not sibling ones** — a parser cleaned an
  alert's `evidence`/`otherinfo` text but forgot a sibling `attack` field, which
  is exactly the field most likely to contain a raw `<script>` payload.
- **`element.find(x) or element.find(y)` in XML parsing** — an `ElementTree`
  Element's truthiness depends on its number of *child elements*, not whether it
  was found. A tag like `<CWE>89</CWE>` (text content, no children) is falsy, so
  `vuln.find("CWE") or vuln.find("CWE_ID")` silently skips a real match. Always
  use `elem = vuln.find("CWE"); if elem is None: elem = vuln.find("CWE_ID")`.
- **Overly generic `validate_file()`** — see the anchoring guidance above.
