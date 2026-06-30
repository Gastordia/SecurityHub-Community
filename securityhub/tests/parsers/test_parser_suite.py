#!/usr/bin/env python3
"""
SecurityHub Parser Test Suite — Network/IP/URL/Domain Parsers
Verifies:
  1. All parsers can parse their real test-scan files without errors
  2. Every finding has the backend-required fields populated
  3. No data is silently lost (key raw_data fields checked)
  4. Output maps correctly to Vulnerability/VulnerableInstance model fields
  5. Identifies parsers NOT yet wired into the integration layer

Run from the securityhub/ directory:
    python test_parser_suite.py
"""

import sys
import os
import json
import re
import textwrap
import time
import multiprocessing
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

# ── Path setup ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
SCAN_DIR = BASE_DIR / "unittest" / "scans"
sys.path.insert(0, str(BASE_DIR))

# ── Colour helpers ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}\u2705 {msg}{RESET}")
def fail(msg):  print(f"  {RED}\u274c {msg}{RESET}")
def warn(msg):  print(f"  {YELLOW}\u26a0\ufe0f  {msg}{RESET}")
def info(msg):  print(f"  {CYAN}\u2139\ufe0f  {msg}{RESET}")
def head(msg):  print(f"\n{BOLD}{CYAN}{'\u2501'*70}{RESET}\n{BOLD}{msg}{RESET}")
def subhead(m): print(f"\n{BOLD}  \u2500\u2500 {m} \u2500\u2500{RESET}")

# ── Watchdog config ────────────────────────────────────────────────────────────
RAM_LIMIT_MB    = 300   # kill a parser worker if it uses more than this
TIMEOUT_SECONDS = 60    # kill a parser worker if it runs longer than this


# ═══════════════════════════════════════════════════════════════════════════════
# BACKEND MODEL CONTRACT
# What a parser finding must produce to be stored in Vulnerability + VulnerableInstance
# ═══════════════════════════════════════════════════════════════════════════════
VULN_REQUIRED_FIELDS = {
    "title":        "vulnerabilityname",
    "severity":     "vulnerabilityseverity",
    "description":  "vulnerabilitydescription",
}

VULN_OPTIONAL_BUT_IMPORTANT = {
    "cvss_score":   "cvssscore",
    "cvss_vector":  "cvssvector",
    "solution":     "vulnerabilitysolution",
    "references":   "vulnerabilityreferlnk",
    "evidence":     "POC",
    "cve_ids":      "cve",          # stored as JSON array
    "cwe_ids":      "cwe",          # stored as JSON array
}

# Fields expected inside raw_data that feed intelligence/asset pipeline
NESSUS_RAW_EXPECTED = [
    "plugin_id", "ip", "fqdn", "port", "protocol", "cve_ids",
    "epss_score", "cvss_v3_temporal", "cvss_v2_temporal",
    "exploit_available", "has_cisa_kev_exploit", "stig_severity",
    "metasploit", "core_impact", "canvas", "affected_endpoints",
]
NMAP_RAW_EXPECTED = [
    "ip_address", "ports", "host_status",
]
OPENVAS_RAW_EXPECTED = [
    "host", "port", "nvt_oid",
]
QUALYS_RAW_EXPECTED = [
    "ip", "host",
]
NEXPOSE_RAW_EXPECTED = [
    "affected_endpoints",
]
BURP_RAW_EXPECTED = [
    "url", "affected_endpoints",
]
ZAP_RAW_EXPECTED = [
    "affected_assets", "plugin_id",
]
NUCLEI_RAW_EXPECTED = [
    "template_id", "matched_at",
]
ACUNETIX_RAW_EXPECTED = [
    "start_url",
]
APPSPIDER_RAW_EXPECTED = [
    "vuln_url",
]

SEVERITY_LEVELS = {"Critical", "High", "Medium", "Low", "Info"}


# ═══════════════════════════════════════════════════════════════════════════════
# Test result tracking
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class ParserResult:
    parser_name: str
    test_file: str
    total_findings: int = 0
    passed: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    missing_required: List[str] = field(default_factory=list)
    missing_optional: List[str] = field(default_factory=list)
    missing_raw: List[str] = field(default_factory=list)
    sample_finding: Optional[Dict] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Import all parsers
# ═══════════════════════════════════════════════════════════════════════════════
def import_parsers():
    parsers = {}
    import_map = {
        "nessus":   ("utils.parsers.nessus.parser",   "NessusParser"),
        "nmap":     ("utils.parsers.nmap.parser",     "NmapParser"),
        "openvas":  ("utils.parsers.openvas.parser",  "OpenVASParser"),
        "qualys":   ("utils.parsers.qualys.parser",   "QualysParser"),
        "nexpose":  ("utils.parsers.nexpose.parser",  "NexposeParser"),
        "burp":     ("utils.parsers.burp.parser",     "BurpParser"),
        "zap":      ("utils.parsers.zap.parser",      "ZAPParser"),
        "nuclei":   ("utils.parsers.nuclei.parser",   "NucleiParser"),
        "acunetix": ("utils.parsers.acunetix.parser", "AcunetixParser"),
        "appspider":("utils.parsers.appspider.parser","AppSpiderParser"),
        "trivy":    ("utils.parsers.trivy.parser",    "TrivyParser"),
        "sarif":    ("utils.parsers.sarif.parser",    "SARIFParser"),
    }
    for name, (module_path, class_name) in import_map.items():
        try:
            import importlib
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            parsers[name] = cls()
            ok(f"Imported {name} parser ({class_name})")
        except Exception as e:
            fail(f"Failed to import {name} parser: {e}")
    return parsers


# ═══════════════════════════════════════════════════════════════════════════════
# Validation helpers
# ═══════════════════════════════════════════════════════════════════════════════
def validate_finding(finding, parser_name: str, raw_expected: List[str]) -> ParserResult:
    r = ParserResult(parser_name=parser_name, test_file="")

    # ── 1. Required fields ───────────────────────────────────────────────────
    for field_key, model_field in VULN_REQUIRED_FIELDS.items():
        val = getattr(finding, field_key, None)
        if not val or (isinstance(val, str) and not val.strip()):
            r.missing_required.append(f"{field_key} → Vulnerability.{model_field}")
        else:
            r.passed.append(f"Required '{field_key}' present")

    # ── 2. Severity must be a known level ───────────────────────────────────
    severity = getattr(finding, "severity", None)
    if severity:
        sev_str = severity.value if hasattr(severity, "value") else str(severity)
        if sev_str not in SEVERITY_LEVELS:
            r.errors.append(f"Invalid severity value: {sev_str!r} (must be one of {SEVERITY_LEVELS})")
        else:
            r.passed.append(f"Severity '{sev_str}' is valid")
    else:
        r.missing_required.append("severity → Vulnerability.vulnerabilityseverity")

    # ── 3. Optional but important fields ────────────────────────────────────
    for field_key, model_field in VULN_OPTIONAL_BUT_IMPORTANT.items():
        val = getattr(finding, field_key, None)
        if val is None or val == [] or val == "":
            r.missing_optional.append(f"{field_key} → Vulnerability.{model_field}")
        else:
            r.passed.append(f"Optional '{field_key}' present")

    # ── 4. affected_asset (→ VulnerableInstance.URL or asset lookup) ────────
    affected = getattr(finding, "affected_asset", None)
    if not affected:
        r.warnings.append("affected_asset is empty — asset linkage will fail")
    else:
        r.passed.append(f"affected_asset: {affected}")

    # ── 5. Raw data field coverage ───────────────────────────────────────────
    raw = getattr(finding, "raw_data", {}) or {}
    for expected_key in raw_expected:
        if expected_key not in raw or raw[expected_key] is None:
            r.missing_raw.append(expected_key)

    # ── 6. Scanner type & ID ────────────────────────────────────────────────
    if not getattr(finding, "scanner_type", None):
        r.errors.append("scanner_type is empty")
    if not getattr(finding, "scanner_id", None):
        r.warnings.append("scanner_id is empty (dedup key may fail)")

    return r


def findings_to_dict(f) -> Dict:
    """Convert a StandardizedFinding to a plain dict for the report."""
    raw = getattr(f, "raw_data", {}) or {}
    sev = f.severity
    return {
        "title": f.title,
        "severity": sev.value if hasattr(sev, "value") else str(sev),
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "cwe_ids": f.cwe_ids,
        "cve_ids": raw.get("cve_ids", getattr(f, "cve_ids", [])),
        "affected_asset": f.affected_asset,
        "evidence_snippet": (f.evidence or "")[:200] if f.evidence else None,
        "solution_snippet": (f.solution or "")[:200] if f.solution else None,
        "references_count": len(f.references or []),
        "scanner_type": f.scanner_type,
        "scanner_id": f.scanner_id,
        "tags": f.tags,
        "raw_keys": list(raw.keys()),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# RAM-safe subprocess worker
# ═══════════════════════════════════════════════════════════════════════════════

def _worker_fn(module_path: str, class_name: str, file_path: str,
               out_file_path: str) -> None:
    """
    Runs inside a child process.
    - Polls its own RSS every 250 ms; self-exits if > RAM_LIMIT_MB.
    - Writes serializable finding dicts to out_file_path via JSON.
    """
    import os, sys, threading, time
    sys.path.insert(0, str(BASE_DIR))

    # ── Memory watchdog thread ────────────────────────────────────────────────
    _stop = threading.Event()
    def _ram_monitor():
        try:
            import resource
            while not _stop.is_set():
                usage_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                # Linux reports KB, macOS reports bytes
                import json
                if usage_mb > RAM_LIMIT_MB:
                    with open(out_file_path, "w") as f:
                        json.dump({"__error__": f"RAM limit exceeded ({usage_mb:.0f} MB > {RAM_LIMIT_MB} MB)"}, f)
                    os._exit(1)
                _stop.wait(0.25)
        except Exception:
            pass

    monitor = threading.Thread(target=_ram_monitor, daemon=True)
    monitor.start()

    try:
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        parser = cls()
        print(f"\033[90m    [Worker] Initialized {class_name} parser, calling parse_findings...\033[0m", flush=True)
        findings = parser.parse_findings(file_path)
        print(f"\033[90m    [Worker] parse_findings returned {len(findings)} findings. Serializing...\033[0m", flush=True)

        # Serialize findings to plain dicts (must be picklable)
        serialized = []
        for i, f in enumerate(findings):
            if i > 0 and i % 500 == 0:
                print(f"\033[90m    [Worker] Serialized {i}/{len(findings)} findings...\033[0m", flush=True)
            raw = getattr(f, "raw_data", {}) or {}
            sev = f.severity
            serialized.append({
                "title":         f.title,
                "severity":      sev.value if hasattr(sev, "value") else str(sev),
                "description":   (f.description or "")[:2000],   # cap size
                "solution":      (f.solution or "")[:500],
                "evidence":      (f.evidence or "")[:500],
                "cvss_score":    f.cvss_score,
                "cvss_vector":   f.cvss_vector,
                "cwe_ids":       f.cwe_ids,
                "references":    f.references,
                "affected_asset":f.affected_asset,
                "scanner_type":  f.scanner_type,
                "scanner_id":    f.scanner_id,
                "tags":          f.tags,
                "raw_data":      {k: (str(v)[:200] if isinstance(v, str) and len(str(v)) > 200 else v)
                                  for k, v in raw.items()
                                  if not isinstance(v, set)},  # sets aren't JSON-safe
            })
        import json
        with open(out_file_path, "w") as f:
            json.dump({"__findings__": serialized}, f)
    except Exception as e:
        import traceback, json
        err_str = f"{e}\n{traceback.format_exc()}"
        print(f"\033[91m    [Worker] ERROR: {err_str}\033[0m", flush=True)
        with open(out_file_path, "w") as f:
            json.dump({"__error__": err_str}, f)
    finally:
        _stop.set()


def safe_parse_findings(module_path: str, class_name: str,
                        file_path: str) -> tuple:
    """
    Run _worker_fn in a subprocess. Returns (findings_list, error_str).
    Kills the child if it exceeds RAM_LIMIT_MB or TIMEOUT_SECONDS.
    """
    import tempfile, json, os
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    
    p = multiprocessing.Process(
        target=_worker_fn,
        args=(module_path, class_name, file_path, out_path),
        daemon=True,
    )
    p.start()
    p.join(timeout=TIMEOUT_SECONDS)

    result = {}
    if os.path.exists(out_path):
        try:
            with open(out_path, "r") as f:
                result = json.load(f)
        except Exception:
            pass
        os.remove(out_path)

    if p.is_alive():
        p.kill()
        p.join()
        return [], f"TIMEOUT: parser exceeded {TIMEOUT_SECONDS}s wall-clock limit"

    if result and "__error__" in result:
        return [], result["__error__"]
        
    if result and "__findings__" in result:
        return result["__findings__"], None

    if p.exitcode != 0:
        return [], f"Worker exited with code {p.exitcode} (likely OOM or signal)"

    return [], f"Worker finished (exit {p.exitcode}) but returned no data"


# ── Parser import map (module_path, class_name) needed by the worker ──────────
IMPORT_MAP = {
    "nessus":   ("utils.parsers.nessus.parser",   "NessusParser"),
    "nmap":     ("utils.parsers.nmap.parser",     "NmapParser"),
    "openvas":  ("utils.parsers.openvas.parser",  "OpenVASParser"),
    "qualys":   ("utils.parsers.qualys.parser",   "QualysParser"),
    "nexpose":  ("utils.parsers.nexpose.parser",  "NexposeParser"),
    "burp":     ("utils.parsers.burp.parser",     "BurpParser"),
    "zap":      ("utils.parsers.zap.parser",      "ZAPParser"),
    "nuclei":   ("utils.parsers.nuclei.parser",   "NucleiParser"),
    "acunetix": ("utils.parsers.acunetix.parser", "AcunetixParser"),
    "appspider":("utils.parsers.appspider.parser","AppSpiderParser"),
    "trivy":    ("utils.parsers.trivy.parser",    "TrivyParser"),
    "sarif":    ("utils.parsers.sarif.parser",    "SARIFParser"),
}


# ═══════════════════════════════════════════════════════════════════════════════
# Per-parser test runners
# ═══════════════════════════════════════════════════════════════════════════════

def run_parser_test(parser, parser_name: str, test_files: List[Path],
                    raw_expected: List[str]) -> List[ParserResult]:
    results = []
    module_path, class_name = IMPORT_MAP.get(parser_name, (None, None))

    for test_file in test_files:
        result = ParserResult(parser_name=parser_name, test_file=test_file.name)
        subhead(f"{parser_name.upper()} \u2190 {test_file.name}")

        try:
            # ── validate_file() runs in-process (fast header read) ───────────
            is_valid = parser.validate_file(str(test_file))
            if not is_valid:
                warn(f"validate_file() returned False for {test_file.name}")
                result.warnings.append("validate_file() returned False")
            else:
                ok(f"validate_file() \u2192 True")

            # ── parse_findings() runs in a RAM-guarded subprocess ────────────
            if module_path:
                file_size_mb = test_file.stat().st_size / (1024 * 1024)
                info(f"Parsing {test_file.name} ({file_size_mb:.1f} MB) — RAM cap: {RAM_LIMIT_MB} MB, timeout: {TIMEOUT_SECONDS}s")
                raw_findings, err = safe_parse_findings(module_path, class_name, str(test_file))
            else:
                # Fallback: run in-process for parsers not in IMPORT_MAP
                raw_findings_obj = parser.parse_findings(str(test_file))
                raw_findings = [findings_to_dict(f) for f in raw_findings_obj]
                err = None

            if err:
                result.errors.append(f"KILLED: {err}")
                fail(f"\U0001f480 Parser killed: {err}")
                results.append(result)
                continue

            result.total_findings = len(raw_findings)
            info(f"parse_findings() \u2192 {len(raw_findings)} findings")

            if not raw_findings:
                warn("Zero findings returned \u2014 check if this is expected for this file")
                result.warnings.append("Zero findings \u2014 possibly empty or filtered scan file")
                results.append(result)
                continue

            # ── Validate each finding dict against backend contract ───────────
            all_missing_req = set()
            all_missing_opt = set()
            all_missing_raw = set()
            all_errors      = set()
            all_warnings    = set()

            for f_dict in raw_findings:
                # Required fields
                for field_key, model_field in VULN_REQUIRED_FIELDS.items():
                    val = f_dict.get(field_key)
                    if not val or (isinstance(val, str) and not val.strip()):
                        all_missing_req.add(f"{field_key} \u2192 Vulnerability.{model_field}")

                # Severity
                sev_str = f_dict.get("severity", "")
                if sev_str not in SEVERITY_LEVELS:
                    all_errors.add(f"Invalid severity: {sev_str!r}")

                # Optional
                for field_key, model_field in VULN_OPTIONAL_BUT_IMPORTANT.items():
                    val = f_dict.get(field_key)
                    if val is None or val == [] or val == "":
                        all_missing_opt.add(f"{field_key} \u2192 Vulnerability.{model_field}")

                # affected_asset
                if not f_dict.get("affected_asset"):
                    all_warnings.add("affected_asset is empty \u2014 asset linkage will fail")

                # Raw data keys
                raw = f_dict.get("raw_data", {}) or {}
                for expected_key in raw_expected:
                    if expected_key not in raw or raw[expected_key] is None:
                        all_missing_raw.add(expected_key)

                # scanner_type
                if not f_dict.get("scanner_type"):
                    all_errors.add("scanner_type is empty")

            result.missing_required = list(all_missing_req)
            result.missing_optional = list(all_missing_opt)
            result.missing_raw      = list(all_missing_raw)
            result.errors           = list(all_errors)
            result.warnings         = list(all_warnings)
            result.sample_finding   = raw_findings[0]

            # Print per-file summary
            if result.missing_required:
                fail(f"MISSING REQUIRED fields (breaks backend): {result.missing_required}")
            else:
                ok("All required backend fields are populated")

            if result.errors:
                fail(f"Errors: {result.errors}")

            if result.missing_optional:
                warn(f"Missing optional fields ({len(result.missing_optional)}): {result.missing_optional}")
            else:
                ok("All important optional fields are populated")

            if not result.missing_raw:
                ok("All expected raw_data keys present")
            else:
                warn(f"Missing raw_data keys ({len(result.missing_raw)}): {result.missing_raw}")

            for w in result.warnings:
                warn(w)

        except Exception as e:
            import traceback
            result.errors.append(f"EXCEPTION: {e}")
            fail(f"Parser raised exception: {e}")
            print(traceback.format_exc())

        results.append(result)
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# Integration check — which parsers are wired into asset_parser_integration.py
# ═══════════════════════════════════════════════════════════════════════════════
INTEGRATION_FILE = BASE_DIR / "utils" / "services" / "asset_parser_integration.py"

def check_integration_status(parser_names: List[str]) -> Dict[str, bool]:
    """Check which parsers have explicit handling in the integration layer."""
    try:
        src = INTEGRATION_FILE.read_text()
    except Exception:
        return {p: False for p in parser_names}

    status = {}
    for name in parser_names:
        # Check if the parser name appears in the integration code
        # (e.g. scanner_type == 'nmap' or _extract_nmap_asset_data)
        integrated = (
            f"scanner_type == '{name}'" in src or
            f"_extract_{name}_asset_data" in src or
            f"elif scanner_type == '{name}'" in src or
            f"== \"{name}\"" in src
        )
        status[name] = integrated
    return status


def check_parser_service_mapping(parser_names: List[str]) -> Dict[str, bool]:
    """Check which parsers have explicit field mappings in parser_service.py."""
    svc_file = BASE_DIR / "utils" / "services" / "parser_service.py"
    try:
        src = svc_file.read_text()
    except Exception:
        return {p: False for p in parser_names}

    status = {}
    for name in parser_names:
        status[name] = f"'{name}'" in src or f'"{name}"' in src
    return status


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TEST RUNNER
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    head("SecurityHub Parser Test Suite — Network/IP/URL/Domain Parsers")
    print("Checking all parsers that deal with IPs, URLs, domains, and network findings")
    print("(Excludes: code/SAST, APK/mobile, SCA-only parsers)")

    # ── Import parsers ────────────────────────────────────────────────────────
    head("Step 1: Importing Parsers")
    parsers = import_parsers()
    if not parsers:
        fail("No parsers loaded — check imports")
        sys.exit(1)

    # ── Define test-file sets ─────────────────────────────────────────────────
    TENABLE_NESSUS = SCAN_DIR / "tenable" / "nessus"
    PARSER_TEST_MAP = {
        "nessus": {
            "files": [
                TENABLE_NESSUS / "nessus_many_vuln.csv",
                TENABLE_NESSUS / "nessus_many_vuln.xml",
                TENABLE_NESSUS / "nessus_with_cvssv3.nessus",
                TENABLE_NESSUS / "nessus_many_vuln2-default.csv",
            ],
            "raw_expected": NESSUS_RAW_EXPECTED,
            "category": "network",
        },
        "nmap": {
            "files": [
                SCAN_DIR / "nmap" / "nmap_1port.xml",
                SCAN_DIR / "nmap" / "nmap_multiple_port.xml",
                SCAN_DIR / "nmap" / "nmap_script_vulners.xml",
            ],
            "raw_expected": NMAP_RAW_EXPECTED,
            "category": "network",
        },
        "openvas": {
            "files": [
                SCAN_DIR / "openvas" / "many_vuln.xml",
                SCAN_DIR / "openvas" / "one_vuln.xml",
                SCAN_DIR / "openvas" / "many_vuln.csv",
                SCAN_DIR / "openvas" / "one_vuln.csv",
            ],
            "raw_expected": OPENVAS_RAW_EXPECTED,
            "category": "network",
        },
        "qualys": {
            "files": [
                SCAN_DIR / "qualys" / "Qualys_Sample_Report.csv",
                SCAN_DIR / "qualys" / "Qualys_Sample_Report.xml",
            ],
            "raw_expected": QUALYS_RAW_EXPECTED,
            "category": "network",
        },
        "nexpose": {
            "files": [
                SCAN_DIR / "nexpose" / "many_vulns.xml",
                SCAN_DIR / "nexpose" / "dns.xml",
                SCAN_DIR / "nexpose" / "report_auth.xml",
            ],
            "raw_expected": NEXPOSE_RAW_EXPECTED,
            "category": "network",
        },
        "burp": {
            "files": [
                SCAN_DIR / "burp" / "one_finding.xml",
                SCAN_DIR / "burp" / "seven_findings.xml",
                SCAN_DIR / "burp" / "one_finding_with_cwe.xml",
            ],
            "raw_expected": BURP_RAW_EXPECTED,
            "category": "web",
        },
        "zap": {
            "files": [
                SCAN_DIR / "zap" / "0_zap_sample.xml",
                SCAN_DIR / "zap" / "zap_2.16.1_with_req_resp.xml",
                SCAN_DIR / "zap" / "5_zap_sample_one.xml",
            ],
            "raw_expected": ZAP_RAW_EXPECTED,
            "category": "web",
        },
        "nuclei": {
            "files": [
                SCAN_DIR / "nuclei" / "many_findings.json",
                SCAN_DIR / "nuclei" / "many_findings_new.json",
                SCAN_DIR / "nuclei" / "many_findings_third.json",
            ],
            "raw_expected": NUCLEI_RAW_EXPECTED,
            "category": "web",
        },
        "acunetix": {
            "files": [
                SCAN_DIR / "acunetix" / "many_findings.xml",
                SCAN_DIR / "acunetix" / "one_finding.xml",
                SCAN_DIR / "acunetix" / "acunetix360_one_finding.json",
                SCAN_DIR / "acunetix" / "acunetix360_many_findings.json",
            ],
            "raw_expected": ACUNETIX_RAW_EXPECTED,
            "category": "web",
        },
        "appspider": {
            "files": [
                SCAN_DIR / "appspider" / "one_vuln.xml",
            ],
            "raw_expected": APPSPIDER_RAW_EXPECTED,
            "category": "web",
        },
    }

    # ── Run tests ─────────────────────────────────────────────────────────────
    head("Step 2: Running Parser Tests Against Real Scan Files")
    all_results: Dict[str, List[ParserResult]] = {}

    for parser_name, cfg in PARSER_TEST_MAP.items():
        if parser_name not in parsers:
            warn(f"Skipping {parser_name} — parser not loaded")
            continue

        parser = parsers[parser_name]
        test_files = [f for f in cfg["files"] if f.exists()]
        missing_files = [f for f in cfg["files"] if not f.exists()]

        if missing_files:
            warn(f"Missing test files for {parser_name}: {[f.name for f in missing_files]}")
        if not test_files:
            fail(f"No test files found for {parser_name}!")
            continue

        results = run_parser_test(
            parser, parser_name, test_files, cfg["raw_expected"]
        )
        all_results[parser_name] = results

    # ── Integration check ─────────────────────────────────────────────────────
    head("Step 3: Integration Layer Audit")
    all_parser_names = list(PARSER_TEST_MAP.keys())
    integration_status = check_integration_status(all_parser_names)
    svc_mapping_status = check_parser_service_mapping(all_parser_names)

    print(f"\n{'Parser':<14} {'asset_parser_integration.py':<30} {'parser_service.py mappings':<30}")
    print("─" * 75)
    not_integrated = []
    for name in all_parser_names:
        integ = integration_status.get(name, False)
        svc   = svc_mapping_status.get(name, False)
        integ_str = f"{GREEN}Integrated{RESET}" if integ else f"{RED}NOT integrated{RESET}"
        svc_str   = f"{GREEN}Has mapping{RESET}" if svc else f"{YELLOW}No mapping{RESET}"
        print(f"  {name:<14} {integ_str:<40} {svc_str}")
        if not integ:
            not_integrated.append(name)

    if not_integrated:
        print(f"\n{RED}⚠️  Parsers with no integration handler:{RESET} {not_integrated}")
        print(f"   These parsers parse correctly but their data is NOT enriched")
        print(f"   in the asset/vulnerability pipeline beyond the generic path.")

    # ── Final summary ─────────────────────────────────────────────────────────
    head("Step 4: Summary Report")

    total_parsers  = len(all_results)
    total_files    = sum(len(v) for v in all_results.values())
    total_findings = sum(r.total_findings for v in all_results.values() for r in v)
    parsers_with_required_failures = []
    parsers_with_errors = []
    parsers_with_warnings = []

    print(f"\n{'Parser':<14} {'Files':<8} {'Findings':<10} {'Required':<12} {'Optional':<12} {'Raw':<8} {'Status'}")
    print("─" * 90)

    for parser_name, results in all_results.items():
        total_f    = sum(r.total_findings for r in results)
        req_miss   = list(set(f for r in results for f in r.missing_required))
        opt_miss   = list(set(f for r in results for f in r.missing_optional))
        raw_miss   = list(set(f for r in results for f in r.missing_raw))
        errs       = list(set(f for r in results for f in r.errors))
        warns      = list(set(f for r in results for f in r.warnings))

        if req_miss or errs:
            status = f"{RED}FAIL{RESET}"
            parsers_with_required_failures.append(parser_name)
        elif opt_miss or raw_miss or warns:
            status = f"{YELLOW}WARN{RESET}"
            parsers_with_warnings.append(parser_name)
        else:
            status = f"{GREEN}PASS{RESET}"

        req_str = f"{RED}{len(req_miss)} missing{RESET}" if req_miss else f"{GREEN}OK{RESET}"
        opt_str = f"{YELLOW}{len(opt_miss)} gaps{RESET}" if opt_miss else f"{GREEN}OK{RESET}"
        raw_str = f"{YELLOW}{len(raw_miss)}{RESET}" if raw_miss else f"{GREEN}OK{RESET}"

        print(f"  {parser_name:<14} {len(results):<8} {total_f:<10} {req_str:<22} {opt_str:<22} {raw_str:<18} {status}")

    print(f"\n{'─'*90}")
    print(f"  Total parsers tested : {total_parsers}")
    print(f"  Total files tested   : {total_files}")
    print(f"  Total findings parsed: {total_findings}")

    # ── Detailed failure analysis ─────────────────────────────────────────────
    if parsers_with_required_failures:
        head("⚠️  CRITICAL: Required Field Failures (data won't be stored)")
        for parser_name in parsers_with_required_failures:
            results = all_results[parser_name]
            req_miss = list(set(f for r in results for f in r.missing_required))
            errs     = list(set(f for r in results for f in r.errors))
            print(f"\n  {RED}{parser_name}{RESET}:")
            for m in req_miss:
                print(f"    ❌ Missing required: {m}")
            for e in errs:
                print(f"    ❌ Error: {e}")

    # ── Sample findings for each parser ──────────────────────────────────────
    head("Sample Findings (First Finding from Each Parser)")
    for parser_name, results in all_results.items():
        sample = next((r.sample_finding for r in results if r.sample_finding), None)
        if sample:
            print(f"\n  {BOLD}{parser_name.upper()}{RESET}")
            for k, v in sample.items():
                if v is not None and v != [] and v != "":
                    if isinstance(v, str) and len(v) > 80:
                        v = v[:80] + "..."
                    print(f"    {k:<25}: {v}")

    # ── Integration gap detail ─────────────────────────────────────────────────
    if not_integrated:
        head("Integration Gaps — What to Wire Up")
        print("""
  The following parsers produce valid findings but have NO custom handling in
  asset_parser_integration.py (_extract_<name>_asset_data) or parser_service.py.

  This means:
  • Their IP/hostname/domain fields are NOT extracted for asset linkage
  • Intelligence metadata (EPSS, VPR, STIG, etc.) may be lost
  • Vulnerable instances may not be linked to the correct asset

  TO FIX: Add an entry to parser_asset_mappings{} in parser_service.py and
  optionally a _extract_<name>_asset_data() method in asset_parser_integration.py
""")
        for name in not_integrated:
            results = all_results.get(name, [])
            if not results:
                continue
            # Show what raw_data fields the parser actually produces
            sample = next((r.sample_finding for r in results if r.sample_finding), None)
            if sample:
                raw_keys = sample.get("raw_keys", [])
                print(f"  {BOLD}{name}{RESET} raw_data keys: {raw_keys}")

    # ── Exit code ─────────────────────────────────────────────────────────────
    if parsers_with_required_failures:
        print(f"\n{RED}{BOLD}❌ CRITICAL failures found. Parser output does not match backend contract.{RESET}")
        return 1
    elif parsers_with_warnings:
        print(f"\n{YELLOW}{BOLD}⚠️  Tests passed with warnings. Some optional data may be missing.{RESET}")
        return 0
    else:
        print(f"\n{GREEN}{BOLD}✅ All parsers pass backend contract validation!{RESET}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
