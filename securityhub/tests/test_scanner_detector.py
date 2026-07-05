import tempfile
from pathlib import Path
from unittest import TestCase

from utils.services.scanner_detector import ScannerDetector


class ScannerDetectorTests(TestCase):
    def setUp(self):
        self.detector = ScannerDetector()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write(self, name: str, content: str) -> str:
        path = self.base / name
        path.write_text(content)
        return str(path)

    def test_detects_acunetix_json_before_nuclei(self):
        path = self._write(
            "acunetix.json",
            '{"Generated":"2026-07-05T00:00:00Z","Vulnerabilities":[{"Name":"Synthetic"}]}',
        )
        self.assertEqual(self.detector.detect_scanner(path), "acunetix")

    def test_detects_trivy_json_before_nuclei(self):
        path = self._write(
            "trivy.json",
            '{"SchemaVersion":2,"ArtifactName":"img","Results":[{"Target":"img","Type":"os","Vulnerabilities":[]}]}',
        )
        self.assertEqual(self.detector.detect_scanner(path), "trivy")

    def test_detects_sarif_extension(self):
        path = self._write(
            "sample.sarif",
            '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Tool"}},"results":[]}]}',
        )
        self.assertEqual(self.detector.detect_scanner(path), "sarif")

    def test_nuclei_validation_rejects_generic_json_object(self):
        path = self._write("generic.json", '{"Generated":"2026-07-05T00:00:00Z"}')
        self.assertNotEqual(self.detector.detect_scanner(path), "nuclei")
