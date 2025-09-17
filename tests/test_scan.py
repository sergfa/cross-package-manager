import unittest
from pathlib import Path

import scan_shai_halud as scanner


FIXTURES = Path(__file__).parent / "fixtures"


class ScanShaiHaludTests(unittest.TestCase):
    def test_parse_affected_packages(self) -> None:
        affected = scanner.parse_affected_packages(FIXTURES / "affected.csv")
        self.assertIn("@art-ws/config-eslint", affected)
        self.assertIn("2.0.5", affected["@art-ws/config-eslint"])
        self.assertIn("0.2.2", affected["json-rules-engine-simplified"])

    def test_parse_package_lock(self) -> None:
        collector = scanner.DependencyCollector()
        scanner.parse_package_lock(FIXTURES / "package-lock.json", collector)
        versions = dict(collector.iter_packages())
        self.assertIn("@art-ws/config-eslint", versions)
        self.assertIn("2.0.5", versions["@art-ws/config-eslint"])
        self.assertIn("html-to-base64-image", versions)

    def test_parse_yarn_lock(self) -> None:
        collector = scanner.DependencyCollector()
        scanner.parse_yarn_lock(FIXTURES / "yarn.lock", collector)
        versions = dict(collector.iter_packages())
        self.assertEqual({"2.0.5"}, versions["@art-ws/config-eslint"])
        self.assertIn("0.2.2", versions["json-rules-engine-simplified"])

    def test_parse_pnpm_lock(self) -> None:
        collector = scanner.DependencyCollector()
        scanner.parse_pnpm_lock(FIXTURES / "pnpm-lock.yaml", collector)
        versions = dict(collector.iter_packages())
        self.assertEqual({"2.0.5"}, versions["@art-ws/config-eslint"])
        self.assertIn("html-to-base64-image", versions)

    def test_build_findings(self) -> None:
        affected = scanner.parse_affected_packages(FIXTURES / "affected.csv")
        collector = scanner.DependencyCollector()
        scanner.parse_package_lock(FIXTURES / "package-lock.json", collector)
        findings = scanner.build_findings(collector, affected)
        packages = {finding.package for finding in findings}
        self.assertIn("@art-ws/config-eslint", packages)
        finding = next(f for f in findings if f.package == "@art-ws/config-eslint")
        self.assertIn("2.0.5", finding.versions_flagged)
        table = scanner.render_table(findings, "lockfile:npm")
        self.assertIn("@art-ws/config-eslint", table)
        self.assertIn("2.0.5", table)


if __name__ == "__main__":
    unittest.main()
