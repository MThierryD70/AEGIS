from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.engine import ScannerEngine
from aegis.reporting.generator import ReportGenerator

print("\n\n\n")


config = Config.from_yaml("config.yaml")
setup_logger(config)

# Lance un scan complet
engine = ScannerEngine(config)
report = engine.scan("Tests/test_files")

# Test 1 — affichage console
reporter = ReportGenerator()
reporter.print_console(report)

# Test 2 — export JSON
reporter.save_json(report, "reports/scan_report.json")

# Test 3 — export CSV
reporter.save_csv(report, "reports/scan_report.csv")