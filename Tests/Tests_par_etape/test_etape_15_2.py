from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.engine import ScannerEngine
from aegis.reporting.generator import ReportGenerator
import time

print ("\n\n")
config = Config.from_yaml("config.yaml")
setup_logger(config)

print ("\n")
engine = ScannerEngine(config)
reporter = ReportGenerator()

print ("\n\n")
# Test 1 — scan test_files
report = engine.scan("aa_test")
reporter.print_console(report)

print ("\n")
# Test 2 — scan du Bureau complet
print("\n--- Scan Bureau ---")
start = time.perf_counter()
report_bureau = engine.scan(
    r"C:\Users\DELL LATITUDE 5420\OneDrive\Bureau"
)
duration = time.perf_counter() - start

print ("\n")
print(f"Fichiers analysés : {report_bureau.total_scanned}")
print(f"Menaces détectées : {report_bureau.threats_found}")
print(f"Durée totale      : {duration:.3f}s")


print ("\n\n")
