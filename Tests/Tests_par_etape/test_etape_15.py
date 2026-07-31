from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.engine import ScannerEngine
from aegis.reporting.generator import ReportGenerator
import time

print("\n\n")
config = Config.from_yaml("config.yaml")
setup_logger(config)

print("\n")
engine = ScannerEngine(config)
reporter = ReportGenerator()

print("\n")
start = time.perf_counter()
report = engine.scan(r"C:\Users\DELL LATITUDE 5420\OneDrive\Bureau")
duration = time.perf_counter() - start

print("\n")
reporter.print_console(report)
print(f"\nTemps total : {duration:.3f}s")
print(f"Modules C++ : actifs")

print("\n\n")

