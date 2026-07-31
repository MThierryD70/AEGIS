from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.engine import ScannerEngine
from aegis.reporting.generator import ReportGenerator

print("\n\n\n")

config = Config.from_yaml("config.yaml")
setup_logger(config)

engine = ScannerEngine(config)
report = engine.scan("tests/test_files")
reporter = ReportGenerator()
reporter.print_console(report)

# Détail par fichier
for result in report.results:
    print(f"\n\n{result.path.name}\n")
    print(f"  Signature  : {result.match_result}\n")
    print(f"  Heuristique: {result.heuristic_result}\n")
    print(f"  YARA       : {result.yara_result}\n\n")