from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.engine import ScannerEngine


print("\n\n\n")

config = Config.from_yaml("config.yaml")
setup_logger(config)

engine = ScannerEngine(config)

report = engine.scan("Tests/test_files")

# Test 1 — statistiques globales
print("\n\n",report.total_scanned,"\n")    # nombre de fichiers scannés
print(report.threats_found,"\n")    # doit être >= 1 (EICAR)
print(report.duration_seconds,"\n") # temps en secondes
print(report,"\n\n\n")                  # résumé complet

# Test 2 — détail des menaces
for threat in report.threats:
    print(f"\n  Fichier  : {threat.path}\n")
    print(f"  Malware  : {threat.match_result.malware_name}\n")
    print(f"  Sévérité : {threat.match_result.severity}/4\n")
    print(f"  SHA-256  : {threat.match_result.matched_hash[:32]}...\n\n")