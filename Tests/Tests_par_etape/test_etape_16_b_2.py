import subprocess
import sys
from pathlib import Path
from aegis.build.detector import EnvironmentDetector

detector = EnvironmentDetector()
report = detector.detect()

print(report.summary())

if not report.can_build:
    print("Environnement incomplet — compilation impossible")
    sys.exit(1)

# Récupère les arguments CMake adaptés
cmake_args = detector.generate_cmake_args(report)

# Ajoute le chemin pybind11
import pybind11
pybind11_dir = pybind11.get_cmake_dir()

build_dir = Path("cpp/build")
build_dir.mkdir(exist_ok=True)

cmd = [
    "cmake", "..",
    f"-Dpybind11_DIR={pybind11_dir}",
] + cmake_args

print(f"\nCommande CMake :\n{' '.join(cmd)}\n")

result = subprocess.run(cmd, cwd=str(build_dir))
if result.returncode != 0:
    print("Erreur configuration CMake")
    sys.exit(1)

# Compilation
result = subprocess.run(
    ["cmake", "--build", ".", "--config", "Release"],
    cwd=str(build_dir)
)

if result.returncode == 0:
    print("\n✓ Compilation réussie")
else:
    print("\n✗ Erreur de compilation")