from aegis.build.detector import EnvironmentDetector

print ("\n\n")
detector = EnvironmentDetector()
report = detector.detect()
print(report.summary())
print(f"\nArguments CMake : {detector.generate_cmake_args(report)}")

print ("\n\n")
