# Test bootstrap
pip uninstall rich -y
python main.py setup
# Doit installer rich et demander de relancer

# Test après relance
python main.py setup
# Doit tout valider proprement

# Test scan normal
python main.py scan test_files