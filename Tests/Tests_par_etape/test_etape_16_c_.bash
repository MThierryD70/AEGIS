# Test 1 — statut environnement
python main.py build status

# Test 2 — compilation normale
# (détecte que c'est déjà compilé)
python main.py build compile

# Test 3 — recompilation forcée
python main.py build compile --force

# Test 4 — aide
python main.py build --help

