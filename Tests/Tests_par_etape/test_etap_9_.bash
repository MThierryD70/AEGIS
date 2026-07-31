# Test 1 — aide générale
python main.py --help

# Test 2 — aide de la commande scan
python main.py scan --help

# Test 3 — scan simple
python main.py scan test_files

# Test 4 — scan avec rapport JSON
python main.py scan test_files --json

# Test 5 — scan avec mise en quarantaine automatique
python main.py scan test_files --quarantine

# Test 6 — liste de la quarantaine
python main.py quarantine list

# Test 7 — restauration (utilise l'ID affiché par la commande list)
python main.py quarantine restore <uuid-affiché>