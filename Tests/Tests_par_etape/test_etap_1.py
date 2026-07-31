from aegis.config.manager import Config


# Test 1 : chargement depuis le fichier YAML
print("\n\n\n# Test 1 : chargement depuis le fichier YAML (affichage des paramètres par défaut)")
config = Config.from_yaml("config.yaml")

print("\n\n",config.scanner.extensions)       # doit afficher ['.exe', '.dll', '.js', '.pdf']
print("\n",config.database.path)            # doit afficher './data/signatures.db'
print("\n",config.quarantine.encrypt,"\n\n")       # doit afficher False


# Test 2 : valeurs par défaut si fichier absent

print(" \n\n# Test 2 : valeurs par défaut si fichier absent\n")
config_default = Config.from_yaml("fichier_inexistant.yaml")
print("\n\n",config_default.scanner.max_file_size_mb,"\n\n")  # doit afficher 100