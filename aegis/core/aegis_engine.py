import sys
import os
from pathlib import Path
from aegis.logger.logger import get_logger, log_section, log_success, log_failure,log_blank

# Chemin vers cpp/bin - contient le .pyd et les DLL
_CPP_BIN = Path(__file__).parent.parent.parent / "cpp" / "bin"


'''def _load_aegis_cpp():
    logger = get_logger()
    if not _CPP_BIN.exists():
        logger.warning("cpp/bin introuvable - modules C++ désactivés")
        return None
    try:
        if str(_CPP_BIN) not in sys.path:
            sys.path.insert(0, str(_CPP_BIN))
        import aegis_cpp
        logger.info("Module aegis_cpp (pybind11) chargé avec succès")
        return aegis_cpp
    except ImportError as e:
        logger.warning(f"aegis_cpp non disponible, fallback Python: {e}")
        return None
'''

def _load_aegis_cpp():
    if not _CPP_BIN.exists():
        return None
    try:
        if str(_CPP_BIN) not in sys.path:
            sys.path.insert(0, str(_CPP_BIN))
        import aegis_cpp
        return aegis_cpp
    except ImportError:
        return None
    
_cpp = _load_aegis_cpp()




'''def log_status():
    """Appelle cette fonction après setup_logger() pour afficher le status."""
    logger = get_logger()
    if _cpp is not None:
        logger.info("Module aegis_cpp (pybind11) chargé avec succès")
    else:
        logger.warning("aegis_cpp non disponible - fallback Python actif")
'''

def log_status():
    log_section("Modules C++")
    if _cpp is not None:
        log_success("Module aegis_cpp (pybind11) chargé")
    else:
        log_failure("aegis_cpp non disponible - fallback Python actif")
    log_blank()




class AegisHasher:
    """Hasher unifié - C++ si disponible, Python sinon."""

    @staticmethod
    def compute(path: Path) -> dict | None:
        logger = get_logger()
        if _cpp is not None:
            try:
                # Normalise le chemin : forward slashes, pas de préfixe \\?\
                chemin = str(path.resolve()).replace("\\", "/")
                return _cpp.compute_hashes(chemin)
            except Exception as e:
                logger.warning(f"Erreur C++ hasher, fallback Python : {e}")

        # Fallback Python
        from aegis.scanner.hasher import HashCalculator
        return HashCalculator.compute(path)



class AegisBloomMatcher:
    """"Bloom Matcher inifié - C++ si disponible, Python sinon."""
    def __init__(self, db):
        self.db = db
        self.logger = get_logger()
        self._use_cpp = _cpp is not None
        self._loaded = False

        from aegis.detection.signature_matcher import SignatureMatcher
        self._fallback = SignatureMatcher(db)

        if self._use_cpp:
            self._load_bloom()
        else:
            self.logger.warning("Bloom Filter C++ non disponible, fallback SQLite")

    def _load_bloom(self):
        hashes = self.db.get_all_hashes()
        _cpp.bloom_load(hashes)
        self._loaded = True
        bits = _cpp.bloom_bit_count()
        self.logger.info(
            f"Bloom Filter chargé : {len(hashes)} signature(s), "
            f"{bits} bits actifs"
        )

    def check(self, hashes: dict):
        from aegis.detection.signature_matcher import MatchResult

        if not self._use_cpp or not self._loaded:
            return self._fallback.check(hashes)

        for hash_type, hash_value in hashes.items():
            # Etape 1: Bloom Filter en RAM
            if _cpp.bloom_check(hash_value):
                # Etape 2: Confirlation SQLite
                result = self.db.lookup(hash_value)
                if result is not None:
                    self.logger.warning(
                        f"Signature trouvée: {result['malware_name']} "
                        f"({hash_type} : {hash_value[:16]}...)"
                    )
                    return MatchResult(
                        is_threat=True,
                        malware_name=result["malware_name"],
                        severity=result["severity"],
                        matched_hash=hash_value,
                        hash_type=hash_type
                    )
        return MatchResult(is_threat=False)

    def reload(self):
        """Recharger le Bloom Filter depuis la DB - utile après un update."""
        if self._use_cpp:
            self._load_bloom()
            self.logger.info("Bloom Filter rechargé")



















