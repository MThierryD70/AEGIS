import logging
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.text import Text
from rich.rule import Rule

# Console rich globale
_console = Console()


class RichHandler(logging.Handler):
    """Handler logging qui utilise rich pour les couleurs et le formatage."""

    LEVEL_STYLES = {
        "DEBUG":    ("dim white",     "DEBUG  "),
        "INFO":     ("bold green",    "INFO   "),
        "WARNING":  ("bold orange1",  "WARN   "),
        "ERROR":    ("bold red",      "ERROR  "),
        "CRITICAL": ("bold red",      "CRITIC "),
    }

    def emit(self, record: logging.LogRecord):
        try:
            style, label = self.LEVEL_STYLES.get(
                record.levelname, ("white", record.levelname)
            )
            time_str = datetime.now().strftime("%H:%M:%S")
            text = Text()
            text.append(f"{time_str} ", style="dim")
            text.append(f"[{label}] ", style=style)
            text.append(record.getMessage())
            _console.print(text)
        except Exception:
            self.handleError(record)


def setup_logger(config) -> logging.Logger:
    logger = logging.getLogger("aegis")

    # Évite les handlers dupliqués si setup appelé plusieurs fois
    if logger.handlers:
        return logger

    logger.setLevel(
        getattr(logging, config.logging.level.upper(), logging.INFO)
    )

    # Handler console rich
    rich_handler = RichHandler()
    logger.addHandler(rich_handler)

    # Handler fichier (sans couleurs)
    log_path = Path(config.logging.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger("aegis")


# ─────────────────────────────────────────
# Fonctions d'espacement et de sections
# ─────────────────────────────────────────

def log_section(title: str):
    """Affiche un séparateur de section bien visible."""
    _console.print()
    _console.rule(f"[bold cyan]{title}[/bold cyan]")
    _console.print()


def log_blank():
    """Ligne vide pour aérer les messages."""
    _console.print()


def log_success(message: str):
    """Message de succès en vert gras - hors système logging."""
    _console.print(f"  [bold green]✓[/bold green] {message}")


def log_failure(message: str):
    """Message d'échec en rouge gras - hors système logging."""
    _console.print(f"  [bold red]X[/bold red] {message}")


def log_warning_inline(message: str):
    """Avertissement inline en orange - hors système logging."""
    _console.print(f"  [bold orange1]⚠[/bold orange1] {message}")



