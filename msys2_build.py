#!/usr/bin/env python3
"""
Compilation des modules C++ AEGIS via l'environnement MSYS2.
"""
import argparse
import sys


def _setup_logger():
    from aegis.logger.logger import get_logger
    try:
        from aegis.config.manager import Config
        from aegis.logger.logger import setup_logger
        config = Config.from_yaml("config.yaml")
        setup_logger(config)
    except Exception:
        import logging
        logging.basicConfig(level=logging.INFO)
    return get_logger()


def _import_detector():
    from aegis.build.msys2_detector import Msys2Detector
    return Msys2Detector()


def cmd_status(detector) -> int:
    from aegis.logger.logger import log_section, log_blank, log_success, log_failure
    from rich.console import Console

    console = Console()
    log_section("Environnement C++ (MSYS2)")

    report = detector.detect()
    for tool in report.tools:
        if tool.found:
            console.print(
                f"  [bold green]✓[/bold green] "
                f"[cyan]{tool.name:<12}[/cyan] {tool.path}"
            )
        else:
            console.print(
                f"  [bold red]✗[/bold red] "
                f"[cyan]{tool.name:<12}[/cyan] "
                f"[dim]{tool.note}[/dim]"
            )

    log_blank()
    fields = [
        ("OpenSSL include", report.openssl_include),
        ("OpenSSL lib    ", report.openssl_lib),
        ("MSYS2 bin      ", report.mingw_bin),
        ("Générateur     ", detector.generator or "non trouvé"),
    ]
    for label, value in fields:
        if value:
            console.print(f"  [dim]{label}[/dim] : [white]{value}[/white]")
        else:
            console.print(f"  [dim]{label}[/dim] : [red]non trouvé[/red]")

    log_blank()
    if report.can_build:
        log_success("Compilation C++ possible")
    else:
        log_failure("Compilation C++ impossible")
        if not detector.is_available():
            console.print("  [dim]Lancez : python msys2_build.py install[/dim]")
    log_blank()

    return 0 if report.can_build else 1


def cmd_compile(detector, force: bool) -> int:
    from aegis.logger.logger import log_section, log_blank, log_success, log_failure
    from rich.console import Console
    from aegis.build.msys2_builder import Msys2CppBuilder

    console = Console()
    if not detector.is_available():
        log_section("Environnement C++ (MSYS2)")
        log_failure("MSYS2 introuvable")
        console.print("  [dim]" + detector.install_help().replace("\n", "\n  ") + "[/dim]")
        log_blank()
        return 1

    log_section("Compilation des modules C++ (MSYS2)")
    builder = Msys2CppBuilder()
    ok = builder.build(force_rebuild=force)

    if ok:
        log_success("Modules C++ prêts (MSYS2)")
    else:
        log_failure("Compilation échouée - AEGIS reste en mode Python pur")
    log_blank()
    return 0 if ok else 1


def cmd_install(detector) -> int:
    from aegis.logger.logger import log_section
    from rich.console import Console

    console = Console()
    log_section("Installation de l'environnement C++ via MSYS2")
    console.print("  " + detector.install_help().replace("\n", "\n  "))
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="msys2_build",
        description="Build C++ AEGIS via l'environnement MSYS2",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Affiche l'état de l'environnement MSYS2")

    p_compile = sub.add_parser("compile", help="Compile les modules C++")
    p_compile.add_argument(
        "--force", action="store_true",
        help="Force la recompilation même si déjà compilé"
    )

    sub.add_parser("install", help="Affiche les commandes d'installation MSYS2")

    args = parser.parse_args()

    _setup_logger()
    detector = _import_detector()

    if args.cmd == "status":
        sys.exit(cmd_status(detector))
    elif args.cmd == "compile":
        sys.exit(cmd_compile(detector, args.force))
    elif args.cmd == "install":
        sys.exit(cmd_install(detector))


if __name__ == "__main__":
    main()
    
