import click

# ─────────────────────────────────────────
# Helpers - imports différés dans chaque fonction
# ─────────────────────────────────────────
def get_config():
    from aegis.config.manager import Config
    from aegis.logger.logger import setup_logger
    
    config = Config.from_yaml("config.yaml")
    setup_logger(config)
    return config

# ─────────────────────────────────────────
# Groupe principal
# ─────────────────────────────────────────
def print_logo_safe():
    """Affiche le logo sans planter si pyfiglet manque."""
    try:
        from aegis.logo import print_logo
        print_logo()
    except Exception:
        pass

class AegisGroup(click.Group):
    """Groupe Click personnalisé qui affiche le logo sur --help ou sans args."""
    def invoke(self, ctx):
        # Affiche le logo si aucune sous-commande ou si --help
        if not ctx.protected_args and not ctx.args:
            print_logo_safe()
        super().invoke(ctx)

    def get_help(self, ctx):
        print_logo_safe()
        return super().get_help(ctx)

@click.group(cls=AegisGroup)
def cli():
    """AEGIS Antivirus - Protection à base de signatures."""
    pass


# ─────────────────────────────────────────
# Commande : setup
# ─────────────────────────────────────────
@cli.command()
@click.option("--no-install", is_flag=True,
              help="Vérifie sans installer automatiquement")
def setup(no_install):
    """Vérifie et installe les dépendances Python manquantes."""
    import sys
    import subprocess
    import importlib

    # Bootstrap — installe rich en premier si absent
    try:
        importlib.import_module("rich")
    except ImportError:
        click.echo("Installation de rich (requis pour le logger)...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "rich>=13.7.0"],
            check=True
        )
        click.echo("rich installé — relancez : python main.py setup")
        return

    # Maintenant rich est disponible — imports différés
    from aegis.config.manager import Config
    from aegis.logger.logger import setup_logger
    from aegis.setup.checker import DependencyChecker

    config = Config.from_yaml("config.yaml")
    setup_logger(config)

    checker = DependencyChecker()
    success = checker.run_full_check(auto_install=not no_install)

    if success:
        click.echo("\n OK Environnement prêt — vous pouvez utiliser AEGIS.\n")
    else:
        click.echo("\n X Certaines dépendances sont manquantes.", err=True)


# ─────────────────────────────────────────
# Commande : scan
# ─────────────────────────────────────────
@cli.command()
@click.argument("path")
@click.option("--json", "save_json", is_flag=True,
              help="Sauvegarde un rapport JSON")
@click.option("--csv", "save_csv", is_flag=True,
              help="Sauvegarde un rapport CSV")
@click.option("--quarantine", is_flag=True,
              help="Met les menaces en quarantaine")
def scan(path, save_json, save_csv, quarantine):
    """Lance un scan sur PATH (fichier ou répertoire)."""
    from aegis.scanner.engine import ScannerEngine
    from aegis.reporting.generator import ReportGenerator
    from aegis.quarantine.manager import QuarantineManager

    config = get_config()
    engine = ScannerEngine(config)
    reporter = ReportGenerator()
    qm = QuarantineManager(config) if quarantine else None

    report = engine.scan(path)
    reporter.print_console(report)

    if save_json:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reporter.save_json(report, f"reports/scan_{timestamp}.json")

    if save_csv:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reporter.save_csv(report, f"reports/scan_{timestamp}.csv")

    if quarantine and qm:
        for threat in report.threats:
            qm.quarantine(
                threat.path,
                malware_name=threat.match_result.malware_name,
                severity=threat.match_result.severity
            )


# ─────────────────────────────────────────
# Groupe : quarantine
# ─────────────────────────────────────────
@cli.group()
def quarantine():
    """Gestion de la quarantaine."""
    pass


@quarantine.command(name="list")
def quarantine_list():
    """Liste les fichiers en quarantaine."""
    from aegis.quarantine.manager import QuarantineManager
    config = get_config()
    qm = QuarantineManager(config)
    items = qm.list_quarantined()

    if not items:
        click.echo("Quarantaine vide.")
        return

    click.echo(f"\n{len(items)} fichier(s) en quarantaine :\n")
    for item in items:
        click.echo(f"  ID       : {item['id']}")
        click.echo(f"  Fichier  : {item['original_path']}")
        click.echo(f"  Malware  : {item['malware_name']}")
        click.echo(f"  Sévérité : {item['severity']}/4")
        click.echo(f"  Date     : {item['date_quarantined']}")
        click.echo()


@quarantine.command(name="restore")
@click.argument("quarantine_id")
def quarantine_restore(quarantine_id):
    """Restaure un fichier depuis la quarantaine."""
    from aegis.quarantine.manager import QuarantineManager
    config = get_config()
    qm = QuarantineManager(config)
    success = qm.restore(quarantine_id)
    if success:
        click.echo("Fichier restauré avec succès.")
    else:
        click.echo("Échec de la restauration.", err=True)


@quarantine.command(name="delete")
@click.argument("quarantine_id")
def quarantine_delete(quarantine_id):
    """Supprime définitivement un fichier de la quarantaine."""
    from aegis.quarantine.manager import QuarantineManager
    config = get_config()
    qm = QuarantineManager(config)
    click.confirm("Supprimer définitivement ce fichier ?", abort=True)
    success = qm.delete(quarantine_id)
    if success:
        click.echo("Fichier supprimé définitivement.")
    else:
        click.echo("Échec de la suppression.", err=True)

# ─────────────────────────────────────────
# Groupe : update
# ─────────────────────────────────────────
@cli.group()
def update():
    """Gestion des mises à jour de signatures."""
    pass

@update.command(name="import")
@click.argument("json_path")
def update_import(json_path):
    """Importe des signatures depuis un fichier JSON local."""
    from aegis.updater.updater import Updater
    config = get_config()
    updater = Updater(config)
    result = updater.import_from_file(json_path)

    if result["success"]:
        click.echo(f"Import réussi :")
        click.echo(f"  Ajoutées : {result['added']}")
        click.echo(f"  Doublons : {result['skipped']}")
        click.echo(f"  Erreurs  : {result['errors']}")
    else:
        click.echo("Import échoué.", err=True)

@update.command(name="fetch")
@click.argument("url")
@click.option("--verify/--no-verify", default=True,
              help="Vérifie l'intégrité SHA-256 si disponible")
def update_fetch(url, verify):
    """Télécharge et importe des signatures depuis une URL."""
    from aegis.updater.updater import Updater
    config = get_config()
    updater = Updater(config)
    result = updater.import_from_url(url)

    if result["success"]:
        click.echo(f"Import depuis URL réussi :")
        click.echo(f"  Ajoutées : {result['added']}")
        click.echo(f"  Doublons : {result['skipped']}")
        click.echo(f"  Erreurs  : {result['errors']}")
    else:
        click.echo("Import depuis URL échoué.", err=True)


@update.command(name="status")
def update_status():
    """Affiche le statut de la base de signatures."""
    from aegis.updater.updater import Updater
    config = get_config()
    updater = Updater(config)
    status = updater.status()
    click.echo(f"Signatures en base : {status['total_signatures']}")
    click.echo(f"Base de données    : {status['database_path']}")

@cli.group()
def build():
    """Compilation des modules C++ haute performance."""
    pass

@build.command(name="compile")
@click.option("--force", is_flag=True,
              help="Force la recompilation même si déjà compilé")
def build_compile(force):
    """Compile les modules C++ (hasher + bloom filter)."""
    from aegis.build.msys2_detector import Msys2Detector
    from aegis.build.msys2_builder import Msys2CppBuilder
    from aegis.build.builder import CppBuilder
    config = get_config()

    # MSYS2 est la chaîne préférée (chemins sans espaces) ;
    # la chaîne classique sert de secours.
    msys2 = Msys2Detector()
    if msys2.is_available():
        builder = Msys2CppBuilder()
    else:
        builder = CppBuilder()

    success = builder.build(force_rebuild=force)

    if success:
        click.echo("\nOK Modules C++ prêts - performances maximales actives")
    else:
        click.echo("\n⚠ Compilation échouée ou environnement incomplet.")
        click.echo("  AEGIS fonctionne en mode Python pur (moins rapide).")
        if not msys2.is_available():
            click.echo("\n  MSYS2 non détecté — chaîne recommandée :")
            click.echo("    1. Installez MSYS2 : https://www.msys2.org")
            click.echo("    2. Dans le terminal « MSYS2 MINGW64 » :")
            click.echo(f"         {msys2.pacman_command()}")
            click.echo("    3. Dans cmd (PATH utilisateur) :")
            click.echo(f"         {msys2.path_command()}")
        else:
            click.echo(
                "\n  Paquets MSYS2 manquants ? "
                "Dans « MSYS2 MINGW64 » :"
            )
            click.echo(f"    {msys2.pacman_command()}")
        click.echo("\n  Puis relancez : aegis build compile")


@build.command(name="status")
def build_status():
    """Affiche le statut des modules C++."""
    from aegis.build.msys2_detector import Msys2Detector
    from aegis.build.detector import EnvironmentDetector
    from aegis.logger.logger import log_section, log_blank, log_success, log_failure
    from rich.console import Console
    from pathlib import Path
    get_config()

    console = Console()
    msys2 = Msys2Detector()

    # --- Section Chaîne MSYS2 (recommandée) ──
    log_section("Environnement C++ (MSYS2)")

    if msys2.is_available():
        report = msys2.detect()

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
            ("Générateur     ", msys2.generator or "non trouvé"),
        ]
        for label, value in fields:
            if value:
                console.print(
                    f"  [dim]{label}[/dim] : "
                    f"[white]{value}[/white]"
                )
            else:
                console.print(
                    f"  [dim]{label}[/dim] : "
                    f"[red]non trouvé[/red]"
                )

        log_blank()

        if report.can_build:
            console.print(
                "  Compilation C++ : [bold green]✓ possible[/bold green]"
            )
        else:
            console.print(
                "  Compilation C++ : [bold red]✗ impossible[/bold red]"
            )
            console.print(
                "  [dim]Paquets MSYS2 manquants — dans « MSYS2 MINGW64 » :\n"
                f"  {msys2.pacman_command()}"
            )
            console.print("  [dim]Puis : aegis build compile[/dim]")

        log_blank()

    else:
        console.print("  [bold red]✗ MSYS2 non installé[/bold red]")
        console.print(
            "  [dim]Chaîne recommandée : chemins sans espaces,"
            " ni ld.exe ni DLL introuvables.[/dim]"
        )
        console.print("  [dim]Installation :[/dim]")
        console.print("    1. [cyan]https://www.msys2.org[/cyan]")
        console.print("    2. Dans le terminal « MSYS2 MINGW64 » :")
        console.print(
            f"       [bold cyan]{msys2.pacman_command()}[/bold cyan]"
        )
        console.print("    3. Dans cmd (PATH utilisateur) :")
        console.print(
            f"       [bold cyan]{msys2.path_command()}[/bold cyan]"
        )
        console.print(
            "       Puis rouvrez le terminal et relancez :"
            " aegis build status"
        )
        log_blank()

        # ── Chaîne de secours (ancien MinGW) ──
        log_section("Chaîne de secours (MinGW classique)")

        report = EnvironmentDetector().detect()
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
            ("MinGW bin      ", report.mingw_bin),
        ]
        for label, value in fields:
            if value:
                console.print(
                    f"  [dim]{label}[/dim] : "
                    f"[white]{value}[/white]"
                )
            else:
                console.print(
                    f"  [dim]{label}[/dim] : "
                    f"[red]non trouvé[/red]"
                )

        log_blank()

        if report.can_build:
            console.print(
                "  Compilation C++ : "
                "[bold yellow]✓ possible (secours)[/bold yellow]"
            )
        else:
            console.print(
                "  Compilation C++ : [bold red]X impossible[/bold red]"
            )
        console.print(
            "  [dim]La chaîne MSYS2 reste recommandée pour éviter"
            " les soucis de chemins avec espaces.[/dim]"
        )
        log_blank()

    # --- Section Modules compilés ──
    log_section("Modules compilés")

    bin_dir = Path("cpp/bin")
    pyd_files = list(bin_dir.glob("aegis_cpp*.pyd")) if bin_dir.exists() else []

    if pyd_files:
        for f in pyd_files:
            console.print(f"  [bold green]✓[/bold green] {f.name}")
    else:
        console.print("  [bold red]X[/bold red] Aucun module compilé")
        console.print(
            "  [dim]Lancez : aegis build compile[/dim]"
        )

    log_blank()

@cli.command()
@click.option("--path", default="Tests/Malwares_test/eicar.com",
              help="Chemin de sortie du fichier de test")
def generate_test(path):
    """Génère un fichier de test EICAR pour valider la détection."""
    import os
    from pathlib import Path

    # La chaîne EICAR est publique et documentée — eicar.org
    # Elle est stockée en deux parties pour éviter les faux positifs
    # sur le code source lui-même
    part1 = r"X5O!P%@AP[4\PZX54(P^)7CC)7}"
    part2 = r"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_string = part1 + part2

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(eicar_string, encoding="ascii")
    click.echo(f"Fichier de test créé : {output}")
    click.echo("Lancez maintenant : aegis scan Tests/Malwares_test/")
    click.echo()
    click.echo("[!] Windows Defender peut supprimer ce fichier immédiatement.")
    click.echo("    C'est normal - ajoutez Tests/Malwares_test/ en exclusion Defender")
    click.echo("    pour tester, puis retirez l'exclusion après.")
