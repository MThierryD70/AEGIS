import click
from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.engine import ScannerEngine
from aegis.quarantine.manager import QuarantineManager



print("\n\n")

def get_config() -> Config:
    config = Config.from_yaml("config.yaml")
    setup_logger(config)
    return config

@click.group()
def cli ():
    """ AEGIS I  ------- Antivirus à base de signature - Phase Python """
    pass

@cli.command()
@click.argument("path")
@click.option("--json", "save_json", is_flag=True, help="Sauvegarder un rapport JSON")
@click.option("--csv", "save_csv", is_flag=True, help="Sauvegarder un rapport CSV")
@click.option("--quarantine", is_flag=True, help="Mettre les menaces en quarantaine")

def scan(path, save_json, save_csv, quarantine):
    """Lance un scan sur Path (fichier ou repertoire)."""

    config = get_config()
    engine = ScannerEngine(config)
    reporter = ReportGenerator()
    qm = QuarantineManager(config) if quarantine else None

    report = engine.scan(path)
    reporter.print_console(report)

    if save_json:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reporter.save_json(report, f" reports/scan_{timestamp}.json")

    if save_csv:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reporter.save_csv(report, f" reports/scan_{timestamp}.csv")

    if quarantine and qm:
        for threat in report.threats:
            qm.quarantine(
                threat.path,
                malware_name = threat.match_result.malware_name,
                severity = threat.match_result.severity
            )

@cli.group()
def quarantine():
    """Gestion de quarantaine"""
    pass

@quarantine.command(name="list")
def quarantine_list():
    """Liste des fichiers en quarantaine"""
    config = get_config()
    qm = QuarantineManager(config)
    items = qm.list_quarantined()

    if not items:
        click.echo("Quarantaine vide")
        return

    click.echo(f" \n{len(items)} fichier(s) en quarantaine :\n")
    for item in items:
        click.echo(f"   ID            :  {item['id']}")
        click.echo(f"   Fichier       :  {item['original_path']}")
        click.echo(f"   MAlware       :  {item['malware_name']}")
        click.echo(f"   Sévérité      :  {item['severity']}")
        click.echo(f"   Date          :  {item['date_quarantined']}")
        click.echo() 


@quarantine.command(name="restore")
@click.argument("quarantine_id")
def quarantine_restore(quarantine_id):
    """Restaurer un fichier depuis la quarantaine via son ID"""
    config = get_config()
    qm = QuarantineManager(config)
    success = qm.restore(quarantine_id)

    if success:
        click.echo(f" Fichier restauré avec succès")
    else:
        click.echo(f" Echec de la restauration", err = True)

@quarantine.command(name="delete")
@click.argument("quarantine_id")
def quarantine_delete (quarantine_id):
    """Supprimer définitivement un fichier de la quarantaine"""
    config = get_config()
    qm = QuarantineManager(config)

    click.confirm (" Supprimer définitivement ce fichier ?", abort = True)
    success = qm.delete(quarantine_id)

    if success:
        click.echo(" Fichier supprimé définitivement.")
    else:
        click.echo("Echec de la suppression", err=True)






@cli.group()
def update():
    """Gestion des mises à jours de signatures."""
    pass


@update.command(name="import")
@click.argument("json_path")
def update_import(json_path):
    """Importe des dignatures depuis un fichier JSON local."""
    config = get_config()
    from aegis.updater.updater import Updater
    updater = Updater(config)
    result = updater.import_from_file (json_path)

    if result ["success"]:
        click.echo(f"\n Import réussi : ")
        click.echo(f"    Ajoutées : {result['added']}")
        click.echo(f"    Doublons : {result['skipped']}")
        click.echo(f"    Erreurs : {result['errors']}")
    else:
        click.echo(" Import échoué. ", err=True)

    
@update.command(name="status")
def update_status():
    """Affiche le status de la base de signatures."""

    config = get_config()

    from aegis.updater.updater import Updater
    updater = Updater(config)
    status = updater.status()
    click.echo(f" Signatures en base : {status['total_signatures']}")
    click.echo(f" Base de données    : {status['database_path']}")




@cli.command()
@click.option("--no-install", is_flag=True,
              help="Vérifier sans installer automatiquement")
def setup(no_install):
    """Vérifier et installer les dépendances Python manquantes."""

    import sys
    import subprocess
    import importlib

    # Bootstrap - installe rich en premier si absent
    # car le logger en dépend

    try:
        importlib.import_module("rich")
    except ImportError:
        click.echo("Installation de rich (requis pour le logger)...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "rich>=13.07.0"],
            check=True
        )
        click.echo("rich installé - relancez la commande setup.")
        return

    config = get_config()
    from aegis.setup.checker import DependancyChecker
    checker = DependancyChecker()
    success = checker.run_full_check(auto_install=not no_install)

    if success:
        click.echo("\n OK Environement prêt - Vous pouvez utiliser AEGIS.\n")
    else:
        click.echo("\n X  Certaines dépendances sont manquantes.",
                   err=True
        )

from aegis.reporting.generator import ReportGenerator
