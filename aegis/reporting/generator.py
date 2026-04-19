import json
import csv
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from aegis.scanner.engine import ScanReport
from aegis.logger.logger import get_logger


class ReportGenerator:

    def __init__(self):
        self.logger = get_logger()
        self.console = Console ()

    def print_console (self, report: ScanReport):
        # Résumé global

        self.console.print()
        self.console.rule("[bold blue] Résultat du scan[/bold blue]")

        color = "red" if report.threats_found > 0 else "green"
        
        self.console.print(
            f"\n  Fichiers analysées : [bold] {report.total_scanned}[/bold]"
        )

        self.console.print(
            f"  MENACES détectées  : [bold {color}]{report.threats_found}[/bold {color}]"
        )

        self.console.print(
            f"  Durée              : [bold] {report.duration_seconds:.2f}s[/bold]\n"
        )


        # Tableau des résultates
        table = Table (box = box.ROUNDED, show_header=True, header_style ="bold cyan")
        table.add_column("Fichiers", style = "dim", max_width=45)
        table.add_column("Statut", justify="center")
        table.add_column("Manace", max_width=30)
        table.add_column("Sévérité", justify="center")


        for result in report.results:
            if result.is_threat:
                statut = "[red]MENACE[/red]"
                manace = f"[red]{result.match_result.malware_name}[/red]"
                severite = f"[red]{result.match_result.severity}/4[/red]"
            else:
                statut = "[green]Propre[/green]"
                manace = "-"
                severite = "-"
            
            table.add_row (result.path.name, statut, manace, severite)
        
        self.console.print(table)
        self.console.print()

    
    def save_json (self, report: ScanReport, output_path: str):

        data = {
            "scan_date": datetime.now().isoformat(),
            
            "summary":{
                "total_scanned": report.total_scanned,
                "threats_found": report.threats_found,
                "duration_seconds": round(report.duration_seconds, 3)
            },

            "results": [
                {
                    "path": str(r.path),
                    "is_threat": r.is_threat,
                    "malware_name": r.match_result.malware_name,
                    "severity": r.match_result.severity,
                    "hashes": r.hashes
                }
                for r in report.results
            ]
        }

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with open (output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f" Rapport JSON sauvegardé: {output}")
    

    def save_csv(self, report: ScanReport, output_path: str):
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with open(output, "w", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "fichier", "est_menace", "malware",
                "severite", "md5", "sha256"
            ])

            for r in report.results:
                writer.writerow([
                    str(r.path),
                    r.is_threat,
                    r.match_result.malware_name or "",
                    r.match_result.severity or "",
                    r.hashes.get("md5", "") if r.hashes else "",
                    r.hashes.get ("sha256", "") if r.hashes else ""
                ])

        self.logger.info(f" Rapport CSV sauvegardé : {output}")
