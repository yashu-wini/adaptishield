#!/usr/bin/env python3
"""
AdaptiShield Demo Script
Run the full pipeline on sample texts.
Usage: python demo.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
import json

console = Console()


def print_banner():
    console.print(Panel.fit(
        "[bold cyan]🛡️  ADAPTISHIELD[/bold cyan]\n"
        "[dim]Context-Aware Privacy Intelligence Framework[/dim]\n"
        "[dim]Version 1.0.0[/dim]",
        border_style="cyan",
        padding=(1, 4)
    ))


def run_demo():
    print_banner()

    console.print("\n[bold yellow]Initializing pipeline...[/bold yellow]")

    from pipeline import AdaptiShieldPipeline
    # Use regex-only for fast demo (no model download needed)
    pipeline = AdaptiShieldPipeline(
        use_transformer=False,
        use_spacy=False,
        encrypt_output=True,
        log_results=True
    )

    test_cases = [
        {
            "name": "Customer Record (Low Risk)",
            "text": "Our customer John Smith lives at 123 MG Road, Bangalore. He can be reached at john.smith@company.com"
        },
        {
            "name": "KYC Document (High Risk)",
            "text": "Name: Priya Mehta | Aadhaar: 2345 6789 0123 | PAN: BVLPM3142K | DOB: 15/03/1988 | Phone: +91-9876543210 | Email: priya.mehta@gmail.com | Bank Account: 1234567890123"
        },
        {
            "name": "Critical - Password Leak",
            "text": "User: admin@company.com | Password: Secure@123! | Credit Card: 4532015112830366 | Aadhaar: 9876 5432 1098"
        },
    ]

    for i, case in enumerate(test_cases, 1):
        console.print(f"\n[bold white]━━━ Test Case {i}: {case['name']} ━━━[/bold white]")
        console.print(f"[dim]Input:[/dim] {case['text'][:100]}...")

        result = pipeline.process_text(case["text"], document_name=case["name"])
        display_result(result)


def display_result(result: dict):
    risk = result["risk_analysis"]
    entities = result["entities"]

    # Risk badge
    risk_colors = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
    risk_icons = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}
    color = risk_colors.get(risk["risk_level"], "white")
    icon = risk_icons.get(risk["risk_level"], "⚪")

    console.print(
        f"  Risk: [{color}]{icon} {risk['risk_level']}[/{color}] | "
        f"Score: [bold]{risk['risk_score']:.1f}[/bold] | "
        f"Entities: [bold]{risk['entity_count']}[/bold] | "
        f"Time: [dim]{result['processing_time_ms']:.0f}ms[/dim]"
    )

    if entities:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 1))
        table.add_column("Entity Type", style="cyan", width=18)
        table.add_column("Original", style="red", width=22)
        table.add_column("Anonymized", style="green", width=25)
        table.add_column("Strategy", style="yellow", width=12)
        table.add_column("Confidence", width=10)
        table.add_column("Level", width=10)

        for e in entities:
            level_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
            lc = level_colors.get(e["sensitivity_level"], "white")
            table.add_row(
                e["entity_type"],
                e["original_value"][:20],
                e["anonymized_value"][:23],
                e["strategy"],
                f"{e['confidence']*100:.0f}%",
                f"[{lc}]{e['sensitivity_level']}[/{lc}]"
            )

        console.print(table)

    # Show anonymized text
    console.print(f"  [dim]Anonymized:[/dim] [green]{result['anonymized_text'][:150]}[/green]")

    # Encryption status
    if result.get("encrypted_payload"):
        enc = result["encrypted_payload"]
        console.print(f"  [cyan]🔐 Encrypted (AES-256-GCM)[/cyan] | Nonce: [dim]{enc['nonce'][:16]}...[/dim]")

    # Recommendations
    for rec in risk.get("recommendations", [])[:2]:
        console.print(f"  [dim]{rec}[/dim]")


def run_tests():
    """Run the test suite."""
    console.print("\n[bold yellow]Running test suite...[/bold yellow]")
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_pipeline.py", "-v", "--tb=short"],
        capture_output=True, text=True
    )
    console.print(result.stdout)
    if result.returncode != 0:
        console.print(f"[red]{result.stderr}[/red]")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AdaptiShield Demo")
    parser.add_argument("--test", action="store_true", help="Run test suite")
    args = parser.parse_args()

    if args.test:
        run_tests()
    else:
        run_demo()
