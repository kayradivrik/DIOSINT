"""
phone_lookup.py - Phone Number Format & Country Identification
==============================================================
Validates phone number prefixes and matches international calling codes.
"""

import re
from rich.console import Console
from rich.table import Table

console = Console()

COUNTRY_CODES = {
    "90": "Turkey (+90)",
    "1": "USA / Canada (+1)",
    "44": "United Kingdom (+44)",
    "49": "Germany (+49)",
    "33": "France (+33)",
    "31": "Netherlands (+31)",
    "7": "Russia / Kazakhstan (+7)",
    "61": "Australia (+61)",
    "41": "Switzerland (+41)",
}


def analyze_phone(phone: str):
    console.print(f"\n[*] Target phone number: [yellow]{phone}[/]\n")
    clean_phone = re.sub(r"[\s\-\(\)\+]", "", phone)
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    
    table.add_row("Raw Input", phone)
    table.add_row("Sanitized Digits", clean_phone)
    table.add_row("Length", str(len(clean_phone)))
    
    country = "Unknown"
    for code, name in COUNTRY_CODES.items():
        if clean_phone.startswith(code):
            country = name
            break
            
    table.add_row("Matched Region", country)
    console.print(table)
    
    return {
        "source": "phone_lookup",
        "type": "phone",
        "value": phone,
        "context": {"country": country, "clean": clean_phone}
    }
