import random
import shutil

from rich import box
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text


TITLE = "KalnemiX"
TAGLINE = "VritraSec • OSINT & Recon"
SUBTITLE = "Security‑first • Privacy‑focused • Operator‑grade"


def _panel_width():
    cols = shutil.get_terminal_size(fallback=(100, 24)).columns
    return min(84, max(56, cols - 28))


def _panel(body, border, style, pad):
    return Panel(Align.center(body), box=border, style=style, padding=pad, width=_panel_width())


def _header():
    title = Text(TITLE, style="bold bright_cyan")
    tag = Text(TAGLINE, style="bright_magenta")
    return Group(Align.center(title), Align.center(tag), Align.center(Text(SUBTITLE, style="dim white")))


def _mini_chips():
    chips = Text.assemble(
        ("WHOIS", "bold white on bright_black"),
        " ",
        ("DNS", "bold white on bright_black"),
        " ",
        ("SUBDOMAINS", "bold white on bright_black"),
        " ",
        ("PORTS", "bold white on bright_black"),
        " ",
        ("SSL", "bold white on bright_black"),
    )
    return Align.center(chips)


def _feature_table():
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1), expand=False)
    table.add_column(justify="right", style="bright_cyan")
    table.add_column(style="white")
    table.add_row("Discovery", "Whois • DNS • Reverse IP • Subnet")
    table.add_row("Mapping", "Subdomains • Hidden files • Robots")
    table.add_row("Analysis", "Headers • SSL • OS Fingerprint")
    table.add_row("Utilities", "Ports • URL extract • Metadata")
    return Align.center(table)


def _feature_table_alt():
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=False)
    table.add_column(justify="right", style="bright_magenta")
    table.add_column(style="white")
    table.add_row("Intel", "Whois • IP Lookup • DNS")
    table.add_row("Surface", "Subdomains • Hidden files")
    table.add_row("Network", "Ports • SSL • Traceroute")
    table.add_row("Data", "URL Extract • IMG Metadata")
    return Align.center(table)


def _feature_table_compact():
    table = Table(box=box.MINIMAL, show_header=False, padding=(0, 1), expand=False)
    table.add_column(justify="right", style="bright_cyan")
    table.add_column(style="white")
    table.add_row("Core", "Whois • IP • DNS • SSL")
    table.add_row("Web", "Headers • Robots • Hidden files")
    table.add_row("Scope", "Subdomains • Subnet • Reverse IP")
    table.add_row("Tools", "Ports • Traceroute • URL Extract")
    return Align.center(table)


def _workflow_block():
    return Align.center(
        Text.assemble(
            ("DISCOVER", "bold bright_cyan"),
            "  →  ",
            ("ENUMERATE", "bold bright_magenta"),
            "  →  ",
            ("VALIDATE", "bold bright_cyan"),
        )
    )


def _b01():
    meta = Text.assemble(("Edition", "dim white"), ": ", ("PRO", "bold bright_cyan"), "   ",
                         ("Mode", "dim white"), ": ", ("ACTIVE", "bold bright_green"))
    body = Group(_header(), Rule(style="bright_cyan"), Align.center(meta), _feature_table())
    return _panel(body, box.ROUNDED, "bright_cyan", (1, 4))


def _b02():
    top = Text.assemble(
        ("MODULES", "dim white"),
        "  ",
        ("WHOIS", "bold bright_cyan"),
        "  ",
        ("DNS", "bold bright_cyan"),
        "  ",
        ("SUBDOMAINS", "bold bright_cyan"),
        "  ",
        ("PORTS", "bold bright_cyan"),
        "  ",
        ("SSL", "bold bright_cyan"),
    )
    body = Group(_header(), Rule(style="bright_magenta"), Align.center(top), _workflow_block())
    return _panel(body, box.HEAVY, "bright_magenta", (1, 4))


def _b03():
    status = Text.assemble(
        ("Status", "dim white"),
        ": ",
        ("READY", "bold bright_green"),
        "   ",
        ("Mode", "dim white"),
        ": ",
        ("PRO", "bold bright_cyan"),
    )
    chips = Align.center(Text.assemble(
        ("WHOIS", "bold white on bright_black"), " ",
        ("DNS", "bold white on bright_black"), " ",
        ("SUB", "bold white on bright_black"), " ",
        ("PORTS", "bold white on bright_black"),
    ))
    body = Group(_header(), Rule(style="bright_magenta"), Align.center(status), chips)
    return _panel(body, box.DOUBLE, "bright_magenta", (1, 6))


def _b05():
    meta = Text.assemble(
        ("Coverage", "dim white"),
        ": ",
        ("Web Surface • DNS • Infra", "white"),
    )
    body = Group(_header(), Rule(style="white"), Align.center(meta), _feature_table_compact())
    return _panel(body, box.SQUARE, "white", (1, 6))


def _b06():
    status = Text.assemble(("Signal", "dim white"), ": ", ("HIGH", "bold bright_green"),
                           "   ", ("Noise", "dim white"), ": ", ("LOW", "bold bright_green"))
    body = Group(_header(), Rule(style="bright_cyan"), Align.center(status), _feature_table_alt())
    return _panel(body, box.MINIMAL_DOUBLE_HEAD, "bright_cyan", (1, 4))


def _b07():
    right = Text("FAST • CLEAN • FIELD‑READY", style="bold bright_magenta")
    body = Group(_header(), Rule(style="bright_magenta"), Align.center(right), _mini_chips())
    return _panel(body, box.MINIMAL, "bright_magenta", (1, 5))


def _b09():
    body = Group(_header(), Rule(style="bright_magenta"), _feature_table(), _mini_chips())
    return _panel(body, box.HEAVY_EDGE, "bright_magenta", (1, 4))


def _b14():
    body = Group(_header(), Rule(style="bright_magenta"), _feature_table_compact(), _mini_chips())
    return _panel(body, box.DOUBLE, "bright_magenta", (1, 4))


def _b15():
    body = Group(_header(), Rule(style="white"), Align.center(Text("OSINT • Recon • Mapping", style="white")), _workflow_block())
    return _panel(body, box.MINIMAL_DOUBLE_HEAD, "white", (1, 4))


BANNERS = [
    _b01,
    _b02,
    _b03,
    _b05,
    _b06,
    _b07,
    _b09,
    _b14,
    _b15,
]


def get_banner():
    return random.choice(BANNERS)()
