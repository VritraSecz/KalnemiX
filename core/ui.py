from colorama import Fore, Style, init
from rich.console import Console

init(autoreset=False)

console = Console()

# Premium palette (cool + neon accents)
PRIMARY = Fore.LIGHTCYAN_EX
ACCENT = Fore.LIGHTMAGENTA_EX
SUCCESS = Fore.LIGHTGREEN_EX
WARN = Fore.LIGHTYELLOW_EX
ERROR = Fore.LIGHTRED_EX
TEXT = Fore.WHITE
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

# Backward-compatible aliases
RED = ACCENT
GREEN = PRIMARY
BLUE = Fore.LIGHTBLUE_EX
YELLOW = WARN

# Common prefixes
PFX_OK = f"{ACCENT}[+]{SUCCESS} "
PFX_INFO = f"{ACCENT}[~]{PRIMARY} "
PFX_FAIL = f"{ACCENT}[x]{ERROR} "
PFX_WARN = f"{ACCENT}[!]{WARN} "

PROMPT = f"{ACCENT}kalnemix{RESET}{PRIMARY}]> {ACCENT}"
