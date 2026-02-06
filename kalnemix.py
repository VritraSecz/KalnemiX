# /bin/python3
# Script by MrHacker-X
# https://github.com/MrHacker-X

import argparse
import sys
import subprocess
import os
import signal
from time import sleep
from urllib.parse import urlparse
from datetime import datetime

from core.kalnemix_features import (
    crack,
    create_reverse_shell,
    deepscan,
    emetad,
    findon,
    findshrs,
    gensel,
    http_hd,
    ipd,
    os_fingerprint,
    passive_subdomains,
    quickscan,
    revip,
    robots,
    routrce,
    rxtrl,
    scanort,
    status_map,
    subnetf,
    tech_fingerprint,
)
from core.ui import (
    BLUE,
    GREEN,
    RED,
    RESET,
    PFX_INFO,
    PFX_OK,
    PFX_WARN,
    YELLOW,
    console,
    PROMPT,
)
from core.banners import get_banner

def signal_handler(sig, frame):
    try:
        exitf()
    finally:
        raise SystemExit(0)

signal.signal(signal.SIGINT, signal_handler)

VERSION = "1.0.2"

def parse_args():
    parser = argparse.ArgumentParser(
        prog="kalnemix",
        add_help=False,
        description="KalnemiX OSINT + Recon Toolkit",
    )
    parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("-a", "--about", action="store_true", help="Show about/info and exit")
    parser.add_argument("-i", "--interactive", action="store_true", help="Start interactive mode")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--ip", help="IP lookup for target")
    action.add_argument("--whois", help="Whois lookup for target")
    action.add_argument("--subdomain-quick", help="Quick subdomain scan for domain")
    action.add_argument("--subdomain-deep", help="Deep subdomain scan for domain")
    action.add_argument("--subdomain-passive", help="Passive subdomain discovery for domain")
    action.add_argument("--httpheader", help="Fetch HTTP headers for URL/domain")
    action.add_argument("--robots", help="Robots.txt analysis for domain")
    action.add_argument("--dns", help="DNS lookup for domain")
    action.add_argument("--reverse-ip", help="Reverse IP lookup")
    action.add_argument("--traceroute", help="Traceroute to target")
    action.add_argument("--portscan", help="Port scan target")
    action.add_argument("--extract-url", help="Extract URLs from domain")
    action.add_argument("--find-hidden", help="Find hidden files/dirs for domain")
    action.add_argument("--crackhash", help="Crack hash value")
    action.add_argument("--imgmeta", help="Extract image metadata for file path")
    action.add_argument("--subnet", help="Subnet info for IP")
    action.add_argument("--sslscan", help="SSL scan for domain/IP")
    action.add_argument("--osfp", help="OS fingerprint target")
    action.add_argument("--reverse-shell", help="Create reverse shell with ip:port")
    action.add_argument("--tech", help="Tech fingerprint for domain/url")
    action.add_argument("--status-map", help="HTTP status map for domain")
    parser.add_argument("--hash-type", help="Hash type for --crackhash (md5/sha1/sha256/sha512/...)")
    parser.add_argument("--wordlist", help="Wordlist path for --crackhash/--find-hidden/--status-map")
    parser.add_argument("--endport", help="End port for --portscan (default 1000)")
    parser.add_argument("--scheme", help="Scheme for --status-map (http/https)")
    return parser.parse_args()


def print_help():
    print(f"{GREEN}KalnemiX{RESET} {RED}v{VERSION}{RESET}")
    print(f"{PFX_OK}Usage:{RESET} python kalnemix.py [options]\n")
    print(f"{PFX_OK}Core options:{RESET}")
    print(f"  {GREEN}-h{RESET}, {GREEN}--help{RESET}           Show this help message and exit")
    print(f"  {GREEN}-v{RESET}, {GREEN}--version{RESET}        Show version and exit")
    print(f"  {GREEN}-a{RESET}, {GREEN}--about{RESET}          Show about/info and exit")
    print(f"  {GREEN}-i{RESET}, {GREEN}--interactive{RESET}    Start interactive mode\n")
    print(f"{PFX_OK}Actions (pick one):{RESET}")
    print(f"  {GREEN}--whois{RESET} <target>             Whois lookup")
    print(f"  {GREEN}--ip{RESET} <ip>                    IP lookup")
    print(f"  {GREEN}--subdomain-quick{RESET} <domain>    Quick subdomain scan")
    print(f"  {GREEN}--subdomain-deep{RESET} <domain>     Deep subdomain scan")
    print(f"  {GREEN}--subdomain-passive{RESET} <domain>  Passive subdomain scan")
    print(f"  {GREEN}--httpheader{RESET} <url/domain>     HTTP headers")
    print(f"  {GREEN}--robots{RESET} <domain>             Robots.txt analysis")
    print(f"  {GREEN}--dns{RESET} <domain>                DNS lookup")
    print(f"  {GREEN}--reverse-ip{RESET} <ip>             Reverse IP lookup")
    print(f"  {GREEN}--traceroute{RESET} <target>         Traceroute")
    print(f"  {GREEN}--portscan{RESET} <target>           Port scan")
    print(f"  {GREEN}--extract-url{RESET} <domain>        Extract URLs")
    print(f"  {GREEN}--find-hidden{RESET} <domain>        Find hidden files/dirs")
    print(f"  {GREEN}--crackhash{RESET} <hash>            Crack hash")
    print(f"  {GREEN}--imgmeta{RESET} <file>              Image metadata")
    print(f"  {GREEN}--subnet{RESET} <ip>                 Subnet info")
    print(f"  {GREEN}--sslscan{RESET} <domain/ip>         SSL scan")
    print(f"  {GREEN}--osfp{RESET} <target>               OS fingerprint")
    print(f"  {GREEN}--reverse-shell{RESET} <ip:port>     Create reverse shell")
    print(f"  {GREEN}--tech{RESET} <url/domain>           Tech fingerprint")
    print(f"  {GREEN}--status-map{RESET} <domain>         HTTP status map\n")
    print(f"{PFX_OK}Helpers (only with matching action):{RESET}")
    print(f"  {GREEN}--hash-type{RESET} <type>            For --crackhash")
    print(f"  {GREEN}--wordlist{RESET} <path>             For deep scans / status-map / crackhash")
    print(f"  {GREEN}--endport{RESET} <port>              For --portscan")
    print(f"  {GREEN}--scheme{RESET} <http|https>         For --status-map")


def _validate_cli(args):
    action_map = {
        "ip": "ip",
        "whois": "whois",
        "subdomain_quick": "subdomain_quick",
        "subdomain_deep": "subdomain_deep",
        "subdomain_passive": "subdomain_passive",
        "httpheader": "httpheader",
        "robots": "robots",
        "dns": "dns",
        "reverse_ip": "reverse_ip",
        "traceroute": "traceroute",
        "portscan": "portscan",
        "extract_url": "extract_url",
        "find_hidden": "find_hidden",
        "crackhash": "crackhash",
        "imgmeta": "imgmeta",
        "subnet": "subnet",
        "sslscan": "sslscan",
        "osfp": "osfp",
        "reverse_shell": "reverse_shell",
        "tech": "tech",
        "status_map": "status_map",
    }

    helper_map = {
        "subdomain_deep": {"wordlist"},
        "find_hidden": {"wordlist"},
        "status_map": {"wordlist", "scheme"},
        "portscan": {"endport"},
        "crackhash": {"hash_type", "wordlist"},
        "reverse_shell": set(),
    }

    selected = [key for key in action_map if getattr(args, key)]
    if not selected:
        return
    action = selected[0]
    allowed_helpers = helper_map.get(action, set())

    used_helpers = set()
    for name in [
        "hash_type",
        "wordlist",
        "endport",
        "scheme",
    ]:
        if getattr(args, name):
            used_helpers.add(name)

    invalid = used_helpers - allowed_helpers
    if invalid:
        invalid_list = ", ".join(sorted(invalid))
        print(f"{PFX_WARN}Invalid helper args for this action: {invalid_list}")
        raise SystemExit(2)


def _cli_action_selected(args):
    return any(
        getattr(args, key)
        for key in [
            "ip",
            "whois",
            "subdomain_quick",
            "subdomain_deep",
            "subdomain_passive",
            "httpheader",
            "robots",
            "dns",
            "reverse_ip",
            "traceroute",
            "portscan",
            "extract_url",
            "find_hidden",
            "crackhash",
            "imgmeta",
            "subnet",
            "sslscan",
            "osfp",
            "reverse_shell",
            "tech",
            "status_map",
        ]
    )




def bnr():
    console.print(get_banner())


def _normalize_target(value):
    value = value.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return urlparse(value).netloc
    return value.strip("/")


def _is_valid_port(value):
    try:
        port = int(value)
        return 1 <= port <= 65535
    except Exception:
        return False

main_menu = f"""{RESET}
{RED}[░░] {GREEN}Select Any Option:

{RED}[01]{GREEN} WhoIs Lookup         {RED}[11]{GREEN} Find Hidden files
{RED}[02]{GREEN} IP Lookup            {RED}[12]{GREEN} Crack Hash
{RED}[03]{GREEN} Find Subdomain       {RED}[13]{GREEN} Get IMG Metadata
{RED}[04]{GREEN} Show Http Header     {RED}[14]{GREEN} Subnet Lookup
{RED}[05]{GREEN} Robots Scanner       {RED}[15]{GREEN} SSL Scan
{RED}[06]{GREEN} DNS Lookup           {RED}[16]{GREEN} OS FingerPrint
{RED}[07]{GREEN} Reverse IP Lookup    {RED}[17]{GREEN} Create Reverse Shell
{RED}[08]{GREEN} Traceroute           {RED}[18]{GREEN} Passive Subdomains
{RED}[09]{GREEN} Scan Open Port       {RED}[19]{GREEN} Tech Fingerprint
{RED}[10]{GREEN} Extract URL          {RED}[20]{GREEN} HTTP Status Map
{YELLOW}[21]{YELLOW} Connect with us      {YELLOW}[22]{YELLOW} About
{YELLOW}[23]{YELLOW} Exit

╔═══╗
╚═══[{PROMPT}"""

soc = f"""
{RED}[░░] {GREEN}Select any options

{RED}[01] {GREEN}Instagram
{RED}[02] {GREEN}Facebook
{RED}[03] {GREEN}Github
{RED}[04] {GREEN}YouTube
{RED}[05] {GREEN}Telegram Channel
{RED}[06] {GREEN}Telegram Community
{RED}[95] {GREEN}Back
{RED}[99] {GREEN}Exit

╔═══╗
╚═══[{PROMPT}"""

rest = f"""{RESET}
{RED}[░░] {GREEN}Select Hash Type:

{RED}[01]{GREEN} md5
{RED}[02]{GREEN} sha1
{RED}[03]{GREEN} sha224
{RED}[04]{GREEN} sha256
{RED}[05]{GREEN} sha384
{RED}[06]{GREEN} sha512
{RED}[07]{GREEN} sha3-224
{RED}[08]{GREEN} sha3-256
{RED}[09]{GREEN} sha3-384
{RED}[10]{GREEN} sha3-512
{RED}[95]{GREEN} Back
{RED}[99]{GREEN} Exit

╔═══╗
╚═══[{PROMPT}"""

subin = f"""
{RED}[░░] {GREEN}Select Any Option:

{RED}[01]{GREEN} Quick Scan
{RED}[02]{GREEN} Deep Scan
{RED}[95]{GREEN} Back
{RED}[99]{GREEN} Exit

╔═══╗
╚═══[{PROMPT}"""

aboutx = f"""
{PFX_OK}Introduction:{RESET}{GREEN} KalnemiX is a professional OSINT and recon toolkit built for fast discovery, clean output, and practical workflows across web targets.

{PFX_OK}Overview:{RESET}{GREEN} Whois/IP/DNS lookups, subdomain discovery (active + passive), HTTP headers and robots analysis, reverse IP, traceroute, port scanning, URL extraction, hidden file discovery, SSL scan, OS fingerprinting, image metadata, and subnet utilities. New additions include tech fingerprinting and HTTP status mapping.

{PFX_OK} The following are some of the key features of KalnemiX:{RESET}{GREEN}

{RED}[01]{GREEN} WhoIs Lookup:{RESET}{GREEN} This feature allows you to perform a WhoIs lookup on a domain name, which can provide useful information about the owner of the domain, its registration details, and more.

{RED}[02]{GREEN} IP Lookup:{RESET}{GREEN} This feature allows you to perform a lookup on an IP address, which can help you identify the location of the server hosting the web application and other useful information.

{RED}[03]{GREEN} Find Subdomain:{RESET}{GREEN} This feature allows you to discover subdomains of a target domain, which can be useful for identifying additional attack surfaces.

{RED}[04]{GREEN} Show HTTP Header:{RESET}{GREEN} This feature allows you to view the HTTP headers of a web page, which can provide information about the web server, software versions, and more.

{RED}[05]{GREEN} Robots Scanner:{RESET}{GREEN} This feature allows you to scan a website for the presence of a robots.txt file, which can reveal information about which pages are excluded from search engines.

{RED}[06]{GREEN} DNS Lookup:{RESET}{GREEN} This feature allows you to perform a DNS lookup on a domain, which can provide information about the DNS servers responsible for resolving the domain name.

{RED}[07]{GREEN} Reverse IP Lookup:{RESET}{GREEN} This feature allows you to perform a reverse IP lookup, which can help you identify other websites hosted on the same server.

{RED}[08]{GREEN} Traceroute:{RESET}{GREEN} This feature allows you to perform a traceroute to a target IP address, which can help you identify the network path taken to reach the target.

{RED}[09]{GREEN} Scan Open Port:{RESET}{GREEN} This feature allows you to scan for open ports on a target IP address, which can help you identify potential attack vectors.

{RED}[10]{GREEN} Extract URL:{RESET}{GREEN} This feature allows you to extract URLs from a web page, which can be useful for identifying hidden pages or directories.

{RED}[11]{GREEN} Find Hidden Files:{RESET}{GREEN} This feature allows you to search for hidden files and directories on a web server, which can reveal additional attack surfaces.

{RED}[12]{GREEN} Crack Hash:{RESET}{GREEN} This feature allows you to crack password hashes, which can be useful for gaining access to protected resources.

{RED}[13]{GREEN} Get IMG Metadata:{RESET}{GREEN} This feature allows you to extract metadata from image files, which can provide information about the camera used to capture the image and other details.

{RED}[14]{GREEN} Subnet Lookup:{RESET}{GREEN} This feature allows you to perform a lookup on a subnet, which can provide information about the range of IP addresses assigned to a particular network.

{RED}[15]{GREEN} SSL Scan:{RESET}{GREEN} This feature scans a website's SSL certificate and provides information about the certificate's validity and strength.

{RED}[16]{GREEN} OS FingerPrint:{RESET}{GREEN} This feature attempts to identify the operating system that a target device is running.

{RED}[17]{GREEN} Create Reverse Shell:{RESET}{GREEN} This feature allows you to create a reverse shell to connect back to a target system, which can be useful for remote access or penetration testing.

{RED}[18]{GREEN} Passive Subdomains:{RESET}{GREEN} Discover subdomains from passive sources like certificate transparency.

{RED}[19]{GREEN} Tech Fingerprint:{RESET}{GREEN} Identify common technologies and frameworks from headers and page signals.

{RED}[20]{GREEN} HTTP Status Map:{RESET}{GREEN} Map common paths and report response codes for quick surface visibility.

{RED}[21]{GREEN} Connect with us:{RESET}{GREEN} This feature provides a way for users to contact you for support, feedback, or collaboration.

{RED}[+]{GREEN} Overall, KalnemiX is a powerful and versatile web pentesting tool that provides a range of features to help you identify and exploit vulnerabilities in your target web application. Whether you are a security professional or a hobbyist, this tool is sure to be a valuable addition to your toolkit.

{PFX_OK}Developer Info:
{GREEN}Name:{RESET}{GREEN} Alex
{GREEN}Role:{RESET}{GREEN} Cybersecurity researcher, developer, and automation-focused engineer
{GREEN}Founder:{RESET}{GREEN} Vritra Security Organization (VritraSec)
{GREEN}Mission:{RESET}{GREEN} Security-first, privacy-focused professional tools for developers, researchers, and power users
{GREEN}Focus:{RESET}{GREEN} Cybersecurity utilities, OSINT frameworks, AI-assisted systems, automation tools, performance-oriented software
{GREEN}Philosophy:{RESET}{GREEN} Transparent behavior, privacy by design, long-term stability and scalability, no bloat or misleading claims
{GREEN}Engineering:{RESET}{GREEN} Clean logic, modular architecture, fault tolerance, efficiency across Linux, Termux, and cross-platform systems
{GREEN}Privacy:{RESET}{GREEN} Minimize data collection, avoid tracking, keep processing local when possible
{GREEN}Specialties:{RESET}{GREEN} Cybersecurity & OSINT tooling, automation, AI-integrated utilities, cross-platform design, performance and reliability
{GREEN}Mindset:{RESET}{GREEN} Strong foundations, clean execution, real usability over noise

{PFX_OK}By VritraSec / Alex
"""

def exitf():
    print()
    print(f"{PFX_OK}Thanks for using {RED}KalnemiX{GREEN}.")
    sleep(0.2)
    print(f"{PFX_OK}Built by {RED}VritraSec{GREEN} • Privacy‑first tooling for real operators.")
    sleep(0.2)
    print(f"{PFX_OK}Links: https://link.vritrasec.com/")
    sleep(0.2)
    os.system("xdg-open https://link.vritrasec.com/")
    print()

def prompt_hash_inputs():
    print()
    while True:
        target_hash = input(f"{PFX_INFO}Enter target Hash: {RED}")
        if target_hash:
            break

    while True:
        wordlist_path = input(
            f"{PFX_INFO}Enter Wordlist Path [{RED}Enter for Default{GREEN}]: {RED}"
        )
        if wordlist_path == '':
            print(f"\n{PFX_OK}Default Wordlist selected")
            wordlist_path = None
            break
        else:
            break

    return target_hash, wordlist_path


################# Check configuration ##################

if any(arg in ("-h", "--help") for arg in sys.argv[1:]):
    print_help()
    raise SystemExit(0)
args = parse_args()
_validate_cli(args)
if args.version:
    print(f"{GREEN}KalnemiX{RESET} {RED}v{VERSION}{RESET}")
    raise SystemExit(0)
if args.about:
    print(aboutx)
    raise SystemExit(0)
if _cli_action_selected(args):
    bnr()

if args.ip:
    ipd(args.ip)
    raise SystemExit(0)
if args.whois:
    target = args.whois.strip()
    print(f"{PFX_INFO}Scanning...")
    subprocess.run(["whois", target], check=False)
    raise SystemExit(0)
if args.subdomain_quick:
    quickscan(_normalize_target(args.subdomain_quick))
    raise SystemExit(0)
if args.subdomain_deep:
    deepscan(_normalize_target(args.subdomain_deep), args.wordlist)
    raise SystemExit(0)
if args.subdomain_passive:
    passive_subdomains(_normalize_target(args.subdomain_passive))
    raise SystemExit(0)
if args.httpheader:
    target = _normalize_target(args.httpheader)
    print(f"{PFX_INFO}Scanning...")
    http_hd(target)
    raise SystemExit(0)
if args.robots:
    target = _normalize_target(args.robots)
    print(f"{PFX_INFO}Scanning...")
    robots(target)
    raise SystemExit(0)
if args.dns:
    target = _normalize_target(args.dns)
    print(f"{PFX_INFO}Scanning...")
    findshrs(target)
    raise SystemExit(0)
if args.reverse_ip:
    revip(args.reverse_ip.strip())
    raise SystemExit(0)
if args.traceroute:
    routrce(args.traceroute.strip())
    raise SystemExit(0)
if args.portscan:
    endport = args.endport if args.endport else "1000"
    if not _is_valid_port(endport):
        print(f"{PFX_WARN}Invalid port number")
        raise SystemExit(2)
    print(f"{PFX_INFO}Scanning...")
    scanort(args.portscan.strip(), endport)
    raise SystemExit(0)
if args.extract_url:
    target = _normalize_target(args.extract_url)
    print(f"{PFX_INFO}Scanning...")
    rxtrl(target)
    raise SystemExit(0)
if args.find_hidden:
    target = _normalize_target(args.find_hidden)
    findon(target, args.wordlist)
    raise SystemExit(0)
if args.crackhash:
    if not args.hash_type:
        print(f"{PFX_WARN}--hash-type is required with --crackhash")
        raise SystemExit(2)
    crack(args.crackhash, args.hash_type, args.wordlist)
    raise SystemExit(0)
if args.imgmeta:
    emetad(args.imgmeta)
    raise SystemExit(0)
if args.subnet:
    subnetf(args.subnet)
    raise SystemExit(0)
if args.sslscan:
    print(f"{PFX_INFO}Scanning...")
    subprocess.run(["sslscan", args.sslscan.strip()], check=False)
    raise SystemExit(0)
if args.osfp:
    os_fingerprint(args.osfp.strip())
    raise SystemExit(0)
if args.reverse_shell:
    if ":" not in args.reverse_shell:
        print(f"{PFX_WARN}--reverse-shell requires ip:port")
        raise SystemExit(2)
    ip_val, port_val = args.reverse_shell.split(":", 1)
    out_path = create_reverse_shell(ip_val.strip(), port_val.strip())
    print(f"{PFX_OK}Reverse shell saved to {out_path}")
    raise SystemExit(0)
if args.tech:
    tech_fingerprint(args.tech)
    raise SystemExit(0)
if args.status_map:
    scheme = args.scheme if args.scheme else "https"
    status_map(args.status_map, wordlist_path=args.wordlist, scheme=scheme)
    raise SystemExit(0)


cmd = "ping -c 1 8.8.8.8"
# Run the command using subprocess
try:
    subprocess.check_output(cmd, shell=True)
    print(f"{GREEN}[✔] Internet Connectivity: Done{RESET}")
    sleep(0.2)
except subprocess.CalledProcessError:
    print(f"{RED}[✘] No internet connection detected. Please check your network connection.{RESET}\n")
    exit()



# Get the file path of the running script
file_path = os.path.abspath(__file__)

# Check if the file path contains the Termux path
if "/data/data/com.termux/files/home/" in file_path:
    print(f"{GREEN}[✔] Platform: Termux{RESET}")
    sleep(0.2)
elif os.name == "posix":
    print(f"{GREEN}[✔] Platform: Linux{RESET}")
    sleep(0.2)
else:
    print(f"{RED}[✘] Unsupported Operating System{RESET}\n")
    exit()

# Check if the user is root
if os.geteuid() == 0:
    print(f"{GREEN}[✔] User privilege: Root{RESET}")
    sleep(0.2)
else:
    print(f"{RED}[✔] User privilege: Normal{RESET}\n")
    sleep(0.2)

### Final msg to launch

print(f"\n{PFX_OK}Starting KalnemiX...")
sleep(2)

## main script starting--------------------------------------

while True:
    os.system("clear")
    bnr()
    men = input(main_menu)
    if men == '01' or men == '1':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target IP/Domain: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print(f"{GREEN}")
                subprocess.run(["whois", ips], check=False)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '2' or men == '02':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target IP/Domain: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                ipd(ips)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '3' or men == '03':
        while True:
            os.system('clear')
            bnr()
            terss = input(subin)
            if terss == '':
                pass
            elif terss == '01' or terss == '1':
                print()
                while True:
                    domain = input(f"{PFX_INFO}Enter Domain: {RED}")
                    if domain == '':
                        pass
                    else:
                        break
                quickscan(domain)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
            elif terss == '02' or terss == '2':
                print()
                while True:
                    domain = input(f"{PFX_INFO}Enter Domain: {RED}")
                    if domain == '':
                        pass
                    else:
                        break
                deepscan(domain)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
            elif terss == "95":
                break
            elif terss == "99":
                exitf()
                exit()
            else:
                print()

    elif men == '4' or men == '04':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target Domain: {RED}")
            if ips == '':
                print()
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                http_hd(ips)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '5' or men == '05':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target Domain: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                robots(ips)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '6':
        print()
        while True:
            domain_name = input(f"{PFX_INFO}Enter Target Domain: {RED}")
            if domain_name == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                findshrs(domain_name)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '7' or men == '07':
        print()
        while True:
            ip = input(f"{PFX_INFO}Enter Target IP Address: {RED}")
            if ip == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                revip(ip)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '8' or men == '08':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target IP/Domain: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                routrce(ips)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '9' or men == '09':
        print()
        while True:
            target = input(f"{PFX_INFO}Enter Target IP/Domain: {RED}")
            if target == '':
                pass
            else:
                break

        while True:
            endport = input(
                f"{PFX_INFO}Enter Endport [{RED}Default is 1000{GREEN}]: {RED}"
            )
            if endport == '':
                print()
                print(f"{PFX_OK}Selected Endport {RED}1000")
                endport = "1000"
                break
            else:
                print()
                print(f"{PFX_OK}Selected Endport {RED}{endport}")
                break

        print()
        print(f"{PFX_INFO}Scanning...")
        print(f"{PFX_INFO}This may take some time so please be patient")
        print()
        scanort(target, endport)
        print()
        input(f"{BLUE}Press ENTER To Continue{RESET}")


    elif men == '10':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target Domain: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                rxtrl(ips)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break
    
    elif men == '11':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target Domain: {RED}")
            if ips == '':
                pass
            else:
                while True:
                    passd = input(
                        f"{PFX_OK}Wordlist Path [{RED}Enter For Default{GREEN}]: {RED}"
                    )
                    if passd == '':
                        print(f"{PFX_INFO}Default Wordlist selected")
                        passd = None
                        break
                    else:
                        break
                findon(ips, passd)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '12':
        print()
        while True:
            os.system('clear')
            bnr()
            asr = input(rest)
            if asr == '':
                pass
            elif asr == '1' or asr == '01':
                hash_type = "md5"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '2' or asr == '02':
                hash_type = "sha1"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '3' or asr == '03':
                hash_type = "sha224"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '4' or asr == '04':
                hash_type = "sha256"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '5' or asr == '05':
                hash_type = "sha384"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '6' or asr == '06':
                hash_type = "sha512"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '7' or asr == '07':
                hash_type = "sha3_224"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '8' or asr == '08':
                hash_type = "sha3_256"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '9' or asr == '09':
                hash_type = "sha3_384"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '10':
                hash_type = "sha3_512"
                target_hash, wordlist_path = prompt_hash_inputs()
                crack(target_hash, hash_type, wordlist_path)
                input(f"\n{BLUE}Press ENTER To Continue{RESET}")
            elif asr == '95':
                break
            elif asr == '99':
                exitf()
                exit()
            else:
                pass

    elif men == '13':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Image path: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                emetad(ips)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break
        
    elif men == '14':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target IP Address: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                subnetf(ips)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '15':
        print()
        while True:
            ips = input(f"{PFX_INFO}Enter Target IP/Domain: {RED}")
            if ips == '':
                pass
            else:
                print()
                print(f"{PFX_INFO}Scanning...")
                print()
                subprocess.run(["sslscan", ips], check=False)
                print()
                input(f"{BLUE}Press ENTER To Continue{RESET}")
                break

    elif men == '16':
        if os.geteuid() != 0:
            print(f"\n{PFX_OK}Root required")
            print()
            input(f"{BLUE}Press ENTER To Continue{RESET}")
        else:
            #pass
            print()
            while True:
                target = input(f"{PFX_OK}Enter Target IP/Domain: {RED}")
                if target == '':
                    pass
                else:
                    print(f"{PFX_OK}Scanning...")
                    print(f"{PFX_INFO}This may take some time so please be patient")
                    break
            os_fingerprint(target)
            print()
            input(f"{BLUE}Press ENTER To Continue{RESET}")

    elif men == '17':
        print()
        out_path = gensel()
        print(f"{PFX_OK}Creating Reverse Shell...")
        sleep(4)
        print(f"\n{PFX_OK}Reverse shell Created and saved in your current working directory")
        print(f"{PFX_OK}File name is: {RED}{out_path}\n")
        input(f"{BLUE}Press ENTER To Continue{RESET}")


    elif men == '21':
        print()
        print(f"{PFX_INFO}Opening VritraSec links...")
        sleep(0.6)
        os.system("xdg-open https://link.vritrasec.com/")
        print()
        input(f"{BLUE}Press ENTER To Continue{RESET}")

    elif men == '22':
        os.system('clear')
        bnr()
        print(aboutx)
        input(f"{BLUE}Press ENTER To Continue{RESET}")

    elif men == '18':
        print()
        while True:
            domain = input(f"{PFX_INFO}Enter Target Domain: {RED}")
            if domain == '':
                pass
            else:
                break
        passive_subdomains(domain)
        print()
        input(f"{BLUE}Press ENTER To Continue{RESET}")

    elif men == '19':
        print()
        while True:
            target = input(f"{PFX_INFO}Enter Target Domain/URL: {RED}")
            if target == '':
                pass
            else:
                break
        tech_fingerprint(target)
        print()
        input(f"{BLUE}Press ENTER To Continue{RESET}")

    elif men == '20':
        print()
        while True:
            domain = input(f"{PFX_INFO}Enter Target Domain: {RED}")
            if domain == '':
                pass
            else:
                break
        scheme = input(f"{PFX_INFO}Scheme [http/https] (default https): {RED}").strip().lower()
        if scheme == "":
            scheme = "https"
        wordlist = input(f"{PFX_INFO}Wordlist Path [Enter for Default]: {RED}").strip()
        if wordlist == "":
            wordlist = None
        status_map(domain, wordlist_path=wordlist, scheme=scheme)
        print()
        input(f"{BLUE}Press ENTER To Continue{RESET}")
   
    elif men == "23":
        exitf()
        exit()

    elif men == '':
        pass
        

    else:
        pass
        
