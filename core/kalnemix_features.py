from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests
import nmap
import ipaddress
import json
import hashlib
import os
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from time import sleep
import multiprocessing
import dns.resolver
from datetime import datetime
import subprocess

from core.ui import GREEN, RED, PFX_FAIL, PFX_INFO, PFX_OK, PFX_WARN


def _core_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def _unique_path(path):
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    idx = 1
    while True:
        candidate = f"{base}-{idx}{ext}"
        if not os.path.exists(candidate):
            return candidate
        idx += 1


def _timestamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _is_domain(value):
    return re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", value or "") is not None


def _is_port(value):
    try:
        port = int(value)
        return 1 <= port <= 65535
    except Exception:
        return False


def _normalize_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc
    return domain.strip("/")


def _safe_get(url, timeout=10, headers=None):
    try:
        return requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
    except Exception:
        return None






def gensel():
    while True:
        user_ip = input(f"{PFX_OK}Enter Your IP address: {RED}")
        if user_ip:
            break
    while True:
        user_port = input(f"{PFX_OK}Enter a Listning Port: {RED}")
        if user_port:
            break
    return create_reverse_shell(user_ip, user_port)

def create_reverse_shell(user_ip, user_port, out_path=None):
    php_file_name = _core_path("main_shell.php")
    with open(php_file_name, "r") as php_file:
        php_contents = php_file.read()

    new_php_contents = php_contents.replace("$ip = '127.0.0.1';", f"$ip = '{user_ip}';")
    new_php_contents = new_php_contents.replace("$port = 1234;", f"$port = {user_port};")

    if out_path is None:
        out_path = f"reverse-shell-{_timestamp()}.php"
    out_path = _unique_path(out_path)
    with open(out_path, "w") as new_php_file:
        new_php_file.write(new_php_contents)
    return out_path


def os_fingerprint(target):
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(target):
        target_ip = target
    else:
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{PFX_FAIL}Invalid input")
            return

    scanner = nmap.PortScanner()
    try:
        scanner.scan(target_ip, arguments="-O")
    except nmap.PortScannerError:
        print(f"\n{PFX_FAIL}Error: {scanner.scaninfo().get('error', 'Unknown error')}")
        return

    if "osmatch" in scanner[target_ip]:
        os_matches = scanner[target_ip]["osmatch"]
        print(
            f"\n{PFX_OK}The following operating systems were identified on{RED} {target_ip}:{GREEN}\n"
        )
        for os_match in os_matches:
            os_name = os_match.get("name", "Unknown")
            os_accuracy = os_match.get("accuracy", "Unknown")
            os_vendor = os_match.get("osclass", [{}])[0].get("vendor", "Unknown")
            os_family = os_match.get("osclass", [{}])[0].get("osfamily", "Unknown")
            os_gen = os_match.get("osclass", [{}])[0].get("osgen", "Unknown")
            print(
                f"{PFX_OK}Name: {os_name}\n{PFX_OK}Accuracy: {os_accuracy}\n{PFX_OK}Vendor: {os_vendor}\n{PFX_OK}OS Family: {os_family}\n{PFX_OK}OS Gen: {os_gen}\n"
            )
    else:
        print(f"{PFX_OK}Unable to identify operating system on{RED} {target_ip}.")


def quickscan(domain):
    domain = _normalize_domain(domain)
    if not _is_domain(domain):
        print(f"{PFX_FAIL}Invalid domain")
        return
    print(f"{PFX_INFO}Scanning...")
    d = "http://api.hackertarget.com/hostsearch/?q=" + domain
    r = _safe_get(d, timeout=12)
    if not r:
        print(f"{PFX_FAIL}Request failed")
        return
    print()

    for line in r.text.splitlines():
        parts = line.split(",")
        if len(parts) < 2:
            continue
        first_part = parts[0]
        firt_part = parts[1]
        print(f"{GREEN}[+] {RED}Subdomain: {GREEN}{first_part}")
        print(f"{GREEN}[+] {RED}IP: {GREEN}{firt_part}")
        print()


def passive_subdomains(domain):
    domain = _normalize_domain(domain)
    if not _is_domain(domain):
        print(f"{PFX_FAIL}Invalid domain")
        return []
    print(f"{PFX_INFO}Passive subdomain sources...")
    results = set()

    headers = {"User-Agent": "KalnemiX/1.0"}
    crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    res = _safe_get(crt_url, timeout=15, headers=headers)
    if res and res.status_code == 200:
        try:
            data = res.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for item in name_value.splitlines():
                    item = item.strip().lower()
                    if item.startswith("*."):
                        item = item[2:]
                    if item.endswith(domain):
                        results.add(item)
        except Exception:
            pass

    certspotter = (
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        "&include_subdomains=true&expand=dns_names"
    )
    res = _safe_get(certspotter, timeout=15, headers=headers)
    if res and res.status_code == 200:
        try:
            data = res.json()
            for entry in data:
                for item in entry.get("dns_names", []):
                    item = item.strip().lower()
                    if item.startswith("*."):
                        item = item[2:]
                    if item.endswith(domain):
                        results.add(item)
        except Exception:
            pass

    sorted_results = sorted(results)
    for sub in sorted_results:
        print(f"{PFX_OK}{sub}")
    print(f"\n{PFX_OK}Total: {len(sorted_results)}")
    return sorted_results


def tech_fingerprint(target):
    domain = _normalize_domain(target)
    if not _is_domain(domain):
        print(f"{PFX_FAIL}Invalid domain")
        return None
    urls = [f"https://{domain}", f"http://{domain}"]
    headers = {"User-Agent": "KalnemiX/1.0"}

    response = None
    url_used = None
    for url in urls:
        response = _safe_get(url, timeout=10, headers=headers)
        if response:
            url_used = url
            break

    if not response:
        print(f"{PFX_FAIL}Failed to connect")
        return None

    tech = set()
    server = response.headers.get("Server", "")
    powered = response.headers.get("X-Powered-By", "")
    content = response.text.lower()

    if "cloudflare" in server.lower() or "cf-ray" in response.headers:
        tech.add("Cloudflare")
    if "nginx" in server.lower():
        tech.add("Nginx")
    if "apache" in server.lower():
        tech.add("Apache")
    if "iis" in server.lower():
        tech.add("IIS")
    if "php" in powered.lower():
        tech.add("PHP")
    if "express" in powered.lower():
        tech.add("Express")
    if "django" in content:
        tech.add("Django")
    if "flask" in content:
        tech.add("Flask")
    if "wordpress" in content or "wp-content" in content:
        tech.add("WordPress")
    if "joomla" in content:
        tech.add("Joomla")
    if "drupal" in content:
        tech.add("Drupal")
    if "react" in content:
        tech.add("React")
    if "vue" in content:
        tech.add("Vue")
    if "angular" in content:
        tech.add("Angular")

    result = {
        "url": url_used,
        "status": response.status_code,
        "server": server,
        "powered_by": powered,
        "technologies": sorted(tech),
    }

    print(f"{PFX_OK}URL: {url_used}")
    print(f"{PFX_OK}Status: {response.status_code}")
    if server:
        print(f"{PFX_OK}Server: {server}")
    if powered:
        print(f"{PFX_OK}X-Powered-By: {powered}")
    if result["technologies"]:
        print(f"{PFX_OK}Detected: {', '.join(result['technologies'])}")
    else:
        print(f"{PFX_WARN}No clear tech fingerprints found")

    return result


def status_map(domain, wordlist_path=None, scheme="https", max_workers=20):
    domain = _normalize_domain(domain)
    if not _is_domain(domain):
        print(f"{PFX_FAIL}Invalid domain")
        return []
    if not wordlist_path:
        wordlist_path = _core_path("dir_list.txt")
    if not os.path.exists(wordlist_path):
        print(f"{PFX_FAIL}Wordlist not found")
        return []

    if scheme not in ("http", "https"):
        scheme = "https"

    base = f"{scheme}://{domain}"
    with open(wordlist_path, "r") as f:
        paths = [line.strip().lstrip("/") for line in f if line.strip()]

    results = []
    headers = {"User-Agent": "KalnemiX/1.0"}

    def check_path(path):
        url = f"{base}/{path}"
        res = _safe_get(url, timeout=6, headers=headers)
        if res:
            return {"url": url, "status": res.status_code, "length": len(res.text)}
        return None

    print(f"{PFX_INFO}Status map scanning...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_path, p) for p in paths]
        for fut in as_completed(futures):
            item = fut.result()
            if item:
                results.append(item)
                print(f"{PFX_OK}{item['status']} {item['url']}")

    return results


def worker(subdomain, domain):
    hostname = subdomain + "." + domain
    try:
        answer = dns.resolver.resolve(hostname)
        for record in answer:
            print(f"{GREEN}[+] {RED}Subdomain: {GREEN}{hostname}")
            print(f"{GREEN}[+] {RED}IP: {GREEN}{record.to_text()}")
            print()
    except Exception:
        pass


def deepscan(domain, wordlist_path=None):
    if not wordlist_path:
        wordlist_path = _core_path("sublist.txt")

    with open(wordlist_path, "r") as f:
        subdomain_list = f.read().splitlines()

    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
    pool.starmap(worker, [(subdomain, domain) for subdomain in subdomain_list])
    pool.close()
    pool.join()


def crack(target_hash, hash_type, wordlist_path=None):
    if not re.match(r"^[a-fA-F0-9]+$", target_hash or ""):
        print(f"{PFX_WARN}Hash format looks invalid")
        return
    if not wordlist_path:
        wordlist_path = _core_path("crack_hash_pass.txt")

    total_words = sum(1 for _ in open(wordlist_path, "r", encoding="latin-1"))
    with open(wordlist_path, "r", encoding="latin-1") as wordlist_file:
        tried = 0
        for line in wordlist_file:
            word_hash = getattr(hashlib, hash_type)(line.strip().encode()).hexdigest()

            tried += 1
            print(f"\r{PFX_INFO}Trying:{RED} {tried}/{total_words}", end="")
            if word_hash == target_hash:
                print(f"\n\n{PFX_OK}Hash is cracked:{RED} {line.strip()}")
                print()
                break
        else:
            print(f"\n{PFX_WARN}Password not found")


def ipd(ips):
    if not _is_ip(ips):
        print(f"{PFX_FAIL}Invalid IP address")
        return
    response = _safe_get("http://ip-api.com/json/" + ips, timeout=10)
    if not response:
        print(f"{PFX_FAIL}Request failed")
        return
    try:
        data = json.loads(response.content)
    except Exception:
        print(f"{PFX_FAIL}Invalid response")
        return
    for key, value in data.items():
        print(f"{PFX_OK}{key}: {value}")


def http_hd(ips):
    ips = _normalize_domain(ips)
    if not _is_domain(ips):
        print(f"{PFX_FAIL}Invalid domain")
        return
    url = "http://" + ips
    r = _safe_get(url, timeout=10)
    if not r:
        print(f"{PFX_FAIL}Request failed")
        return
    for key, value in r.headers.items():
        print(f"{PFX_OK}{key} : {value}")


def robots(ips):
    ips = _normalize_domain(ips)
    if not _is_domain(ips):
        print(f"{PFX_FAIL}Invalid domain")
        return
    isp = "http://" + ips
    res = _safe_get(isp + "/robots.txt", timeout=10)
    if not res:
        print(f"{PFX_FAIL}Request failed")
        return
    if res.status_code != 200:
        print(f"{PFX_WARN}robots.txt not found (status {res.status_code})")
        return
    disallowed_paths = re.findall("Disallow: (.*)", res.text)
    print(f"{PFX_OK}The following paths are disallowed in robots.txt:")
    for path in disallowed_paths:
        print(path)


def revip(ips):
    try:
        hostname, _, ipaddrlist = socket.gethostbyaddr(ips)
        ip_address = ipaddrlist[0] if ipaddrlist else ips
    except socket.herror:
        hostname = "Unable to get hostname"
        ip_address = ips

    print(f"{PFX_OK}Hostname: {RED}{hostname}")
    print(f"{PFX_OK}IP Address: {RED}{ip_address}")


def routrce(ips):
    subprocess.run(["traceroute", ips], check=False)


def scanort(target, endport):
    if not _is_port(endport):
        print(f"{PFX_FAIL}Invalid port range")
        return
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-vv -p1-" + endport + " -T4")

    for host in scanner.all_hosts():
        print("Host : %s (%s)" % (host, scanner[host].hostname()))
        print("State : %s" % scanner[host].state())
        for proto in scanner[host].all_protocols():
            print("Protocol : %s" % proto)

            lport = scanner[host][proto].keys()
            lport = sorted(lport)
            for port in lport:
                print("port : %s\tstate : %s" % (port, scanner[host][proto][port]["state"]))


def rxtrl(ips):
    ips = _normalize_domain(ips)
    if not _is_domain(ips):
        print(f"{PFX_FAIL}Invalid domain")
        return
    ipsr = "http://" + ips
    response = _safe_get(ipsr, timeout=10)
    if not response:
        print(f"{PFX_FAIL}Request failed")
        return
    try:
        soup = BeautifulSoup(response.content, "html5lib")
    except Exception:
        print(f"{PFX_FAIL}Failed to parse HTML")
        return
    links = soup.find_all("a")

    for link in links:
        href = link.get("href")
        if not href:
            continue
        if urlparse(href).query:
            print(f"{PFX_OK}{href}")
        else:
            print(f"{PFX_OK}{urlparse(ips)._replace(path=href).geturl()}")
            sleep(0.1)


def findon(ips, passd=None):
    def check_url(url):
        try:
            req = requests.get(url, timeout=3, allow_redirects=True)
            if req.status_code != 404:
                print(f"{PFX_OK}Found: {GREEN}{url}")
            return True
        except Exception:
            return False

    def find_admin(url, wordlist_path):
        with open(wordlist_path, "r") as fp:
            lines = fp.readlines()
        lines = [line.strip() for line in lines]

        with ThreadPoolExecutor(max_workers=10) as executor:
            for line in lines:
                test_url = url + "/" + line + "/"
                executor.submit(check_url, test_url)

    if not passd:
        passd = _core_path("dir_list.txt")
    if not os.path.exists(passd):
        print(f"{PFX_FAIL}Wordlist not found")
        return

    print(f"\n{PFX_OK}Scanning...\n")
    url = "http://" + ips
    parsed_url = urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc

    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
        find_admin(base_url, passd)
    except KeyboardInterrupt:
        print(f"\n{PFX_WARN}Stopping...\n")


def emetad(ips):
    if not os.path.exists(ips):
        print(f"{PFX_FAIL}File not found")
        return
    print(f"{GREEN}")
    subprocess.run(["exiftool", ips], check=False)


def findshrs(domain_name):
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    timeout = 5
    results = {}

    for record_type in record_types:
        try:
            records = dns.resolver.resolve(domain_name, record_type, lifetime=timeout)
            results[record_type] = [str(record) for record in records]
        except dns.resolver.NoAnswer:
            results[record_type] = ["No {} record found".format(record_type)]
        except dns.resolver.LifetimeTimeout:
            results[record_type] = ["DNS resolution for {} timed out".format(record_type)]

    for record_type, records in results.items():
        print(f"{PFX_OK}{record_type} : {', '.join(records)}")


def subnetf(ips):
    ip_address = ipaddress.IPv4Address(ips)
    subnet = ipaddress.IPv4Network(ips + "/32", strict=False)
    netmask = subnet.netmask
    broadcast = subnet.broadcast_address
    wildcard_mask = subnet.hostmask
    hosts_bits = subnet.max_prefixlen - subnet.prefixlen
    max_hosts = 2 ** hosts_bits - 2
    host_range = ip_address, ip_address

    print(f"{PFX_OK}Address      :{RED} {ips}")
    print(f"{PFX_OK}Network      :{RED} {subnet}")
    print(f"{PFX_OK}Netmask      :{RED} {netmask}")
    print(f"{PFX_OK}Broadcast    :{RED} {broadcast}")
    print(f"{PFX_OK}Wildcard Mask:{RED} {wildcard_mask}")
    print(f"{PFX_OK}Hosts Bits   :{RED} {hosts_bits}")
    print(f"{PFX_OK}Max Hosts    :{RED} {max_hosts}   (2^{hosts_bits} - 2)")
    print(f"{PFX_OK}Host Range   :{RED} {{ {host_range[0]} - {host_range[1]} }}")
