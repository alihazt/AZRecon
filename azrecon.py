#!/usr/bin/env python3
"""
AzRecon v6.0 — Azərbaycan bazarına fokuslanmış passiv OSINT/Recon aləti
==========================================================================
Yalnız icazəli (authorized) hədəflər üzərində — öz domeninizdə və ya rəsmi
icazəniz (scope) olan pentest/bug-bounty çərçivəsində istifadə edin.
"""

import os
import sys
import shutil
import subprocess
import re
import json
import ssl
import socket
import base64
import asyncio
import argparse
import configparser
import time
import shutil
import subprocess
from datetime import datetime

try:
    import requests
    import aiohttp
    import dns.resolver
    import dns.query
    import dns.message
    import dns.rdatatype
    import dns.rdataclass
    import mmh3
    from colorama import init, Fore, Style
    from tqdm import tqdm
except ImportError as e:
    print(f"Kitabxana çatışmır: {e}")
    print("Quraşdırın: pip install -r requirements.txt --break-system-packages")
    sys.exit(1)

init(autoreset=True)

# ======================================================================
# KONFİQURASİYA — API key-lər (opsional). Ya environment variable, ya da
# config.ini faylı vasitəsilə verilə bilər. Heç biri olmasa, həmin
# mənbələr sadəcə atlanılır, skript yenə tam işləyir.
# ======================================================================

CONFIG = {
    "SHODAN_API_KEY": os.environ.get("SHODAN_API_KEY", ""),
    "SECURITYTRAILS_API_KEY": os.environ.get("SECURITYTRAILS_API_KEY", ""),
    "FULLHUNT_API_KEY": os.environ.get("FULLHUNT_API_KEY", ""),
    "HIBP_API_KEY": os.environ.get("HIBP_API_KEY", ""),
    "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN", ""),
    "CENSYS_API_ID": os.environ.get("CENSYS_API_ID", ""),
    "CENSYS_API_SECRET": os.environ.get("CENSYS_API_SECRET", ""),
    "FOFA_EMAIL": os.environ.get("FOFA_EMAIL", ""),
    "FOFA_KEY": os.environ.get("FOFA_KEY", ""),
    "ZOOMEYE_API_KEY": os.environ.get("ZOOMEYE_API_KEY", ""),
    "WHOISFREAKS_API_KEY": os.environ.get("WHOISFREAKS_API_KEY", ""),
}

if os.path.exists("config.ini"):
    cp = configparser.ConfigParser()
    cp.read("config.ini")
    if "api_keys" in cp:
        for key in CONFIG:
            CONFIG[key] = CONFIG[key] or cp["api_keys"].get(key, "")

HEADERS = {"User-Agent": "Mozilla/5.0 (AzRecon/4.0; +passive-osint-tool)"}

# ----------------------------------------------------------------------
# Azərbaycanın əsas lokal internet provayder/ASN-ləri (ictimai mənbələr —
# RIPE/PeeringDB üzərindən dəqiqləşdirilə bilər). Naməlum ASN aşkarlansa,
# "Naməlum / Xarici hosting" kimi göstərilir.
# ----------------------------------------------------------------------
AZ_KNOWN_ASNS = {
    "AS29049":  "Delta Telecom",
    "AS200919": "Delta Telecom LLC",
    "AS9066":   "Baktelecom",
    "AS39232":  "Aztelekom",
    "AS197188": "AzerTelecom",
    "AS58224":  "AzInTelecom",
    "AS41997":  "Bakcell",
    "AS35805":  "Baku Telephone Communication (BTC)",
    "AS48928":  "Aztelekom LLC",
    "AS57293":  "Sazz.az / Digital Innovations",
    "AS205864": "Naxtel",
    "AS201897": "CATV / Kabel TV Provayder",
    "AS50597":  "B.EST Communication",
}

# ----------------------------------------------------------------------
# .AZ ikinci səviyyə domen-lərinin təsnifatı — hədəfin növünü (dövlət,
# təhsil, kommersiya və s.) bir baxışda göstərmək üçün.
# ----------------------------------------------------------------------
AZ_SUBTLD_MEANINGS = {
    "gov.az":  "Dövlət qurumu",
    "mil.az":  "Hərbi qurum",
    "edu.az":  "Təhsil müəssisəsi",
    "int.az":  "Beynəlxalq təşkilat",
    "org.az":  "Qeyri-kommersiya təşkilatı",
    "com.az":  "Kommersiya",
    "net.az":  "Şəbəkə/İnternet xidməti",
    "info.az": "İnformasiya sayti",
    "biz.az":  "Biznes",
    "co.az":   "Şirkət",
    "pro.az":  "Peşəkar fəaliyyət",
    "name.az": "Şəxsi domen",
    "pp.az":   "Şəxsi səhifə",
}

# ----------------------------------------------------------------------
# JS fayllarında axtarılan "sirr" pattern-ləri (klassik SecretFinder/
# LinkFinder üsulu). Tapılan dəyərlər hesabatda MASKALANIR (yalnız ilk/son
# simvollar göstərilir) — məqsəd risk barədə xəbərdarlıqdır, açar/token-in
# özünü hazır formada ötürmək deyil.
# ----------------------------------------------------------------------
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Token":   r"ya29\.[0-9A-Za-z\-_]+",
    "Slack Token":          r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Stripe Live Key":      r"sk_live_[0-9a-zA-Z]{24,}",
    "Firebase URL":         r"[a-z0-9-]+\.firebaseio\.com",
    "Generic API Key/Secret": r'(?:api[_-]?key|apikey|secret|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']',
    "JWT Token":            r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
}

# JS fayllarından çıxarılan API/endpoint yolları üçün pattern
ENDPOINT_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_\-/.]{2,80}?)["\']')

# Məlum subdomain-takeover fingerprint-ləri (CNAME hədəfi -> body/işarə)
# Qırmızı komanda üçün faydalı, tez-tez unudulan "dangling DNS" zəiflik növü.
TAKEOVER_FINGERPRINTS = {
    "github.io":            ("There isn't a GitHub Pages site here", "GitHub Pages"),
    "herokuapp.com":        ("No such app", "Heroku"),
    "s3.amazonaws.com":     ("NoSuchBucket", "AWS S3"),
    "azurewebsites.net":    ("404 Web Site not found", "Azure Web Apps"),
    "cloudapp.net":         ("404", "Azure Cloud Service"),
    "wordpress.com":        ("Do you want to register", "WordPress.com"),
    "shopify.com":          ("Sorry, this shop is currently unavailable", "Shopify"),
    "surge.sh":             ("project not found", "Surge.sh"),
    "readme.io":            ("Project doesnt exist", "ReadMe.io"),
    "unbounce.com":         ("The requested URL was not found on this server", "Unbounce"),
    "fastly.net":           ("Fastly error: unknown domain", "Fastly"),
    "pantheon.io":          ("404 error unknown site", "Pantheon"),
    "zendesk.com":          ("Help Center Closed", "Zendesk"),
}

# Sadə texnologiya fingerprint-ləri (header/body əsaslı, Wappalyzer-lite)
TECH_SIGNATURES = {
    "ASAN Login / e-Gov (AZ)": ["asan.gov.az", "e-gov.az", "asanimza"],
    "1C-Bitrix": ["bitrix", "bx_user_id", "BITRIX_SM"],
    "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
    "Joomla": ["joomla", "/media/jui/"],
    "Drupal": ["drupal.js", "sites/default/files"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS / ASP.NET": ["asp.net", "x-aspnet-version", "microsoft-iis"],
    "Cloudflare": ["cloudflare", "cf-ray"],
    "cPanel": ["cpanel"],
}

# ----------------------------------------------------------------------
# Versiya aşkarlama pattern-ləri — header/body-dən konkret versiya
# nömrələrini regex ilə çıxarır (klassik "banner grabbing" texnikası).
# Qrup 1 tapılan versiya nömrəsini əhatə edir.
# ----------------------------------------------------------------------
VERSION_PATTERNS = {
    "Nginx":            r"nginx/([\d.]+)",
    "Apache":           r"Apache/([\d.]+)",
    "Microsoft-IIS":    r"Microsoft-IIS/([\d.]+)",
    "OpenSSL":          r"OpenSSL/([\d.\w]+)",
    "PHP":              r"PHP/([\d.]+)",
    "ASP.NET":          r"ASP\.NET(?: Version)?[:/ ]([\d.]+)",
    "WordPress":        r'(?:content=["\']WordPress\s|wp-emoji-release\.min\.js\?ver=)([\d.]+)',
    "Joomla":           r'content=["\']Joomla!\s*([\d.]+)',
    "Drupal":           r'Drupal\s+([\d.]+)',
    "1C-Bitrix":        r'/bitrix/.*?ver=([\d.]+)',
    "jQuery":           r'jquery[/-]?([\d.]+)(?:\.min)?\.js',
    "Bootstrap":        r'bootstrap[/-]?([\d.]+)(?:\.min)?\.(?:css|js)',
    "React":            r'"react":"([\d.]+)"',
    "Node.js/Express":  r"X-Powered-By:\s*Express",
    "cPanel":           r"cpanel[/-]?([\d.]+)",
    "OpenSSH":          r"OpenSSH[_/]([\d.\w]+)",
}


def extract_versions(headers, body):
    """Header və body-də mövcud olan bütün versiya nişanlarını çıxarır."""
    versions = {}
    header_blob = " | ".join(f"{k}: {v}" for k, v in dict(headers).items())
    combined = f"{header_blob}\n{body}"

    for tech, pattern in VERSION_PATTERNS.items():
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            versions[tech] = m.group(1) if m.groups() else "aşkarlandı (versiya yoxdur)"

    # Generic <meta name="generator" content="..."> — çoxlu CMS/builder
    # bunu açıq şəkildə göstərir, hardcode edilməmiş alətləri də tutur.
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if gen:
        versions["meta_generator"] = gen.group(1).strip()

    return versions


def get_dns_server_version(domain):
    """
    Nameserver-lərin CHAOS class 'version.bind' sorğusu ilə versiyasını
    almağa cəhd edir — klassik DNS fingerprinting texnikası. Bir çox
    müasir server bunu bağlayıb, o halda boş nəticə qayıdır (xəta deyil).
    """
    results = {}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 4
        ns_answers = resolver.resolve(domain, "NS")
        for ns in ns_answers:
            ns_host = str(ns.target).rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                query = dns.message.make_query(
                    "version.bind", dns.rdatatype.TXT, dns.rdataclass.CHAOS
                )
                response = dns.query.udp(query, ns_ip, timeout=4)
                for rrset in response.answer:
                    for item in rrset:
                        results[ns_host] = item.to_text().strip('"')
            except Exception:
                continue
    except Exception:
        pass
    return results

CONCURRENCY_LIMIT = 40
HTTP_TIMEOUT = 6

# ----------------------------------------------------------------------
# Sadələşdirilmiş çıxış rejimi — True olanda ara-mərhələ "[*] ... aparılır"
# tipli proqres mesajları gizlədilir, yalnız NƏTİCƏLƏR (tapılan
# subdomen/sirr/breach və s.) və son xülasə göstərilir.
# ----------------------------------------------------------------------
QUIET = False


def _info(msg):
    """Proqres/status mesajı — QUIET rejimində gizlədilir."""
    if not QUIET:
        print(msg)


def banner():
    if QUIET:
        return
    print(f"""{Fore.CYAN}
 █████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗╚══███╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║  ███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║ ███╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
         v6.0 - Azərbaycan bazarı üçün xüsusi dizayn edilmiş OSINT aləti
    {Style.RESET_ALL}""")


def _safe_get(url, timeout=20, headers=None):
    try:
        resp = requests.get(url, timeout=timeout, headers=headers or HEADERS)
        if resp.status_code == 200:
            return resp
    except Exception:
        pass
    return None


# ======================================================================
# 1) ALT DOMEN TOPLAMA — 10+ passiv mənbə, hər biri ayrıca funksiya
# ======================================================================

def src_crtsh(domain):
    resp = _safe_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=45)
    found = set()
    if resp:
        try:
            for entry in resp.json():
                name = entry.get("name_value", "")
                if name.startswith("*."):
                    name = name[2:]
                for n in name.split("\n"):
                    found.add(n.strip().lower())
        except Exception:
            pass
    return found


def src_hackertarget(domain):
    resp = _safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    found = set()
    if resp and "API count exceeded" not in resp.text:
        for line in resp.text.split("\n"):
            if line.strip() and "," in line:
                found.add(line.split(",")[0].strip().lower())
    return found


def src_wayback(domain):
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=json&collapse=urlkey&fl=original&limit=20000")
    resp = _safe_get(url, timeout=45)
    found = set()
    if resp:
        try:
            rows = resp.json()
            pattern = re.compile(r"https?://([a-zA-Z0-9_.-]+)")
            for row in rows[1:]:
                if row:
                    m = pattern.match(row[0])
                    if m:
                        found.add(m.group(1).lower())
        except Exception:
            pass
    return found


def src_alienvault_otx(domain):
    """AlienVault OTX passiv DNS — pulsuz, key tələb etmir."""
    resp = _safe_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    found = set()
    if resp:
        try:
            for rec in resp.json().get("passive_dns", []):
                host = rec.get("hostname", "")
                if host:
                    found.add(host.strip().lower())
        except Exception:
            pass
    return found


def src_rapiddns(domain):
    """RapidDNS.io — pulsuz HTML scrape (subdomain sayı üçün faydalı ehtiyat mənbə)."""
    resp = _safe_get(f"https://rapiddns.io/subdomain/{domain}?full=1")
    found = set()
    if resp:
        for m in re.findall(r'<td>([a-zA-Z0-9_.-]+\.' + re.escape(domain) + r')</td>', resp.text):
            found.add(m.strip().lower())
    return found


def src_anubisdb(domain):
    """Anubis-DB (jonluca/anubis) — pulsuz, key tələb etmir."""
    resp = _safe_get(f"https://jldc.me/anubis/subdomains/{domain}")
    found = set()
    if resp:
        try:
            for h in resp.json():
                found.add(h.strip().lower())
        except Exception:
            pass
    return found


def src_threatminer(domain):
    """ThreatMiner — pulsuz passiv DNS/subdomain mənbəyi."""
    resp = _safe_get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5")
    found = set()
    if resp:
        try:
            for h in resp.json().get("results", []):
                found.add(h.strip().lower())
        except Exception:
            pass
    return found


def src_certspotter(domain):
    """CertSpotter (SSLMate) — pulsuz tier, sertifikat şəffaflığı mənbəyi."""
    resp = _safe_get(
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        f"&include_subdomains=true&expand=dns_names"
    )
    found = set()
    if resp:
        try:
            for entry in resp.json():
                for name in entry.get("dns_names", []):
                    found.add(name.lstrip("*.").strip().lower())
        except Exception:
            pass
    return found


def src_bufferover(domain):
    """BufferOver DNS — pulsuz passiv DNS aggregator."""
    resp = _safe_get(f"https://dns.bufferover.run/dns?q=.{domain}")
    found = set()
    if resp:
        try:
            data = resp.json()
            for key in ("FDNS_A", "RDNS"):
                for rec in data.get(key, []) or []:
                    parts = rec.split(",")
                    if len(parts) == 2:
                        found.add(parts[1].strip().lower())
        except Exception:
            pass
    return found


def src_urlscan(domain):
    """urlscan.io ictimai axtarış API-si — pulsuz, key tələb etmir."""
    resp = _safe_get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200")
    found = set()
    if resp:
        try:
            for result in resp.json().get("results", []):
                page = result.get("page", {})
                dom = page.get("domain", "")
                if dom:
                    found.add(dom.strip().lower())
        except Exception:
            pass
    return found


def src_shodan(domain):
    """Shodan — YALNIZ SHODAN_API_KEY verilibsə işə düşür."""
    key = CONFIG["SHODAN_API_KEY"]
    found = set()
    if not key:
        return found
    resp = _safe_get(f"https://api.shodan.io/dns/domain/{domain}?key={key}")
    if resp:
        try:
            for sub in resp.json().get("subdomains", []):
                found.add(f"{sub}.{domain}".lower())
        except Exception:
            pass
    return found


def src_securitytrails(domain):
    """SecurityTrails — YALNIZ SECURITYTRAILS_API_KEY verilibsə işə düşür."""
    key = CONFIG["SECURITYTRAILS_API_KEY"]
    found = set()
    if not key:
        return found
    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={**HEADERS, "APIKEY": key}, timeout=20,
        )
        if resp.status_code == 200:
            for sub in resp.json().get("subdomains", []):
                found.add(f"{sub}.{domain}".lower())
    except Exception:
        pass
    return found


def src_fullhunt(domain):
    """FullHunt — YALNIZ FULLHUNT_API_KEY verilibsə işə düşür."""
    key = CONFIG["FULLHUNT_API_KEY"]
    found = set()
    if not key:
        return found
    try:
        resp = requests.get(
            f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
            headers={**HEADERS, "X-API-KEY": key}, timeout=20,
        )
        if resp.status_code == 200:
            for h in resp.json().get("hosts", []):
                found.add(h.strip().lower())
    except Exception:
        pass
    return found


def src_censys(domain):
    """
    Censys Hosts Search API (v2) — YALNIZ CENSYS_API_ID + CENSYS_API_SECRET
    verilibsə işə düşür. Shodan-ın görmədiyi/blokladığı infrastrukturu
    (unudulmuş dev/test serverlər) üzə çıxara bilir.
    """
    api_id = CONFIG["CENSYS_API_ID"]
    api_secret = CONFIG["CENSYS_API_SECRET"]
    found = set()
    if not (api_id and api_secret):
        return found
    try:
        resp = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": f"dns.names: {domain}", "per_page": 100},
            auth=(api_id, api_secret), timeout=20,
        )
        if resp.status_code == 200:
            for hit in resp.json().get("result", {}).get("hits", []):
                for name in hit.get("dns", {}).get("names", []) or []:
                    found.add(name.strip().lower())
    except Exception:
        pass
    return found


def src_fofa(domain):
    """
    FOFA (Çin mənşəli) — YALNIZ FOFA_EMAIL + FOFA_KEY verilibsə işə düşür.
    Bəzən Shodan/Censys-in görmədiyi yerli/regional infrastrukturu tapır.
    """
    email = CONFIG["FOFA_EMAIL"]
    key = CONFIG["FOFA_KEY"]
    found = set()
    if not (email and key):
        return found
    try:
        query = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        resp = requests.get(
            "https://fofa.info/api/v1/search/all",
            params={"email": email, "key": key, "qbase64": query, "size": 100, "fields": "host"},
            timeout=20,
        )
        if resp.status_code == 200:
            data = resp.json()
            if not data.get("error"):
                for row in data.get("results", []):
                    host = row[0] if isinstance(row, list) else row
                    if host:
                        found.add(str(host).strip().lower())
    except Exception:
        pass
    return found


def src_zoomeye(domain):
    """ZoomEye — YALNIZ ZOOMEYE_API_KEY verilibsə işə düşür."""
    key = CONFIG["ZOOMEYE_API_KEY"]
    found = set()
    if not key:
        return found
    try:
        resp = requests.get(
            "https://api.zoomeye.org/host/search",
            params={"query": f"hostname:{domain}"},
            headers={"API-KEY": key}, timeout=20,
        )
        if resp.status_code == 200:
            for match in resp.json().get("matches", []):
                name = match.get("site") or (match.get("hostname") if isinstance(match.get("hostname"), str) else None)
                if name:
                    found.add(name.strip().lower())
    except Exception:
        pass
    return found


SOURCES = [
    ("crt.sh", src_crtsh),
    ("hackertarget", src_hackertarget),
    ("wayback", src_wayback),
    ("alienvault_otx", src_alienvault_otx),
    ("rapiddns", src_rapiddns),
    ("anubisdb", src_anubisdb),
    ("threatminer", src_threatminer),
    ("certspotter", src_certspotter),
    ("bufferover", src_bufferover),
    ("urlscan", src_urlscan),
    ("shodan", src_shodan),
    ("securitytrails", src_securitytrails),
    ("fullhunt", src_fullhunt),
    ("censys", src_censys),
    ("fofa", src_fofa),
    ("zoomeye", src_zoomeye),
]


# ======================================================================
# AKTİV DNS BRUTE-FORCE (Gobuster / ffuf) — DEFOLT SÖNÜLÜDÜR.
# Yalnız istifadəçi --bruteforce (gobuster, DNS) və ya --fuzz-paths
# (ffuf, HTTP path/directory) bayrağını AÇIQ ŞƏKİLDƏ verib öz wordlist
# faylını göstərəndə işə düşür. Heç bir wordlist bu alətin daxilində
# bundle/download edilmir — istifadəçi öz wordlist-ini (məs. SecLists-
# dən) təmin etməlidir. Bu, passiv OSINT-dən fərqli olaraq hədəfin DNS/
# HTTP infrastrukturuna birbaşa çoxlu sorğu göndərir — YALNIZ icazəli
# (authorized) hədəflərdə istifadə edilməlidir.
# ======================================================================

def run_gobuster_dns(domain, wordlist_path, threads=50, timeout=900):
    path = find_external_tool("gobuster")
    if not path:
        print(f"{Fore.RED}[!] 'gobuster' PATH-də tapılmadı. Quraşdırın: "
              f"https://github.com/OJ/gobuster{Style.RESET_ALL}")
        return set()
    if not wordlist_path or not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!] Wordlist faylı tapılmadı: {wordlist_path}{Style.RESET_ALL}")
        return set()

    print(f"{Fore.YELLOW}[*] gobuster ilə AKTİV DNS brute-force başladılır "
          f"(wordlist: {wordlist_path})... Bu, hədəfə çoxlu DNS sorğusu göndərəcək.{Style.RESET_ALL}")
    found = set()
    try:
        result = subprocess.run(
            [path, "dns", "-d", domain, "-w", wordlist_path, "-q", "-t", str(threads)],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in result.stdout.splitlines():
            m = re.match(r"Found:\s*(\S+)", line.strip())
            if m:
                found.add(m.group(1).rstrip(".").lower())
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[!] gobuster timeout-a düşdü ({timeout}san) — nəticələr natamam ola bilər.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] gobuster xətası: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[+] gobuster DNS brute-force: {len(found)} yeni subdomen tapıldı.{Style.RESET_ALL}")
    return found


def run_ffuf_content_discovery(base_url, wordlist_path, threads=50, timeout=900):
    """ffuf ilə hədəf saytda gizli path/directory kəşfiyyatı (HTTP fuzzing)."""
    path = find_external_tool("ffuf")
    if not path:
        print(f"{Fore.RED}[!] 'ffuf' PATH-də tapılmadı. Quraşdırın: "
              f"https://github.com/ffuf/ffuf{Style.RESET_ALL}")
        return []
    if not wordlist_path or not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!] Wordlist faylı tapılmadı: {wordlist_path}{Style.RESET_ALL}")
        return []

    print(f"{Fore.YELLOW}[*] ffuf ilə AKTİV path/directory fuzzing başladılır "
          f"({base_url})... Bu, hədəfə çoxlu HTTP sorğusu göndərəcək.{Style.RESET_ALL}")
    found_paths = []
    try:
        result = subprocess.run(
            [path, "-u", f"{base_url}/FUZZ", "-w", wordlist_path,
             "-mc", "200,204,301,302,307,401,403", "-t", str(threads), "-s"],
            capture_output=True, text=True, timeout=timeout,
        )
        found_paths = [line.strip() for line in result.stdout.splitlines() if line.strip()][:300]
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[!] ffuf timeout-a düşdü ({timeout}san) — nəticələr natamam ola bilər.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] ffuf xətası: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[+] ffuf: {len(found_paths)} path/directory tapıldı.{Style.RESET_ALL}")
    return found_paths




def is_valid_subdomain(subdomain, target_domain):
    if not subdomain.endswith(f".{target_domain}") and subdomain != target_domain:
        return False
    pattern = re.compile(
        r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
    )
    return bool(pattern.match(subdomain))


def get_all_subdomains(domain):
    _info(f"{Fore.YELLOW}[*] Alt domen axtarışı aparılır...{Style.RESET_ALL}")
    merged = {}
    for name, func in SOURCES:
        try:
            subs = func(domain)
        except Exception:
            subs = set()
        for sub in subs:
            sub = sub.strip().lower()
            if sub.startswith("www."):
                sub = sub[4:]
            if not sub or sub == domain or not is_valid_subdomain(sub, domain):
                continue
            merged.setdefault(sub, set()).add(name)
    return {k: sorted(v) for k, v in merged.items()}


# ======================================================================
# 1.5) HƏDƏF DOMENİN ÜMUMİ PROFİLİ — IP, geolokasiya, WHOIS/RDAP, SSL
# ======================================================================

def get_ip_geolocation(ip):
    """ip-api.com — pulsuz, key tələb etmir. Ölkə/şəhər/provayder/ASN verir."""
    resp = _safe_get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                      f"region,regionName,city,zip,lat,lon,isp,org,as,mobile,proxy,hosting")
    if resp:
        try:
            data = resp.json()
            if data.get("status") == "success":
                return data
        except Exception:
            pass
    return None


def get_whois_rdap(domain):
    """RDAP (rdap.org üzərindən) — standart, pulsuz whois əvəzedicisi.
    .az domenlərdə dəstək məhdud ola bilər, o halda None qaytarır."""
    resp = _safe_get(f"https://rdap.org/domain/{domain}", timeout=15)
    if not resp:
        return None
    try:
        data = resp.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        registrar = field[3]
        return {
            "registrar": registrar,
            "created": events.get("registration"),
            "last_changed": events.get("last changed"),
            "expires": events.get("expiration"),
            "nameservers": nameservers,
            "status": data.get("status", []),
        }
    except Exception:
        return None


def classify_az_domain(domain):
    """.AZ ikinci səviyyə suffiksinə görə hədəfin növünü müəyyən edir."""
    for suffix, meaning in sorted(AZ_SUBTLD_MEANINGS.items(), key=lambda x: -len(x[0])):
        if domain == suffix or domain.endswith("." + suffix):
            return meaning
    if domain.endswith(".az"):
        return "Ümumi .AZ qeydiyyatı (ikinci səviyyə domen)"
    return None


def get_iana_referral_server(tld):
    """IANA WHOIS-dan (whois.iana.org, port 43) TLD üçün rəsmi referral
    whois serverini soruşur — standart 'universal whois client' texnikası."""
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=8) as sock:
            sock.sendall(f"{tld}\r\n".encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            text = data.decode(errors="ignore")
            m = re.search(r"whois:\s*(\S+)", text)
            return m.group(1) if m else None
    except Exception:
        return None


def raw_whois_query(domain, server, port=43, timeout=8):
    """Standart WHOIS protokolu (port 43) sorğusu — captcha/anti-bot
    qorumasından yan keçmə cəhdi ETMİR, yalnız açıq protokolu istifadə edir."""
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 100_000:
                    break
            return data.decode(errors="ignore")
    except Exception:
        return None


# .AZ üçün cəhd ediləcək port-43 WHOIS server namizədləri. IANA-nın
# rəsmi referral zəncirində .az adətən görünmür, ona görə bu ayrıca,
# əl ilə təsdiqlənməli namizəd siyahısıdır — qaranti verilmir ki, bu
# server(lər) canlıdır və ya cavab formatı aşağıdakı parser-lə tam
# uyğundur (registry format-ı dəyişə bilər).
AZ_WHOIS_SERVER_CANDIDATES = ["whois.az", "whois.nic.az"]


def get_az_raw_whois(domain, timeout=10):
    """
    .AZ domenlər üçün birbaşa port-43 WHOIS protokol sorğusu.
    Diqqət: bu, whois.az VEB PORTALINDAKI CAPTCHA-dan tamamilə fərqli,
    ayrı bir xidmətdir (standart WHOIS protokolu, TCP/43) — heç bir
    anti-bot qorumasını dəf etmə cəhdi yoxdur. Server cavab verməzsə
    (bağlıdırsa/mövcud deyilsə) sadəcə None qaytarılır.
    """
    for server in AZ_WHOIS_SERVER_CANDIDATES:
        raw = raw_whois_query(domain, server, timeout=timeout)
        if not raw:
            continue
        low = raw.lower()
        if "no match" in low or "not found" in low or "no entries found" in low or len(raw.strip()) < 5:
            continue

        # Format qaranti edilmədiyi üçün bir neçə mümkün etiket variantını sınayırıq.
        registrar_m = re.search(r"(?:Registrar|Sponsoring Registrar)[:\s]+(.+)", raw, re.IGNORECASE)
        created_m = re.search(r"(?:Creation Date|Created On|Registered)[:\s]+(.+)", raw, re.IGNORECASE)
        expires_m = re.search(r"(?:Expiry Date|Expiration Date|Expires On)[:\s]+(.+)", raw, re.IGNORECASE)
        ns_matches = re.findall(r"(?:Name Server|Nserver|NS)[:\s]+(\S+)", raw, re.IGNORECASE)
        status_matches = re.findall(r"(?:Status|Domain Status)[:\s]+(.+)", raw, re.IGNORECASE)

        return {
            "method": f"Xam WHOIS ({server}:43)",
            "registrar": registrar_m.group(1).strip() if registrar_m else None,
            "created": created_m.group(1).strip() if created_m else None,
            "last_changed": None,
            "expires": expires_m.group(1).strip() if expires_m else None,
            "nameservers": [n.strip() for n in ns_matches] or None,
            "status": [s.strip() for s in status_matches],
            "raw_snippet": raw[:2000],
            "note": "Format .az registri tərəfindən sənədləşdirilmədiyi üçün yuxarıdakı "
                    "sahələr best-effort parse edilib — dəqiq məlumat üçün raw_snippet-ə baxın.",
        }
    return None


def get_whoisfreaks_data(domain):
    """
    WhoisFreaks API (v2.0) — YALNIZ WHOISFREAKS_API_KEY verilibsə işə
    düşür. Rəsmi, key-gated WHOIS xidmətidir (qeydiyyatda 500 pulsuz
    kredit verir), 1500+ TLD dəstəkləyir və .az daxil bir çox ccTLD-də
    RDAP/port-43-dən daha etibarlı nəticə verə bilir.
    """
    key = CONFIG["WHOISFREAKS_API_KEY"]
    if not key:
        return None
    try:
        resp = requests.get(
            "https://api.whoisfreaks.com/v2.0/whois/live",
            params={"format": "json", "domainName": domain, "apiKey": key},
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if isinstance(data, list):
            data = data[0] if data else {}
        if not data.get("status") or data.get("domain_registered") == "no":
            return None

        registrar = (data.get("domain_registrar") or {}).get("registrar_name")
        nameservers = data.get("name_servers") or data.get("nameservers") or []

        return {
            "method": "WhoisFreaks API",
            "registrar": registrar,
            "created": data.get("create_date"),
            "last_changed": data.get("update_date"),
            "expires": data.get("expiry_date"),
            "nameservers": nameservers if isinstance(nameservers, list) else None,
            "status": data.get("domain_status") or [],
        }
    except Exception:
        return None


def get_whois_local(domain):
    """
    Yerli WHOIS məntiqi — beş qatlı fallback:
      0) WhoisFreaks API (opsional key) — verilibsə ilk növbədə sınanır,
         çünki ən etibarlı/rəsmi mənbədir.
      1) RDAP (rdap.org) — strukturlaşdırılmış, ən etibarlı pulsuz mənbə.
      2) IANA referral zənciri ilə xam WHOIS protokolu (port 43) —
         bir çox qədim TLD registri RDAP dəstəkləmədiyi üçün lazımdır.
      3) .AZ üçün: birbaşa whois.az:43 xam WHOIS PROTOKOLU (HTTP veb
         portalından FƏRQLİDİR — CAPTCHA yalnız veb interfeysinə aiddir,
         port 43 standart protokol sorğusudur, bypass deyil).
      4) Hamısı boş qalarsa: istifadəçiyə manual axtarış linki verilir.
    """
    whoisfreaks = get_whoisfreaks_data(domain)
    if whoisfreaks:
        return whoisfreaks

    rdap = get_whois_rdap(domain)
    if rdap:
        rdap["method"] = "RDAP"
        return rdap

    tld = domain.split(".")[-1]
    referral_server = get_iana_referral_server(tld)
    if referral_server:
        raw = raw_whois_query(domain, referral_server)
        if raw and "no match" not in raw.lower() and "not found" not in raw.lower():
            registrar_m = re.search(r"Registrar:\s*(.+)", raw)
            created_m = re.search(r"Creation Date:\s*(.+)", raw)
            expires_m = re.search(r"Registry Expiry Date:\s*(.+)", raw)
            ns_matches = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
            return {
                "method": f"Xam WHOIS ({referral_server})",
                "registrar": registrar_m.group(1).strip() if registrar_m else None,
                "created": created_m.group(1).strip() if created_m else None,
                "last_changed": None,
                "expires": expires_m.group(1).strip() if expires_m else None,
                "nameservers": [n.strip() for n in ns_matches] or None,
                "status": [],
                "raw_snippet": raw[:1500],
            }

    if tld == "az":
        az_result = get_az_raw_whois(domain)
        if az_result:
            return az_result
        return {
            "method": "manual_required",
            "registrar": None, "created": None, "last_changed": None,
            "expires": None, "nameservers": None, "status": [],
            "note": ".AZ üçün nə RDAP, nə də port-43 WHOIS cavab vermədi "
                    "(server bağlıdır və ya cavab formatı fərqlidir). "
                    "Manual yoxlama üçün (veb portalda CAPTCHA var):",
            "manual_url": f"https://www.whois.az/?domain={domain}",
        }

    return None


# ======================================================================
# 1.6) SIZINTI (DATA BREACH) AXTARIŞI — Have I Been Pwned API
#      (opsional key; YALNIZ hansı breach-lərdə görünüb və hansı data
#      növü (email/parol/telefon) sızıb — real parolları QAYTARMIR)
# ======================================================================

def check_hibp_breaches(email):
    """
    Have I Been Pwned API v3 — YALNIZ HIBP_API_KEY verilibsə işə düşür.
    Qaytarır: [{"Name":..., "BreachDate":..., "DataClasses":[...]}]
    Diqqət: bu API heç vaxt real parol qaytarmır, yalnız "bu email hansı
    sızıntılarda görünüb" məlumatını verir.
    """
    key = CONFIG["HIBP_API_KEY"]
    if not key:
        return None
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": key, "User-Agent": "AzRecon-v4"},
            params={"truncateResponse": "false"},
            timeout=15,
        )
        if resp.status_code == 200:
            return [
                {
                    "name": b.get("Name"),
                    "breach_date": b.get("BreachDate"),
                    "data_classes": b.get("DataClasses", []),
                }
                for b in resp.json()
            ]
        if resp.status_code == 404:
            return []  # heç bir sızıntıda görünməyib
        return None  # rate-limit/auth xətası
    except Exception:
        return None


def check_domain_breaches(emails):
    """Ehtimal olunan korporativ e-poçtları HIBP-də yoxlayır (key varsa)."""
    if not CONFIG["HIBP_API_KEY"]:
        return {"enabled": False, "results": {}}
    results = {}
    for email in emails:
        breaches = check_hibp_breaches(email)
        if breaches:
            results[email] = breaches
        time.sleep(1.6)  # HIBP rate-limit-ə hörmət (adətən ~1.5 req/san)
    return {"enabled": True, "results": results}


# ======================================================================
# 1.8) İCTİMAİ KOD REPOZİTORİLƏRİ (GITHUB SECRET SCANNING)
#      GitHub Code Search API ilə hədəf domenlə birlikdə "password",
#      "api_key", "secret" və s. sözlərin keçdiyi public repo faylları
#      axtarılır. Bu, tərtibatçıların səhvən public repoya sızdırdığı
#      açar/parolların tapılması üçün standart, tamamilə qanuni texnikadır
#      (bütün məlumat onsuz da GitHub-da publikdir).
# ======================================================================

GITHUB_SECRET_KEYWORDS = [
    "password", "api_key", "apikey", "secret", "token",
    "db_password", "database_password", "access_key", "private_key",
]


def search_github_code_leaks(domain):
    """
    YALNIZ GITHUB_TOKEN verilibsə işə düşür (GitHub Code Search API
    autentifikasiyasız praktik olaraq istifadəyə yararsızdır — çox aşağı
    rate-limit). Token GitHub Settings -> Developer settings ->
    Personal access tokens bölümündən pulsuz yaradıla bilər (heç bir
    xüsusi scope tələb etmir, public repo axtarışı üçün).
    """
    token = CONFIG["GITHUB_TOKEN"]
    if not token:
        return {"enabled": False, "results": []}

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.text-match+json",
        "User-Agent": "AzRecon-v4",
    }
    findings = []
    seen = set()

    for keyword in GITHUB_SECRET_KEYWORDS:
        query = f'"{domain}" {keyword}'
        try:
            resp = requests.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 10},
                headers=headers, timeout=20,
            )
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    key = item.get("html_url")
                    if not key or key in seen:
                        continue
                    seen.add(key)

                    snippet = None
                    matches = item.get("text_matches", [])
                    if matches:
                        raw_fragment = matches[0].get("fragment", "")
                        snippet = _mask_line_secrets(raw_fragment)[:300]

                    findings.append({
                        "repo": item.get("repository", {}).get("full_name"),
                        "file_path": item.get("path"),
                        "url": key,
                        "matched_keyword": keyword,
                        "snippet_masked": snippet,
                    })
            elif resp.status_code == 403:
                # rate-limit — davam etmədən dayan
                break
        except Exception:
            continue
        time.sleep(2.5)  # GitHub Code Search rate-limit-inə hörmət (~10 sorğu/dəq)

    return {"enabled": True, "results": findings[:60]}


def _mask_line_secrets(text):
    """Kod fraqmentindəki ehtimal edilən açar/parol dəyərlərini maskalayır."""
    def repl(m):
        return f"{m.group(1)}{_mask_secret(m.group(2))}"
    pattern = re.compile(
        r'((?:password|api[_-]?key|secret|token)["\']?\s*[:=]\s*["\'])([^"\']{6,80})',
        re.IGNORECASE,
    )
    return pattern.sub(repl, text)


# ======================================================================
# 1.7) JAVASCRIPT (END-POINT) ANALİZİ — JS fayllarından gizli API
#      yollarının və mümkün açıqlanmış açarların (maskalanmış) tapılması
# ======================================================================

def extract_js_file_urls(html, base_url):
    """Səhifədəki <script src="..."> teqlərindən JS fayl URL-lərini çıxarır."""
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    resolved = set()
    for src in srcs:
        if src.startswith("//"):
            resolved.add("https:" + src)
        elif src.startswith("http"):
            resolved.add(src)
        elif src.startswith("/"):
            resolved.add(base_url.rstrip("/") + src)
        else:
            resolved.add(base_url.rstrip("/") + "/" + src)
    return list(resolved)[:15]  # yükü məhdudlaşdırmaq üçün max 15 fayl


def _mask_secret(value):
    """Tapılan 'sirr' dəyərini maskalayır — yalnız ilk/son simvollar görünür."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _analyze_js_content(content, source_label):
    """
    Tək bir JS faylının məzmunundan endpoint/sirr çıxarışı — həm canlı,
    həm də arxivlənmiş (Wayback) JS fayllar üçün ortaq məntiq.
    """
    endpoints = set()
    secrets_found = []

    for m in ENDPOINT_PATTERN.findall(content):
        if any(m.lower().endswith(ext) for ext in (".png", ".jpg", ".svg", ".css", ".woff", ".woff2", ".gif")):
            continue
        endpoints.add(m)

    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in re.findall(pattern, content):
            raw_value = match if isinstance(match, str) else match[0]
            secrets_found.append({
                "type": secret_type,
                "masked_value": _mask_secret(raw_value),
                "source_file": source_label,
            })

    return endpoints, secrets_found


def analyze_js_endpoints(base_url, html):
    """
    Səhifədəki CANLI JS fayllarını çəkir, içindən:
      - API/endpoint yollarını (məs. /api/v1/user)
      - mümkün açıqlanmış açar/token-ləri (MASKALANMIŞ şəkildə)
    çıxarır. Bu, LinkFinder/SecretFinder tipli standart passiv JS
    recon texnikasıdır.
    """
    js_urls = extract_js_file_urls(html, base_url)
    endpoints = set()
    secrets_found = []

    for js_url in js_urls:
        resp = _safe_get(js_url, timeout=10)
        if not resp:
            continue
        content = resp.text[:500_000]  # fayl başına max ~500KB
        ep, sec = _analyze_js_content(content, js_url)
        endpoints |= ep
        secrets_found.extend(sec)

    return {
        "js_files_analyzed": len(js_urls),
        "endpoints_found": sorted(endpoints)[:200],
        "possible_secrets": secrets_found[:50],
    }


def analyze_wayback_js(domain, max_files=20):
    """
    DƏRİN ARXİV ANALİZİ — Wayback Machine CDX API-dən domenə aid
    arxivlənmiş .js fayllarını tapır, hər birinin köhnə (silinmiş/
    unudulmuş) versiyasını çəkib eyni endpoint/sirr regex-ləri ilə
    analiz edir. Canlı saytda artıq mövcud olmayan, amma keşdə qalmış
    "unudulmuş" API endpoint-lərini üzə çıxarmaq üçün çox dəyərlidir.
    """
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=json&collapse=urlkey&fl=timestamp,original&filter=original:.*\\.js.*&limit=3000")
    resp = _safe_get(url, timeout=45)
    if not resp:
        return {"archived_js_files_analyzed": 0, "endpoints_found": [], "possible_secrets": []}

    try:
        rows = resp.json()
    except Exception:
        return {"archived_js_files_analyzed": 0, "endpoints_found": [], "possible_secrets": []}

    js_snapshots = []
    seen_originals = set()
    for row in rows[1:]:  # ilk sətir header
        if len(row) < 2:
            continue
        timestamp, original = row[0], row[1]
        if not original.lower().split("?")[0].endswith(".js"):
            continue
        if original in seen_originals:
            continue
        seen_originals.add(original)
        js_snapshots.append((timestamp, original))
        if len(js_snapshots) >= max_files:
            break

    endpoints = set()
    secrets_found = []
    for timestamp, original in js_snapshots:
        archive_url = f"http://web.archive.org/web/{timestamp}id_/{original}"
        resp_js = _safe_get(archive_url, timeout=15)
        if not resp_js:
            continue
        content = resp_js.text[:500_000]
        ep, sec = _analyze_js_content(content, f"[arxiv] {original}")
        endpoints |= ep
        secrets_found.extend(sec)

    return {
        "archived_js_files_analyzed": len(js_snapshots),
        "endpoints_found": sorted(endpoints)[:200],
        "possible_secrets": secrets_found[:50],
    }


def get_target_overview(domain, dns_records):
    _info(f"{Fore.CYAN}[*] Hədəf domenin ümumi profili toplanılır (IP, geolokasiya, WHOIS)...{Style.RESET_ALL}")
    ip = resolve_ip(domain)
    overview = {"domain": domain, "ip": ip}
    overview["az_domain_type"] = classify_az_domain(domain)

    if ip:
        asn_info = get_asn_info(ip)
        overview["asn_info"] = asn_info
        geo = get_ip_geolocation(ip)
        overview["geolocation"] = geo
    else:
        overview["asn_info"] = None
        overview["geolocation"] = None

    overview["whois"] = get_whois_local(domain)
    overview["ssl"] = get_ssl_cert_info(domain)
    overview["dns_server_versions"] = get_dns_server_version(domain)

    html_body = ""
    try:
        resp = requests.get(f"https://{domain}", timeout=8, headers=HEADERS, allow_redirects=True)
        overview["http_status"] = resp.status_code
        overview["server_header"] = resp.headers.get("Server", "")
        overview["final_url"] = str(resp.url)
        overview["technologies"] = detect_technologies(resp.headers, resp.text[:6000])
        overview["versions"] = extract_versions(resp.headers, resp.text[:6000])
        html_body = resp.text
    except Exception:
        overview["http_status"] = None
        overview["server_header"] = None
        overview["final_url"] = None
        overview["technologies"] = []
        overview["versions"] = {}

    _info(f"{Fore.YELLOW}[*] JavaScript fayllarında endpoint/sirr analizi aparılır (canlı)...{Style.RESET_ALL}")
    if html_body:
        overview["js_analysis"] = analyze_js_endpoints(f"https://{domain}", html_body)
    else:
        overview["js_analysis"] = {"js_files_analyzed": 0, "endpoints_found": [], "possible_secrets": []}

    _info(f"{Fore.YELLOW}[*] Wayback Machine arxivindən köhnə JS fayllar analiz edilir "
          f"(unudulmuş endpoint-lər)...{Style.RESET_ALL}")
    overview["archived_js_analysis"] = analyze_wayback_js(domain)

    if CONFIG["GITHUB_TOKEN"]:
        _info(f"{Fore.YELLOW}[*] GitHub public repo-larında sızıntı axtarılır...{Style.RESET_ALL}")
    overview["github_leaks"] = search_github_code_leaks(domain)

    # ---- konsola çap ----
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  HƏDƏF PROFİLİ: {domain}")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}IP ünvanı:{Style.RESET_ALL}        {ip or 'tapılmadı'}")
    if overview["az_domain_type"]:
        print(f"  {Fore.GREEN}Domen növü:{Style.RESET_ALL}         {overview['az_domain_type']}")
    if overview["asn_info"]:
        a = overview["asn_info"]
        print(f"  {Fore.GREEN}ASN / Holder:{Style.RESET_ALL}      {a['asn']} — {a['holder']}")
        print(f"  {Fore.GREEN}AZ lokal provayder:{Style.RESET_ALL} {a['az_local_provider']}")
    if overview["geolocation"]:
        g = overview["geolocation"]
        print(f"  {Fore.GREEN}Yerləşmə:{Style.RESET_ALL}          {g.get('city')}, {g.get('country')}")
        print(f"  {Fore.GREEN}İSP/Təşkilat:{Style.RESET_ALL}       {g.get('isp')} / {g.get('org')}")
        print(f"  {Fore.GREEN}Hosting/Proxy:{Style.RESET_ALL}      hosting={g.get('hosting')}, proxy={g.get('proxy')}")
    if overview["whois"]:
        w = overview["whois"]
        if w.get("method") == "manual_required":
            print(f"  {Fore.YELLOW}WHOIS:{Style.RESET_ALL} {w['note']}")
            print(f"      {Fore.YELLOW}{w['manual_url']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}Qeydiyyatçı (Registrar):{Style.RESET_ALL} {w.get('registrar')} [{w.get('method')}]")
            print(f"  {Fore.GREEN}Yaradılma tarixi:{Style.RESET_ALL}   {w.get('created')}")
            print(f"  {Fore.GREEN}Bitmə tarixi:{Style.RESET_ALL}       {w.get('expires')}")
            if w.get("nameservers"):
                print(f"  {Fore.GREEN}Nameserver-lər:{Style.RESET_ALL}     {', '.join(w['nameservers'])}")
    else:
        print(f"  {Fore.LIGHTBLACK_EX}WHOIS: heç bir mənbədən məlumat alınmadı{Style.RESET_ALL}")
    if overview["ssl"]:
        s = overview["ssl"]
        print(f"  {Fore.GREEN}SSL Issuer:{Style.RESET_ALL}         {s.get('issuer')}")
        print(f"  {Fore.GREEN}SSL bitmə tarixi:{Style.RESET_ALL}   {s.get('not_after')}")
        print(f"  {Fore.GREEN}TLS versiyası:{Style.RESET_ALL}      {s.get('tls_version')}")
        print(f"  {Fore.GREEN}Cipher suite:{Style.RESET_ALL}       {s.get('cipher_suite')}")
    print(f"  {Fore.GREEN}HTTP status:{Style.RESET_ALL}        {overview['http_status']}")
    print(f"  {Fore.GREEN}Server header:{Style.RESET_ALL}      {overview['server_header']}")
    if overview["technologies"]:
        print(f"  {Fore.GREEN}Texnologiyalar:{Style.RESET_ALL}     {', '.join(overview['technologies'])}")
    if overview["versions"]:
        print(f"  {Fore.GREEN}Aşkarlanan versiyalar:{Style.RESET_ALL}")
        for tech, ver in overview["versions"].items():
            print(f"      - {tech}: {Fore.YELLOW}{ver}{Style.RESET_ALL}")
    ja = overview["js_analysis"]
    if ja["js_files_analyzed"]:
        print(f"  {Fore.GREEN}JS faylları analiz edildi (canlı):{Style.RESET_ALL}  {ja['js_files_analyzed']}")
        print(f"  {Fore.GREEN}Aşkarlanan endpoint sayı:{Style.RESET_ALL}   {len(ja['endpoints_found'])}")
        if ja["possible_secrets"]:
            print(f"  {Fore.RED}Mümkün açıqlanmış sirr(lər): {len(ja['possible_secrets'])} (maskalanıb){Style.RESET_ALL}")
            for sec in ja["possible_secrets"][:5]:
                print(f"      - {sec['type']}: {sec['masked_value']} ({sec['source_file']})")

    aja = overview["archived_js_analysis"]
    if aja["archived_js_files_analyzed"]:
        print(f"  {Fore.GREEN}Arxivlənmiş JS faylları analiz edildi:{Style.RESET_ALL}  {aja['archived_js_files_analyzed']}")
        print(f"  {Fore.GREEN}Arxivdən tapılan əlavə endpoint sayı:{Style.RESET_ALL}  {len(aja['endpoints_found'])}")
        if aja["possible_secrets"]:
            print(f"  {Fore.RED}Arxivdə mümkün açıqlanmış sirr(lər): {len(aja['possible_secrets'])} (maskalanıb){Style.RESET_ALL}")
            for sec in aja["possible_secrets"][:5]:
                print(f"      - {sec['type']}: {sec['masked_value']} ({sec['source_file']})")

    gh = overview["github_leaks"]
    if gh["enabled"]:
        if gh["results"]:
            print(f"  {Fore.RED}GitHub public repo-larında {len(gh['results'])} ehtimal edilən sızıntı tapıldı:{Style.RESET_ALL}")
            for f in gh["results"][:5]:
                print(f"      - {f['repo']}/{f['file_path']} [{f['matched_keyword']}] -> {f['url']}")
        else:
            print(f"  {Fore.GREEN}GitHub public repo-larında sızıntı tapılmadı.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.LIGHTBLACK_EX}GitHub sızıntı axtarışı: GITHUB_TOKEN verilməyib, atlanıldı.{Style.RESET_ALL}")

    if overview["dns_server_versions"]:
        print(f"  {Fore.GREEN}DNS server versiyası:{Style.RESET_ALL}")
        for ns, ver in overview["dns_server_versions"].items():
            print(f"      - {ns}: {Fore.YELLOW}{ver}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}SPF mövcuddur:{Style.RESET_ALL}      {dns_records.get('spf_present')}")
    print(f"  {Fore.GREEN}DMARC mövcuddur:{Style.RESET_ALL}    {dns_records.get('dmarc_present')}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    return overview


# ======================================================================
# 2) DNS DƏRİNLƏŞDİRMƏ — A/AAAA/MX/TXT/NS + SPF/DMARC yoxlaması
# ======================================================================

def get_dns_records(domain):
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r).strip('"') for r in answers]
        except Exception:
            records[rtype] = []

    spf = any("v=spf1" in t for t in records.get("TXT", []))
    dmarc = []
    try:
        dmarc_ans = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = [str(r).strip('"') for r in dmarc_ans]
    except Exception:
        pass

    records["spf_present"] = spf
    records["dmarc_present"] = bool(dmarc)
    records["dmarc_record"] = dmarc[0] if dmarc else None
    return records


def get_cname(hostname):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 4
    try:
        answers = resolver.resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".").lower()
    except Exception:
        return None


def check_takeover(hostname, cname):
    if not cname:
        return None
    for pattern, (fingerprint_text, service) in TAKEOVER_FINGERPRINTS.items():
        if pattern in cname:
            try:
                resp = requests.get(f"http://{hostname}", timeout=6, headers=HEADERS)
                if fingerprint_text.lower() in resp.text.lower():
                    return {"service": service, "cname": cname, "confidence": "yüksək"}
            except Exception:
                return {"service": service, "cname": cname, "confidence": "yoxlanılmayıb (bağlantı xətası)"}
    return None


# ======================================================================
# 3) SSL SERTİFİKAT ANALİZİ — SAN-lardan əlavə subdomain çıxarışı
# ======================================================================

def get_ssl_cert_info(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                tls_version = ssock.version()
                cipher = ssock.cipher()
                if not cert:
                    return {
                        "issuer": None, "subject_cn": None, "not_after": None,
                        "san_domains": [], "tls_version": tls_version,
                        "cipher_suite": cipher[0] if cipher else None,
                    }
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                return {
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "subject_cn": subject.get("commonName"),
                    "not_after": cert.get("notAfter"),
                    "san_domains": sans,
                    "tls_version": tls_version,
                    "cipher_suite": cipher[0] if cipher else None,
                }
    except Exception:
        return None


# ======================================================================
# 4) FAVICON HASH — Shodan-stil "http.favicon.hash" pivot texnikası
#    (eyni favicon-a malik başqa infrastrukturu tapmaq üçün niche üsul)
# ======================================================================

def get_favicon_hash(base_url):
    try:
        resp = requests.get(f"{base_url}/favicon.ico", timeout=5, headers=HEADERS)
        if resp.status_code == 200 and resp.content:
            b64 = base64.encodebytes(resp.content)
            return mmh3.hash(b64)
    except Exception:
        pass
    return None


# ======================================================================
# 5) CANLILIQ + TEXNOLOGİYA FINGERPRINT — async
# ======================================================================

def detect_technologies(headers, body_snippet):
    detected = []
    combined = (json.dumps(dict(headers)).lower() + " " + body_snippet.lower())
    for tech, signatures in TECH_SIGNATURES.items():
        if any(sig.lower() in combined for sig in signatures):
            detected.append(tech)
    return detected


async def check_one(session, sub, semaphore):
    async with semaphore:
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    body = ""
                    try:
                        raw = await resp.content.read(4096)
                        body = raw.decode(errors="ignore")
                    except Exception:
                        pass
                    techs = detect_technologies(resp.headers, body)
                    versions = extract_versions(resp.headers, body)
                    return {
                        "subdomain": sub,
                        "status": f"LIVE ({scheme.upper()} {resp.status})",
                        "scheme": scheme,
                        "http_status": resp.status,
                        "final_url": str(resp.url),
                        "server_header": resp.headers.get("Server", ""),
                        "technologies": techs,
                        "versions": versions,
                    }
            except Exception:
                continue
        return {
            "subdomain": sub, "status": "OFFLINE", "scheme": None,
            "http_status": None, "final_url": None,
            "server_header": None, "technologies": [], "versions": {},
        }


async def check_live_subdomains_async(subdomains):
    _info(f"\n{Fore.YELLOW}[*] Canlılıq + texnologiya fingerprint yoxlanılır "
          f"(async, {CONCURRENCY_LIMIT} paralel)...{Style.RESET_ALL}")
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY_LIMIT, ssl=False)
    results = []
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_one(session, sub, semaphore) for sub in subdomains]
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Yoxlanılır", ncols=80, disable=QUIET):
            res = await coro
            results.append(res)
            is_live = "LIVE" in res["status"]
            if QUIET and not is_live:
                continue  # sadələşdirilmiş rejimdə OFFLINE sətirləri gizlədilir
            color = Fore.GREEN if is_live else Fore.RED
            tech_note = f" [{', '.join(res['technologies'])}]" if res["technologies"] else ""
            ver_note = ""
            if res.get("versions"):
                ver_parts = [f"{k}:{v}" for k, v in res["versions"].items()]
                ver_note = f" {{{', '.join(ver_parts)}}}"
            print(f"   {color}[{res['status']}] -> {res['subdomain']}{tech_note}{ver_note}{Style.RESET_ALL}")
    return results


# ======================================================================
# 6) IP / ASN LOOKUP — RIPEstat (pulsuz, key tələb etmir)
# ======================================================================

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def get_asn_info(ip):
    try:
        net_resp = _safe_get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=10)
        if not net_resp:
            return None
        data = net_resp.json().get("data", {})
        asns = data.get("asns", [])
        if not asns:
            return None
        asn_id = f"AS{asns[0]}"

        holder_resp = _safe_get(f"https://stat.ripe.net/data/as-overview/data.json?resource={asn_id}", timeout=10)
        holder_name = asn_id
        if holder_resp:
            holder_name = holder_resp.json().get("data", {}).get("holder", asn_id)

        return {
            "ip": ip,
            "asn": asn_id,
            "holder": holder_name,
            "az_local_provider": AZ_KNOWN_ASNS.get(asn_id, "Naməlum / Xarici hosting"),
        }
    except Exception:
        return None


def enrich_results(live_results):
    _info(f"\n{Fore.YELLOW}[*] IP/ASN, DNS CNAME, SSL sertifikat və takeover yoxlaması aparılır...{Style.RESET_ALL}")
    enriched = []
    ip_cache = {}
    extra_ssl_subdomains = set()

    for res in tqdm(live_results, desc="Zənginləşdirilir", ncols=80, disable=QUIET):
        if "LIVE" not in res["status"]:
            res.update({"ip": None, "asn_info": None, "cname": None,
                        "takeover_risk": None, "ssl_info": None, "favicon_hash": None})
            enriched.append(res)
            continue

        sub = res["subdomain"]
        ip = resolve_ip(sub)
        res["ip"] = ip

        if ip:
            if ip not in ip_cache:
                ip_cache[ip] = get_asn_info(ip)
            res["asn_info"] = ip_cache[ip]
        else:
            res["asn_info"] = None

        cname = get_cname(sub)
        res["cname"] = cname
        res["takeover_risk"] = check_takeover(sub, cname)

        ssl_info = get_ssl_cert_info(sub) if res["scheme"] == "https" else None
        res["ssl_info"] = ssl_info
        if ssl_info and ssl_info.get("san_domains"):
            extra_ssl_subdomains.update(d.lower().lstrip("*.") for d in ssl_info["san_domains"])

        res["favicon_hash"] = get_favicon_hash(res["final_url"].split("://")[0] + "://" + sub) if res.get("final_url") else None

        if res["takeover_risk"]:
            print(f"   {Fore.RED}[TƏHLÜKƏ] Mümkün subdomain takeover: {sub} -> "
                  f"{res['takeover_risk']['service']}{Style.RESET_ALL}")

        enriched.append(res)

    return enriched, extra_ssl_subdomains


# ======================================================================
# 7) EHTİMAL OLUNAN KORPORATIV E-POÇTLAR + robots.txt/security.txt tarama
# ======================================================================

def get_probable_emails(domain):
    prefixes = ["info", "admin", "support", "hr", "security", "office",
                "contact", "sales", "it", "helpdesk", "noreply"]
    return [f"{p}@{domain}" for p in prefixes]


def harvest_from_wellknown(domain):
    """robots.txt, sitemap.xml, security.txt-dən əlavə yollar/e-poçtlar."""
    findings = {"robots_paths": [], "security_txt_emails": [], "sitemap_urls_sample": []}
    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        robots = _safe_get(f"{base}/robots.txt", timeout=6)
        if robots:
            findings["robots_paths"] = [
                line.split(":", 1)[1].strip() for line in robots.text.splitlines()
                if line.lower().startswith(("disallow", "allow")) and ":" in line
            ][:30]

        sec_txt = _safe_get(f"{base}/.well-known/security.txt", timeout=6) or _safe_get(f"{base}/security.txt", timeout=6)
        if sec_txt:
            findings["security_txt_emails"] = re.findall(r"mailto:([^\s]+)", sec_txt.text)

        sitemap = _safe_get(f"{base}/sitemap.xml", timeout=6)
        if sitemap:
            findings["sitemap_urls_sample"] = re.findall(r"<loc>(.*?)</loc>", sitemap.text)[:20]

        if robots or sec_txt or sitemap:
            break
    return findings


# ======================================================================
# 8) HESABAT
# ======================================================================

def save_report(domain, source_map, live_results, emails, wellknown, dns_records, target_overview, breach_data, output_path):
    live_count = sum(1 for r in live_results if "LIVE" in r["status"])
    local_count = sum(
        1 for r in live_results
        if r.get("asn_info") and r["asn_info"]["az_local_provider"] != "Naməlum / Xarici hosting"
    )
    takeover_count = sum(1 for r in live_results if r.get("takeover_risk"))

    report = {
        "target": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_overview": target_overview,
        "dns_records": dns_records,
        "breach_search": breach_data,
        "summary": {
            "total_subdomains_found": len(source_map),
            "live_subdomains": live_count,
            "offline_subdomains": len(live_results) - live_count,
            "hosted_on_az_local_infra": local_count,
            "possible_subdomain_takeovers": takeover_count,
            "spf_present": dns_records.get("spf_present"),
            "dmarc_present": dns_records.get("dmarc_present"),
            "breached_emails_found": len(breach_data.get("results", {})),
            "js_endpoints_found": len(target_overview.get("js_analysis", {}).get("endpoints_found", [])),
            "js_possible_secrets": len(target_overview.get("js_analysis", {}).get("possible_secrets", [])),
            "archived_js_endpoints_found": len(target_overview.get("archived_js_analysis", {}).get("endpoints_found", [])),
            "github_leaks_found": len(target_overview.get("github_leaks", {}).get("results", [])),
        },
        "subdomains": [
            {
                "subdomain": r["subdomain"],
                "status": r["status"],
                "ip": r.get("ip"),
                "asn": (r.get("asn_info") or {}).get("asn"),
                "holder": (r.get("asn_info") or {}).get("holder"),
                "az_local_provider": (r.get("asn_info") or {}).get("az_local_provider"),
                "server_header": r.get("server_header"),
                "technologies": r.get("technologies", []),
                "versions": r.get("versions", {}),
                "cname": r.get("cname"),
                "takeover_risk": r.get("takeover_risk"),
                "ssl_issuer": (r.get("ssl_info") or {}).get("issuer"),
                "ssl_not_after": (r.get("ssl_info") or {}).get("not_after"),
                "favicon_hash": r.get("favicon_hash"),
            }
            for r in live_results
        ],
        "probable_emails": emails,
        "wellknown_findings": wellknown,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print(f"\n{Fore.GREEN}[+] Hesabat yadda saxlandı: {output_path}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}    Toplam alt domen: {report['summary']['total_subdomains_found']}")
    print(f"    Canlı: {report['summary']['live_subdomains']}")
    print(f"    Ofline: {report['summary']['offline_subdomains']}")
    print(f"    AZ lokal infrastrukturda: {report['summary']['hosted_on_az_local_infra']}")
    print(f"    Mümkün subdomain takeover: {report['summary']['possible_subdomain_takeovers']}")
    print(f"    SPF mövcuddur: {report['summary']['spf_present']} | "
          f"DMARC mövcuddur: {report['summary']['dmarc_present']}")
    print(f"    Sızıntıda tapılan email sayı: {report['summary']['breached_emails_found']}")
    print(f"    JS-də tapılan endpoint sayı: {report['summary']['js_endpoints_found']}")
    print(f"    JS-də mümkün açıqlanmış sirr sayı: {report['summary']['js_possible_secrets']}{Style.RESET_ALL}")


# ======================================================================
# MAIN
# ======================================================================

# ======================================================================
# 1.10) AÇIQ-MƏNBƏLİ OSINT ALƏTLƏRİNƏ ACCESS — sistemdə quraşdırılmış
#      tanınmış açıq-mənbəli recon alətlərini (theHarvester, Amass,
#      Subfinder) aşkarlayıb işə salır və nəticələrini birləşdirir.
#      Bu alətlər AzRecon-un bir hissəsi kimi YENİDƏN YAZILMIR — mövcud
#      quraşdırmaları çağırıb, əlavə əhatə dairəsi üçün nəticələrini
#      alt domen siyahısına inteqrasiya edir.
# ======================================================================

EXTERNAL_TOOL_BINARIES = {
    "theHarvester": ["theHarvester", "theharvester"],
    "amass": ["amass"],
    "subfinder": ["subfinder"],
    "assetfinder": ["assetfinder"],
    "gobuster": ["gobuster"],
    "ffuf": ["ffuf"],
}


def find_external_tool(name):
    """PATH-da alət binarının olub-olmadığını yoxlayır (heç nə quraşdırmır)."""
    for candidate in EXTERNAL_TOOL_BINARIES.get(name, [name]):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def run_theharvester(domain, timeout=120):
    binary = find_external_tool("theHarvester")
    if not binary:
        return None, "quraşdırılmayıb"
    try:
        result = subprocess.run(
            [binary, "-d", domain, "-b", "crtsh,otx,urlscan"],
            capture_output=True, text=True, timeout=timeout,
        )
        found = set(re.findall(rf"([a-zA-Z0-9_\-.]+\.{re.escape(domain)})", result.stdout))
        return found, None
    except subprocess.TimeoutExpired:
        return None, f"timeout ({timeout}s)"
    except Exception as e:
        return None, str(e)


def run_amass(domain, timeout=180):
    binary = find_external_tool("amass")
    if not binary:
        return None, "quraşdırılmayıb"
    try:
        result = subprocess.run(
            [binary, "enum", "-passive", "-d", domain, "-timeout", str(max(1, timeout // 60))],
            capture_output=True, text=True, timeout=timeout,
        )
        found = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
        return found, None
    except subprocess.TimeoutExpired:
        return None, f"timeout ({timeout}s)"
    except Exception as e:
        return None, str(e)


def run_subfinder(domain, timeout=90):
    binary = find_external_tool("subfinder")
    if not binary:
        return None, "quraşdırılmayıb"
    try:
        result = subprocess.run(
            [binary, "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=timeout,
        )
        found = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
        return found, None
    except subprocess.TimeoutExpired:
        return None, f"timeout ({timeout}s)"
    except Exception as e:
        return None, str(e)


def run_assetfinder(domain, timeout=90):
    binary = find_external_tool("assetfinder")
    if not binary:
        return None, "quraşdırılmayıb"
    try:
        result = subprocess.run(
            [binary, "--subs-only", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        found = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
        return found, None
    except subprocess.TimeoutExpired:
        return None, f"timeout ({timeout}s)"
    except Exception as e:
        return None, str(e)


def run_external_tools(domain):
    """
    Sistemdə tapılan xarici açıq-mənbəli OSINT alətlərini işə salır və
    nəticələrini {alət_adı: {subdomenlər}} formasında qaytarır. Quraşdırılmamış
    alətlər üçün xəbərdarlıq göstərilir, skript sınmır.
    """
    runners = {
        "theHarvester": run_theharvester,
        "amass": run_amass,
        "subfinder": run_subfinder,
        "assetfinder": run_assetfinder,
    }
    results = {}
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  AÇIQ-MƏNBƏLİ XARİCİ ALƏTLƏR")
    print(f"{'='*60}{Style.RESET_ALL}")
    for name, runner in runners.items():
        binary_path = find_external_tool(name)
        if not binary_path:
            print(f"  {Fore.LIGHTBLACK_EX}[atlanıldı] {name}: sistemdə tapılmadı "
                  f"(quraşdırmaq istəsəniz README-ə baxın){Style.RESET_ALL}")
            continue
        print(f"  {Fore.YELLOW}[işə salınır] {name} ({binary_path})...{Style.RESET_ALL}")
        found, error = runner(domain)
        if error:
            print(f"    {Fore.RED}xəta: {error}{Style.RESET_ALL}")
            continue
        results[name] = found or set()
        print(f"    {Fore.GREEN}{len(found or [])} nəticə{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    return results


def run_nmap_scan(domain, ip, timeout=300):
    """
    [AKTİV SKAN] nmap ilə yüngül port skanı — YALNIZ --nmap flag-ı ilə
    açıq şəkildə istənəndə işə düşür. Bu, alətin qalan hissəsindən
    fərqli olaraq PASSİV DEYİL — hədəfə birbaşa paket göndərir.
    YALNIZ icazəniz olan hədəflərdə istifadə edin.
    """
    binary = find_external_tool("nmap") or shutil.which("nmap")
    if not binary:
        print(f"{Fore.RED}[!] nmap sistemdə tapılmadı — atlanıldı.{Style.RESET_ALL}")
        return None
    print(f"\n{Fore.RED}{'='*60}")
    print(f"  [AKTİV SKAN XƏBƏRDARLIĞI] nmap {ip or domain} üzərində işə salınır")
    print(f"  Bu artıq passiv OSINT deyil — yalnız icazəli hədəflərdə istifadə edin!")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    try:
        result = subprocess.run(
            [binary, "-sV", "-T4", "--top-ports", "100", ip or domain],
            capture_output=True, text=True, timeout=timeout,
        )
        print(result.stdout)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[!] nmap timeout ({timeout}s){Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] nmap xətası: {e}{Style.RESET_ALL}")
        return None


# ======================================================================
# 1.9) CANLI SERTİFİKAT AXINI (CertStream) — real vaxtda yeni SSL
#      sertifikatlarının izlənməsi. Certificate Transparency log-larının
#      ictimai axınına (wss://certstream.calidog.io) qoşulur; hədəf
#      domenlə uyğun gələn hər yeni sertifikatı ANINDA göstərir. Bu, gündə
#      bir dəfə crt.sh sorğulamaqdan fərqli olaraq, YENİ yaranan (test/dev)
#      subdomenləri saniyələr içində tutmağa imkan verir.
# ======================================================================

def watch_certstream(domain):
    try:
        import certstream
    except ImportError:
        print(f"{Fore.RED}[!] 'certstream' kitabxanası quraşdırılmayıb.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Quraşdırın: pip install certstream --break-system-packages{Style.RESET_ALL}")
        return

    domain_lower = domain.lower()
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  CANLI SERTİFİKAT İZLƏMƏSİ: *.{domain_lower}")
    print(f"  Dayandırmaq üçün Ctrl+C basın")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    def on_message(message, context):
        try:
            if message.get("message_type") != "certificate_update":
                return
            leaf = message["data"]["leaf_cert"]
            all_domains = leaf.get("all_domains", [])
            matched = [d for d in all_domains if domain_lower in d.lower()]
            if matched:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"{Fore.GREEN}[{ts}] [YENİ SERTİFİKAT] {Fore.YELLOW}{', '.join(matched)}{Style.RESET_ALL}")
                print(f"    Issuer: {leaf.get('issuer', {}).get('O', 'N/A')}")
        except Exception:
            pass

    try:
        certstream.listen_for_events(on_message, url="wss://certstream.calidog.io")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Canlı izləmə dayandırıldı.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] CertStream bağlantı xətası: {e}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}    (Qeyd: certstream.calidog.io ictimai xidmətdir, "
              f"bəzən müvəqqəti əlçatan olmaya bilər){Style.RESET_ALL}")


def main():
    global QUIET

    parser = argparse.ArgumentParser(
        description="AzRecon v6.0 — Azərbaycan bazarına fokuslanmış passiv OSINT aləti"
    )
    parser.add_argument("domain", help="Hədəf domen (məs: unibank.az)")
    parser.add_argument("-o", "--output", default=None,
                         help="Çıxış JSON faylının adı (default: report_<domain>.json)")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="Sadələşdirilmiş çıxış: ara-mərhələ proqres mesajlarını gizlədir, "
                              "yalnız tapılan nəticələri və son xülasəni göstərir")
    parser.add_argument("--watch", action="store_true",
                         help="Adi taramadan sonra CertStream-ə qoşulub hədəflə bağlı yeni "
                              "SSL sertifikatlarını REAL VAXTDA izləməyə başlayır (Ctrl+C ilə dayandırılır)")
    parser.add_argument("--watch-only", action="store_true",
                         help="Adi taramanı KEÇ, birbaşa CertStream canlı izləmə rejiminə keç")
    parser.add_argument("--external-tools", action="store_true",
                         help="Sistemdə quraşdırılmış açıq-mənbəli OSINT alətlərini (theHarvester, "
                              "Amass -passive, Subfinder, Assetfinder) aşkarlayıb nəticələrini "
                              "alt domen siyahısına birləşdirir")
    parser.add_argument("--nmap", action="store_true",
                         help="[AKTİV SKAN] nmap quraşdırılıbsa, hədəfə qarşı yüngül port skanı işə "
                              "salır. DİQQƏT: bu artıq passiv deyil — YALNIZ icazəniz olan hədəflərdə istifadə edin")
    parser.add_argument("--bruteforce", action="store_true",
                         help="[AKTİV SKAN] gobuster ilə DNS subdomain brute-force işə salır. "
                              "--wordlist ilə birlikdə istifadə edilməlidir. YALNIZ icazəli hədəflərdə istifadə edin")
    parser.add_argument("--wordlist", default=None,
                         help="--bruteforce üçün wordlist fayl yolu (məs. SecLists-dən subdomains-top1million-5000.txt)")
    parser.add_argument("--fuzz-paths", action="store_true",
                         help="[AKTİV SKAN] ffuf ilə hədəf saytda gizli path/directory axtarışı işə salır. "
                              "--wordlist-paths (və ya --wordlist) tələb edir. YALNIZ icazəli hədəflərdə istifadə edin")
    parser.add_argument("--wordlist-paths", default=None,
                         help="--fuzz-paths üçün ayrı wordlist (verilməzsə --wordlist istifadə olunur)")
    args = parser.parse_args()

    QUIET = args.quiet
    banner()

    target_domain = args.domain.strip().lower()
    output_path = args.output or f"report_{target_domain}.json"

    if args.watch_only:
        watch_certstream(target_domain)
        return

    _info(f"{Fore.CYAN}[*] DNS qeydləri (A/AAAA/MX/NS/TXT/SPF/DMARC) yoxlanılır...{Style.RESET_ALL}")
    dns_records = get_dns_records(target_domain)

    target_overview = get_target_overview(target_domain, dns_records)

    source_map = get_all_subdomains(target_domain)

    if args.external_tools:
        external_results = run_external_tools(target_domain)
        for tool_name, found_subs in external_results.items():
            for sub in found_subs:
                sub = sub.strip().lower()
                if sub.startswith("www."):
                    sub = sub[4:]
                if sub and sub != target_domain and is_valid_subdomain(sub, target_domain):
                    source_map.setdefault(sub, [])

    subdomains = sorted(source_map.keys())

    if not subdomains:
        print(f"{Fore.RED}[-] Heç bir alt domen tapılmadı.{Style.RESET_ALL}")
        live_results = []
    else:
        print(f"\n{Fore.GREEN}[+] Ümumi unikal alt domenlər: {len(subdomains)}{Style.RESET_ALL}")
        live_results = asyncio.run(check_live_subdomains_async(subdomains))
        live_results, extra_ssl_subs = enrich_results(live_results)
        if extra_ssl_subs:
            new_ones = extra_ssl_subs - set(source_map.keys())
            new_ones = {s for s in new_ones if is_valid_subdomain(s, target_domain)}
            if new_ones:
                print(f"\n{Fore.MAGENTA}[+] SSL sertifikatından {len(new_ones)} əlavə subdomen aşkarlandı "
                      f"(canlılıq yoxlanılmadı):{Style.RESET_ALL}")
                for s in sorted(new_ones):
                    source_map.setdefault(s, [])
                    print(f"    {Fore.MAGENTA}- {s}{Style.RESET_ALL}")

    emails = get_probable_emails(target_domain)
    print(f"\n{Fore.GREEN}[+] Ehtimal olunan korporativ e-poçtlar:{Style.RESET_ALL}")
    for e in emails:
        print(f"   - {e}")

    _info(f"\n{Fore.YELLOW}[*] robots.txt / security.txt / sitemap.xml taranılır...{Style.RESET_ALL}")
    wellknown = harvest_from_wellknown(target_domain)
    if wellknown["security_txt_emails"]:
        print(f"    {Fore.GREEN}security.txt e-poçtları: {', '.join(wellknown['security_txt_emails'])}{Style.RESET_ALL}")

    all_emails_to_check = list(dict.fromkeys(emails + wellknown["security_txt_emails"]))
    if CONFIG["HIBP_API_KEY"]:
        _info(f"\n{Fore.YELLOW}[*] Sızıntı (data breach) axtarışı aparılır (HIBP)...{Style.RESET_ALL}")
    breach_data = check_domain_breaches(all_emails_to_check)
    if breach_data["enabled"]:
        if breach_data["results"]:
            for email, breaches in breach_data["results"].items():
                names = ", ".join(b["name"] for b in breaches)
                print(f"   {Fore.RED}[SIZINTI] {email} -> {names}{Style.RESET_ALL}")
        else:
            print(f"   {Fore.GREEN}Heç bir email məlum sızıntılarda tapılmadı.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.LIGHTBLACK_EX}[*] Sızıntı axtarışı üçün HIBP_API_KEY verilməyib — bu bölmə atlanıldı "
              f"(config.ini və ya environment variable ilə əlavə edə bilərsiniz).{Style.RESET_ALL}")

    save_report(target_domain, source_map, live_results, emails, wellknown, dns_records,
                target_overview, breach_data, output_path)

    if args.bruteforce:
        wordlist = args.wordlist
        if not wordlist:
            print(f"{Fore.RED}[!] --bruteforce üçün --wordlist tələb olunur. "
                  f"Məs: --bruteforce --wordlist /path/to/subdomains.txt{Style.RESET_ALL}")
        else:
            brute_found = run_gobuster_dns(target_domain, wordlist)
            new_ones = {s for s in brute_found if is_valid_subdomain(s, target_domain) and s != target_domain}
            for s in new_ones:
                source_map.setdefault(s, [])
            if new_ones:
                print(f"{Fore.MAGENTA}[+] Brute-force ilə tapılan yeni subdomenlər hesabata əlavə olundu "
                      f"({len(new_ones)} ədəd) — yenidən JSON-a yazılır...{Style.RESET_ALL}")
                save_report(target_domain, source_map, live_results, emails, wellknown, dns_records,
                            target_overview, breach_data, output_path)

    if args.fuzz_paths:
        wordlist_paths = args.wordlist_paths or args.wordlist
        if not wordlist_paths:
            print(f"{Fore.RED}[!] --fuzz-paths üçün --wordlist-paths (və ya --wordlist) tələb olunur.{Style.RESET_ALL}")
        else:
            discovered_paths = run_ffuf_content_discovery(f"https://{target_domain}", wordlist_paths)
            if discovered_paths:
                print(f"\n{Fore.MAGENTA}[+] ffuf ilə tapılan path-lər:{Style.RESET_ALL}")
                for p in discovered_paths[:30]:
                    print(f"    {p}")

    if args.nmap:
        run_nmap_scan(target_domain, target_overview.get("ip"))

    if args.watch:
        watch_certstream(target_domain)


if __name__ == "__main__":
    main()
