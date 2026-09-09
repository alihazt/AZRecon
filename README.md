# AzRecon v6.0

Azərbaycan bazarına fokuslanmış, passiv (yalnız ictimai mənbələrdən istifadə
edən) subdomain enumeration və OSINT recon aləti.

⚠️ **Yalnız icazəli (authorized) hədəflər üzərində istifadə edin** — öz
domeninizdə və ya rəsmi icazəniz (scope) olan pentest/bug-bounty
çərçivəsində. Skript heç bir aktiv exploit, brute-force və ya icazəsiz
giriş cəhdi etmir — yalnız açıq/ictimai mənbələrdən məlumat toplayır.

## Quraşdırma

```bash
git clone https://github.com/alihazt/AZRecon
cd AZRecon
pip install -r requirements.txt --break-system-packages
```

Virtual environment ilə (tövsiyə olunur):

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## İstifadə

```bash
python3 azrecon.py hedef-domen.az
python3 azrecon.py hedef-domen.az -o report.json
```

## Opsional API key-lər

Bəzi mənbələr (Shodan, SecurityTrails, FullHunt) key tələb edir. Key
olmadan da skript tam işləyir — sadəcə bu mənbələr atlanılır.

```bash
cp config.ini.example config.ini
# config.ini faylını açıb key-ləri əlavə edin
```

və ya environment variable ilə:

```bash
export SHODAN_API_KEY="sizin-key"
python3 azrecon.py hedef-domen.az
```

## Nə edir

- **13 passiv OSINT mənbəyi**: crt.sh, HackerTarget, Wayback Machine,
  AlienVault OTX, RapidDNS, Anubis-DB, ThreatMiner, CertSpotter,
  BufferOver, urlscan.io + opsional Shodan/SecurityTrails/FullHunt
- **Async canlılıq yoxlaması** — paralel HTTP/HTTPS sorğuları
- **Texnologiya fingerprinting** — WordPress, 1C-Bitrix, ASAN Login/e-Gov,
  Joomla, Drupal, Laravel, Nginx/Apache/IIS, Cloudflare və s.
- **Versiya aşkarlama (banner grabbing)** — Nginx/Apache/IIS/PHP/OpenSSL
  versiyaları, WordPress/Joomla/Drupal/Bitrix versiyaları, jQuery/Bootstrap/
  React versiyaları, meta-generator etiketləri, TLS protokol versiyası +
  cipher suite, hətta DNS server versiyası (CHAOS `version.bind` sorğusu)
- **DNS dərinləşdirmə** — A/AAAA/MX/NS/TXT qeydləri, SPF/DMARC yoxlaması
- **AZ ASN/provayder aşkarlanması** — RIPEstat vasitəsilə (Delta Telecom,
  Baktelecom, Aztelekom, Bakcell və s.)
- **SSL sertifikat analizi** — SAN-lardan əlavə subdomain çıxarışı
- **Subdomain takeover yoxlaması** — dangling CNAME fingerprint aşkarlanması
- **Favicon hash** (mmh3) — Shodan-stil `http.favicon.hash` pivot texnikası
- **robots.txt / security.txt / sitemap.xml** taraması
- **Sızıntı (data breach) axtarışı** — Have I Been Pwned (opsional key).
  Yalnız "bu email hansı sızıntılarda görünüb" məlumatını verir, real
  parolları HEÇ VAXT qaytarmır
- **JavaScript endpoint analizi** — səhifədəki JS fayllarından gizli
  API path-lərini çıxarır, mümkün açıqlanmış API açar/token-ləri aşkarlayır
  (tapılan dəyərlər hesabatda maskalanır, məs. `AKIA****MNOP`)
- **Yerli .AZ WHOIS məntiqi** — WhoisFreaks API (opsional) → RDAP →
  IANA referral xam WHOIS protokolu → whois.az:43 birbaşa protokol
  sorğusu → (hamısı boş qalarsa) manual keçid linki (CAPTCHA-nı bypass
  etmədən) + .az ikinci səviyyə domenin növünün (gov/edu/com/org və s.)
  təsnifatı
- **GitHub Code Search sızıntı axtarışı** — public repolarda hədəf domenlə
  birlikdə password/api_key/secret/token sözlərinin keçdiyi faylları
  tapır (GITHUB_TOKEN tələb edir, pulsuz)
- **CertStream canlı sertifikat izləməsi** (`--watch` / `--watch-only`) —
  Certificate Transparency log-larının real-vaxt axınına qoşulub hədəflə
  bağlı YENİ yaranan SSL sertifikatlarını saniyələr içində göstərir
- **Alternativ axtarış mühərrikləri** — Censys, FOFA, ZoomEye (hər biri
  opsional, öz açarınızla) — Shodan-ın görmədiyi infrastrukturu tapmaq üçün
- **Dərin arxiv JS analizi** — Wayback Machine-dən arxivlənmiş (silinmiş/
  unudulmuş) JS fayllarını çəkib köhnə/unudulmuş API endpoint-lərini tapır

## CertStream canlı izləmə

```bash
python3 azrecon.py hedef-domen.az --watch        # adi tarama + sonra canlı izləmə
python3 azrecon.py hedef-domen.az --watch-only   # birbaşa canlı izləmə (tarama yox)
```

Ctrl+C ilə dayandırılır. `certstream.calidog.io` ictimai xidmətdir, uptime-i
zəmanətli deyil.
- Strukturlaşdırılmış JSON hesabat

## Sadələşdirilmiş çıxış (Quiet rejim)

```bash
python3 azrecon.py hedef-domen.az -q
```

Ara-mərhələ "[*] ... aparılır" proqres mesajlarını və OFFLINE sətirlərini
gizlədir — yalnız tapılan canlı subdomenlər, sızıntılar, endpoint-lər və
son xülasə göstərilir.

## Açıq-mənbəli xarici OSINT alətlərinə giriş

```bash
python3 azrecon.py hedef-domen.az --external-tools
```

Sistemdə əvvəlcədən quraşdırılmış aşağıdakı tanınmış açıq-mənbəli
alətləri avtomatik aşkarlayır və işə salır (quraşdırılmayıbsa sadəcə
atlanılır, xəta vermir):

- **theHarvester** — `pip install theHarvester`
- **Amass** (OWASP, passiv rejimdə: `-passive`) — https://github.com/owasp-amass/amass
- **Subfinder** (ProjectDiscovery) — https://github.com/projectdiscovery/subfinder
- **Assetfinder** — https://github.com/tomnomnom/assetfinder

Tapılan bütün nəticələr avtomatik alt domen siyahısına birləşdirilir.

## Aktiv skan (opsional, ehtiyatla istifadə edin)

```bash
python3 azrecon.py hedef-domen.az --nmap
python3 azrecon.py hedef-domen.az --bruteforce --wordlist /path/to/subdomains.txt
python3 azrecon.py hedef-domen.az --fuzz-paths --wordlist-paths /path/to/dirlist.txt
```

Bunların hər biri **alətin qalan hissəsindən fərqli olaraq artıq passiv
deyil** — hədəfə birbaşa çoxlu şəbəkə sorğusu/paket göndərir. Yalnız
icazəniz olan (authorized) hədəflərdə istifadə edin.

- `--nmap` — `nmap` quraşdırılıbsa hədəfin əsas IP-sinə qarşı yüngül
  port skanı işə salır.
- `--bruteforce` — `gobuster` (https://github.com/OJ/gobuster)
  quraşdırılıbsa DNS subdomain brute-force aparır. Öz wordlist faylınızı
  göstərməlisiniz (məs. [SecLists](https://github.com/danielmiessler/SecLists)-
  dən `Discovery/DNS/subdomains-top1million-5000.txt`) — heç bir wordlist
  alətin daxilində bundle edilməyib.
- `--fuzz-paths` — `ffuf` (https://github.com/ffuf/ffuf) quraşdırılıbsa
  hədəf saytda gizli path/directory axtarışı aparır. Eyni şəkildə öz
  wordlist-inizi verməlisiniz.

## Lisenziya / Məsuliyyət

Bu alət yalnız təhsil və icazəli təhlükəsizlik testi məqsədləri üçündür.
İcazəsiz istifadə hüquqi məsuliyyət yarada bilər.
