"""ramen_cve.constants — immutable config, regexes, and lookup tables.

Layer-0 leaf: zero first-party dependencies. Path(__file__).resolve()
.parent stays at src/ramen_cve/, so DEFAULT_DATA_DIR / DEFAULT_CONFIG_DIR
resolve byte-identically to the pre-split monolith. See
docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)

# Non-CVE IOC regexes. These are intentionally simple — high-precision matches on
# defanged-aware text rather than perfect RFC compliance. extract_iocs() defangs
# the input (hxxp → http, [.] → ., etc.) before running these.
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
URL_REGEX = re.compile(r"https?://[^\s<>\"'`)\],]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
MD5_REGEX = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1_REGEX = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA256_REGEX = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)

# Defang substitutions. Applied in order; each is a literal needle/replacement
# pair so an attacker can't inject regex metacharacters via a feed item.
_DEFANG_MAP: list[tuple[str, str]] = [
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("[://]", "://"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[@]", "@"),
    ("(@)", "@"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[:]", ":"),
]
_DEFANG_DETECT = re.compile(
    r"hxxps?://|\[\.\]|\(\.\)|\[dot\]|\(dot\)|\[at\]|\(at\)|\[:\]",
    re.IGNORECASE,
)

# Suffixes that DOMAIN_REGEX would happily match but which are almost never
# real domain names in CTI feeds. Skipping these stops `report.pdf` and
# `payload.exe` from being emitted as IOCs.
_FILE_EXT_TLDS: frozenset[str] = frozenset(
    {
        "exe", "dll", "bin", "iso", "img", "tar", "gz", "bz2", "xz", "7z", "rar",
        "zip", "txt", "md", "pdf", "doc", "docx", "rtf", "odt", "ods", "ppt",
        "pptx", "xls", "xlsx", "py", "js", "ts", "jsx", "tsx", "html", "htm",
        "css", "json", "yaml", "yml", "xml", "sh", "bat", "ps1", "cmd", "go",
        "rs", "rb", "php", "java", "class", "jar", "war", "log", "csv", "tsv",
        "ini", "cfg", "conf", "lnk", "msi", "vbs", "vbe", "wsh", "ipynb",
    }
)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# Exploit / PoC tracking endpoints. All are free; only the GitHub search benefits
# from an authenticated token (rate-limit jumps from 10 → 30 req/min).
EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
NUCLEI_TEMPLATES_TREE_URL = (
    "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
)
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

# Display order for the per-CVE "Exploit Status" line — most authoritative first.
EXPLOIT_STATUS_VALUES = (
    "metasploit",        # Metasploit module (not yet auto-detected; reserved)
    "exploit_db",        # Exploit-DB entry exists for this CVE
    "nuclei_template",   # Nuclei community template exists for this CVE
    "github_poc",        # GitHub repo name/description references the CVE
    "none",              # No public exploit signal we recognize
)

DEFAULT_CVSS_THRESHOLD = 7.0
DEFAULT_EPSS_THRESHOLD = 0.10
DEFAULT_CACHE_PATH = ".ramen-cache.db"
DEFAULT_CACHE_TTL_HOURS = 24

USER_AGENT = "ramen-cve/0.1 (+https://github.com/cesiumskater)"

# Bundled lookup data ships under data/ next to ramen_cve.py so the repo's
# top level stays tidy. Override any of these with the corresponding CLI flag
# (--associations-file / --hunt-dir / --pir-dir) when running against a
# different deployment.
DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_ASSOCIATIONS_PATH = DEFAULT_DATA_DIR / "associations.json"
DEFAULT_HUNT_DIR = DEFAULT_DATA_DIR / "hunts"
DEFAULT_PIR_DIR = DEFAULT_DATA_DIR / "pirs"

# YAML configuration presets ship alongside the package. The documented
# template at src/ramen_cve/config/config.yaml records every key the tool
# recognizes; named presets land in src/ramen_cve/config/presets/<name>.yaml.
DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent / "config"
DEFAULT_CONFIG_TEMPLATE = DEFAULT_CONFIG_DIR / "config.yaml"
DEFAULT_PRESETS_DIR = DEFAULT_CONFIG_DIR / "presets"
# Tiny state file that "remembers" the last OPML source so a subsequent
# `opml` run with no path argument can reuse it. Separate from presets so
# it isn't accidentally shared/committed alongside a named configuration.
DEFAULT_LAST_OPML_PATH = DEFAULT_CONFIG_DIR / "last_opml.json"

HUNT_STATUSES = (
    "open",
    "in_progress",
    "closed_true_positive",
    "closed_false_positive",
    "closed_inconclusive",
)

# PIR (Priority Intelligence Requirement) lifecycle states. Mirrors how a
# leadership-tracked question moves from "we want answers" to "shelved" via
# the analyst team.
PIR_STATUSES = (
    "active",
    "monitoring",
    "satisfied",
    "retired",
)

# TLP (Traffic Light Protocol) levels in ascending order of restrictiveness.
# CLEAR is the public-share default; RED is "internal eyes only".
TLP_LEVELS = ("CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED")

# NATO Admiralty Code grades (e.g. "B2"). First letter A-F is source reliability;
# digit 1-6 is information credibility. Lower letter+digit = more reliable.

# Curated CWE → MITRE ATT&CK technique-ID mapping. Each CWE may map to one or
# more techniques. This is intrinsically lossy: a CWE describes a *type* of
# weakness and a technique describes an adversary action — the mapping captures
# the techniques an adversary is most likely to use *given* the CWE, not a
# guaranteed observation. References:
#   https://attack.mitre.org/techniques/enterprise/
#   https://github.com/center-for-threat-informed-defense/attack_to_cve
CWE_TO_ATTACK: dict[str, list[str]] = {
    "CWE-22": ["T1083"],                      # Path Traversal → File and Directory Discovery
    "CWE-77": ["T1059"],                      # Command Injection → Cmd & Scripting Interpreter
    "CWE-78": ["T1059"],                      # OS Command Injection
    "CWE-79": ["T1059.007"],                  # XSS → JavaScript
    "CWE-89": ["T1190"],                      # SQL Injection → Exploit Public-Facing App
    "CWE-94": ["T1059", "T1203"],             # Code Injection
    "CWE-119": ["T1190", "T1203"],            # Buffer Overread/Overwrite
    "CWE-120": ["T1190", "T1203"],            # Classic Buffer Overflow
    "CWE-121": ["T1190", "T1203"],            # Stack-based Buffer Overflow
    "CWE-122": ["T1190", "T1203"],            # Heap-based Buffer Overflow
    "CWE-125": ["T1212"],                     # Out-of-bounds Read
    "CWE-200": ["T1083"],                     # Information Disclosure
    "CWE-269": ["T1068"],                     # Improper Privilege Mgmt → PrivEsc
    "CWE-276": ["T1222"],                     # Incorrect Default Permissions
    "CWE-287": ["T1190", "T1078"],            # Improper Authentication
    "CWE-295": ["T1557"],                     # Improper Cert Validation → AiTM
    "CWE-306": ["T1190"],                     # Missing Authentication
    "CWE-319": ["T1040", "T1557"],            # Cleartext Transmission
    "CWE-352": ["T1190"],                     # CSRF
    "CWE-400": ["T1499"],                     # Resource Exhaustion → Endpoint DoS
    "CWE-416": ["T1203", "T1068"],            # Use After Free
    "CWE-426": ["T1574.001"],                 # Untrusted Search Path → DLL Hijack
    "CWE-434": ["T1190"],                     # Unrestricted File Upload
    "CWE-502": ["T1190", "T1059"],            # Deserialization of Untrusted Data
    "CWE-521": ["T1110"],                     # Weak Password Requirements → Brute Force
    "CWE-522": ["T1552"],                     # Insufficiently Protected Credentials
    "CWE-552": ["T1083", "T1213"],            # Files Accessible to External Parties
    "CWE-601": ["T1566.002"],                 # Open Redirect → Spearphishing Link
    "CWE-611": ["T1190", "T1083"],            # XXE
    "CWE-732": ["T1222"],                     # Incorrect Permission Assignment
    "CWE-787": ["T1190", "T1203"],            # Out-of-bounds Write
    "CWE-798": ["T1078"],                     # Hardcoded Credentials → Valid Accounts
    "CWE-863": ["T1190"],                     # Incorrect Authorization
    "CWE-918": ["T1090", "T1190"],            # SSRF → Proxy + Exploit Public-Facing App
    "CWE-1021": ["T1185"],                    # UI Restriction Bypass → Browser Hijack
    "CWE-1188": ["T1078"],                    # Insecure Default Initialization → Valid Accounts
}

# Technique-ID → human-readable name lookup, used in Markdown cross-tab output.
ATTACK_TECHNIQUE_NAMES: dict[str, str] = {
    "T1040": "Network Sniffing",
    "T1059": "Command and Scripting Interpreter",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1068": "Exploitation for Privilege Escalation",
    "T1078": "Valid Accounts",
    "T1083": "File and Directory Discovery",
    "T1090": "Proxy",
    "T1110": "Brute Force",
    "T1185": "Browser Session Hijacking",
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Exploitation for Client Execution",
    "T1212": "Exploitation for Credential Access",
    "T1213": "Data from Information Repositories",
    "T1222": "File and Directory Permissions Modification",
    "T1499": "Endpoint Denial of Service",
    "T1552": "Unsecured Credentials",
    "T1557": "Adversary-in-the-Middle",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1574.001": "Hijack Execution Flow: DLL Search Order Hijacking",
}


BUCKET_ACTIONS: dict[str, str] = {
    "kev_override": ("Patch immediately — CISA KEV listed; exploitation confirmed in the wild."),
    "patch_now": "Patch now — high CVSS and high EPSS; likely exploitable and high impact.",
    "plan_and_patch": (
        "Plan and patch — high CVSS but low EPSS; exploit unlikely but impact severe."
    ),
    "watch_closely": (
        "Watch closely — low CVSS but high EPSS; active exploitation of a lower-impact flaw."
    ),
    "deprioritize": "Deprioritize — low severity and low exploitation probability.",
    "unknown": "Insufficient data; manual review required.",
}
