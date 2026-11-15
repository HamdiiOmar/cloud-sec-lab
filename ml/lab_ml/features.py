"""Turn one Suricata `http` event into a numeric feature vector.

Shared by training and the scoring service, so both always compute features the same way.

Deliberately NOT used as features: the response status and size. A 403 means the WAF already blocked
the request; training on it would teach the model to copy the WAF, while the point of this layer is to
catch what the WAF misses.
"""
import math
import re
from collections import Counter
from urllib.parse import unquote_plus, urlsplit

FEATURE_VERSION = 2   # v2: encoded-character features ignore encoded spaces (normal multi-word searches)

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
SPECIAL = {
    "quote": "'", "dquote": '"', "lt": "<", "gt": ">", "lparen": "(", "rparen": ")", "semicolon": ";",
    "pipe": "|", "backtick": "`", "dollar": "$", "lbrace": "{", "rbrace": "}", "star": "*", "bang": "!",
}
KEYWORDS = {
    "sql": r"\b(select|union|insert|update|delete|drop|sleep|benchmark|waitfor|information_schema|"
           r"or\s+\d+\s*=\s*\d+|and\s+\d+\s*=\s*\d+|order\s+by|group_concat|load_file|xp_cmdshell)\b|--|/\*",
    "xss": r"<\s*script|javascript:|on(error|load|mouseover|focus|click)\s*=|<\s*(img|svg|iframe|body|object)|"
           r"alert\s*\(|document\.(cookie|location)|eval\s*\(",
    "traversal": r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|/proc/self",
    "cmd": r"(;|\||&&|`|\$\()\s*(cat|id|ls|whoami|uname|wget|curl|nc|bash|sh|ping|python|perl)\b",
    "probe": r"\.(php|asp|aspx|jsp|cgi|pl|bak|old|orig|swp|env|ini|conf|sql|zip|tar|gz)(\?|$)|/\.(git|svn|env|htaccess)|"
             r"/(wp-|admin|phpmyadmin|cgi-bin|actuator|server-status|console|manager/html)",
}
KEYWORD_RE = {k: re.compile(v, re.I) for k, v in KEYWORDS.items()}
ENC_SPECIAL = re.compile(r"%(?!20)[0-9a-fA-F]{2}")
TOOL_RE = re.compile(r"sqlmap|nikto|hydra|nmap|masscan|gobuster|dirbuster|wfuzz|ffuf|nuclei|zgrab|curl/|python-requests|go-http-client|wget/", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def extract(http: dict) -> dict:
    """http = the `http` object of a Suricata eve.json event."""
    raw = http.get("url") or ""
    parts = urlsplit(raw)
    path, query = parts.path, parts.query
    dec = unquote_plus(unquote_plus(raw))          # double-decode: attackers double-encode
    ua = http.get("http_user_agent") or ""
    method = (http.get("http_method") or "").upper()

    f = {
        "url_len": len(raw),
        "path_len": len(path),
        "query_len": len(query),
        "path_depth": path.count("/"),
        "n_params": len([p for p in query.split("&") if p]) if query else 0,
        # Encoded characters, except spaces: "%20"/"+" is ordinary multi-word search input (v1 counted it and
        # flagged searches like "apple pomace"); encoded quotes, brackets, slashes, "%25" are what attackers send.
        "pct_encoded": len(ENC_SPECIAL.findall(raw)),
        "pct_ratio": len(ENC_SPECIAL.findall(raw)) / max(len(raw), 1),
        "digit_ratio": sum(c.isdigit() for c in dec) / max(len(dec), 1),
        "upper_ratio": sum(c.isupper() for c in dec) / max(len(dec), 1),
        "nonalnum_ratio": sum(not c.isalnum() and c not in "/?&=._- " for c in dec) / max(len(dec), 1),
        "query_entropy": entropy(unquote_plus(query)),
        "max_param_len": max((len(p) for p in query.split("&")), default=0) if query else 0,
        "dotdot": dec.count(".."),
        "dash_dash": dec.count("--"),
        "spaces": int(unquote_plus(query).count(" ") > 3),   # a few words = search; many = injected statement
        "has_body_type_json": int("json" in (http.get("http_content_type") or "")),
        "ua_len": len(ua),
        "ua_browser": int(ua.startswith("Mozilla/")),
        "ua_tool": int(bool(TOOL_RE.search(ua))),
        "ua_empty": int(not ua),
    }
    for name, ch in SPECIAL.items():
        f[f"c_{name}"] = dec.count(ch)
    for name, rx in KEYWORD_RE.items():
        f[f"kw_{name}"] = len(rx.findall(dec))
    for m in METHODS:
        f[f"m_{m}"] = int(method == m)
    f["m_other"] = int(method not in METHODS)
    return f


FEATURE_NAMES = list(extract({"url": "/", "http_method": "GET"}).keys())


def vector(http: dict) -> list:
    f = extract(http)
    return [f[n] for n in FEATURE_NAMES]
