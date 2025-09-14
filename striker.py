#!/usr/bin/env python3
import sys
if sys.platform.startswith("win"):
    import asyncio as _asyncio_mod
    _asyncio_mod.set_event_loop_policy(_asyncio_mod.WindowsSelectorEventLoopPolicy())

import argparse, asyncio, aiohttp, ssl, socket, json, os, re, time, pathlib
import pyfiglet
from colorama import Fore, Style, init
from aiohttp import ClientTimeout, TCPConnector
import certifi
from datetime import datetime, timezone

init(autoreset=True)

COMMON_PATHS = ["/", "/admin/", "/administrator/", "/login", "/wp-admin/", "/wp-login.php",
                "/xmlrpc.php", "/.env", "/config.php", "/composer.json", "/.git/", "/.git/config",
                "/backup.zip", "/backup.tar.gz", "/.htpasswd", "/server-status", "/phpinfo.php",
                "/sitemap.xml", "/robots.txt"]
SECURITY_HEADERS = ["content-security-policy", "strict-transport-security", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy",
                    "expect-ct", "x-xss-protection"]
USER_AGENT = "Striker/2.0 (by panda_big_money)"
DIR_WORDLIST = ["admin","administrator","login","wp-admin","backup.zip","backup.tar.gz","config.php",".env","phpinfo.php",".git","uploads","old","test","staging","dev","portal","server-status"]
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- "]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "%3Cscript%3Ealert(1)%3C/script%3E"]
OPENREDIRECT_PARAMS = ["redirect","url","next","return","r","continue","redir"]
COMMON_SUBDOMAINS = ["www","dev","staging","test","mail","webmail","api","admin","portal","shop","beta"]

def banner():
    print(Fore.CYAN + pyfiglet.figlet_format("Striker", font="slant") + Style.RESET_ALL)
    print(Fore.MAGENTA + "Made by: panda_big_money" + Style.RESET_ALL)
    print(Fore.WHITE + "Interactive scanner • safe-by-default • advanced passive checks\n" + Style.RESET_ALL)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def normalize_url(t):
    t = t.strip()
    if not t:
        return ""
    if t.startswith("http://") or t.startswith("https://"):
        return t.rstrip("/")
    return ("https://" + t).rstrip("/")

def looks_like_dir_listing(text):
    snippet = (text or "")[:4000]
    patterns = [r"Index of /", r"Directory listing for", r"<title>Index of", r"Parent Directory"]
    for p in patterns:
        if re.search(p, snippet, re.IGNORECASE):
            return True
    links = re.findall(r"<a\s+href=", snippet, re.IGNORECASE)
    return len(links) > 20

def cms_hints(text, headers):
    hints = []
    m = re.search(r'<meta name=["\']generator["\'] content=["\']([^"\']+)["\']', text or "", re.I)
    if m: hints.append(f"generator:{m.group(1)}")
    if "wp-content" in (text or "") or "/wp-admin" in (text or ""): hints.append("wordpress")
    if "Joomla!" in (text or "") or "content=\"Joomla" in (text or ""): hints.append("joomla")
    if "drupal" in (text or "").lower(): hints.append("drupal")
    server = headers.get("server") or headers.get("x-powered-by") or ""
    if server: hints.append(f"server:{server}")
    return hints

def get_cert_info_sync(hostname: str, port: int = 443, timeout: float = 5.0):
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {"ok": True, "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                        "issuer": cert.get("issuer"), "subject": cert.get("subject")}
    except Exception as e:
        return {"ok": False, "error": str(e)}

async def spinner_task(evt: asyncio.Event, label: str):
    chars = "⣾⣽⣻⢿⡿⣟⣯⣷"
    i = 0
    while not evt.is_set():
        print(Fore.BLUE + f"\r{chars[i%len(chars)]} {label}" + Style.RESET_ALL, end="", flush=True)
        i += 1
        await asyncio.sleep(0.08)
    print("\r" + " " * (len(label) + 6) + "\r", end="", flush=True)

async def fetch(session, method, url, timeout, allow_redirects=True, debug=False, params=None):
    try:
        if method == "head":
            async with session.head(url, timeout=ClientTimeout(total=timeout)) as r:
                return {"status": r.status, "headers": {k.lower(): v for k, v in r.headers.items()}}
        async with session.get(url, allow_redirects=allow_redirects, timeout=ClientTimeout(total=timeout), params=params) as r:
            text = await r.text(errors="ignore")
            headers = {k.lower(): v for k, v in r.headers.items()}
            return {"status": r.status, "url": str(r.url), "headers": headers, "text": text}
    except Exception as e:
        if debug:
            print(Fore.MAGENTA + f"[debug] {method.upper()} {url} failed: {e}" + Style.RESET_ALL)
        return {"error": str(e)}

async def fetch_root(session, url, timeout, debug=False):
    return await fetch(session, "get", url, timeout, True, debug)

async def head_or_get(session, url, timeout, debug=False):
    h = await fetch(session, "head", url, timeout, True, debug)
    if isinstance(h, dict) and h.get("status") and h["status"] == 200:
        return h
    g = await fetch(session, "get", url, timeout, True, debug)
    return g

def extract_params_from_url(u):
    parts = u.split("?",1)
    if len(parts) == 1: return {}
    qs = parts[1]
    pairs = {}
    for kv in qs.split("&"):
        if "=" in kv:
            k,v = kv.split("=",1)
            pairs[k] = v
    return pairs

async def check_sqli(session, base_url, timeout, debug=False):
    findings = []
    parsed = base_url.split("?",1)
    if len(parsed) == 1:
        return findings
    base, qs = parsed[0], parsed[1]
    params = extract_params_from_url(base_url)
    for p in params:
        for payload in SQLI_PAYLOADS:
            test_params = dict(params)
            test_params[p] = params[p] + payload
            res = await fetch(session, "get", base, timeout, True, debug, params=test_params)
            if isinstance(res, dict) and res.get("text"):
                text = res["text"].lower()
                errors = ["mysql", "syntax error", "sqlstate", "unterminated", "warning: mysql"]
                baseline = (await fetch(session,"get", base, timeout, True, debug)).get("text","")
                if any(e in text for e in errors) or (res.get("status") and res["status"] < 500 and len(text) != 0 and len(text) != len(baseline)):
                    findings.append({"param": p, "payload": payload, "url": res.get("url")})
                    if debug: print(Fore.MAGENTA + f"[debug] SQLi candidate param={p} payload={payload}" + Style.RESET_ALL)
                    break
    return findings

async def check_xss(session, base_url, timeout, debug=False):
    findings = []
    params = extract_params_from_url(base_url)
    if not params:
        return findings
    for p in params:
        for payload in XSS_PAYLOADS:
            test_params = dict(params)
            test_params[p] = payload
            res = await fetch(session, "get", base_url.split("?",1)[0], timeout, True, debug, params=test_params)
            if isinstance(res, dict) and res.get("text"):
                if payload in res["text"]:
                    findings.append({"param": p, "payload": payload, "url": res.get("url")})
                    if debug: print(Fore.MAGENTA + f"[debug] XSS reflected param={p}" + Style.RESET_ALL)
                    break
    return findings

async def check_open_redirect(session, url, timeout, debug=False):
    findings = []
    base = url.split("?",1)[0]
    params = extract_params_from_url(url)
    for p in params:
        for op in OPENREDIRECT_PARAMS:
            test = dict(params)
            test[op] = "http://example.com/"
            res = await fetch(session, "get", base, timeout, True, debug, params=test)
            loc = None
            if isinstance(res, dict) and res.get("url"):
                loc = res["url"]
            if isinstance(res, dict) and res.get("headers") and res["headers"].get("location"):
                loc = res["headers"].get("location")
            if loc and "example.com" in str(loc):
                findings.append({"param": op, "url": res.get("url", base)})
                if debug: print(Fore.MAGENTA + f"[debug] Open redirect param={op}" + Style.RESET_ALL)
                break
    return findings

async def brute_paths(session, base_url, paths, timeout, concurrency=10, debug=False):
    found = []
    sem = asyncio.Semaphore(concurrency)
    async def worker(p):
        async with sem:
            url = base_url.rstrip("/") + p
            res = await head_or_get(session, url, timeout, debug)
            if isinstance(res, dict) and res.get("status") == 200:
                found.append({"path": p, "url": url})
    tasks = [worker(p) for p in paths]
    await asyncio.gather(*tasks)
    return found

async def subdomain_check(host, subdomains, timeout, debug=False):
    valid = []
    loop = asyncio.get_event_loop()
    for sd in subdomains:
        fq = f"{sd}.{host}"
        try:
            await loop.run_in_executor(None, socket.gethostbyname, fq)
            valid.append(fq)
            if debug: print(Fore.MAGENTA + f"[debug] Subdomain resolved: {fq}" + Style.RESET_ALL)
        except Exception:
            pass
    return valid

async def check_target(session, target, timeout, paths, debug=False, spinner_event=None, extra_checks=None):
    url = normalize_url(target)
    result = {"target": target, "url": url, "scanned_at": now_iso(), "root": {}, "tls": {}, "paths": [], "cms_hints": [], "dir_listing": [], "sqli": [], "xss": [], "openredirect": [], "found_subdomains": [], "bruteforce_paths": []}
    if spinner_event: spinner_event.clear()
    root = await fetch_root(session, url, timeout, debug=debug)
    result["root"] = root
    headers = root.get("headers", {}) if isinstance(root, dict) else {}
    if isinstance(root, dict) and "text" in root:
        text = root["text"]
        result["cms_hints"] = cms_hints(text, headers)
        if looks_like_dir_listing(text):
            result["dir_listing"].append(url)
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    result["security_headers_missing"] = missing
    hostname = url.split("://",1)[1].split("/")[0].split(":")[0]
    loop = asyncio.get_event_loop()
    cert = await loop.run_in_executor(None, lambda: get_cert_info_sync(hostname, 443, timeout))
    result["tls"] = cert
    robots = await fetch_root(session, url + "/robots.txt", timeout, debug=debug)
    if robots.get("status") == 200:
        result["robots"] = robots.get("text","")[:2000]
    sitemap = await fetch_root(session, url + "/sitemap.xml", timeout, debug=debug)
    if sitemap.get("status") == 200:
        result["sitemap"] = sitemap.get("text","")[:2000]
    for p in paths:
        full = url.rstrip("/") + p
        res = await head_or_get(session, full, timeout, debug=debug)
        if isinstance(res, dict) and res.get("status") == 200:
            snippet = res.get("text","")[:800] if "text" in res else None
            result["paths"].append({"path": p, "status": 200, "snippet": snippet})
            if looks_like_dir_listing(res.get("text","")):
                result["dir_listing"].append(full)
    if extra_checks and extra_checks.get("sqli"):
        sqli = await check_sqli(session, url, timeout, debug)
        result["sqli"] = sqli
    if extra_checks and extra_checks.get("xss"):
        xss = await check_xss(session, url, timeout, debug)
        result["xss"] = xss
    if extra_checks and extra_checks.get("openredirect"):
        orr = await check_open_redirect(session, url, timeout, debug)
        result["openredirect"] = orr
    if extra_checks and extra_checks.get("subdomains"):
        host = hostname
        subs = await subdomain_check(host, COMMON_SUBDOMAINS, timeout, debug)
        result["found_subdomains"] = subs
    if extra_checks and extra_checks.get("dirbrute"):
        bf = await brute_paths(session, url, DIR_WORDLIST, timeout, concurrency=5, debug=debug)
        result["bruteforce_paths"] = bf
        result["paths"].extend([{"path": b["path"], "status":200, "snippet": None} for b in bf])
    if spinner_event: spinner_event.set()
    return result

async def run_single(target, timeout, paths, concurrency, debug, extra_checks):
    connector = TCPConnector(ssl=False, limit_per_host=concurrency)
    timeout_cfg = ClientTimeout(total=timeout)
    headers = {"User-Agent": USER_AGENT}
    spinner_event = asyncio.Event()
    async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg, headers=headers) as session:
        spinner = asyncio.create_task(spinner_task(spinner_event, f"Scanning {target}"))
        try:
            res = await check_target(session, target, timeout, paths, debug=debug, spinner_event=spinner_event, extra_checks=extra_checks)
        finally:
            spinner_event.set()
            await spinner
    return res

def pretty_print_report(report):
    print(Fore.YELLOW + "========================" + Style.RESET_ALL)
    print(Fore.CYAN + report.get("target","") + Style.RESET_ALL)
    root = report.get("root",{})
    if "error" in root:
        print(Fore.RED + "  HTTP Error: " + str(root["error"]) + Style.RESET_ALL)
    else:
        print("  Status:", root.get("status"), "URL:", root.get("url"))
    missing = report.get("security_headers_missing",[])
    if missing:
        print(Fore.YELLOW + "  Missing security headers: " + ", ".join(missing) + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "  Security headers: present (some)" + Style.RESET_ALL)
    if report.get("cms_hints"):
        print("  CMS hints:", ", ".join(report["cms_hints"]))
    if report.get("dir_listing"):
        print(Fore.YELLOW + "  Possible directory listing(s): " + ", ".join(report["dir_listing"]) + Style.RESET_ALL)
    if report.get("paths"):
        print("  Interesting paths found:")
        for p in report["paths"]:
            print("   -", p["path"], "status:", p.get("status"))
    if report.get("bruteforce_paths"):
        print(Fore.YELLOW + "  Bruteforce found paths:" + Style.RESET_ALL)
        for b in report["bruteforce_paths"]:
            print("   -", b["path"], "->", b["url"])
    if report.get("openredirect"):
        print(Fore.YELLOW + "  Possible open redirects:")
        for o in report["openredirect"]:
            print("   - param:", o.get("param"), "url:", o.get("url"))
    if report.get("sqli"):
        print(Fore.RED + "  Possible SQLi findings:")
        for s in report["sqli"]:
            print("   - param:", s.get("param"), "payload:", s.get("payload"))
    if report.get("xss"):
        print(Fore.RED + "  Possible XSS findings:")
        for x in report["xss"]:
            print("   - param:", x.get("param"), "payload:", x.get("payload"))
    if report.get("found_subdomains"):
        print(Fore.GREEN + "  Found subdomains:" + Style.RESET_ALL, ", ".join(report["found_subdomains"]))
    tls = report.get("tls",{})
    if tls.get("ok"):
        print("  TLS notAfter:", tls.get("not_after"))
    elif tls.get("error"):
        print(Fore.YELLOW + "  TLS fetch error: " + str(tls.get("error")) + Style.RESET_ALL)

def render_html(report, filename):
    title = f"Striker Report - {report.get('target')}"
    now = report.get("scanned_at", now_iso())
    root = report.get("root", {})
    missing = ", ".join(report.get("security_headers_missing", [])) or "None"
    cms = ", ".join(report.get("cms_hints", [])) or "None"
    paths = report.get("paths", [])
    dirlist = report.get("dir_listing", [])
    tls = report.get("tls", {})
    html = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>{title}</title>",
        "<style>body{font-family:Inter,Segoe UI,Arial;background:#0b1220;color:#e6eef8;padding:28px} .card{background:#071025;padding:18px;border-radius:10px;margin-bottom:14px;box-shadow:0 8px 20px rgba(0,0,0,0.6)} .muted{color:#94a3b8}</style>",
        "</head><body>",
        f"<h1 style='color:#7dd3fc'>{title}</h1>",
        f"<div class='card'><strong>Target:</strong> {report.get('target')}<br/><strong>URL:</strong> {report.get('url')}<br/><strong>Scanned at:</strong> {now}</div>",
        f"<div class='card'><h3>HTTP</h3><div class='muted'><strong>Status:</strong> {root.get('status','err')}<br/><strong>URL:</strong> {root.get('url')}<br/><strong>Missing security headers:</strong> {missing}</div></div>",
        f"<div class='card'><h3>TLS</h3><div class='muted'><strong>notAfter:</strong> {tls.get('not_after')}<br/><strong>issuer:</strong> {tls.get('issuer')}</div></div>",
        f"<div class='card'><h3>CMS hints</h3><div class='muted'>{cms}</div></div>",
        "<div class='card'><h3>Interesting paths</h3><ul>"
    ]
    for p in paths:
        html.append(f"<li>{p.get('path')} - status {p.get('status')}</li>")
    html.append("</ul></div>")
    if dirlist:
        html.append("<div class='card'><h3>Possible directory listings</h3><ul>")
        for d in dirlist: html.append(f"<li>{d}</li>")
        html.append("</ul></div>")
    if report.get("bruteforce_paths"):
        html.append("<div class='card'><h3>Bruteforce found</h3><ul>")
        for b in report["bruteforce_paths"]:
            html.append(f"<li>{b['path']} - {b['url']}</li>")
        html.append("</ul></div>")
    if report.get("sqli"):
        html.append("<div class='card'><h3>Possible SQLi</h3><ul>")
        for s in report["sqli"]:
            html.append(f"<li>param: {s['param']} payload: {s['payload']}</li>")
        html.append("</ul></div>")
    if report.get("xss"):
        html.append("<div class='card'><h3>Possible XSS</h3><ul>")
        for x in report["xss"]:
            html.append(f"<li>param: {x['param']} payload: {x['payload']}</li>")
        html.append("</ul></div>")
    if report.get("openredirect"):
        html.append("<div class='card'><h3>Open redirects</h3><ul>")
        for o in report["openredirect"]:
            html.append(f"<li>param: {o.get('param')} url: {o.get('url')}</li>")
        html.append("</ul></div>")
    if report.get("found_subdomains"):
        html.append("<div class='card'><h3>Subdomains</h3><div class='muted'>" + ", ".join(report["found_subdomains"]) + "</div></div>")
    html.append(f"<div style='color:#94a3b8;margin-top:18px'>Generated by Striker • panda_big_money • {now}</div>")
    html.append("</body></html>")
    with open(filename, "w", encoding="utf-8") as f: f.write("\n".join(html))
    return filename

def save_json(report, outpath):
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return outpath

def interactive_prompt(prompt, default=None, validator=None):
    while True:
        if default is None:
            ans = input(Fore.CYAN + prompt + " " + Style.RESET_ALL).strip()
        else:
            ans = input(Fore.CYAN + f"{prompt} [{default}]: " + Style.RESET_ALL).strip() or str(default)
        if validator:
            ok, msg = validator(ans)
            if ok: return ans
            print(Fore.YELLOW + f"Invalid: {msg}" + Style.RESET_ALL)
        else:
            return ans

def validate_multiple_targets(s):
    parts = [p.strip() for p in s.split(",") if p.strip()]
    return (len(parts) > 0, "enter at least one target (comma separated)")

def validate_positive_int(s):
    try:
        v = int(s)
        return (v > 0, "must be > 0")
    except Exception:
        return (False, "must be integer")

def validate_float(s):
    try:
        float(s); return (True, "")
    except Exception:
        return (False, "must be a number")

async def orchestrate_targets(targets, concurrency, timeout, rate, debug, save_json_choice, save_html_choice, paths, extra_checks):
    results = []
    sem = asyncio.Semaphore(concurrency)
    async def worker(t):
        async with sem:
            try:
                res = await run_single(t, timeout, paths, max(1,concurrency), debug, extra_checks)
                pretty_print_report(res)
                if save_json_choice:
                    name = re.sub(r"[^0-9a-zA-Z\-_.]","_", t)
                    fname = f"{name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
                    save_json(res, fname)
                    print(Fore.GREEN + f"Saved JSON: {fname}" + Style.RESET_ALL)
                if save_html_choice:
                    name = re.sub(r"[^0-9a-zA-Z\-_.]","_", t)
                    fname = f"{name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.html"
                    render_html(res, fname)
                    print(Fore.GREEN + f"Saved HTML: {fname}" + Style.RESET_ALL)
                results.append(res)
            except Exception as e:
                print(Fore.RED + f"Error scanning {t}: {e}" + Style.RESET_ALL)
            if rate and rate > 0:
                await asyncio.sleep(1.0/float(rate))
    tasks = [worker(t) for t in targets]
    await asyncio.gather(*tasks)
    return results

def main():
    os.system('cls' if os.name=='nt' else 'clear')
    banner()
    raw_targets = interactive_prompt("Enter target(s) (comma separated, domains or URLs):", validator=validate_multiple_targets)
    targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
    conf = input(Fore.YELLOW + f"Scan targets {targets}? Confirm (y/N): " + Style.RESET_ALL).strip().lower()
    if conf not in ("y","yes"):
        print(Fore.RED + "Aborted." + Style.RESET_ALL); sys.exit(0)
    concurrency = int(interactive_prompt("Concurrency (parallel targets)", default="2", validator=validate_positive_int))
    timeout = float(interactive_prompt("Request timeout (seconds)", default="12", validator=validate_float))
    rate = float(interactive_prompt("Rate (requests/sec, approximate)", default="2.0", validator=validate_float))
    debug = interactive_prompt("Enable debug output? (y/N)", default="N").strip().lower() in ("y","yes")
    save_json_choice = interactive_prompt("Save JSON report after each target? (y/N)", default="N").strip().lower() in ("y","yes")
    save_html_choice = interactive_prompt("Save HTML report after each target? (y/N)", default="N").strip().lower() in ("y","yes")
    do_paths = interactive_prompt("Probe common paths? (y/N)", default="Y").strip().lower() in ("y","yes")
    do_sqli = interactive_prompt("Check for basic SQLi? (y/N)", default="N").strip().lower() in ("y","yes")
    do_xss = interactive_prompt("Check for basic XSS? (y/N)", default="N").strip().lower() in ("y","yes")
    do_openredirect = interactive_prompt("Detect open redirects? (y/N)", default="N").strip().lower() in ("y","yes")
    do_subdomains = interactive_prompt("Do simple subdomain discovery? (y/N)", default="N").strip().lower() in ("y","yes")
    do_dirbrute = interactive_prompt("Run small directory brute-force? (y/N)", default="N").strip().lower() in ("y","yes")
    paths = COMMON_PATHS if do_paths else []
    extra_checks = {"sqli": do_sqli, "xss": do_xss, "openredirect": do_openredirect, "subdomains": do_subdomains, "dirbrute": do_dirbrute}
    print(Fore.MAGENTA + "\nStarting passive scans..." + Style.RESET_ALL)
    results = asyncio.run(orchestrate_targets(targets, concurrency, timeout, rate, debug, save_json_choice, save_html_choice, paths, extra_checks))
    if not save_json_choice and not save_html_choice:
        q = input(Fore.YELLOW + "Save combined JSON report for all targets? (y/N): " + Style.RESET_ALL).strip().lower()
        if q in ("y","yes"):
            base = "striker-multi"
            fname = f"{base}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
            save_json({"scanned_at": now_iso(), "results": results}, fname)
            print(Fore.GREEN + f"Saved: {fname}" + Style.RESET_ALL)
    print(Fore.GREEN + "\nAll scans complete." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Interrupted. Exiting." + Style.RESET_ALL)
        sys.exit(1)
