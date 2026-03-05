#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations

import dataclasses
import html
import json
import random
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Generator, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CYBER_CAT_SVG = r"""
<svg width="140" height="140" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="g1" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#00D4FF"/>
      <stop offset="1" stop-color="#5A67D8"/>
    </linearGradient>
  </defs>
  <path d="M55 92 L35 50 L78 72 Q105 52 128 52 Q151 52 178 72 L221 50 L201 92 Q212 118 212 144 Q212 206 128 218 Q44 206 44 144 Q44 118 55 92 Z" fill="#0A192F" stroke="url(#g1)" stroke-width="4" stroke-linejoin="round"/>
  <rect x="62" y="110" width="132" height="54" rx="16" fill="rgba(0,212,255,0.08)" stroke="url(#g1)" stroke-width="3"/>
  <rect x="72" y="120" width="48" height="34" rx="8" fill="rgba(0,212,255,0.15)" stroke="#00D4FF" stroke-width="2"/>
  <rect x="136" y="120" width="48" height="34" rx="8" fill="rgba(90,103,216,0.15)" stroke="#5A67D8" stroke-width="2"/>
  <circle cx="96" cy="136" r="4" fill="#00D4FF"/>
  <circle cx="160" cy="136" r="4" fill="#5A67D8"/>
  <path d="M128 162 l8 8 h-16 z" fill="url(#g1)"/>
</svg>
"""

LOG_LOCK = threading.Lock()
LOG_SEQ = 0
LOGS: List[Dict[str, Any]] = []
SESSIONS: Dict[int, Dict[str, Any]] = {}
SESSION_SEQ = 0

def _now() -> float:
    return time.time()

def _log(entry: Dict[str, Any]) -> None:
    global LOG_SEQ
    with LOG_LOCK:
        LOG_SEQ += 1
        entry["id"] = LOG_SEQ
        LOGS.append(entry)

def _get_logs_since(last_id: int) -> List[Dict[str, Any]]:
    with LOG_LOCK:
        return [e for e in LOGS if e["id"] > last_id]

@dataclasses.dataclass
class Config:
    threads: int = 8
    timeout_s: float = 15.0
    retries: int = 2
    backoff_base_s: float = 0.8
    jitter_min_s: float = 0.1
    jitter_max_s: float = 0.4
    polite_mode: bool = True
    respect_429: bool = True
    max_mutations: int = 300
    anomaly_len_ratio: float = 0.2
    enabled_categories: List[str] = dataclasses.field(default_factory=list)

CATEGORY_NAMES = {
    "method": "HTTP Method",
    "method_override": "Method Override", 
    "parameter_pollution": "Parameter Pollution",
    "content_type": "Content-Type",
    "header_injection": "Header Injection",
    "extended_headers": "Extended Headers",
    "user_agent": "User-Agent",
    "path_fuzzing": "Path Fuzzing",
    "case_switching": "Case Switching",
    "json_structure": "JSON Structure",
    "mass_assignment": "Mass Assignment",
    "numeric_overflow": "Numeric Overflow",
    "boolean_bypass": "Boolean Bypass",
}

DEFAULT_ENABLED = list(CATEGORY_NAMES.keys())

USER_AGENT_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

def parse_raw_request(raw: str) -> Optional[Tuple[str, str, Dict[str, str], str]]:
    raw = raw.replace("\r\n", "\n").strip("\n")
    if not raw.strip():
        return None
    lines = raw.split("\n")
    first = lines[0].strip()
    parts = first.split()
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    path = parts[1]

    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    reading_headers = True
    for line in lines[1:]:
        if reading_headers and line.strip() == "":
            reading_headers = False
            continue
        if reading_headers:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        else:
            body_lines.append(line)
    body = "\n".join(body_lines).strip()
    return method, path, headers, body

def build_url(base_url: str, path_or_url: str, headers: Dict[str, str]) -> str:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return path_or_url
    base_url = base_url.strip()
    if not base_url:
        host = headers.get("host", "").strip()
        if host:
            return f"http://{host}{path_or_url}"
        raise ValueError("Base URL required")
    return base_url.rstrip("/") + path_or_url

def mutate_methods(method: str, path: str, headers: Dict[str, str], body: str):
    for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]:
        yield {"category": "method", "description": f"Method: {m}", "method": m, "path": path, "headers": dict(headers), "body": body}

def mutate_method_override(method: str, path: str, headers: Dict[str, str], body: str):
    overrides = ["PUT", "PATCH", "DELETE", "POST"]
    headers_list = ["X-HTTP-Method-Override", "X-Method-Override", "X-Http-Method-Override"]
    for override in overrides:
        for h in headers_list:
            hh = dict(headers)
            hh[h] = override
            yield {"category": "method_override", "description": f"{h}: {override}", "method": method, "path": path, "headers": hh, "body": body}

def mutate_parameter_pollution(method: str, path: str, headers: Dict[str, str], body: str):
    u = urllib.parse.urlparse(path)
    qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    if qs:
        for k, vals in qs.items():
            if vals:
                new_qs = dict(qs)
                new_qs[k] = [vals[0], vals[0], "1", ""]
                q = urllib.parse.urlencode(new_qs, doseq=True)
                new_path = u._replace(query=q).geturl()
                yield {"category": "parameter_pollution", "description": f"Pollute: {k}", "method": method, "path": new_path, "headers": dict(headers), "body": body}

    ct = headers.get("content-type", "")
    if "form-urlencoded" in ct and body:
        form = urllib.parse.parse_qs(body, keep_blank_values=True)
        for k, vals in form.items():
            if vals:
                new_form = dict(form)
                new_form[k] = [vals[0], vals[0], "1"]
                new_body = urllib.parse.urlencode(new_form, doseq=True)
                yield {"category": "parameter_pollution", "description": f"Pollute: {k}", "method": method, "path": path, "headers": dict(headers), "body": new_body}

def mutate_content_type(method: str, path: str, headers: Dict[str, str], body: str):
    types = [
        "application/json",
        "application/x-www-form-urlencoded", 
        "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
        "text/plain",
        "application/xml",
        "text/xml"
    ]
    for ct in types:
        hh = dict(headers)
        hh["content-type"] = ct
        new_body = body
        if ct == "application/x-www-form-urlencoded" and body:
            try:
                j = json.loads(body)
                if isinstance(j, dict):
                    new_body = urllib.parse.urlencode({k: str(v) for k, v in j.items()})
            except:
                pass
        yield {"category": "content_type", "description": f"Content-Type: {ct}", "method": method, "path": path, "headers": hh, "body": new_body}

def mutate_header_injection(method: str, path: str, headers: Dict[str, str], body: str):
    payloads = {
        "X-Forwarded-For": ["127.0.0.1", "0", "::1"],
        "X-Originating-IP": ["127.0.0.1", "0"],
        "X-Remote-IP": ["127.0.0.1"],
        "X-Real-IP": ["127.0.0.1"],
        "X-Original-URL": ["/admin", "/dashboard"],
        "X-Rewrite-URL": ["/admin"],
    }
    for k, vals in payloads.items():
        for v in vals:
            hh = dict(headers)
            hh[k] = v
            yield {"category": "header_injection", "description": f"{k}: {v}", "method": method, "path": path, "headers": hh, "body": body}

def mutate_extended_headers(method: str, path: str, headers: Dict[str, str], body: str):
    names = ["X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "Forwarded", "Via", "X-Remote-Addr"]
    ips = ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "0"]
    for n in names:
        for ip in ips:
            hh = dict(headers)
            hh[n] = ip
            yield {"category": "extended_headers", "description": f"{n}: {ip}", "method": method, "path": path, "headers": hh, "body": body}

def mutate_user_agent(method: str, path: str, headers: Dict[str, str], body: str):
    for ua in USER_AGENT_LIST:
        hh = dict(headers)
        hh["user-agent"] = ua
        yield {"category": "user_agent", "description": "UA Rotation", "method": method, "path": path, "headers": hh, "body": body}

def mutate_path_fuzzing(method: str, path: str, headers: Dict[str, str], body: str):
    if "?" in path:
        p, q = path.split("?", 1)
        q = "?" + q
    else:
        p, q = path, ""
    if not p.startswith("/"):
        p = "/" + p
    fuzzers = [
        p + "/./",
        p + "/..;/",
        p + "/%2e/",
        p + "/%252e/",
        p + "/../",
        p + "/%2e%2e/",
        p + "/%2e%2e%2f"
    ]
    for np in fuzzers:
        yield {"category": "path_fuzzing", "description": f"Path: {np.split('/')[-1]}", "method": method, "path": np + q, "headers": dict(headers), "body": body}

def mutate_case_switching(method: str, path: str, headers: Dict[str, str], body: str):
    if "?" in path:
        p, q = path.split("?", 1)
        q = "?" + q
    else:
        p, q = path, ""
    if not p:
        return
    base = p if p.startswith("/") else "/" + p
    variants = [base.upper(), base.lower()]
    segs = [s.capitalize() for s in base.split("/")]
    variants.append("/".join(segs))
    for np in variants:
        if np != base:
            yield {"category": "case_switching", "description": f"Case: {np.split('/')[-1]}", "method": method, "path": np + q, "headers": dict(headers), "body": body}

def mutate_json_structure(method: str, path: str, headers: Dict[str, str], body: str):
    if not body:
        return
    try:
        j = json.loads(body)
    except:
        return
    if not isinstance(j, dict):
        return
    for k in list(j.keys())[:15]:
        j1 = dict(j)
        j1[k] = [j1[k]]
        yield {"category": "json_structure", "description": f"Array: {k}", "method": method, "path": path, "headers": dict(headers), "body": json.dumps(j1)}
        
        j2 = dict(j)
        j2[k] = {"value": j2[k]}
        yield {"category": "json_structure", "description": f"Object: {k}", "method": method, "path": path, "headers": dict(headers), "body": json.dumps(j2)}

def mutate_mass_assignment(method: str, path: str, headers: Dict[str, str], body: str):
    if not body:
        return
    try:
        j = json.loads(body)
    except:
        return
    if not isinstance(j, dict):
        return
    extras = {
        "admin": True, "role": "admin", "isAdmin": True, "is_admin": True,
        "permissions": ["*"], "access_level": 999, "privileges": ["all"]
    }
    j2 = dict(j)
    j2.update(extras)
    yield {"category": "mass_assignment", "description": "Admin fields", "method": method, "path": path, "headers": dict(headers), "body": json.dumps(j2)}

def mutate_numeric_overflow(method: str, path: str, headers: Dict[str, str], body: str):
    if not body:
        return
    try:
        j = json.loads(body)
    except:
        return
    if not isinstance(j, dict):
        return
    big_nums = [99999999999999999999, -99999999999999999999, 2**64-1]
    for k, v in j.items():
        if isinstance(v, (int, float)):
            for big in big_nums:
                j2 = dict(j)
                j2[k] = big
                yield {"category": "numeric_overflow", "description": f"{k}: {big}", "method": method, "path": path, "headers": dict(headers), "body": json.dumps(j2)}

def mutate_boolean_bypass(method: str, path: str, headers: Dict[str, str], body: str):
    if not body:
        return
    try:
        j = json.loads(body)
    except:
        return
    if not isinstance(j, dict):
        return
    truthy = [True, 1, "1", "true", "on", "yes"]
    falsy = [False, 0, "0", "false", "off", "no"]
    for k, v in j.items():
        if isinstance(v, bool):
            for t in truthy:
                j2 = dict(j)
                j2[k] = t
                yield {"category": "boolean_bypass", "description": f"{k}: {t}", "method": method, "path": path, "headers": dict(headers), "body": json.dumps(j2)}

MUTATORS = [
    mutate_methods, mutate_method_override, mutate_parameter_pollution,
    mutate_content_type, mutate_header_injection, mutate_extended_headers,
    mutate_user_agent, mutate_path_fuzzing, mutate_case_switching,
    mutate_json_structure, mutate_mass_assignment, mutate_numeric_overflow,
    mutate_boolean_bypass,
]

def generate_mutations(method: str, path: str, headers: Dict[str, str], body: str) -> Generator[Dict[str, Any], None, None]:
    for gen in MUTATORS:
        try:
            for m in gen(method, path, headers, body):
                yield m
        except:
            continue

def response_fingerprint(resp: requests.Response, text: str) -> Dict[str, Any]:
    ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    fp: Dict[str, Any] = {
        "status": resp.status_code,
        "ctype": ctype,
        "length": len(text),
        "json_keys": None,
    }
    if "json" in ctype:
        try:
            j = resp.json()
            if isinstance(j, dict):
                fp["json_keys"] = sorted(list(j.keys()))[:30]
        except:
            pass
    return fp

def is_anomaly(base_fp: Dict[str, Any], new_fp: Dict[str, Any], len_ratio: float) -> bool:
    if base_fp.get("status") != new_fp.get("status"):
        return True
    if base_fp.get("ctype") != new_fp.get("ctype"):
        return True
    b_len = max(1, base_fp.get("length", 0))
    n_len = new_fp.get("length", 0)
    if abs(n_len - b_len) / b_len >= len_ratio:
        return True
    if base_fp.get("json_keys") != new_fp.get("json_keys"):
        return bool(base_fp.get("json_keys") or new_fp.get("json_keys"))
    return False

def send_once(url: str, method: str, headers: Dict[str, str], body: str, timeout_s: float) -> Tuple[Optional[requests.Response], str, float, Optional[str]]:
    start = _now()
    try:
        kwargs: Dict[str, Any] = {"headers": headers, "timeout": timeout_s, "verify": False, "allow_redirects": False}
        ct = headers.get("content-type", "")
        if body and "json" in ct:
            kwargs["json"] = json.loads(body)
        elif body:
            kwargs["data"] = body.encode("utf-8")
        resp = requests.request(method=method.upper(), url=url, **kwargs)
        return resp, resp.text, (_now() - start) * 1000, None
    except Exception as e:
        return None, "", (_now() - start) * 1000, str(e)

def send_with_retries(url: str, method: str, headers: Dict[str, str], body: str, cfg: Config) -> Tuple[Optional[requests.Response], str, float, Optional[str]]:
    for attempt in range(cfg.retries + 1):
        time.sleep(random.uniform(cfg.jitter_min_s, cfg.jitter_max_s))
        resp, txt, dur, err = send_once(url, method, headers, body, cfg.timeout_s)
        if resp is None:
            if attempt < cfg.retries:
                time.sleep(cfg.backoff_base_s * (2 ** attempt))
                continue
            return None, "", dur, err

        if cfg.respect_429 and resp.status_code in (429, 503):
            if attempt < cfg.retries:
                ra = resp.headers.get("retry-after")
                if ra and ra.isdigit():
                    time.sleep(float(ra))
                else:
                    time.sleep(cfg.backoff_base_s * (2 ** attempt))
                continue
        return resp, txt, dur, None
    return None, "", 0, "Max retries exceeded"

PAGE_TEMPLATE = """<!doctype html>
  <html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>__TITLE__</title>
    <style>
      :root {
        --bg: #09090b;
        --panel: #18181b;
        --border: #27272a;
        --text: #fafafa;
        --text-muted: #a1a1aa;
        --primary: #3b82f6;
        --secondary: #2563eb;
        --success: #10b981;
        --danger: #ef4444;
        --warning: #f59e0b;
        --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3);
        --radius: 8px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      }
      * { box-sizing: border-box; }
      body { margin: 0; padding: 20px 20px 40px; background: var(--bg); color: var(--text); line-height: 1.6; font-size: 14px; }
      .container { max-width: 1400px; margin: 0 auto; }
      .header { display: flex; align-items: center; justify-content: space-between; padding: 20px 0; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
      .logo { display: flex; align-items: center; gap: 12px; }
      .logo h1 { margin: 0; font-size: 22px; font-weight: 600; color: var(--text); letter-spacing: -0.5px; }
      .beta-badge { font-size: 11px; background: rgba(59, 130, 246, 0.15); color: #60a5fa; padding: 2px 8px; border-radius: 12px; font-weight: 600; vertical-align: middle; margin-left: 8px; border: 1px solid rgba(59, 130, 246, 0.3); }
      .status-badge { display: inline-flex; padding: 6px 12px; border-radius: 6px; background: rgba(255,255,255,0.03); color: var(--text-muted); font-size: 12px; font-weight: 500; border: 1px solid var(--border); }
      .grid { display: grid; grid-template-columns: 1fr 400px; gap: 24px; }
      @media(max-width:1200px){ .grid { grid-template-columns: 1fr; gap: 20px; } }
      .card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
      .card-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; font-size: 14px; font-weight: 600; background: rgba(255,255,255,0.02); }
      .card-body { padding: 20px; }
      .form-group { margin-bottom: 20px; }
      .form-label { display: block; margin-bottom: 8px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
      input, textarea { width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 6px; background: rgba(0,0,0,0.2); color: var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; transition: all 0.2s; box-shadow: inset 0 1px 2px rgba(0,0,0,0.1); }
      input:focus, textarea:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); }
      textarea { min-height: 200px; resize: vertical; }
      .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }
      .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; padding: 16px; border-radius: 6px; border: 1px solid var(--border); background: rgba(0,0,0,0.1); margin-top: 12px; }
      .checkbox-grid label { display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 13px; }
      .checkbox-grid input { width: auto; height: 16px; accent-color: var(--primary); }
      .btns { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 24px; border-top: 1px solid var(--border); padding-top: 20px; }
      .btn { padding: 10px 20px; border: 0; border-radius: 6px; font-weight: 500; cursor: pointer; font-size: 14px; transition: all 0.2s; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; justify-content: center; border: 1px solid transparent; }
      .btn-primary { background: var(--primary); color: #ffffff; }
      .btn-primary:hover { background: var(--secondary); }
      .btn-secondary { background: rgba(255,255,255,0.05); color: var(--text); border-color: var(--border); }
      .btn-secondary:hover { background: rgba(255,255,255,0.08); }
      .btn-danger { background: rgba(239,68,68,0.1); color: #f87171; border-color: rgba(239,68,68,0.2); }
      .btn-danger:hover { background: rgba(239,68,68,0.2); border-color: rgba(239,68,68,0.3); }
      .log-container { height: 600px; overflow: auto; border: 1px solid var(--border); border-radius: 6px; background: rgba(0,0,0,0.2); padding: 16px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }
      .log-entry { padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; gap: 16px; }
      .log-badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
      .log-badge--anomaly { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
      .log-badge--ok { background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }
      .log-badge--warn { background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }
      .log-meta { min-width: 180px; color: var(--text-muted); font-size: 11px; }
      .log-content { flex: 1; color: var(--text); white-space: pre-wrap; font-size: 12px; }
      .alert { padding: 16px; border-radius: 6px; margin-bottom: 20px; font-weight: 500; }
      .alert--error { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
      .footer { padding: 24px 0; color: var(--text-muted); font-size: 12px; margin-top: 40px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
      .stats { display: flex; gap: 24px; font-size: 12px; }
      .stat-item { display: flex; flex-direction: column; align-items: flex-end; }
      .stat-number { font-size: 20px; font-weight: 600; color: var(--text); }
      table { width: 100%; border-collapse: collapse; font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
      th { background: rgba(255,255,255,0.02); color: var(--text-muted); font-weight: 500; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
      td, th { padding: 12px 16px; text-align: left; }
      td { border-bottom: 1px solid rgba(255,255,255,0.05); }
      tr:hover td { background: rgba(255,255,255,0.02); }
      .social-links { display: flex; gap: 16px; margin-top: 8px; }
      .social-links a { color: var(--text-muted); text-decoration: none; display: inline-flex; align-items: center; gap: 6px; font-weight: 500; transition: color 0.2s; }
      .social-links a:hover { color: var(--primary); }
      .social-links svg { width: 16px; height: 16px; fill: currentColor; }
      @media(max-width:768px){ .header { flex-direction: column; gap: 16px; text-align: center; } .grid { gap: 16px; } .form-row { grid-template-columns: 1fr; } .footer { flex-direction: column; text-align: center; } .stat-item { align-items: center; } .social-links { justify-content: center; } }
    
      /* Translate Button */
      .translate-btn {
        background: rgba(255,255,255,0.05);
        border: 1px solid var(--border);
        color: var(--text);
        padding: 6px 12px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 12px;
        font-weight: 500;
        transition: all 0.2s;
        display: inline-flex;
        align-items: center;
        gap: 6px;
      }
      .translate-btn:hover { background: rgba(255,255,255,0.1); }
      
      /* Silk Background Canvas */
      #silk-bg {
        position: fixed;
        top: 0; left: 0; width: 100vw; height: 100vh;
        z-index: -1;
        pointer-events: none;
        opacity: 0.2;
      }

      /* Fuzzy Text Canvas container */
      .fuzzy-title-container {
        position: relative;
        display: inline-block;
        height: 40px;
      }
      #fuzzy-title-canvas {
        cursor: crosshair;
      }
  
  </style>
  </head>
  <body>
    <div class="container">
      <header class="header">
      <button type="button" class="translate-btn" onclick="toggleLanguage()">🌐 Translate to Arabic</button>
        <div class="logo">
          <h1>Mutation Portal <span class="beta-badge">بيتا</span></h1>
        </div>
        <div class="status-badge">Professional Edition • Live Analysis</div>
      </header>

      __BODY__

      <footer class="footer">
        <div>
          <div>Authorized Testing Tool • Beta Version</div>
          <div class="social-links">
            <a href="https://discord.gg/z99qMbu54N" target="_blank">
              <svg viewBox="0 0 24 24"><path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z"/></svg>
              Discord
            </a>
            <a href="https://x.com/N163361N" target="_blank">
              <svg viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              X (Twitter)
            </a>
            <a href="https://github.com/1celec-N163361N/" target="_blank">
              <svg viewBox="0 0 24 24"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.205 11.387.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.298 24 12c0-6.627-5.373-12-12-12"/></svg>
              GitHub
            </a>
          </div>
        </div>
        <div class="stats">
          <div class="stat-item">
            <div class="stat-number" id="stat-mutations">0</div>
            <div>Total Mutations</div>
          </div>
          <div class="stat-item">
            <div class="stat-number" id="stat-anomalies">0</div>
            <div>Detected Anomalies</div>
          </div>
        </div>
      </footer>
    </div>
  
    <canvas id="silk-bg"></canvas>
    <script>
      // --- TRANSLATION LOGIC ---
      const dict = {
        "Mutation Portal": "بوابة الطفرات",
        "Professional Edition • Live Analysis": "النسخة الاحترافية • تحليل مباشر",
        "Authorized Testing Tool • Beta Version": "أداة اختبار مصرحة • نسخة تجريبية",
        "Total Mutations": "إجمالي الطفرات",
        "Detected Anomalies": "الشذوذ المكتشف",
        "Target Base URL": "الرابط الأساسي للهدف",
        "Raw HTTP Request": "طلب HTTP الخام",
        "Threads": "الخيوط (Threads)",
        "Timeout (s)": "المهلة (ثواني)",
        "Retries": "المحاولات",
        "Backoff (s)": "التراجع (ثواني)",
        "Jitter Min (s)": "الحد الأدنى للارتعاش (ثواني)",
        "Jitter Max (s)": "الحد الأقصى للارتعاش (ثواني)",
        "Rate Limiting": "تحديد المعدل",
        "Respect 429": "احترام 429",
        "Mutation Categories": "فئات الطفرات",
        "Execute Mutations": "تنفيذ الطفرات",
        "Live Logs": "السجلات المباشرة",
        "Clear All": "مسح الكل",
        "Clear Logs": "مسح السجلات",
        "Mutation Engine": "محرك الطفرات",
        "Full Control": "تحكم كامل",
        "Live Response Monitor": "مراقب الاستجابة المباشر",
        "Real-time": "الوقت الفعلي",
        "Translate to Arabic": "ترجمة للإنجليزية",
        "Discord": "ديسكورد",
        "X (Twitter)": "اكس (تويتر)",
        "GitHub": "جيت هب"
      };
      
      let isArabic = false;
      function toggleLanguage() {
        isArabic = !isArabic;
        document.documentElement.dir = isArabic ? 'rtl' : 'ltr';
        document.body.style.fontFamily = isArabic ? "'Tajawal', 'Cairo', sans-serif" : "inherit";
        
        const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
        let n;
        while(n = walk.nextNode()) {
          const txt = n.nodeValue.trim();
          if(txt === "بيتا" || txt === "Beta") continue; // keep beta
          
          if(isArabic) {
            if(dict[txt]) { n.originalText = txt; n.nodeValue = dict[txt]; }
          } else {
            if(n.originalText) { n.nodeValue = n.originalText; }
          }
        }
        
        // Update inputs placeholders
        document.querySelectorAll('input, textarea').forEach(el => {
          if(el.placeholder) {
            if(isArabic && dict[el.placeholder]) { el.originalPlaceholder = el.placeholder; el.placeholder = dict[el.placeholder]; }
            else if(!isArabic && el.originalPlaceholder) { el.placeholder = el.originalPlaceholder; }
          }
        });
      }

      // --- SILK BACKGROUND LOGIC ---
      const bg = document.getElementById('silk-bg');
      const bgCtx = bg.getContext('2d');
      let t = 0;
      function resizeBg() { bg.width = window.innerWidth; bg.height = window.innerHeight; }
      window.addEventListener('resize', resizeBg);
      resizeBg();
      
      function drawSilk() {
        bgCtx.clearRect(0, 0, bg.width, bg.height);
        bgCtx.lineWidth = 1;
        const lines = 12;
        for(let i=0; i<lines; i++) {
          bgCtx.beginPath();
          bgCtx.strokeStyle = `rgba(123, 116, 129, ${0.1 + (i/lines)*0.3})`;
          for(let x=0; x<=bg.width; x+=30) {
            const noise = Math.sin(x*0.005 + t*10.9*0.001 + i*0.2) * 100 * 1.1;
            const y = bg.height/2 + noise + Math.cos(x*0.002 - t*0.005)*50;
            x===0 ? bgCtx.moveTo(x, y) : bgCtx.lineTo(x, y);
          }
          bgCtx.stroke();
        }
        t++;
        requestAnimationFrame(drawSilk);
      }
      drawSilk();


      const fuzzyCanvas = document.createElement('canvas');
      fuzzyCanvas.id = 'fuzzy-title-canvas';
      
      // Replace the title with our fuzzy canvas container
      const h1 = document.querySelector('.logo h1');
      const container = document.createElement('div');
      container.className = 'fuzzy-title-container';
      container.appendChild(fuzzyCanvas);
      
      // We want the Beta badge to stay next to it, so we append it back
      const badge = document.createElement('span');
      badge.className = 'beta-badge';
      badge.innerText = 'بيتا';
      
      h1.parentNode.insertBefore(container, h1);
      h1.parentNode.insertBefore(badge, h1);
      h1.style.display = 'none';
    container.style.display = 'inline-block';
    container.style.verticalAlign = 'middle';

      // Fuzzy text implementation in vanilla JS
      const fCtx = fuzzyCanvas.getContext('2d');
      const text = "Mutation Portal";
      const fontSize = 26;
      const fuzzRange = 8;
      const baseIntensity = 0.18;
      const hoverIntensity = 0.5;
      
      let isHoveringTitle = false;
      let targetFuzzIntensity = baseIntensity;
      let currentFuzzIntensity = baseIntensity;
      
      fuzzyCanvas.addEventListener('mouseenter', () => isHoveringTitle = true);
      fuzzyCanvas.addEventListener('mouseleave', () => isHoveringTitle = false);
      
      // Prepare offscreen canvas to hold the text
      const off = document.createElement('canvas');
      const offCtx = off.getContext('2d');
      offCtx.font = `600 ${fontSize}px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`;
      const metrics = offCtx.measureText(text);
      const textWidth = Math.ceil(metrics.width);
      const textHeight = Math.ceil(fontSize * 1.5);
      
      off.width = textWidth;
      off.height = textHeight;
      offCtx.font = `600 ${fontSize}px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`;
      offCtx.fillStyle = '#fafafa';
      offCtx.textBaseline = 'middle';
      offCtx.fillText(text, 0, textHeight / 2);
      
      fuzzyCanvas.width = textWidth + fuzzRange * 2;
      fuzzyCanvas.height = textHeight + fuzzRange * 2;
      fCtx.translate(fuzzRange, fuzzRange);
      
      function drawFuzzy() {
        fCtx.clearRect(-fuzzRange, -fuzzRange, fuzzyCanvas.width, fuzzyCanvas.height);
        
        targetFuzzIntensity = isHoveringTitle ? hoverIntensity : baseIntensity;
        currentFuzzIntensity += (targetFuzzIntensity - currentFuzzIntensity) * 0.1;
        
        // Horizontal displace
        for(let y=0; y<textHeight; y++) {
          const dx = Math.floor(currentFuzzIntensity * (Math.random() - 0.5) * fuzzRange);
          fCtx.drawImage(off, 0, y, textWidth, 1, dx, y, textWidth, 1);
        }
        
        requestAnimationFrame(drawFuzzy);
      }
      drawFuzzy();
  
    </script>
  
</body>
  </html>"""

INDEX_TEMPLATE = """
__ERROR__
<div class="grid">
  <div class="card">
    <div class="card-header">
      <span>Mutation Engine</span>
      <span class="status-badge">Full Control</span>
    </div>
    <div class="card-body">
      <form method="POST" action="/run">
        <div class="form-group">
          <label class="form-label">Target Base URL</label>
          <input type="url" name="base_url" placeholder="https://target.com" value="__BASE_URL__"/>
        </div>

        <div class="form-group">
          <label class="form-label">Raw HTTP Request</label>
          <textarea name="raw_request" placeholder="POST /api/users HTTP/1.1&#10;Host: target.com&#10;Content-Type: application/json&#10;&#10;{&#10;  &quot;username&quot;: &quot;test&quot;&#10;}">__RAW__</textarea>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Threads</label>
            <input type="number" name="threads" min="1" max="50" value="__THREADS__"/>
          </div>
          <div class="form-group">
            <label class="form-label">Timeout (s)</label>
            <input type="number" name="timeout_s" min="5" max="60" step="1" value="__TIMEOUT__"/>
          </div>
          <div class="form-group">
            <label class="form-label">Retries</label>
            <input type="number" name="retries" min="0" max="5" value="__RETRIES__"/>
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Backoff (s)</label>
            <input type="number" name="backoff" min="0" max="5" step="0.1" value="__BACKOFF__"/>
          </div>
          <div class="form-group">
            <label class="form-label">Jitter Min (s)</label>
            <input type="number" name="jitter_min" min="0" max="2" step="0.05" value="__JMIN__"/>
          </div>
          <div class="form-group">
            <label class="form-label">Jitter Max (s)</label>
            <input type="number" name="jitter_max" min="0" max="2" step="0.05" value="__JMAX__"/>
          </div>
        </div>

        <div class="form-row">
          <div style="display:flex;gap:16px;align-items:center">
            <label><input type="checkbox" name="polite" value="1" __POLITE__/> Rate Limiting</label>
            <label><input type="checkbox" name="respect_429" value="1" __R429__/> Respect 429</label>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Mutation Categories</label>
          <div class="checkbox-grid">__CHECKS__</div>
        </div>

        <div class="btns">
          <button type="submit" class="btn btn-primary"> Execute Mutations</button>
          <a href="/logs" class="btn btn-secondary"> Live Logs</a>
          <button type="button" class="btn btn-danger" onclick="clearLogs()"> Clear All</button>
        </div>
      </form>
    </div>
  </div>

  <div class="card">
    <div class="card-header">
      <span>Live Response Monitor</span>
      <span class="status-badge">Real-time</span>
    </div>
    <div class="card-body p-0">
      <div class="log-container" id="logbox"></div>
    </div>
  </div>
</div>

<script>
let lastId=0;let mutations=0;let anomalies=0;
const box=document.getElementById('logbox');
async function poll(){
  try{
    const r=await fetch('/api/logs?since='+lastId);
    const data=await r.json();
    for(const e of data.items){
      lastId=Math.max(lastId,e.id);
      if(e.kind==='mut' || e.kind==='orig'){
        mutations++;
        if(e.anomaly) anomalies++;
        document.getElementById('stat-mutations').textContent=mutations;
        document.getElementById('stat-anomalies').textContent=anomalies;
      }
      const badge=e.kind==='error'?'anomaly':e.anomaly?'anomaly':e.status==429||e.status==503?'warn':'ok';
      const ts=new Date(e.ts*1000).toLocaleTimeString();
      const line=document.createElement('div');
      line.className='log-entry';
      line.innerHTML=`<div class="log-badge log-badge--${badge}">${e.anomaly?'ANOMALY':e.kind==='error'?'ERROR':e.status||'OK'}</div>
        <div class="log-meta">${ts} • ${e.kind?.toUpperCase()} • #${e.session_id}</div>
        <div class="log-content">${(e.method||'')+' '+(e.url||'')+'\\n'+(e.desc||'')}</div>`;
      box.prepend(line); while(box.children.length>150) box.removeChild(box.lastChild);
    }
  }catch(e){}
}
function clearLogs(){fetch('/api/clear',{method:'POST'}).then(()=>location.reload());}
setInterval(poll,800);poll();
</script>
"""

def render_index(error: str = "", preset: Optional[Dict[str, Any]] = None) -> str:
    preset = preset or {}
    enabled = set(preset.get("enabled", DEFAULT_ENABLED))
    checks = "".join(f'<label><input type="checkbox" name="enabled" value="{html.escape(k)}" {"checked" if k in enabled else ""}/> {html.escape(v)}</label>' for k,v in CATEGORY_NAMES.items())

    err_html = f'<div class="alert alert--error">{html.escape(error)}</div>' if error else ""
    
    body = INDEX_TEMPLATE.replace("__ERROR__", err_html).replace("__BASE_URL__", html.escape(preset.get("base_url", ""))).replace("__RAW__", html.escape(preset.get("raw_request", ""))).replace("__THREADS__", str(int(preset.get("threads", 8)))).replace("__TIMEOUT__", str(int(preset.get("timeout_s", 15)))).replace("__RETRIES__", str(int(preset.get("retries", 2)))).replace("__BACKOFF__", str(float(preset.get("backoff", 0.8)))).replace("__JMIN__", str(float(preset.get("jitter_min", 0.1)))).replace("__JMAX__", str(float(preset.get("jitter_max", 0.4)))).replace("__POLITE__", "checked" if preset.get("polite", True) else "").replace("__R429__", "checked" if preset.get("respect_429", True) else "").replace("__CHECKS__", checks)
    return PAGE_TEMPLATE.replace("__TITLE__", "Mutation Portal Beta").replace("__BODY__", body).replace("__CAT_SVG__", CYBER_CAT_SVG)

def render_logs_page() -> str:
    body = """
    <div class="card" style="max-width:1200px;margin:0 auto">
      <div class="card-header">
        <span>Live Response Log</span>
        <span class="status-badge">Unlimited History</span>
      </div>
      <div class="card-body p-0">
        <div class="log-container" id="logbox" style="height:80vh"></div>
      </div>
      <div style="padding:20px;display:flex;gap:12px">
        <a href="/" class="btn btn-secondary">← Dashboard</a>
        <button class="btn btn-danger" onclick="clearLogs()">Clear Logs</button>
      </div>
    </div>
    <script>
    let lastId=0;const box=document.getElementById('logbox');
    async function poll(){try{const r=await fetch('/api/logs?since='+lastId);const data=await r.json();for(const e of data.items){lastId=Math.max(lastId,e.id);const badge=e.kind==='error'?'anomaly':e.anomaly?'anomaly':e.status==429||e.status==503?'warn':'ok';const ts=new Date(e.ts*1000).toLocaleString();const line=document.createElement('div');line.className='log-entry';line.innerHTML=`<div class="log-badge log-badge--${badge}">${e.anomaly?'ANOMALY':e.kind==='error'?'ERROR':e.status||'OK'}</div><div class="log-meta">${ts} • ${e.kind?.toUpperCase()} • #${e.session_id}</div><div class="log-content">${(e.method||'')+' '+(e.url||'')+'\\n'+(e.desc||'')}</div>`;box.prepend(line);while(box.children.length>500)box.removeChild(box.lastChild);}}catch(e){}}function clearLogs(){fetch('/api/clear',{method:'POST'}).then(()=>location.reload());}setInterval(poll,1000);poll();
    </script>
    """
    return PAGE_TEMPLATE.replace("__TITLE__", "Live Logs").replace("__BODY__", body).replace("__CAT_SVG__", CYBER_CAT_SVG)

def render_results(session_id: int) -> str:
    s = SESSIONS.get(session_id)
    if not s:
        return PAGE_TEMPLATE.replace("__TITLE__", "Session Not Found").replace("__BODY__", '<div class="card"><div class="card-body">Session not found</div></div>').replace("__CAT_SVG__", CYBER_CAT_SVG)
    
    base_fp = s["original"]["fp"]
    muts = s["mutations"]
    anomalies = sum(1 for m in muts if m.get("anomaly"))
    
    rows = []
    for m in muts:
        badge = '<span class="log-badge log-badge--anomaly">ANOMALY</span>' if m["anomaly"] else '<span class="log-badge log-badge--ok">OK</span>'
        rows.append(f'<tr><td>{badge}</td><td>{html.escape(m["category"])}</td><td>{html.escape(m["description"])}</td><td>{html.escape(m["method"])}</td><td>{html.escape(m["url"])}</td><td>{m["fp"].get("status", "?")}</td><td>{m["fp"].get("length", 0)}</td><td>{int(m["dur_ms"])}ms</td></tr>')
    
    body = f'''
    <div class="card">
      <div class="card-header">
        <span>Analysis Results • Session #{session_id}</span>
        <span class="status-badge">Mutations: {len(muts)} • Anomalies: {anomalies}</span>
      </div>
      <div class="card-body">
        <div style="background:rgba(16,185,129,0.1);padding:16px;border-radius:8px;border-left:4px solid var(--success);margin-bottom:24px">
          <strong>Baseline:</strong> Status={base_fp.get('status')} • Type={html.escape(base_fp.get('ctype','unknown'))} • Size={base_fp.get('length',0)} bytes
        </div>
        <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap">
          <a href="/" class="btn btn-secondary">← New Test</a>
          <a href="/logs" class="btn btn-secondary">Live Logs</a>
          <a href="/api/session?id={session_id}" class="btn btn-secondary" download="session-{session_id}.json">📥 JSON Export</a>
        </div>
        <div style="overflow:auto">
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <thead><tr style="border-bottom:2px solid var(--border)"><th style="padding:12px 8px;text-align:left;font-weight:600">Status</th><th style="padding:12px 8px;text-align:left;font-weight:600">Category</th><th style="padding:12px 8px;text-align:left;font-weight:600">Payload</th><th style="padding:12px 8px;text-align:left;font-weight:600">Method</th><th style="padding:12px 8px;text-align:left;font-weight:600">Target</th><th style="padding:12px 8px;text-align:center;font-weight:600">Code</th><th style="padding:12px 8px;text-align:right;font-weight:600">Size</th><th style="padding:12px 8px;text-align:right;font-weight:600">Time</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </div>
      </div>
    </div>
    '''
    return PAGE_TEMPLATE.replace("__TITLE__", f"Results #{session_id}").replace("__BODY__", body).replace("__CAT_SVG__", CYBER_CAT_SVG)

def run_session(base_url: str, raw_request: str, cfg: Config) -> int:
    global SESSION_SEQ
    parsed = parse_raw_request(raw_request)
    if not parsed:
        raise ValueError("Invalid HTTP request format")
    method, path, headers, body = parsed

    with LOG_LOCK:
        SESSION_SEQ += 1
        session_id = SESSION_SEQ

    url = build_url(base_url, path, headers)
    
    _log({"ts": _now(), "session_id": session_id, "kind": "info", "method": method, "url": url, "status": None, "anomaly": False, "desc": "Session started"})
    
    resp, txt, dur_ms, err = send_with_retries(url, method, headers, body, cfg)
    if resp is None:
        fp0 = {"status": None, "ctype": "", "length": 0, "json_keys": None}
        _log({"ts": _now(), "session_id": session_id, "kind": "error", "method": method, "url": url, "status": None, "anomaly": True, "desc": f"Baseline failed: {err}"})
    else:
        fp0 = response_fingerprint(resp, txt)
        _log({"ts": _now(), "session_id": session_id, "kind": "orig", "method": method, "url": url, "status": fp0["status"], "anomaly": False, "desc": f"Baseline OK • {int(dur_ms)}ms • {fp0['length']} bytes"})

    enabled = set(cfg.enabled_categories or DEFAULT_ENABLED)
    muts = []
    for m in generate_mutations(method, path, headers, body):
        if m["category"] in enabled:
            muts.append(m)
        if len(muts) >= cfg.max_mutations:
            break

    sess = {
        "id": session_id, "created_at": _now(), "base_url": base_url, "raw_request": raw_request,
        "config": dataclasses.asdict(cfg), "original": {"url": url, "method": method, "headers": headers, "body": body, "fp": fp0},
        "mutations": []
    }
    SESSIONS[session_id] = sess

    if not muts:
        _log({"ts": _now(), "session_id": session_id, "kind": "info", "method": "", "url": "", "status": None, "anomaly": False, "desc": "No mutations generated"})
        return session_id

    q_lock = threading.Lock()
    idx = 0

    def worker():
        nonlocal idx
        while True:
            with q_lock:
                if idx >= len(muts):
                    return
                m = muts[idx]
                idx += 1

            m_method = m["method"]
            m_path = m["path"]
            m_headers = m["headers"]
            m_body = m.get("body", "")
            m_url = build_url(base_url, m_path, m_headers)

            _log({"ts": _now(), "session_id": session_id, "kind": "mut", "method": m_method, "url": m_url, "status": None, "anomaly": False, "desc": f"{m['category']}: {m['description']}"})

            r, t, d, e = send_with_retries(m_url, m_method, m_headers, m_body, cfg)
            if r is None:
                fp = {"status": None, "ctype": "", "length": 0}
                anomaly = True
                _log({"ts": _now(), "session_id": session_id, "kind": "error", "method": m_method, "url": m_url, "status": None, "anomaly": True, "desc": f"{m['category']}: Failed - {e}"})
            else:
                fp = response_fingerprint(r, t)
                anomaly = is_anomaly(fp0, fp, cfg.anomaly_len_ratio) if fp0.get("status") else True
                _log({"ts": _now(), "session_id": session_id, "kind": "mut", "method": m_method, "url": m_url, "status": fp["status"], "anomaly": anomaly, "desc": f"{m['category']}: {m['description']} • {int(d)}ms • {fp['length']} bytes"})

            sess["mutations"].append({
                "category": m["category"], "description": m["description"],
                "method": m_method, "url": m_url, "headers": m_headers, "body": m_body,
                "fp": fp, "dur_ms": d, "anomaly": anomaly
            })

    threads = min(cfg.threads, len(muts))
    ths = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ths: t.start()
    for t in ths: t.join()

    sess["mutations"].sort(key=lambda x: (x["category"], x["description"]))
    anomalies = sum(1 for x in sess["mutations"] if x["anomaly"])
    _log({"ts": _now(), "session_id": session_id, "kind": "info", "method": "", "url": "", "status": None, "anomaly": False, "desc": f"Complete • {len(sess['mutations'])} mutations • {anomalies} anomalies"})
    return session_id

class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj: Any, status: int = 200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        try:
            if self.path in ["/", "/index.html"]:
                self._send(200, render_index())
            elif self.path.startswith("/logs"):
                self._send(200, render_logs_page())
            elif self.path.startswith("/results"):
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                sid = int(qs.get("id", ["0"])[0])
                self._send(200, render_results(sid))
            elif self.path.startswith("/api/logs"):
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                since = int(qs.get("since", ["0"])[0])
                self._send_json({"ok": True, "items": _get_logs_since(since)})
            elif self.path.startswith("/api/session"):
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                sid = int(qs.get("id", ["0"])[0])
                s = SESSIONS.get(sid)
                self._send_json({"ok": bool(s), "session": s} if s else {"ok": False, "error": "not_found"})
            else:
                self._send(404, PAGE_TEMPLATE.replace("__TITLE__", "404").replace("__BODY__", '<div class="card"><div class="card-body text-center py-12">Not Found</div></div>').replace("__CAT_SVG__", CYBER_CAT_SVG))
        except Exception:
            self._send(500, PAGE_TEMPLATE.replace("__TITLE__", "Error").replace("__BODY__", f'<div class="card"><div class="card-body"><pre>{html.escape(traceback.format_exc())}</pre></div></div>').replace("__CAT_SVG__", CYBER_CAT_SVG))

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="ignore")
            form = urllib.parse.parse_qs(raw)

            if self.path.startswith("/api/clear"):
                global LOG_SEQ, LOGS, SESSIONS, SESSION_SEQ
                LOGS.clear(); SESSIONS.clear(); LOG_SEQ = SESSION_SEQ = 0
                self._send_json({"ok": True})
                return

            if self.path.startswith("/run"):
                base_url = form.get("base_url", [""])[0].strip()
                raw_req = form.get("raw_request", [""])[0].strip()

                cfg = Config()
                cfg.threads = max(1, min(int(form.get("threads", ["8"])[0]), 50))
                cfg.timeout_s = max(5.0, min(float(form.get("timeout_s", ["15"])[0]), 60.0))
                cfg.retries = max(0, min(int(form.get("retries", ["2"])[0]), 5))
                cfg.backoff_base_s = max(0.1, min(float(form.get("backoff", ["0.8"])[0]), 5.0))
                cfg.jitter_min_s = max(0.05, min(float(form.get("jitter_min", ["0.1"])[0]), 2.0))
                cfg.jitter_max_s = max(cfg.jitter_min_s, min(float(form.get("jitter_max", ["0.4"])[0]), 2.0))
                cfg.polite_mode = "polite" in form
                cfg.respect_429 = "respect_429" in form
                cfg.enabled_categories = [k for k in form.get("enabled", []) if k in CATEGORY_NAMES]

                try:
                    sid = run_session(base_url, raw_req, cfg)
                    self.send_response(302)
                    self.send_header("Location", f"/results?id={sid}")
                    self.end_headers()
                except Exception as e:
                    self._send(200, render_index(str(e), {
                        "base_url": base_url, "raw_request": raw_req, "threads": cfg.threads,
                        "timeout_s": cfg.timeout_s, "retries": cfg.retries, "backoff": cfg.backoff_base_s,
                        "jitter_min": cfg.jitter_min_s, "jitter_max": cfg.jitter_max_s,
                        "polite": cfg.polite_mode, "respect_429": cfg.respect_429,
                        "enabled": cfg.enabled_categories
                    }))
        except Exception:
            self._send(500, PAGE_TEMPLATE.replace("__TITLE__", "Error").replace("__BODY__", f'<div class="card"><div class="card-body"><pre>{html.escape(traceback.format_exc())}</pre></div></div>').replace("__CAT_SVG__", CYBER_CAT_SVG))

def main():
    host, port = "127.0.0.1", 5050
    print(" Mutation Portal Beta - Professional Edition")
    print("   http://127.0.0.1:5050")
    print("   Press CTRL+C to stop")
    srv = ThreadingHTTPServer((host, port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n Shutdown complete")

if __name__ == "__main__":
    main()

