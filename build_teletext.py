#!/usr/bin/env python3
"""
NERD-TEXT Static Generator
Fetches CISA KEV vulnerabilities, Linux Security Advisories, and Roguelike/Nerd-Game RSS feeds,
enforces a strict 40-character Teletext grid, and outputs:
  - dist/pages.json (for the Web UI)
  - dist/<page>.txt (for terminal `curl` access)
"""

import json
import os
import re
import textwrap
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html import unescape
from pathlib import Path

DIST_DIR = Path("dist")
WIDTH = 40

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

LINUX_SEC_FEEDS = [
    ("Debian DSA", "https://www.debian.org/security/dsa"),
    ("Ubuntu USN", "https://ubuntu.com/security/notices/rss.xml"),
    ("Kernel", "https://www.kernel.org/feeds/kdist.xml"),
]

GAME_FEEDS = [
    ("Dwarf Fortress", "https://www.bay12games.com/dwarves/dev_now.rss"),
    ("Caves of Qud", "https://steamcommunity.com/games/333640/rss/"),
    ("Cataclysm: DDA", "https://github.com/CleverRaven/Cataclysm-DDA/releases.atom"),
    ("NetHack", "https://github.com/NetHack/NetHack/releases.atom"),
    ("Libretro", "https://www.libretro.com/index.php/feed/"),
]

USER_AGENT = "NerdText-Bot/1.0 (+https://nerdtext.local)"


def fetch_url(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def clean_text(raw: str) -> str:
    text = unescape(raw or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = text.encode("ascii", errors="ignore").decode("ascii")
    return text


def dedup_prefix(prefix: str, text: str) -> str:
    """Entfernt doppelte Hersteller-/Spielnamen, Autoren-Tags und Datums-Präfixe."""
    t = text.strip()
    t = re.sub(r"^\([A-Za-z0-9 _.-]+\)\s*", "", t)
    t = re.sub(r"^\d{4}-\d{2}-\d{2}\s*[:\-]\s*", "", t)
    p = prefix.strip()
    if t.lower().startswith(p.lower()):
        t = t[len(p):].lstrip(" :-|–—")
    return t


def is_date_only(text: str) -> bool:
    return bool(re.fullmatch(r"[\d./\-:\s]+", text.strip()))


def smart_truncate(text: str, max_len: int) -> str:
    """Kürzt bevorzugt am Satzende, sonst sauber an Wortgrenzen."""
    t = text.strip()
    if len(t) <= max_len:
        return t
    sub = t[:max_len]
    last_dot = sub.rfind(". ")
    if last_dot >= max_len // 2:
        return sub[: last_dot + 1]
    cut = sub.rsplit(" ", 1)[0]
    return cut if len(cut) >= max_len // 2 else sub


def wrap_40(text: str, indent: str = "") -> list[str]:
    clean = clean_text(text)
    if not clean:
        return []
    wrapped = textwrap.wrap(
        clean,
        width=WIDTH,
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=True,
        break_on_hyphens=True,
    )
    return [line[:WIDTH] for line in wrapped]


def resolve_gemini_model(api_key: str) -> str:
    """Ermittelt dynamisch ein verfügbares Flash-Modell für den hinterlegten API-Key."""
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        req = urllib.request.Request(list_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [
                m["name"].replace("models/", "")
                for m in data.get("models", [])
                if "generateContent" in m.get("supportedGenerationMethods", [])
            ]
            for preferred in (
                "gemini-2.5-flash",
                "gemini-2.5-flash-lite",
                "gemini-2.0-flash",
                "gemini-flash-latest",
                "gemini-1.5-flash",
            ):
                if preferred in models:
                    return preferred
            flash_models = [m for m in models if "flash" in m]
            if flash_models:
                return flash_models[0]
            if models:
                return models[0]
    except Exception as exc:
        print(f"[WARN] Could not list models ({exc}), trying fallback.")
    return "gemini-2.0-flash"


def summarize_with_llm(items: list[dict], category: str) -> list[dict] | None:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key or not items:
        return None

    model = resolve_gemini_model(api_key)
    prompt = (
        f"You are a senior Teletext news editor for {category}. "
        "Rewrite each raw feed item into crisp, complete Teletext copy:\n"
        "1) 'headline': max 34 chars, complete words (NEVER cut off mid-word), "
        "format 'Vendor/Game: Core Issue' (e.g. 'Cisco BroadWorks: XXE Flaw').\n"
        "2) 'summary': 150 to 200 chars of dense technical facts ending with a full period. "
        "State attack vector, impact, and patch/fix. Never repeat the headline.\n"
        "Return ONLY a raw JSON array of objects with keys 'headline' and 'summary'. No markdown.\n\n"
        f"Items:\n{json.dumps(items, ensure_ascii=True)}"
    )

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
            raw_text = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text)
            parsed = json.loads(raw_text)
            if isinstance(parsed, list) and len(parsed) == len(items):
                print(f"[INFO] LLM editorial rewrite succeeded via {model}.")
                return parsed
    except Exception as exc:
        print(f"[WARN] LLM step skipped on {model} ({exc}), using deterministic formatter.")
    return None


def get_cisa_cves(limit: int = 3) -> list[dict]:
    try:
        raw = fetch_url(CISA_KEV_URL)
        data = json.loads(raw.decode("utf-8"))
        vulns = data.get("vulnerabilities", [])
        vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        results = []
        for v in vulns[:limit]:
            cve = clean_text(v.get("cveID", "CVE-UNKNOWN"))
            vendor = clean_text(v.get("vendorProject", ""))
            product = clean_text(v.get("product", ""))
            name = clean_text(v.get("vulnerabilityName", ""))
            desc = clean_text(v.get("shortDescription", ""))
            action = clean_text(v.get("requiredAction", ""))
            due = clean_text(v.get("dueDate", ""))

            target = dedup_prefix(vendor, product)
            label = f"{vendor} {target}".strip() if target else vendor
            clean_name = dedup_prefix(label, name) or name

            body = desc if desc else clean_name
            if action and len(body) < 160:
                body = f"{body} Fix: {action}"

            results.append({
                "id": cve,
                "headline": smart_truncate(f"{label}: {clean_name}", 34),
                "summary": smart_truncate(body, 220),
                "meta": f"CISA KEV | Added: {v.get('dateAdded', '')} | Due: {due}",
            })
        return results
    except Exception as exc:
        print(f"[ERROR] CISA KEV fetch failed: {exc}")
        return []


def parse_feed_items(xml_bytes: bytes, source_name: str, max_items: int = 2, short_tag: str = "") -> list[dict]:
    items = []
    try:
        root = ET.fromstring(xml_bytes)
        entries = root.findall(".//item")
        is_atom = False
        is_rdf = False

        if not entries:
            entries = root.findall(".//{http://purl.org/rss/1.0/}item")
            is_rdf = bool(entries)
        if not entries:
            entries = root.findall(".//{http://www.w3.org/2005/Atom}entry")
            is_atom = bool(entries)

        for entry in entries[:max_items]:
            if is_atom:
                title_el = entry.find("{http://www.w3.org/2005/Atom}title")
                sum_el = (
                    entry.find("{http://www.w3.org/2005/Atom}summary")
                    or entry.find("{http://www.w3.org/2005/Atom}content")
                )
                date_el = entry.find("{http://www.w3.org/2005/Atom}updated")
            elif is_rdf:
                title_el = entry.find("{http://purl.org/rss/1.0/}title")
                sum_el = entry.find("{http://purl.org/rss/1.0/}description")
                date_el = entry.find("{http://purl.org/dc/elements/1.1/}date")
            else:
                title_el = entry.find("title")
                sum_el = entry.find("description")
                date_el = entry.find("pubDate")

            raw_title = clean_text(title_el.text if title_el is not None else "")
            summary = clean_text(sum_el.text if sum_el is not None else "")
            pub = clean_text(date_el.text if date_el is not None else "")[:16]

            title = dedup_prefix(source_name, raw_title)
            if short_tag:
                title = dedup_prefix(short_tag, title)
            if not title or is_date_only(title):
                title = dedup_prefix(short_tag or source_name, summary[:65]) if summary else "Update"

            tag = short_tag or source_name
            items.append({
                "id": source_name.upper(),
                "headline": smart_truncate(f"{tag}: {title}", 34),
                "summary": smart_truncate(summary or title, 220),
                "meta": f"Source: {source_name} ({pub})" if pub else f"Source: {source_name}",
            })
    except Exception as exc:
        print(f"[WARN] Failed parsing {source_name}: {exc}")
    return items


def get_security_items() -> list[dict]:
    cves = get_cisa_cves(limit=3)
    linux_items = []
    for name, url in LINUX_SEC_FEEDS:
        try:
            raw = fetch_url(url, timeout=12)
            tag = "DSA" if "Debian" in name else ("USN" if "Ubuntu" in name else "Linux")
            linux_items.extend(parse_feed_items(raw, name, max_items=1, short_tag=tag))
        except Exception as exc:
            print(f"[WARN] Security feed unreachable ({name}): {exc}")

    combined = (cves + linux_items)[:5]
    if not combined:
        return [{
            "id": "SEC-OFFLINE",
            "headline": "Security feeds offline",
            "summary": "Upstream CISA/Linux endpoints unreachable during build.",
            "meta": "Retry scheduled",
        }]
    return combined


def get_nerd_games(limit: int = 5) -> list[dict]:
    collected = []
    for name, url in GAME_FEEDS:
        try:
            raw = fetch_url(url, timeout=12)
            tag = "DF" if name == "Dwarf Fortress" else name
            collected.extend(parse_feed_items(raw, name, max_items=2, short_tag=tag))
        except Exception as exc:
            print(f"[WARN] Feed unreachable ({name}): {exc}")

    if not collected:
        return [{
            "id": "GAMES-OFFLINE",
            "headline": "Game feeds unreachable",
            "summary": "Upstream RSS endpoints did not respond during build.",
            "meta": "Retry next cycle",
        }]
    return collected[:limit]


def build_pages(sec_items: list[dict], games: list[dict], stamp: str) -> dict:
    pages = {}

    # --- PAGE 100: INDEX ---
    p100 = [
        {"t": "banner", "s": "  NERD-TEXT // ZERO-BLOAT TELETEXT    "},
        {"t": "sep", "s": "=" * 40},
        {"t": "sec_cyan", "s": "SECURITY & LINUX ADVISORIES (P200)"},
    ]
    for idx, item in enumerate(sec_items[:3], start=201):
        p100.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})

    p100.append({"t": "blank", "s": ""})
    p100.append({"t": "sec_green", "s": "NERD GAMES & ROGUELIKES (FROM 300)"})
    for idx, item in enumerate(games[:3], start=301):
        p100.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})

    p100.extend([
        {"t": "blank", "s": ""},
        {"t": "sep", "s": "-" * 40},
        {"t": "nav", "s": "[200] Security  [300] Games   [999] Info"},
    ])
    pages["100"] = {"title": "INDEX", "next": "200", "prev": "999", "lines": p100}

    # --- PAGE 200: SECURITY & LINUX OVERVIEW ---
    p200 = [
        {"t": "hdr_red", "s": "CISA KEV & LINUX SECURITY (DSA/USN)"},
        {"t": "sep", "s": "=" * 40},
    ]
    for idx, item in enumerate(sec_items, start=201):
        p200.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})
        p200.extend({"t": "body", "s": l} for l in wrap_40(item["summary"], "     ")[:2])
    p200.append({"t": "nav", "s": "[100] Index      [201] Details     [300]"})
    pages["200"] = {"title": "SECURITY", "next": "201", "prev": "100", "lines": p200}

    # --- PAGES 201..20N: SECURITY DETAILS ---
    for i, item in enumerate(sec_items):
        pg = str(201 + i)
        nxt = str(201 + i + 1) if i + 1 < len(sec_items) else "300"
        prv = str(201 + i - 1) if i > 0 else "200"
        lines = [
            {"t": "hdr_red", "s": f"SECURITY ADVISORY ({i+1}/{len(sec_items)})"},
            {"t": "sep", "s": "=" * 40},
            {"t": "item_yel", "s": f"> {item['id']}"[:40]},
        ]
        lines.extend({"t": "sec_cyan", "s": l} for l in wrap_40(item["headline"], "  "))
        lines.append({"t": "blank", "s": ""})
        lines.extend({"t": "body", "s": l} for l in wrap_40(item["summary"], "  ")[:6])
        lines.append({"t": "blank", "s": ""})
        lines.extend({"t": "warn_red", "s": l} for l in wrap_40(item["meta"], "  "))
        lines.append({"t": "nav", "s": f"[100] Index  [{prv}] Prev  [{nxt}] Next"})
        pages[pg] = {"title": item["id"][:12], "next": nxt, "prev": prv, "lines": lines}

    # --- PAGE 300: NERD GAMES OVERVIEW ---
    p300 = [
        {"t": "hdr_grn", "s": "ROGUELIKES & SYSTEM-DRIVEN GAMES"},
        {"t": "sep", "s": "=" * 40},
    ]
    for idx, item in enumerate(games, start=301):
        p300.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})
        p300.extend({"t": "body", "s": l} for l in wrap_40(item["summary"], "     ")[:2])
    p300.append({"t": "nav", "s": "[100] Index      [301] Details     [999]"})
    pages["300"] = {"title": "NERD GAMES", "next": "301", "prev": "200", "lines": p300}

    # --- PAGES 301..30N: GAME DETAILS ---
    for i, item in enumerate(games):
        pg = str(301 + i)
        nxt = str(301 + i + 1) if i + 1 < len(games) else "999"
        prv = str(301 + i - 1) if i > 0 else "300"
        lines = [
            {"t": "hdr_grn", "s": f"GAME LOG ({i+1}/{len(games)})"},
            {"t": "sep", "s": "=" * 40},
            {"t": "item_yel", "s": f"> {item['id']}"[:40]},
        ]
        lines.extend({"t": "sec_cyan", "s": l} for l in wrap_40(item["headline"], "  "))
        lines.append({"t": "blank", "s": ""})
        lines.extend({"t": "body", "s": l} for l in wrap_40(item["summary"], "  ")[:6])
        lines.append({"t": "blank", "s": ""})
        lines.extend({"t": "warn_grn", "s": l} for l in wrap_40(item["meta"], "  "))
        lines.append({"t": "nav", "s": f"[100] Index  [{prv}] Prev  [{nxt}] Next"})
        pages[pg] = {"title": item["id"][:12], "next": nxt, "prev": prv, "lines": lines}

    # --- PAGE 999: INFO & CURL ACCESS ---
    pages["999"] = {
        "title": "INFO",
        "next": "100",
        "prev": "300",
        "lines": [
            {"t": "hdr_mag", "s": "ABOUT NERD-TEXT // ARCHITECTURE"},
            {"t": "sep", "s": "=" * 40},
            {"t": "body", "s": "Zero ads. Zero tracking. Finite pages."},
            {"t": "body", "s": "Built for instant loading on weak"},
            {"t": "body", "s": "mobile links and terminal workflows."},
            {"t": "blank", "s": ""},
            {"t": "sec_cyan", "s": "TERMINAL / CURL ACCESS:"},
            {"t": "item_yel", "s": "  $ curl <host>/100.txt"},
            {"t": "item_yel", "s": "  $ curl <host>/204.txt"},
            {"t": "blank", "s": ""},
            {"t": "body", "s": f"Last build: {stamp} UTC"},
            {"t": "nav", "s": "[100] Index   [200] Sec   [300] Games"},
        ],
    }

    return pages


def render_plain_txt(page_num: str, page_obj: dict, stamp: str) -> str:
    header = f"P{page_num}  NERD-TEXT {page_num}   {stamp} UTC"[:40].ljust(40)
    out = [header, "=" * 40]
    for line in page_obj["lines"]:
        out.append(line["s"][:40].ljust(40))
    out.append("=" * 40)
    out.append("RED:100  GRN:200  YEL:300  CYN:999".ljust(40))
    return "\n".join(out) + "\n"


def main() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    now_utc = datetime.now(timezone.utc)
    stamp = now_utc.strftime("%d.%m.%y %H:%M")

    print("[1/4] Fetching CISA KEV & Linux Security feeds...")
    sec_items = get_security_items()
    llm_sec = summarize_with_llm(sec_items, "Cybersecurity, CVEs & Linux Advisories")
    if llm_sec:
        for orig, refined in zip(sec_items, llm_sec):
            orig["headline"] = smart_truncate(clean_text(refined.get("headline", orig["headline"])), 34)
            orig["summary"] = smart_truncate(clean_text(refined.get("summary", orig["summary"])), 220)

    print("[2/4] Fetching Nerd-Game & Roguelike feeds...")
    games = get_nerd_games(limit=5)
    llm_games = summarize_with_llm(games, "Roguelikes & Deep System Games")
    if llm_games:
        for orig, refined in zip(games, llm_games):
            orig["headline"] = smart_truncate(clean_text(refined.get("headline", orig["headline"])), 34)
            orig["summary"] = smart_truncate(clean_text(refined.get("summary", orig["summary"])), 220)

    print("[3/4] Building 40-char Teletext grid...")
    pages = build_pages(sec_items, games, stamp)

    payload = {"generated_utc": now_utc.isoformat(), "pages": pages}
    (DIST_DIR / "pages.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("[4/4] Writing plain-text pages for curl...")
    for pg_num, pg_obj in pages.items():
        txt_content = render_plain_txt(pg_num, pg_obj, stamp)
        (DIST_DIR / f"{pg_num}.txt").write_text(txt_content, encoding="utf-8")

    print(f"[DONE] Built {len(pages)} pages into ./{DIST_DIR}/")


if __name__ == "__main__":
    main()