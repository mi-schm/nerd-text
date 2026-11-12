#!/usr/bin/env python3
"""
NERD-TEXT Static Generator
Fetches CISA KEV vulnerabilities, Linux Security Advisories, Retro Gaming news,
and Top 10 Hacker News stories, enforces a strict 40-character Teletext grid,
and outputs:
  - dist/pages.json (Web UI)
  - dist/<page>.txt (terminal curl access)
  - dist/all.txt (complete offline bundle)
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

AD_EMAIL = "ads@nerdtext.net"
AD_SLOT = f"AD: Your 40-char link -> {AD_EMAIL}"[:WIDTH].ljust(WIDTH)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

LINUX_SEC_FEEDS = [
    ("Debian DSA", "https://www.debian.org/security/dsa"),
    ("Ubuntu USN", "https://ubuntu.com/security/notices/rss.xml"),
    ("Kernel", "https://www.kernel.org/feeds/kdist.xml"),
]

RETRO_FEEDS = [
    ("TimeExt", "https://www.timeextension.com/feeds/latest"),
    ("RetroRGB", "https://www.retrorgb.com/feed"),
    ("Libretro", "https://www.libretro.com/index.php/feed/"),
    ("GBATemp", "https://gbatemp.net/forums/-/index.rss"),
    ("Romhack", "https://www.romhacking.net/news/feed/"),
]

HN_ALGOLIA_URL = (
    "https://hn.algolia.com/api/v1/search"
    "?tags=story&numericFilters=created_at_i>{}&hitsPerPage=15"
)

USER_AGENT = "NerdText-Bot/1.0 (+https://teletext.nerdtext.net)"


def fetch_url(url: str, timeout: int = 12) -> bytes:
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


def preview_2_lines(text: str, indent: str = "     ") -> list[str]:
    """Erzeugt maximal 2 sauber abgeschlossene Vorschauzeilen (ggf. mit '...')."""
    lines = wrap_40(text, indent)
    if len(lines) <= 2:
        return lines
    second = lines[1].rstrip(" .,;:-")
    if len(second) > WIDTH - 3:
        second = second[: WIDTH - 3].rsplit(" ", 1)[0].rstrip(" .,;:-")
    return [lines[0], f"{second}..."]


def resolve_gemini_models(api_key: str) -> list[str]:
    preferred_order = [
        "gemini-flash-latest",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
        "gemini-1.5-flash",
    ]
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        req = urllib.request.Request(list_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            available = [
                m["name"].replace("models/", "")
                for m in data.get("models", [])
                if "generateContent" in m.get("supportedGenerationMethods", [])
            ]
            ordered = [m for m in preferred_order if m in available]
            for m in available:
                if "flash" in m and m not in ordered and "tts" not in m and "image" not in m and "2.5" not in m:
                    ordered.append(m)
            if ordered:
                return ordered
    except Exception as exc:
        print(f"[WARN] Could not list models ({exc}), using static fallback list.")
    return preferred_order


def summarize_with_llm(items: list[dict], category: str, extra_rules: str = "") -> list[dict] | None:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key or not items:
        return None

    models = resolve_gemini_models(api_key)
    prompt = (
        f"You are a senior Teletext news editor for {category}. "
        "Rewrite each raw feed item into crisp, complete Teletext copy:\n"
        "1) 'headline': max 34 chars, complete words (NEVER cut off mid-word), "
        "format 'Topic: Core Fact'.\n"
        "2) 'summary': 150 to 200 chars of dense technical/editorial facts ending with a full period. "
        "Explain what happened, why it matters, or key specs. Never repeat the headline.\n"
        f"{extra_rules}"
        "Return ONLY a raw JSON array of objects with keys 'headline' and 'summary'. No markdown.\n\n"
        f"Items:\n{json.dumps(items, ensure_ascii=True)}"
    )

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }

    for model in models:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                raw_text = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text)
                parsed = json.loads(raw_text)
                if isinstance(parsed, list) and len(parsed) == len(items):
                    print(f"[INFO] LLM editorial rewrite succeeded via {model} ({category}).")
                    return parsed
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="ignore")[:140]
            print(f"[WARN] {model} failed ({exc.code}): {err_body}")
        except Exception as exc:
            print(f"[WARN] {model} failed: {exc}")

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
            is_atom = True

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


def get_retro_games(limit: int = 5) -> list[dict]:
    collected = []
    for name, url in RETRO_FEEDS:
        try:
            raw = fetch_url(url, timeout=12)
            collected.extend(parse_feed_items(raw, name, max_items=2, short_tag=name))
        except Exception as exc:
            print(f"[WARN] Retro feed unreachable ({name}): {exc}")

    if not collected:
        return [{
            "id": "RETRO-OFFLINE",
            "headline": "Retro feeds unreachable",
            "summary": "Upstream retro gaming RSS feeds did not respond.",
            "meta": "Retry next cycle",
        }]
    return collected[:limit]


def extract_article_snippet(url: str) -> str:
    if not url or url.lower().endswith((".pdf", ".zip", ".png", ".jpg")):
        return ""
    try:
        raw = fetch_url(url, timeout=6)[:25000]
        html = raw.decode("utf-8", errors="ignore")
        html = re.sub(r"<(script|style|nav|header|footer)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
        paragraphs = re.findall(r"<p[^>]*>(.*?)</p>", html, flags=re.S | re.I)
        cleaned_p = [clean_text(p) for p in paragraphs if len(clean_text(p)) > 50]
        if cleaned_p:
            return " ".join(cleaned_p[:3])[:600]
        return clean_text(html)[:500]
    except Exception:
        return ""


HN_ALGOLIA_URL = (
    "https://hn.algolia.com/api/v1/search"
    "?tags=story&numericFilters=created_at_i>{}&hitsPerPage=15"
)


def get_hacker_news(limit: int = 10) -> list[dict]:
    results = []
    cutoff = int(datetime.now(timezone.utc).timestamp()) - 86400
    try:
        data = json.loads(fetch_url(HN_ALGOLIA_URL.format(cutoff), timeout=10).decode("utf-8"))
        hits = data.get("hits", [])
        hits.sort(key=lambda h: h.get("points") or 0, reverse=True)

        for hit in hits:
            if len(results) >= limit:
                break
            title = clean_text(hit.get("title", ""))
            url = hit.get("url") or ""
            score = hit.get("points") or 0
            comments = hit.get("num_comments") or 0
            domain = (
                re.sub(r"^https?://(?:www\.)?([^/]+).*$", r"\1", url)
                if url
                else "news.ycombinator.com"
            )

            snippet = extract_article_snippet(url) if url else clean_text(hit.get("story_text") or "")[:500]
            raw_summary = snippet if snippet else f"{title} ({domain})."

            results.append({
                "id": f"HN #{len(results)+1} | {domain[:24]}",
                "headline": smart_truncate(title, 34),
                "summary": smart_truncate(raw_summary, 220),
                "meta": f"{score} pts | {comments} comments | {domain[:18]}",
            })
    except Exception as exc:
        print(f"[ERROR] Hacker News Algolia fetch failed: {exc}")

    if not results:
        return [{
            "id": "HN-OFFLINE",
            "headline": "Hacker News unreachable",
            "summary": "Hacker News Algolia API did not respond during build.",
            "meta": "Retry next cycle",
        }]
    return results


def build_pages(sec_items: list[dict], retro_items: list[dict], hn_items: list[dict], stamp: str) -> dict:
    pages = {}

    # --- PAGE 100: INDEX ---
    p100 = [
        {"t": "banner", "s": "  NERD-TEXT // TECH & RETRO TELETEXT  "},
        {"t": "sep", "s": "=" * 40},
        {"t": "sec_cyan", "s": "SECURITY & LINUX ADVISORIES     [200]"},
    ]
    for idx, item in enumerate(sec_items[:2], start=201):
        p100.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})

    p100.append({"t": "blank", "s": ""})
    p100.append({"t": "sec_green", "s": "RETRO GAMING & HANDHELDS        [300]"})
    for idx, item in enumerate(retro_items[:2], start=301):
        p100.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})

    p100.append({"t": "blank", "s": ""})
    p100.append({"t": "item_yel", "s": "TOP 10 HACKER NEWS              [400]"})
    for idx, item in enumerate(hn_items[:3], start=401):
        p100.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})

    p100.extend([
        {"t": "sep", "s": "-" * 40},
        {"t": "item_yel", "s": AD_SLOT},
        {"t": "nav", "s": "[200] Sec  [300] Retro  [400] HN  [999]"},
    ])
    pages["100"] = {"title": "INDEX", "next": "200", "prev": "999", "lines": p100}

    # --- PAGE 200: SECURITY OVERVIEW ---
    p200 = [
        {"t": "hdr_red", "s": "CISA KEV & LINUX SECURITY (DSA/USN)"},
        {"t": "sep", "s": "=" * 40},
    ]
    for idx, item in enumerate(sec_items, start=201):
        p200.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})
        p200.extend({"t": "body", "s": l} for l in preview_2_lines(item["summary"], "     "))
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

    # --- PAGE 300: RETRO GAMING OVERVIEW ---
    p300 = [
        {"t": "hdr_grn", "s": "RETRO GAMING, HANDHELDS & ROMHACKS"},
        {"t": "sep", "s": "=" * 40},
    ]
    for idx, item in enumerate(retro_items, start=301):
        p300.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})
        p300.extend({"t": "body", "s": l} for l in preview_2_lines(item["summary"], "     "))
    p300.append({"t": "nav", "s": "[100] Index      [301] Details     [400]"})
    pages["300"] = {"title": "RETRO GAMES", "next": "301", "prev": "200", "lines": p300}

    # --- PAGES 301..30N: RETRO DETAILS ---
    for i, item in enumerate(retro_items):
        pg = str(301 + i)
        nxt = str(301 + i + 1) if i + 1 < len(retro_items) else "400"
        prv = str(301 + i - 1) if i > 0 else "300"
        lines = [
            {"t": "hdr_grn", "s": f"RETRO LOG ({i+1}/{len(retro_items)})"},
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

    # --- PAGE 400: TOP 10 HACKER NEWS OVERVIEW ---
    p400 = [
        {"t": "banner", "s": "  TOP 10 HACKER NEWS // FRONT PAGE    "},
        {"t": "sep", "s": "=" * 40},
    ]
    for idx, item in enumerate(hn_items, start=401):
        p400.append({"t": "link", "p": str(idx), "s": f"{idx}  {item['headline'][:35]}"})
    p400.extend([
        {"t": "blank", "s": ""},
        {"t": "sep", "s": "-" * 40},
        {"t": "nav", "s": "[100] Index      [401] Story 1     [999]"},
    ])
    pages["400"] = {"title": "HACKER NEWS", "next": "401", "prev": "300", "lines": p400}

    # --- PAGES 401..410: HACKER NEWS DETAILS ---
    for i, item in enumerate(hn_items):
        pg = str(401 + i)
        nxt = str(401 + i + 1) if i + 1 < len(hn_items) else "999"
        prv = str(401 + i - 1) if i > 0 else "400"
        lines = [
            {"t": "banner", "s": f"  HACKER NEWS ({i+1}/{len(hn_items)})                  "[:40]},
            {"t": "sep", "s": "=" * 40},
            {"t": "item_yel", "s": f"> {item['id']}"[:40]},
        ]
        lines.extend({"t": "sec_cyan", "s": l} for l in wrap_40(item["headline"], "  "))
        lines.append({"t": "blank", "s": ""})
        lines.extend({"t": "body", "s": l} for l in wrap_40(item["summary"], "  ")[:6])
        lines.append({"t": "blank", "s": ""})
        lines.extend({"t": "warn_grn", "s": l} for l in wrap_40(item["meta"], "  "))
        lines.append({"t": "nav", "s": f"[100] Index  [{prv}] Prev  [{nxt}] Next"})
        pages[pg] = {"title": f"HN #{i+1}", "next": nxt, "prev": prv, "lines": lines}

    # --- PAGE 999: INFO & SPONSORING ---
    pages["999"] = {
        "title": "INFO",
        "next": "100",
        "prev": "400",
        "lines": [
            {"t": "hdr_mag", "s": "ABOUT NERD-TEXT // ARCHITECTURE"},
            {"t": "sep", "s": "=" * 40},
            {"t": "body", "s": "No tracking. No popups. Finite pages."},
            {"t": "body", "s": "200: Security | 300: Retro | 400: HN"},
            {"t": "blank", "s": ""},
            {"t": "sec_cyan", "s": "SPONSORING (1 LINE / 40 CHARS):"},
            {"t": "item_yel", "s": f"  Contact: {AD_EMAIL}"},
            {"t": "blank", "s": ""},
            {"t": "sec_cyan", "s": "TERMINAL / CURL ACCESS:"},
            {"t": "item_yel", "s": "  $ curl <host>/100.txt"},
            {"t": "item_yel", "s": "  $ curl <host>/all.txt"},
            {"t": "blank", "s": ""},
            {"t": "body", "s": f"Last build: {stamp} UTC"},
            {"t": "nav", "s": "[100] Index   [200] Sec   [400] HN"},
        ],
    }

    return pages


def render_plain_txt(page_num: str, page_obj: dict, stamp: str) -> str:
    header = f"P{page_num}  NERD-TEXT {page_num}   {stamp} UTC"[:40].ljust(40)
    out = [header, "=" * 40]
    for line in page_obj["lines"]:
        out.append(line["s"][:40].ljust(40))
    out.append("-" * 40)
    out.append(AD_SLOT)
    out.append("=" * 40)
    out.append("100:IDX  200:SEC  300:RETRO  400:HN".ljust(40))
    return "\n".join(out) + "\n"


def main() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    now_utc = datetime.now(timezone.utc)
    stamp = now_utc.strftime("%d.%m.%y %H:%M")

    print("[1/5] Fetching CISA KEV & Linux Security feeds...")
    sec_items = get_security_items()
    llm_sec = summarize_with_llm(sec_items, "Cybersecurity, CVEs & Linux Advisories")
    if llm_sec:
        for orig, refined in zip(sec_items, llm_sec):
            orig["headline"] = smart_truncate(clean_text(refined.get("headline", orig["headline"])), 34)
            orig["summary"] = smart_truncate(clean_text(refined.get("summary", orig["summary"])), 220)

    print("[2/5] Fetching Retro Gaming & Handheld feeds...")
    retro_items = get_retro_games(limit=5)
    llm_retro = summarize_with_llm(retro_items, "Retro Gaming, Handhelds & ROM Hacks")
    if llm_retro:
        for orig, refined in zip(retro_items, llm_retro):
            orig["headline"] = smart_truncate(clean_text(refined.get("headline", orig["headline"])), 34)
            orig["summary"] = smart_truncate(clean_text(refined.get("summary", orig["summary"])), 220)

    print("[3/5] Fetching Top 10 Hacker News stories...")
    hn_items = get_hacker_news(limit=10)
    hn_rules = (
        "3) NEVER start 'headline' with a website/domain name like GitHub/, Blog/, News/, Reuters/, or BBC/ — "
        "always start directly with the project, company, or core topic (e.g. 'JaneStreet: Socratic AI').\n"
    )
    llm_hn = summarize_with_llm(hn_items, "Hacker News Tech & Programming Stories", extra_rules=hn_rules)
    if llm_hn:
        for orig, refined in zip(hn_items, llm_hn):
            orig["headline"] = smart_truncate(clean_text(refined.get("headline", orig["headline"])), 34)
            orig["summary"] = smart_truncate(clean_text(refined.get("summary", orig["summary"])), 220)

    print("[4/5] Building 40-char Teletext grid...")
    pages = build_pages(sec_items, retro_items, hn_items, stamp)

    payload = {"generated_utc": now_utc.isoformat(), "pages": pages}
    (DIST_DIR / "pages.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("[5/5] Writing plain-text pages & offline bundle...")
    bundle_parts = []
    for pg_num in sorted(pages.keys(), key=int):
        txt_content = render_plain_txt(pg_num, pages[pg_num], stamp)
        (DIST_DIR / f"{pg_num}.txt").write_text(txt_content, encoding="utf-8")
        bundle_parts.append(txt_content)

    (DIST_DIR / "all.txt").write_text("\n".join(bundle_parts), encoding="utf-8")
    print(f"[DONE] Built {len(pages)} pages + all.txt into ./{DIST_DIR}/")


if __name__ == "__main__":
    main()