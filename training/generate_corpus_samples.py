#!/usr/bin/env python3
"""
Generate training & test samples from corpus CSV.
Outputs:
  corpus-samples.json     → test runner loadable JSON
  corpus-samples.js       → embedded JS for BUILTIN_*_LARGE vars
"""

import csv, json, os, re, random
from urllib.parse import urlparse

CSV_PATH = r"C:\Users\OseasyVM\Documents\corpus_export_2026-07-21.csv"
OUTPUT_JSON = os.path.join(os.path.dirname(__file__), "corpus-samples.json")
OUTPUT_JS = os.path.join(os.path.dirname(__file__), "corpus-samples.js")

SAMPLE_SIZE = 500  # balanced samples per class

def is_valid_url(url):
    if not url or len(url) < 5 or len(url) > 500:
        return False
    try:
        u = urlparse(url)
        return bool(u.scheme in ("http", "https") and u.netloc)
    except:
        return False

def extract_phishing_urls():
    """Extract phishing URLs from corpus, prioritizing those with security features."""
    phishing = []
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "").strip()
            if not is_valid_url(url):
                continue
            phishing.append({
                "url": url,
                "target_brand": row.get("target_brand", ""),
                "has_password": row.get("has_password", ""),
                "has_cross_origin_form": row.get("has_cross_origin_form", ""),
                "n_forms": row.get("n_forms", "0"),
                "page_lang": row.get("page_lang", ""),
                "tech": row.get("tech", ""),
                "title": row.get("title", "")
            })
    return phishing

def extract_benign_urls():
    """Extract benign URLs from corpus."""
    benign = []
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("label", "") != "benign":
                continue
            url = row.get("url", "").strip()
            if not is_valid_url(url):
                continue
            benign.append({
                "url": url,
                "target_brand": row.get("target_brand", ""),
                "title": row.get("title", "")
            })
    return benign

def deduplicate_by_domain(items, max_per_domain=3):
    """Keep at most max_per_domain URLs per domain for diversity."""
    domains = {}
    result = []
    for item in items:
        try:
            domain = urlparse(item["url"]).netloc.replace("www.", "")
        except:
            domain = "unknown"
        if domain not in domains:
            domains[domain] = 0
        if domains[domain] < max_per_domain:
            domains[domain] += 1
            result.append(item)
    return result

def main():
    print("=== Corpus-based Training Data Generator ===\n")

    print("Extracting phishing URLs...")
    all_phishing = extract_phishing_urls()
    print(f"  Found {len(all_phishing)} valid phishing URLs")

    print("Extracting benign URLs...")
    all_benign = extract_benign_urls()
    print(f"  Found {len(all_benign)} valid benign URLs")

    # Deduplicate
    all_phishing = deduplicate_by_domain(all_phishing, max_per_domain=2)
    all_benign = deduplicate_by_domain(all_benign, max_per_domain=2)
    print(f"  After dedup: {len(all_phishing)} phishing, {len(all_benign)} benign")

    # Balance and sample
    random.shuffle(all_phishing)
    random.shuffle(all_benign)

    sample_size = min(SAMPLE_SIZE, len(all_phishing), len(all_benign))
    phish_sample = all_phishing[:sample_size]
    benign_sample = all_benign[:sample_size]

    # Categorize phishing by type for quality
    categorized = {"password": [], "redirect": [], "brand": [], "suspicious_url": []}
    for p in all_phishing:
        url_lower = p["url"].lower()
        has_pwd = p.get("has_password", "").strip() == "True"
        has_cross = p.get("has_cross_origin_form", "").strip() == "True"
        has_brand = bool(p.get("target_brand", "").strip())
        # URL-based heuristics for suspicious features
        has_security_kw = any(k in url_lower for k in ["login","signin","verify","secure","account","update","confirm","bank","paypal","password","wallet"])
        has_suspicious_tld = any(t in url_lower for t in [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".click",".download",".review",".trade",".bid",".win",".stream",".racing",".science",".cyou",".monster",".quest",".lol",".live",".shop"])
        has_suspicious_host = any(s in url_lower for s in ["bit.ly","tinyurl","pages.dev","netlify.app","vercel.app","github.io","firebaseapp.com","azurewebsites.net","herokuapp.com","fly.dev","railway.app","onrender.com","glitch.me","replit.app"])
        # Quality score: higher = more likely to be a real phishing page
        quality = (1 if has_pwd else 0) + (1 if has_brand else 0) + (1 if has_security_kw else 0) + (1 if has_suspicious_tld else 0) + (1 if has_suspicious_host else 0)
        if quality >= 2:
            cat = "password" if has_pwd else "brand" if has_brand else "redirect" if has_cross else "suspicious_url"
            categorized[cat].append(p)

    # Build diverse sample
    diverse_phishing = []
    per_cat = sample_size // 4
    for cat in ["password", "brand", "suspicious_url", "redirect"]:
        items = categorized[cat][:per_cat]
        diverse_phishing.extend(items)

    # Fill remaining if needed
    if len(diverse_phishing) < sample_size:
        remaining = [p for p in all_phishing if p not in diverse_phishing]
        diverse_phishing.extend(remaining[:sample_size - len(diverse_phishing)])

    random.shuffle(diverse_phishing)

    # Build output
    phish_urls = [p["url"] for p in diverse_phishing[:sample_size]]
    benign_urls = [b["url"] for b in benign_sample[:sample_size]]

    # Write JSON (for test runner file load)
    json_output = {"phishing": phish_urls, "benign": benign_urls}
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(json_output, f, indent=2, ensure_ascii=False)
    print(f"\nJSON written: {OUTPUT_JSON}")

    # Write JS (for embedding as BUILTIN_*_LARGE)
    js_phish = json.dumps(phish_urls, indent=2, ensure_ascii=False)
    js_benign = json.dumps(benign_urls, indent=2, ensure_ascii=False)
    js_content = f"""// Auto-generated corpus samples
var BUILTIN_PHISHING_LARGE = {js_phish};
var BUILTIN_BENIGN_LARGE = {js_benign};
"""
    with open(OUTPUT_JS, "w", encoding="utf-8") as f:
        f.write(js_content)
    print(f"JS written: {OUTPUT_JS}")

    # Stats
    print(f"\n=== Summary ===")
    print(f"  Phishing: {len(phish_urls)} URLs")
    print(f"  Benign:   {len(benign_urls)} URLs")
    print(f"  Total:    {len(phish_urls) + len(benign_urls)} URLs")

    # Sample URLs
    print(f"\n=== Sample phishing URLs ===")
    for u in phish_urls[:5]:
        print(f"  {u}")
    print(f"\n=== Sample benign URLs ===")
    for u in benign_urls[:5]:
        print(f"  {u}")

if __name__ == "__main__":
    main()
