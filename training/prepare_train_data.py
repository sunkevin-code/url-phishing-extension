#!/usr/bin/env python3
"""
Prepare a larger, more diverse training dataset from the full corpus CSV.

Unlike generate_corpus_samples.py (which produces the 500+500 test corpus),
this produces a larger training set for model retraining. More benign samples
— especially cloud/CDN/bank/commercial domains — directly reduce false positives.

Output: training/train_data.json  { phishing: [...], benign: [...] }
"""

import csv, json, os, random
from urllib.parse import urlparse

CSV_PATH = r"C:\Users\OseasyVM\Documents\corpus_export_2026-07-21.csv"
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "train_data.json")

PHISH_N = 3000
BENIGN_N = 3000

SUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".click",".download",
            ".review",".trade",".bid",".win",".stream",".racing",".science",".cyou",
            ".monster",".quest",".lol",".live",".shop",".ren",".date",".men",".loan",".party"]
SEC_KW = ["login","signin","verify","secure","account","update","confirm","bank","paypal",
          "password","wallet","credit","authenticate","security","unusual","suspended",
          "claim","bonus","airdrop","reward","restore","unlock","validate","recover","reset"]
HOSTING = ["pages.dev","netlify.app","vercel.app","github.io","firebaseapp.com",
           "azurewebsites.net","herokuapp.com","fly.dev","railway.app","onrender.com",
           "glitch.me","replit.app","blogspot","wixsite","weebly","webflow.io"]

def is_valid_url(u):
    if not u or len(u) < 5 or len(u) > 500: return False
    try:
        p = urlparse(u)
        return p.scheme in ("http","https") and bool(p.netloc)
    except: return False

def domain(u):
    try: return urlparse(u).netloc.replace("www.","").lower()
    except: return ""

def main():
    phishing = []
    benign = []
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url","").strip()
            if not is_valid_url(url): continue
            label = row.get("label","")
            if label == "phish":
                # quality heuristic: prefer URLs with strong phishing signals
                u = url.lower()
                q = (1 if row.get("has_password","").strip()=="True" else 0) + \
                    (1 if row.get("target_brand","").strip() else 0) + \
                    (1 if any(k in u for k in SEC_KW) else 0) + \
                    (1 if any(t in u for t in SUS_TLDS) else 0) + \
                    (1 if any(h in u for h in HOSTING) else 0)
                phishing.append((q, url))
            elif label == "benign":
                benign.append(url)

    # Sort phishing by quality desc, then take top + fill
    phishing.sort(key=lambda x: -x[0])
    phish_urls = [u for _, u in phishing[:PHISH_N]]

    # Dedup benign by domain for diversity
    seen = set(); benign_dedup = []
    for u in benign:
        d = domain(u)
        if d and d not in seen:
            seen.add(d); benign_dedup.append(u)
    random.shuffle(benign_dedup)
    benign_urls = benign_dedup[:BENIGN_N]

    # Dedup phishing by domain too
    seen_p = set(); phish_dedup = []
    for u in phish_urls:
        d = domain(u)
        if d and d not in seen_p:
            seen_p.add(d); phish_dedup.append(u)
    phish_urls = phish_dedup[:PHISH_N]

    out = {"phishing": phish_urls, "benign": benign_urls}
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"Phishing: {len(phish_urls)} (from {len(phishing)} candidates)")
    print(f"Benign:   {len(benign_urls)} (from {len(benign_dedup)} unique domains)")
    print(f"Written:  {OUTPUT}")

    # sanity: TLD diversity
    from collections import Counter
    bt = Counter(domain(u).split('.')[-1] for u in benign_urls if domain(u))
    print("\nBenign TLD diversity (top 15):")
    for t, c in bt.most_common(15): print(f"  .{t}: {c}")

if __name__ == "__main__":
    main()
