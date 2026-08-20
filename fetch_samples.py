"""Fetch phishing URLs from OpenPhish, PhishTank, and generate synthetic samples.
Saves combined 1000-sample dataset to samples.json."""
import json, os, random, sys
from datetime import datetime

OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples.json")

# --- Generate synthetic phishing (400) ---
def gen_synthetic_phishing(n=400):
    brands = [
        "google","facebook","youtube","paypal","amazon","netflix","microsoft","apple",
        "binance","coinbase","metamask","instagram","twitter","whatsapp","telegram",
        "discord","tiktok","snapchat","linkedin","github","spotify","dropbox","steam",
        "epicgames","roblox","uber","airbnb","twitch","reddit","pinterest","shopify",
        "alibaba","taobao","tmall","jd","baidu","weixin","qq","alipay","weibo",
        "douyin","bilibili","zhihu","meituan","didi","bybit","okx","kucoin","kraken",
        "gemini","huobi","phantom","trustwallet","opensea","uniswap","pancakeswap",
        "hyperliquid","gmail","outlook","yahoo","icloud","protonmail","office365",
        "adobe","canva","figma","notion","slack","zoom","atlassian","salesforce"
    ]
    tlds_bad = ["tk","ml","ga","cf","gq","xyz","top","work","date","men","loan",
                "click","download","review","trade","bid","win","party","stream",
                "racing","accountant","science","webcam","country","faith","cricket"]
    platforms = ["wixsite.com","weebly.com","webflow.io","github.io","netlify.app",
                 "vercel.app","pages.dev","firebaseapp.com","herokuapp.com",
                 "000webhostapp.com","blogspot.com","wordpress.com","strikingly.com",
                 "site123.me","godaddysites.com","azurewebsites.net","fly.dev",
                 "railway.app","onrender.com","glitch.me","replit.app","surge.sh"]
    paths = ["login","signin","verify","secure","account","update","confirm","auth",
             "password","reset","recover","unlock","validate","check","claim","bonus",
             "airdrop","reward","promo","free","gift","winner","support","security",
             "wallet","restore","connect","access","admin","portal","dashboard"]
    hex_chars = "0123456789abcdef"
    subs = {"o":"0","i":"1","l":"1","e":"3","a":"4","s":"5","t":"7","b":"8","g":"9"}
    shorteners = ["bit.ly","tinyurl.com","cutt.ly","shorturl.at","rb.gy","tiny.cc","is.gd","ow.ly","buff.ly","t.co"]

    results = []

    def rpick(lst, k):
        return random.sample(lst, min(k, len(lst)))

    for b in rpick(brands, 30):
        for tld in rpick(tlds_bad, 2):
            results.extend([f"https://www.{b}-login.{tld}/login", f"https://{b}-verify.{tld}/signin"])
    for b in rpick(brands, 25):
        sb = "".join(subs.get(c,c) for c in b)
        if sb != b: results.extend([f"https://www.{sb}.com/login", f"https://{sb}-secure.com/account"])
    for b in rpick(brands, 20):
        for p in rpick(platforms, 2):
            results.extend([f"https://{b}-secure.{p}/login", f"https://{b}-verify.{p}/auth"])
    for b in rpick(brands, 20):
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        results.extend([f"http://{ip}/{b}/login"])
    for b in rpick(brands, 15):
        for tld in rpick(tlds_bad, 2):
            results.extend([f"https://{b}.com.login.verify.{tld}/", f"https://account.{b}.secure.auth.{tld}/login"])
    for b in rpick(brands, 25):
        for p in rpick(paths, 2):
            results.append(f"https://{b}-{p}.{random.choice(tlds_bad)}/{p}")
    for b in rpick(brands, 15):
        hexp = "".join(f"%{random.choice(hex_chars)}{random.choice(hex_chars)}" for _ in range(10))
        results.append(f"https://{b}-safe.com/login?token={hexp}")
    for _ in range(40):
        rdom = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(18,32)))
        results.append(f"https://{rdom}.{random.choice(tlds_bad)}/login")
    for _ in range(25):
        s = random.choice(shorteners)
        rid = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(5,9)))
        results.append(f"https://{s}/{rid}")
    services = ["paypal","google","facebook","apple","microsoft","amazon","netflix","binance","coinbase","metamask"]
    for s in rpick(services, 8):
        for tld in rpick(tlds_bad, 2):
            results.extend([f"https://{s}-service.{tld}/verify", f"https://{s}.account.recover.{tld}/login"])
    for b in rpick(brands, 15):
        tld = random.choice(tlds_bad)
        results.append(f"https://{b}-login-verify-secure.{tld}/account/auth/signin?redirect=login")
    for _ in range(20):
        r1 = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(8,15)))
        r2 = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(6,12)))
        results.append(f"https://{r1}.{r2}.{random.choice(tlds_bad)}/verify")
    for b in rpick(brands, 10):
        results.append(f"https://{b}-{random.choice(paths)}.{random.choice(platforms)}/{random.choice(paths)}")
    for _ in range(20):
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        results.append(f"http://{ip}:{random.choice([8080,8443,3000,5000,9000])}/login")
    for b in rpick(brands, 10):
        results.append(f"https://{b}0.com/login")
        results.append(f"https://{b}v.net/verify")

    random.shuffle(results)
    return results[:n]


# --- Fetch from OpenPhish ---
def fetch_openphish():
    """Try to fetch phishing URLs from OpenPhish feed."""
    try:
        import urllib.request, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request("https://openphish.com/feed.txt",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        urls = [line.strip() for line in text.split("\n") if line.strip().startswith("http")]
        return urls
    except Exception as e:
        print(f"  [OpenPhish] Fetch failed: {e}")
        return []


# --- Fetch from PhishTank ---
def fetch_phishtank():
    """Try to fetch from PhishTank public data."""
    try:
        import urllib.request, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request("https://data.phishtank.com/data/online-valid.json",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        urls = []
        for entry in data if isinstance(data, list) else data.get("data", []):
            url = entry.get("url") or entry.get("phish_detail_url")
            if url and url.startswith("http"): urls.append(url)
        return urls
    except Exception as e:
        print(f"  [PhishTank] Fetch failed: {e}")
        return []


# --- Benign URLs (100) ---
BENIGN_URLS = [
    "https://www.google.com","https://www.youtube.com","https://www.facebook.com",
    "https://www.instagram.com","https://www.x.com","https://www.linkedin.com",
    "https://www.microsoft.com","https://www.apple.com","https://www.amazon.com",
    "https://www.github.com","https://www.stackoverflow.com","https://www.wikipedia.org",
    "https://www.reddit.com","https://www.netflix.com","https://www.spotify.com",
    "https://www.dropbox.com","https://www.cloudflare.com","https://www.mozilla.org",
    "https://www.nytimes.com","https://www.bbc.com","https://www.baidu.com",
    "https://www.taobao.com","https://www.jd.com","https://www.zhihu.com",
    "https://www.bilibili.com","https://www.csdn.net","https://www.163.com",
    "https://www.qq.com","https://www.sina.com.cn","https://www.sohu.com",
    "https://www.ebay.com","https://www.paypal.com","https://www.adobe.com",
    "https://www.twitch.tv","https://www.salesforce.com","https://www.oracle.com",
    "https://www.ibm.com","https://www.intel.com","https://www.cisco.com",
    "https://www.nvidia.com","https://www.amd.com","https://www.bloomberg.com",
    "https://www.reuters.com","https://www.cnn.com","https://www.theguardian.com",
    "https://www.w3.org","https://www.npmjs.com","https://pypi.org",
    "https://www.docker.com","https://www.gitlab.com","https://www.atlassian.com",
    "https://www.figma.com","https://www.notion.so","https://www.slack.com",
    "https://www.zoom.us","https://www.udemy.com","https://www.coursera.org",
    "https://www.khanacademy.org","https://www.freecodecamp.org",
    "https://www.harvard.edu","https://www.mit.edu","https://www.stanford.edu",
    "https://www.nasa.gov","https://www.nih.gov","https://www.cdc.gov",
    "https://www.who.int","https://www.un.org","https://www.worldbank.org",
    "https://www.imf.org","https://www.nationalgeographic.com","https://www.nature.com",
    "https://www.medium.com","https://www.quora.com","https://www.producthunt.com",
    "https://www.techcrunch.com","https://www.wired.com","https://www.theverge.com",
    "https://www.arstechnica.com","https://www.stackexchange.com","https://www.wikihow.com",
    "https://www.hackerrank.com","https://www.leetcode.com","https://www.geeksforgeeks.org",
    "https://www.codecademy.com","https://www.science.org","https://arxiv.org",
    "https://www.ted.com","https://www.britannica.com","https://www.merriam-webster.com",
    "https://www.imdb.com","https://www.rottentomatoes.com","https://www.goodreads.com",
    "https://www.etsy.com","https://www.kickstarter.com","https://www.indeed.com",
    "https://www.glassdoor.com","https://www.monster.com","https://www.zillow.com",
    "https://www.webmd.com","https://www.mayoclinic.org","https://www.healthline.com",
]


def main():
    print("=" * 50)
    print("  Phishing URL Sample Fetcher")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    # 1. Generate synthetic phishing URLs
    print("\n[1/3] Generating synthetic phishing URLs...")
    synth = gen_synthetic_phishing(400)
    print(f"  Generated {len(synth)} synthetic phishing URLs")

    # 2. Fetch from OpenPhish
    print("\n[2/3] Fetching from OpenPhish...")
    op = fetch_openphish()
    print(f"  Fetched {len(op)} URLs from OpenPhish")

    # 3. Fetch from PhishTank
    print("\n[3/3] Fetching from PhishTank...")
    pt = fetch_phishtank()
    print(f"  Fetched {len(pt)} URLs from PhishTank")

    # Combine, deduplicate
    all_phish = list(dict.fromkeys(synth + op + pt))
    # Cap at 900 to make room for 100 benign = 1000 total
    all_phish = all_phish[:900]
    random.shuffle(all_phish)

    total = len(all_phish) + len(BENIGN_URLS)

    data = {
        "phishing": all_phish,
        "benign": BENIGN_URLS,
        "meta": {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "synthetic": len(synth),
            "openphish": len(op),
            "phishtank": len(pt),
            "total_phishing": len(all_phish),
            "total_benign": len(BENIGN_URLS),
            "total": total
        }
    }

    with open(OUTFILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"\n{'=' * 50}")
    print(f"  DONE: {total} total URLs")
    print(f"  Saved to: {OUTFILE}")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    main()