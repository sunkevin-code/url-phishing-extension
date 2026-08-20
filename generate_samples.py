import json, random

random.seed(42)

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

phishing = []

# 1) Brand typosquatting on bad TLDs
for b in random.sample(brands, min(30, len(brands))):
    for tld in random.sample(tlds_bad, 2):
        phishing.append(f"https://www.{b}-login.{tld}/login")
        phishing.append(f"https://{b}-verify.{tld}/signin")

# 2) Homoglyph/leet substitutions
subs = {"o":"0","i":"1","l":"1","e":"3","a":"4","s":"5","t":"7","b":"8","g":"9"}
for b in random.sample(brands, min(25, len(brands))):
    sb = "".join(subs.get(c,c) for c in b)
    if sb != b:
        phishing.append(f"https://www.{sb}.com/login")
        phishing.append(f"https://{sb}-secure.com/account")

# 3) Brand on third-party platforms
for b in random.sample(brands, min(20, len(brands))):
    for p in random.sample(platforms, 2):
        phishing.append(f"https://{b}-secure.{p}/login")
        phishing.append(f"https://{b}-verify.{p}/auth")

# 4) IP-based hosts
for b in random.sample(brands, min(15, len(brands))):
    ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    phishing.append(f"http://{ip}/{b}/login")
    phishing.append(f"http://{ip}/{b}-verify/secure")

# 5) Multi-subdomain
for b in random.sample(brands, min(15, len(brands))):
    for tld in random.sample(tlds_bad, 2):
        phishing.append(f"https://{b}.com.login.verify.{tld}/")
        phishing.append(f"https://account.{b}.secure.auth.{tld}/signin")

# 6) Brand + suspicious paths
for b in random.sample(brands, min(25, len(brands))):
    for p in random.sample(paths, 2):
        tld = random.choice(tlds_bad)
        phishing.append(f"https://{b}-{p}.{tld}/{p}")

# 7) Hex-encoded paths
for b in random.sample(brands, min(15, len(brands))):
    hexpath = "".join(f"%{random.choice(hex_chars)}{random.choice(hex_chars)}" for _ in range(8))
    phishing.append(f"https://{b}-safe.com/login?token={hexpath}")

# 8) Long/random domains
for i in range(30):
    rdom = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(16,30)))
    tld = random.choice(tlds_bad)
    phishing.append(f"https://{rdom}.{tld}/login")

# 9) Shortened URLs
shorteners = ["bit.ly","tinyurl.com","cutt.ly","shorturl.at","rb.gy","tiny.cc","is.gd","ow.ly","buff.ly","t.co"]
for i in range(20):
    s = random.choice(shorteners)
    randid = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(5,9)))
    phishing.append(f"https://{s}/{randid}")

# 10) Service spoofing in subdomain
services = ["paypal","google","facebook","apple","microsoft","amazon","netflix","binance","coinbase","metamask"]
for s in random.sample(services, min(len(services), 8)):
    for tld in random.sample(tlds_bad, 2):
        phishing.append(f"https://{s}-service.{tld}/verify")
        phishing.append(f"https://{s}.account.recover.{tld}/login")

# Shuffle
random.shuffle(phishing)
phishing = phishing[:300]

# ====== BENIGN URLs ======
benign = [
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
    "https://www.w3.org","https://www.npmjs.com","https://www.pypi.org",
    "https://www.docker.com","https://www.kubernetes.io","https://www.terraform.io",
    "https://www.ansible.com","https://www.jenkins.io","https://www.gitlab.com",
    "https://www.bitbucket.org","https://www.atlassian.com","https://www.figma.com",
    "https://www.notion.so","https://www.slack.com","https://www.zoom.us",
    "https://www.harvard.edu","https://www.mit.edu","https://www.stanford.edu",
    "https://www.ox.ac.uk","https://www.cam.ac.uk","https://www.berkeley.edu",
    "https://www.yale.edu","https://www.princeton.edu","https://www.whitehouse.gov","https://www.nasa.gov",
    "https://www.nih.gov","https://www.cdc.gov","https://www.who.int",
    "https://www.un.org","https://www.worldbank.org","https://www.imf.org",
    "https://www.nationalgeographic.com","https://www.nature.com",
    "https://www.medium.com","https://www.quora.com","https://www.producthunt.com",
    "https://www.techcrunch.com","https://www.wired.com","https://www.theverge.com",
    "https://www.arstechnica.com","https://www.stackexchange.com","https://www.wikihow.com","https://www.khanacademy.org",
    "https://www.coursera.org","https://www.udemy.com","https://www.edx.org",
    "https://www.codecademy.com","https://www.freecodecamp.org","https://www.hackerrank.com",
    "https://www.leetcode.com","https://www.geeksforgeeks.org",
]

data = {"phishing": phishing, "benign": benign}
import os
outdir = os.path.dirname(os.path.abspath(__file__))
outpath = os.path.join(outdir, "samples.json")
with open(outpath, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print(f"Generated {len(phishing)} phishing + {len(benign)} benign = {len(phishing)+len(benign)} total URLs")
print(f"Saved to: {outpath}")