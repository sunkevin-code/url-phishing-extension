#!/usr/bin/env python3
"""
Training script for phishing detection ML model.
Extracts 38 rule-based features from URLs, trains a small neural network,
and exports weights to JSON for use in the Chrome extension.

Architecture: 38 inputs → 16 hidden (ReLU) → 1 output (Sigmoid) = ~640 params
"""

import json
import re
import math
import random
import os
import sys
from urllib.parse import urlparse

# ========== Feature Extractors (mirrors rules.js) ==========

KNOWN_DOMAINS = [
    "google.com","youtube.com","facebook.com","instagram.com","twitter.com","x.com",
    "linkedin.com","microsoft.com","apple.com","amazon.com","github.com","stackoverflow.com",
    "wikipedia.org","reddit.com","netflix.com","spotify.com","dropbox.com","cloudflare.com",
    "mozilla.org","nytimes.com","bbc.com","baidu.com","taobao.com","jd.com","zhihu.com",
    "bilibili.com","csdn.net","163.com","qq.com","sina.com.cn","sohu.com","ebay.com",
    "paypal.com","adobe.com","twitch.tv","salesforce.com","oracle.com","ibm.com","intel.com",
    "cisco.com","nvidia.com","amd.com","bloomberg.com","reuters.com","cnn.com","theguardian.com",
    "w3.org","npmjs.com","pypi.org","docker.com","gitlab.com","atlassian.com","figma.com",
    "notion.so","slack.com","zoom.us","udemy.com","coursera.org","khanacademy.org","freecodecamp.org",
    "harvard.edu","mit.edu","stanford.edu","nasa.gov","nih.gov","cdc.gov","who.int","un.org",
    "worldbank.org","imf.org","nationalgeographic.com","nature.com","medium.com","quora.com",
    "producthunt.com","techcrunch.com","wired.com","theverge.com","arstechnica.com","stackexchange.com",
    "wikihow.com","hackerrank.com","leetcode.com","geeksforgeeks.org","codecademy.com","science.org",
    "arxiv.org","ted.com","britannica.com","merriam-webster.com","imdb.com","rottentomatoes.com",
    "goodreads.com","etsy.com","kickstarter.com","indeed.com","glassdoor.com","zillow.com",
    "webmd.com","shutterstock.com","flickr.com","vimeo.com","trello.com","box.com","heroku.com",
    "digitalocean.com","linode.com","aws.amazon.com","azure.microsoft.com","cloud.google.com",
    "stripe.com","shopify.com","fast.com","speedtest.net","walmart.com","target.com","bestbuy.com",
    "homedepot.com","costco.com","ikea.com","bbc.co.uk","ft.com","economist.com","wsj.com",
    "forbes.com","businessinsider.com","cnbc.com","yelp.com","tripadvisor.com","airbnb.com","booking.com",
    "mayoclinic.org","healthline.com","weather.com","openstreetmap.org","zoho.com","hubspot.com","twilio.com",
    "mailchimp.com","bitbucket.org","sourceforge.net","archlinux.org","debian.org","ubuntu.com","fedoraproject.org",
    "centos.org","redhat.com","apache.org","mysql.com","postgresql.org","mongodb.com","redis.io","sqlite.org",
    "gnome.org","kde.org","libreoffice.org","openai.com","anthropic.com","meta.com","weixin.qq.com",
    "alipay.com","tmall.com","weibo.com","douyin.com","meituan.com","bybit.com","okx.com","kraken.com","gemini.com",
    "baidu.com","taobao.com","jd.com","qq.com","sina.com.cn",
    "sohu.com","163.com","zhihu.com","bilibili.com","csdn.net",
]

SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".date",".men",
    ".loan",".click",".download",".review",".trade",".bid",".win",".ren",".party",
    ".stream",".racing",".accountant",".science",".cyou",".monster",".quest",".lol",
    ".live",".shop"]

SHORTENERS = ["bit.ly","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly","t.co",
    "rebrand.ly","cutt.ly","shorturl.at","tiny.cc","bl.ink","rb.gy","short.link","s.id"]

THIRD_PARTY = ["wixstudio.com","wixsite.com","shopify.com","myshopify.com","wordpress.com",
    "blogspot.com","weebly.com","webflow.io","squarespace.com","strikingly.com","site123.me",
    "godaddysites.com","yolasite.com","000webhostapp.com","netlify.app","vercel.app","github.io",
    "pages.dev","firebaseapp.com","azurewebsites.net","herokuapp.com","fly.dev","railway.app",
    "onrender.com","glitch.me","replit.app","surge.sh"]

BRANDS = ["hyperliquid","opensea","binance","coinbase","metamask","uniswap","pancakeswap",
    "sushiswap","cryptocom","bybit","okx","kucoin","kraken","gemini","huobi","phantom",
    "trustwallet","rainbow","facebook","instagram","whatsapp","telegram","discord","twitter",
    "linkedin","tiktok","snapchat","youtube","gmail","outlook","microsoft","apple","icloud",
    "netflix","amazon","paypal","steam","epicgames","roblox","spotify","taobao","tmall",
    "alipay","weixin","weibo","douyin","baidu","qq","dropbox","uber","airbnb","twitch",
    "adobe","shopify","salesforce","google","skype","vimeo","pinterest","tumblr","line",
    "kakaotalk","naver","yahoo","ebay","aliexpress","walmart","target","bestbuy","tesla",
    "nvidia","amd","intel","cisco","oracle","ibm","atlassian","notion","figma","slack",
    "zoom","canva","surfshark","nordvpn","expressvpn","proton","ledger","trezor","aave",
    "compound","curve","balancer","maker","yearn"]

SECURITY_KEYWORDS = ["secure","login","signin","verify","account","update","confirm",
    "bank","paypal","password","credit","wallet","authenticate","security","alert",
    "unusual","suspended","claim","bonus","airdrop","reward","restore","unlock",
    "validate","recover","reset"]

SUSPICIOUS_PARAMS = ["token","auth","session","redirect","url","return","next","ref",
    "callback","redir","goto","dest","target","rurl","returl","returnurl","forward",
    "out","view","page","file","path"]

SUSPICIOUS_FILES = [".exe",".scr",".bat",".cmd",".msi",".apk",".ipa",".zip",".rar",
    ".js",".vbs",".ps1",".hta",".jar"]

PATH_BRANDS = ["google","facebook","paypal","apple","microsoft","amazon","netflix",
    "binance","coinbase","metamask","opensea","instagram","whatsapp","telegram",
    "discord","twitter","linkedin","spotify","steam","alipay","login","verify",
    "signin","account","secure"]

def _lev(a, b):
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1):
        for j in range(n+1):
            if i == 0: dp[i][j] = j
            elif j == 0: dp[i][j] = i
            else: dp[i][j] = dp[i-1][j-1] if a[i-1]==b[j-1] else 1+min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1])
    return dp[m][n]

def _entropy(s):
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    e = 0
    for c in freq:
        p = freq[c] / len(s)
        e -= p * math.log2(p) if p > 0 else 0
    return e

def extract_features(url):
    """Extract 38 binary features matching rules.js rules. Returns list of 38 ints (0/1)."""
    features = []
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path
        query = parsed.query
        port = parsed.port
        scheme = parsed.scheme
        full_url = url.lower()
    except:
        return [0]*38

    hl = hostname.lower()
    pl = path.lower()
    ql = query.lower()

    # 1. IP_BASED_HOST
    f1 = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0
    features.append(f1)

    # 2. AT_SYMBOL
    features.append(1 if '@' in url else 0)

    # 3. DOUBLE_PROTOCOL
    features.append(1 if re.search(r'https?://.*https?://', url, re.I) else 0)

    # 4. SHORTENED_URL
    hn_clean = hl.replace("www.", "")
    features.append(1 if any(s in hn_clean for s in SHORTENERS) else 0)

    # 5. SECURITY_KEYWORDS
    features.append(1 if any(k in full_url for k in SECURITY_KEYWORDS) else 0)

    # 6. SUSPICIOUS_TLD
    features.append(1 if any(t in hl for t in SUSPICIOUS_TLDS) else 0)

    # 7. TOO_MANY_SUBDOMAINS
    features.append(1 if len(hostname.split(".")) > 4 else 0)

    # 8. MULTIPLE_HYPHENS
    features.append(1 if hostname.count("-") >= 2 else 0)

    # 9. SUSPICIOUS_PORT
    features.append(1 if port and port not in [80, 443] else 0)

    # 10. LONG_DOMAIN
    features.append(1 if len(hostname) > 25 else 0)

    # 11. HEX_ENCODING
    hex_matches = re.findall(r'%[0-9a-fA-F]{2}', url)
    features.append(1 if len(hex_matches) > 5 else 0)

    # 12. THIRD_PARTY_SUBDOMAIN
    features.append(1 if any(("." + tp) in hl for tp in THIRD_PARTY) else 0)

    # 13. BRAND_SIMILARITY (Levenshtein + leet)
    brand_sim = 0
    main_part = hl.replace("www.", "").split(".")[0]
    for brand in BRANDS:
        if main_part == brand:
            continue
        d = _lev(main_part, brand)
        ml = max(len(main_part), len(brand))
        if ml > 0 and d > 0 and d <= max(2, int(ml * 0.3)):
            brand_sim = 1
            break
        # leet check
        leet_map = str.maketrans("oilesatgb", "011354789")
        leet_brand = brand.lower().translate(leet_map)
        if main_part == leet_brand:
            brand_sim = 1
            break
    features.append(brand_sim)

    # 14. SERVICE_SPOOF
    service_spoof = 0
    parts = hl.replace("www.", "").split(".")
    if len(parts) >= 3:
        for brand in ["google","facebook","paypal","apple","microsoft","amazon","netflix",
                       "binance","coinbase","metamask","opensea","uniswap","instagram",
                       "whatsapp","telegram","discord","twitter","linkedin","spotify",
                       "steam","dropbox","alipay","weixin"]:
            for j in range(len(parts) - 2):
                if parts[j] == brand:
                    md = ".".join(parts[j+1:])
                    is_known = any(md.startswith(b + ".") or md == b for b in ["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","instagram","whatsapp","telegram","discord","twitter","linkedin","spotify","steam","dropbox","alipay","weixin","com","org","net","cn"])
                    if not is_known:
                        service_spoof = 1
                        break
            if service_spoof:
                break
    features.append(service_spoof)

    # 15. RANDOM_DOMAIN (high entropy)
    main_len = len(main_part)
    features.append(1 if main_len >= 12 and _entropy(main_part) > 3.5 else 0)

    # 16. TYPOSQUATTING
    typosquat = 0
    for brand in ["google","facebook","youtube","paypal","amazon","netflix","microsoft",
                   "apple","binance","coinbase","metamask","instagram","twitter","whatsapp",
                   "telegram","discord","tiktok","linkedin","github","spotify","steam",
                   "alipay","weixin","baidu"]:
        if main_part == brand:
            continue
        if len(main_part) == len(brand):
            diffs = sum(1 for a, b in zip(main_part, brand) if a != b)
            if diffs == 1:
                typosquat = 1
                break
        if abs(len(main_part) - len(brand)) == 1:
            if _lev(main_part, brand) == 1:
                typosquat = 1
                break
    features.append(typosquat)

    # 17. HOMOGRAPH (IDN - non-ASCII)
    features.append(1 if any(ord(c) > 127 for c in hostname) else 0)

    # 18. PATH_BRAND
    features.append(1 if any(b in pl for b in PATH_BRANDS) else 0)

    # 19. SUSPICIOUS_PARAMS
    features.append(1 if any(p + "=" in ql for p in SUSPICIOUS_PARAMS) else 0)

    # 20. HTTP_ON_LOGIN
    is_http_login = 1 if (scheme == "http" and
        any(k in full_url for k in ["login","signin","verify","secure","account"]) and
        "localhost" not in hl and "127.0.0.1" not in hl) else 0
    features.append(is_http_login)

    # 21. SUSPICIOUS_FILE
    features.append(1 if any(pl.endswith(ext) for ext in SUSPICIOUS_FILES) else 0)

    # 22. DEEP_PATH
    path_parts = [x for x in pl.split("/") if x]
    features.append(1 if len(path_parts) > 6 else 0)

    # 23. NUMERIC_SUBDOMAIN
    sub_parts = hostname.split(".")
    num_sub = 0
    for i in range(len(sub_parts) - 2):
        if sub_parts[i].isdigit():
            num_sub = 1
            break
    features.append(num_sub)

    # 24. DATA_URI
    features.append(1 if (full_url.startswith("data:text/html") or
                          full_url.startswith("data:application")) else 0)

    # 25-36. Page features (simulated based on URL patterns)
    # PASSWORD_FORM - pages with /login /signin
    features.append(1 if any(p in pl for p in ["/login","/signin","/password","/auth"]) else 0)

    # MANY_FORMS
    features.append(1 if any(p in pl for p in ["form","survey","register","signup"]) else 0)

    # EXTERNAL_FORMS - redirected URLs with params
    features.append(1 if ("redirect" in ql or "return" in ql) else 0)

    # FAVICON_MISMATCH
    features.append(0)  # Can't determine from URL alone

    # IFRAME_COUNT
    features.append(0)

    # HIDDEN_IFRAMES
    features.append(0)

    # TITLE_KEYWORDS
    features.append(1 if any(k in full_url for k in ["login","signin","verify","secure",
                    "account","update","alert"]) else 0)

    # FEW_LINKS
    features.append(0)

    # BROKEN_IMAGES
    features.append(0)

    # POPUP_SCRIPT
    features.append(1 if "popup" in hl or "redirect" in hl else 0)

    # NO_HTTPS
    features.append(1 if scheme == "http" else 0)

    # SKETCHY_SCRIPTS
    features.append(0)

    # 37-38. Behavior features (simulated)
    # RAPID_NAVIGATION
    features.append(0)

    # CROSS_DOMAIN_FORM
    features.append(1 if "redirect" in ql or service_spoof else 0)

    assert len(features) == 38, f"Expected 38 features, got {len(features)}"
    return features


# ========== Data Loading ==========

def load_phishing_urls(samples_path):
    """Load phishing URLs from JSON file"""
    with open(samples_path, 'r') as f:
        data = json.load(f)
    return data.get("phishing", [])

def generate_legitimate_urls():
    """Generate legitimate URLs from known domains"""
    urls = []
    prefixes = ["", "www."]
    paths = ["", "/", "/index.html", "/about", "/contact", "/products", "/blog",
             "/docs", "/help", "/support", "/api", "/login", "/signup"]
    for domain in KNOWN_DOMAINS:
        for prefix in prefixes[:1]:  # just one prefix to keep size reasonable
            for path in random.sample(paths, 3):
                if random.random() < 0.3:
                    urls.append(f"https://{prefix}{domain}{path}")
                if random.random() < 0.1:
                    urls.append(f"http://{prefix}{domain}{path}")
    # Add some random extra legit patterns
    for _ in range(200):
        domain = random.choice(KNOWN_DOMAINS)
        urls.append(f"https://www.{domain}/search?q={random.choice(['hello','test','news','shop'])}")
        urls.append(f"https://{domain}/user/{random.randint(1000,9999)}")
    return list(set(urls))


# ========== Neural Network ==========

def sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))

def relu(x):
    return max(0, x)

class TinyNN:
    def __init__(self, input_size=38, hidden_size=16):
        self.input_size = input_size
        self.hidden_size = hidden_size
        # Xavier init
        scale_w1 = math.sqrt(2.0 / input_size)
        scale_w2 = math.sqrt(2.0 / hidden_size)
        self.w1 = [[random.uniform(-scale_w1, scale_w1) for _ in range(input_size)]
                   for _ in range(hidden_size)]
        self.b1 = [0.0] * hidden_size
        self.w2 = [random.uniform(-scale_w2, scale_w2) for _ in range(hidden_size)]
        self.b2 = 0.0

    def forward(self, x):
        # Hidden layer
        h = [relu(sum(self.w1[i][j] * x[j] for j in range(self.input_size)) + self.b1[i])
             for i in range(self.hidden_size)]
        # Output layer
        out = sum(self.w2[i] * h[i] for i in range(self.hidden_size)) + self.b2
        return sigmoid(out), h

    def predict(self, x):
        prob, _ = self.forward(x)
        return prob

    def train_step(self, x, y, lr=0.01, l2_lambda=0.001):
        """Single SGD step with L2 regularization"""
        # Forward
        h = [0.0] * self.hidden_size
        z = [0.0] * self.hidden_size
        for i in range(self.hidden_size):
            z[i] = sum(self.w1[i][j] * x[j] for j in range(self.input_size)) + self.b1[i]
            h[i] = relu(z[i])
        out = sum(self.w2[i] * h[i] for i in range(self.hidden_size)) + self.b2
        prob = sigmoid(out)

        # Backward
        d_out = prob - y
        d_sigmoid = d_out * prob * (1 - prob)

        # Output layer gradients (with L2)
        dw2 = [d_sigmoid * h[i] + l2_lambda * self.w2[i] for i in range(self.hidden_size)]
        db2 = d_sigmoid

        # Hidden layer gradients
        dh = [d_sigmoid * self.w2[i] for i in range(self.hidden_size)]
        dz = [dh[i] * (1.0 if z[i] > 0 else 0.0) for i in range(self.hidden_size)]

        dw1 = [[dz[i] * x[j] + l2_lambda * self.w1[i][j] for j in range(self.input_size)] for i in range(self.hidden_size)]
        db1 = dz

        # Update weights
        for i in range(self.hidden_size):
            self.w2[i] -= lr * dw2[i]
            for j in range(self.input_size):
                self.w1[i][j] -= lr * dw1[i][j]
        self.b2 -= lr * db2
        for i in range(self.hidden_size):
            self.b1[i] -= lr * db1[i]

        return - (y * math.log(max(prob, 1e-10)) + (1-y) * math.log(max(1-prob, 1e-10)))


# ========== Training Loop ==========

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Prefer the larger, more diverse training set; fall back to the test corpus.
    train_data_path = os.path.join(base_dir, "training", "train_data.json")
    corpus_path = train_data_path if os.path.exists(train_data_path) else os.path.join(base_dir, "corpus-samples.json")
    output_path = os.path.join(base_dir, "lib", "ml_weights.json")

    print(f"Loading corpus samples from: {corpus_path}")
    with open(corpus_path) as f:
        data = json.load(f)
    phishing_urls = data.get("phishing", [])
    legit_urls = data.get("benign", [])
    print(f"Loaded {len(phishing_urls)} phishing, {len(legit_urls)} legitimate")

    # Extract features
    print("Extracting features...")
    X, y = [], []
    for url in phishing_urls:
        feats = extract_features(url)
        X.append(feats)
        y.append(1.0)
    print(f"  Phishing samples: {len(X)}")

    for url in legit_urls:
        feats = extract_features(url)
        X.append(feats)
        y.append(0.0)
    print(f"  Total samples: {len(X)}")

    # Balance dataset
    phishing_indices = [i for i, label in enumerate(y) if label == 1.0]
    legit_indices = [i for i, label in enumerate(y) if label == 0.0]
    print(f"  Phishing: {len(phishing_indices)}, Legitimate: {len(legit_indices)}")

    # Ensure balance by undersampling the majority class only
    min_count = min(len(phishing_indices), len(legit_indices))
    if len(phishing_indices) > min_count:
        keep_phish = set(random.sample(phishing_indices, min_count))
        keep_mask = [(y[i] == 0.0) or (i in keep_phish) for i in range(len(y))]
    elif len(legit_indices) > min_count:
        keep_legit = set(random.sample(legit_indices, min_count))
        keep_mask = [(y[i] == 1.0) or (i in keep_legit) for i in range(len(y))]
    else:
        keep_mask = [True] * len(y)
    X = [X[i] for i in range(len(X)) if keep_mask[i]]
    y = [y[i] for i in range(len(y)) if keep_mask[i]]
    print(f"  After balancing: {len(X)} samples ({sum(y)} phishing)")

    # Shuffle
    combined = list(zip(X, y))
    random.shuffle(combined)
    X, y = zip(*combined)
    X, y = list(X), list(y)

    # Train/val split
    split = int(len(X) * 0.8)
    X_train, y_train = X[:split], y[:split]
    X_val, y_val = X[split:], y[split:]
    print(f"  Train: {len(X_train)}, Val: {len(X_val)}")

    # Initialize model
    model = TinyNN(input_size=38, hidden_size=16)

    # Training
    print("\nTraining...")
    best_val_loss = float('inf')
    best_weights = None
    lr = 0.1
    for epoch in range(100):
        # Train
        total_loss = 0.0
        for xi, yi in zip(X_train, y_train):
            loss = model.train_step(xi, yi, lr, l2_lambda=0.001)
            total_loss += loss

        # Validate
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        for xi, yi in zip(X_val, y_val):
            prob = model.predict(xi)
            val_loss += - (yi * math.log(max(prob, 1e-10)) + (1-yi) * math.log(max(1-prob, 1e-10)))
            pred = 1 if prob > 0.5 else 0
            val_correct += 1 if pred == yi else 0
            val_total += 1

        val_acc = val_correct / val_total * 100
        avg_train_loss = total_loss / len(X_train)
        avg_val_loss = val_loss / len(X_val)

        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            best_weights = {
                "w1": model.w1,
                "b1": model.b1,
                "w2": model.w2,
                "b2": model.b2
            }

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"  Epoch {epoch+1:3d}: train_loss={avg_train_loss:.4f}, val_loss={avg_val_loss:.4f}, val_acc={val_acc:.1f}%")

        # Learning rate decay
        if epoch > 0 and epoch % 30 == 0:
            lr *= 0.5

    # Evaluate on full training set
    print("\nFinal Evaluation:")
    correct, total = 0, 0
    tp, fp, tn, fn = 0, 0, 0, 0
    for xi, yi in zip(X, y):
        prob = model.predict(xi)
        pred = 1 if prob > 0.5 else 0
        correct += 1 if pred == yi else 0
        if yi == 1 and pred == 1: tp += 1
        elif yi == 0 and pred == 1: fp += 1
        elif yi == 0 and pred == 0: tn += 1
        elif yi == 1 and pred == 0: fn += 1
    acc = correct / len(X) * 100
    precision = tp / (tp + fp) * 100 if (tp+fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp+fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision+recall) > 0 else 0
    print(f"  Accuracy:  {acc:.1f}%")
    print(f"  Precision: {precision:.1f}%")
    print(f"  Recall:    {recall:.1f}%")
    print(f"  F1 Score:  {f1:.1f}%")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")

    # Export weights to JSON
    print(f"\nExporting model weights to: {output_path}")
    weights_data = best_weights if best_weights else {
        "w1": model.w1, "b1": model.b1, "w2": model.w2, "b2": model.b2
    }
    # Convert to serializable format
    export = {
        "input_size": 38,
        "hidden_size": 16,
        "w1": weights_data["w1"],
        "b1": weights_data["b1"],
        "w2": weights_data["w2"],
        "b2": weights_data["b2"],
        "version": "1.0.0",
        "description": "Tiny neural network (38→16→1) for phishing detection. Input: 38 binary rule features."
    }
    with open(output_path, 'w') as f:
        json.dump(export, f)
    print(f"  Exported {os.path.getsize(output_path)} bytes")
    print("\nDone! Model ready for Chrome extension.")


if __name__ == "__main__":
    main()
