#!/usr/bin/env python3
"""
Train Random Forest model on corpus data and export to JSON.
Architecture: 38 features → 30 trees (max_depth=6) → averaged probability
"""
import json, re, math, os, sys
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import numpy as np

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Prefer the larger, more diverse training set; fall back to the test corpus.
_train_path = os.path.join(BASE, "training", "train_data.json")
corpus = json.load(open(_train_path if os.path.exists(_train_path) else os.path.join(BASE, "corpus-samples.json")))

# ========== Feature extraction (same as neural net) ==========
SEC_KW = ["secure","login","signin","verify","account","update","confirm","bank","paypal","password","credit","wallet","authenticate","security","alert","unusual","suspended","claim","bonus","airdrop","reward","restore","unlock","validate","recover","reset"]
SUSP_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".date",".men",".loan",".click",".download",".review",".trade",".bid",".win",".stream",".racing",".accountant",".science",".cyou",".monster",".quest",".lol",".live",".shop"]
BRANDS = ["hyperliquid","opensea","binance","coinbase","metamask","uniswap","pancakeswap","sushiswap","cryptocom","bybit","okx","kucoin","kraken","gemini","huobi","phantom","trustwallet","rainbow","facebook","instagram","whatsapp","telegram","discord","twitter","linkedin","tiktok","snapchat","youtube","gmail","outlook","microsoft","apple","icloud","netflix","amazon","paypal","steam","epicgames","roblox","spotify","taobao","tmall","alipay","weixin","weibo","douyin","baidu","qq","dropbox","uber","airbnb","twitch","adobe","shopify","salesforce","google","skype","vimeo","pinterest","tumblr","line","kakaotalk","naver","yahoo","ebay","aliexpress","walmart","target","bestbuy","tesla","nvidia","amd","intel","cisco","oracle","ibm","atlassian","notion","figma","slack","zoom","canva","surfshark","nordvpn","expressvpn","proton","ledger","trezor","aave","compound","curve","balancer","maker","yearn"]
_SHORTENERS = ["bit.ly","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly","t.co","rebrand.ly","cutt.ly","shorturl.at","tiny.cc","bl.ink","rb.gy","short.link","s.id"]
_PATH_KW = ["/login","/signin","/password","/auth","form","survey","register","signup"]
_SUSP_PARAMS = ["token","auth","session","redirect","url","return","next","ref","callback","redir","goto","dest","target"]
_SUSP_FILES = [".exe",".scr",".bat",".cmd",".msi",".apk",".ipa",".zip",".rar",".js",".vbs",".ps1",".hta",".jar"]

def _lev(a,b):
    m,n=len(a),len(b); dp=[[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1):
        for j in range(n+1):
            if i==0: dp[i][j]=j
            elif j==0: dp[i][j]=i
            else: dp[i][j]=dp[i-1][j-1] if a[i-1]==b[j-1] else 1+min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1])
    return dp[m][n]

def _ent(s):
    f={};
    for c in s: f[c]=f.get(c,0)+1
    e=0
    for c in f: p=f[c]/len(s); e-=p*math.log2(p) if p>0 else 0
    return e

def extract_features(url):
    try:
        u=urlparse(url); hostname=u.hostname or ""; path=u.path; query=u.query
        port=u.port; scheme=u.scheme
    except: return [0]*38
    hl=hostname.lower(); pl=path.lower(); ql=query.lower(); fl=url.lower()
    f=[]
    f.append(1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",hl) else 0)
    f.append(1 if "@" in url else 0)
    f.append(1 if re.search(r"https?://.*https?://",url,re.I) else 0)
    f.append(1 if any(hl.replace("www.","")==s for s in _SHORTENERS) else 0)
    f.append(1 if any(k in fl for k in SEC_KW) else 0)
    f.append(1 if any(t in hl for t in SUSP_TLDS) else 0)
    f.append(1 if hostname.count(".")>4 else 0)
    f.append(1 if hostname.count("-")>=2 else 0)
    f.append(1 if port and port not in (80,443) else 0)
    f.append(1 if len(hostname)>25 else 0)
    hm=re.findall(r"%[0-9a-fA-F]{2}",url)
    f.append(1 if len(hm)>5 else 0)
    f.append(0)
    mp=hl.replace("www.","").split(".")[0]
    bs=0
    for brand in BRANDS:
        if mp==brand: continue
        d=_lev(mp,brand); ml=max(len(mp),len(brand))
        if ml>0 and d>0 and d<=max(2,int(ml*0.3)): bs=1; break
        lb="".join({"o":"0","i":"1","l":"1","e":"3","a":"4","s":"5","t":"7","b":"8","g":"9"}.get(c,c) for c in brand)
        if mp==lb: bs=1; break
    f.append(bs)
    f.append(0); f.append(1 if len(mp)>=12 and _ent(mp)>3.5 else 0); f.append(0)
    f.append(1 if any(ord(c)>127 for c in hostname) else 0)
    f.append(1) if any(b in pl for b in ["login","verify","signin","account","secure","password","bank","paypal"]) else f.append(0)
    f.append(1 if any(p+"=" in ql for p in _SUSP_PARAMS) else 0)
    f.append(1 if (scheme=="http" and any(k in fl for k in SEC_KW) and "localhost" not in hl and "127.0.0.1" not in hl) else 0)
    f.append(1 if any(pl.endswith(e) for e in _SUSP_FILES) else 0)
    f.append(1 if len([x for x in path.split("/") if x])>6 else 0)
    ns=0; sp2=hostname.split(".")
    for ni in range(len(sp2)-2):
        if sp2[ni].isdigit(): ns=1; break
    f.append(ns)
    f.append(1 if fl.startswith("data:text/html") or fl.startswith("data:application") else 0)
    f.append(1 if any(p in pl for p in ["/login","/signin","/password","/auth"]) else 0)
    f.append(1 if any(p in pl for p in ["form","survey","register","signup"]) else 0)
    f.append(1 if ("redirect" in ql or "return" in ql) else 0)
    f+=[0]*2; f+=[0]; f.append(1 if any(k in pl for k in SEC_KW) or any(k in ql for k in SEC_KW) else 0)
    f+=[0]*2; f.append(1 if ("popup" in hl or "redirect" in hl) else 0)
    f.append(1 if scheme=="http" else 0); f.append(0); f.append(0); f.append(1 if "redirect" in ql else 0)
    while len(f)<38: f.append(0)
    return f[:38]

# ========== Train Random Forest ==========
print("Extracting features...")
X, y = [], []
for url in corpus["phishing"]:
    X.append(extract_features(url)); y.append(1)
for url in corpus["benign"]:
    X.append(extract_features(url)); y.append(0)
X = np.array(X); y = np.array(y)
print(f"  {len(X)} samples, {X.shape[1]} features")

# Train (balanced, 30 trees, depth 6 for compact export)
rf = RandomForestClassifier(
    n_estimators=30, max_depth=6, random_state=42,
    class_weight="balanced", n_jobs=-1
)
rf.fit(X, y)

# Evaluate (simple CV)
from sklearn.model_selection import cross_val_predict
from sklearn.metrics import classification_report
y_pred = cross_val_predict(rf, X, y, cv=5)
print(f"\n5-fold CV:\n{classification_report(y, y_pred, target_names=['benign','phish'])}")

# Get per-class probabilities
from sklearn.model_selection import cross_val_predict
y_prob = cross_val_predict(rf, X, y, cv=5, method='predict_proba')
# Per-class metrics on CV
from sklearn.metrics import precision_recall_fscore_support
p,r,f1,_ = precision_recall_fscore_support(y, y_pred, average='binary')
print(f"Precision: {p:.1%}, Recall: {r:.1%}, F1: {f1:.1%}")

# ========== Export to JSON ==========
def export_tree(tree, tree_id):
    """Export a sklearn decision tree to compact JSON."""
    tree_data = tree.tree_
    n_nodes = tree_data.node_count
    return {
        "id": tree_id,
        "n_nodes": n_nodes,
        "feature": tree_data.feature.tolist(),     # feature index, -2 = leaf
        "threshold": [round(t, 4) for t in tree_data.threshold.tolist()],
        "children_left": tree_data.children_left.tolist(),
        "children_right": tree_data.children_right.tolist(),
        "value": [[round(v[0][0], 4), round(v[0][1], 4)] for v in tree_data.value]
    }

trees = []
for i, tree in enumerate(rf.estimators_):
    t = export_tree(tree, i)
    trees.append(t)
    print(f"  Tree {i}: {t['n_nodes']} nodes")

# Calculate export size estimate
export_data = {
    "n_estimators": len(trees),
    "n_features": X.shape[1],
    "trees": trees,
    "feature_importance": [round(f, 4) for f in rf.feature_importances_]
}

json_str = json.dumps(export_data)
print(f"\nExport size: {len(json_str)} bytes ({len(json_str)/1024:.0f} KB)")
print(f"  Trees: {len(trees)}")
print(f"  Total nodes: {sum(t['n_nodes'] for t in trees)}")

# Write
output_path = os.path.join(BASE, "lib", "rf_weights.json")
with open(output_path, "w") as f:
    json.dump(export_data, f)
print(f"Exported to: {output_path}")

# Feature importance
feat_names = [
    "IP_host","@_symbol","dual_proto","shortener","sec_kw","susp_tld",
    "many_subdom","hyphens","susp_port","long_domain","hex_enc","third_party",
    "brand_sim","svc_spoof","random_dom","typosquat","homograph","path_brand",
    "susp_params","http_login","susp_file","deep_path","num_subdom","data_uri",
    "page_pwd","page_forms","page_extform","page_fav","page_iframe","page_hidiframe",
    "page_title","page_fewlinks","page_brokenimg","page_popup","page_nohttps",
    "page_sketchy","beh_rapid","beh_cross"
    ]
print("\nTop 10 features:")
imp = sorted(zip(feat_names, rf.feature_importances_), key=lambda x:-x[1])
for name, val in imp[:10]:
    print(f"  {name}: {val:.3f}")
