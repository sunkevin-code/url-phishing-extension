# URL Phishing Detector

A Chrome Manifest V3 extension for phishing website detection. It identifies phishing URLs and malicious pages in real time through a **multi-layer detection architecture** — URL rules + page content + behavior analysis + machine learning + external threat intelligence.

> All detection runs locally in the browser. ML models are pure-JavaScript inference with no external dependencies, and no browsing data is ever sent to any server.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Detection Engine](#detection-engine)
- [Machine Learning](#machine-learning)
- [Scoring & Risk Levels](#scoring--risk-levels)
- [Project Structure](#project-structure)
- [Local Development](#local-development)
- [Testing](#testing)

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 Real-time detection | Auto-detection on page navigation — no manual action required |
| 🧠 AI/ML inference | Neural network + random forest ensemble, pure-JS local inference |
| 🛡️ Safe Browsing | Optional Google Safe Browsing API integration (requires API key) |
| 📄 Page content analysis | Detects phishing forms, brand imitation, hidden iframes, external scripts |
| ⌨️ Keylogger detection | MAIN-world script hooks to detect keylogging / form-grabbing behavior |
| 🚫 Block & warn | Auto-block high-risk pages, warning banners for medium/low risk |
| 📊 Dashboard | Detection stats, method contribution, threat list, engine health |
| ⚙️ List management | Whitelist/blacklist with bulk import/export |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Chrome Extension (MV3)              │
│                                                         │
│  ┌───────────┐   ┌────────────┐   ┌──────────────────┐  │
│  │  popup    │   │ dashboard  │   │     options      │  │
│  │ (popup UI)│   │ (stats)    │   │   (settings)     │  │
│  └─────┬─────┘   └─────┬──────┘   └────────┬─────────┘  │
│        │  chrome.runtime.sendMessage       │             │
│        ▼               ▼                   ▼             │
│  ┌──────────────────────────────────────────────────┐   │
│  │         Service Worker (lib/background.js)       │   │
│  │                                                  │   │
│  │  checkUrl() ── 5-layer engine ── fusion ── action│   │
│  │                                                  │   │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐           │   │
│  │  │ rules.js│ │ml_infer  │ │rf_infer │           │   │
│  │  │ rules   │ │ NN infer │ │ RF infer│           │   │
│  │  └─────────┘ └──────────┘ └─────────┘           │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │ chrome.tabs.sendMessage        │
│                         ▼                                │
│  ┌──────────────────────────────────────────────────┐   │
│  │        Content Script (lib/content.js)            │   │
│  │  analyzePage() page analysis + message listener  │   │
│  │  └─ injects MAIN-world: keylogger-detector.js    │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

**Data flow**: navigation → `webNavigation` event → `checkUrl()` → layered detection → weighted scoring → risk level → block / warn / allow.

---

## Detection Engine

`checkUrl()` uses a **five-layer detection + page-content analysis** architecture. Each layer scores independently, then results are fused.

### Layer 1 — URL Feature Rules (29 rules)

Pattern matching on the URL string, each rule weighted 6–35 points:

- **Structural anomalies**: IP-based hosts, `@` symbol, double protocol, unusual ports
- **Suspicious domains**: long domains, multiple hyphens, many subdomains, suspicious TLDs, high-entropy random domains
- **Brand spoofing**: brand similarity (Levenshtein + leet), typosquatting, IDN homographs, service spoofing
- **Path features**: base64 paths, suspicious params, brand names in path, deep paths
- **Encoding obfuscation**: hex encoding, punycode hosts

Combo bonuses add extra points when multiple weak signals co-occur.

### Layer 2 — Behavior Detection (2 rules)

Based on navigation history: rapid navigation, cross-domain form submission.

### Layer 3 — ML Neural Network + Random Forest

See [Machine Learning](#machine-learning). Uses a **rescue-only gate** (below).

### Layer 4 — Google Safe Browsing API

Optional. +60 points (high confidence) on a known malicious URL match. Disabled by default; requires the user to configure an API key.

### Layer 5 — SSL Certificate Check

Flags plain-HTTP pages (non-HTTPS), especially login pages.

### Page Content Analysis (Content Script, 12 rules)

Analyzes the page DOM: password forms, external form submission, hidden iframes, favicon mismatch, phishing title keywords, external scripts, etc.

### Keylogger / Form-Grabbing Detection

A MAIN-world script hooks native APIs (`addEventListener`, `fetch`, `sendBeacon`, `WebSocket`, `XMLHttpRequest`) to detect whether a page is silently logging keystrokes or scraping form data.

---

## Machine Learning

### Feature Engineering (38 binary features)

`extractMLFeatures(url)` extracts 38 binary features mapped to the three rule layers:

| Range | Source | Description |
|-------|--------|-------------|
| 0–23 | URL rules | URL structure, domain, brand spoofing (24 dims) |
| 24–35 | Page rules | Estimated from URL patterns (12 dims, some hardcoded 0) |
| 36–37 | Behavior rules | Estimated from URL patterns (2 dims) |

### Model Architectures

**Neural Network (NN)** — `lib/ml_inference.js`

```
38 inputs → 16 hidden (ReLU) → 1 output (Sigmoid)
```

- Pure-JS matrix math, zero dependencies
- Weights cached in `chrome.storage.local` (key: `ml_weights_cache_v2`) — cold start reads cache first, falls back to fetch

**Random Forest (RF)** — `lib/rf_inference.js`

- 30 trees, max depth 6
- Weight cache key: `rf_weights_cache_v2`

**Ensemble strategy**: `ensemble` (default) averages the NN and RF probabilities.

### Fusion: Rescue-Only Gate

This is the key false-positive-control design. ML's 0–100 probability is **NOT added** to the rule score (early versions added it directly, which pushed benign sites averaging ~28 points over the threshold and produced a 12% false-positive rate). Instead it acts as a **rescue gate**:

```
totalScore = urlScore + behaviorScore + sbScore + sslScore

if (ML ≥ 90 and urlScore < 10):
    totalScore = max(totalScore, 30)   # promote to "medium" — rescue phish the rules missed
    detectedRules.push("ml_rescue")
```

- **Lower false positives**: ML no longer dumps noisy probability onto every URL
- **Higher recall**: ML rescues phishing the rule engine missed
- Measured result: false-positive rate 12% → **0.8%**, detection rate 60%

---

## Scoring & Risk Levels

```
Fusion: totalScore = urlScore + behaviorScore + sbScore + sslScore (ML gated separately)
Thresholds: safe < 10 ≤ low < 28 ≤ medium < 55 ≤ high
```

| Level | Score | Action |
|-------|-------|--------|
| Safe | < 10 | Allow |
| Low | 10–27 | Optional warning |
| Medium | 28–54 | Warning banner |
| High | ≥ 55 | Block (autoBlock) or warn |

Known domains (`KNOWN_DOMAINS`, e.g. google.com, baidu.com) have their score capped at 9 to prevent false positives.

---

## Project Structure

```
url phishing extension/
├── manifest.json                  # MV3 config, default_locale: en
├── popup.html / popup.js          # Popup UI (instant detection result)
├── dashboard.html / dashboard.js  # Statistics panel
├── options.html / options.js      # Settings page
├── blocked.html                   # Block page
├── lib/
│   ├── background.js              # Service Worker, checkUrl core engine
│   ├── rules.js                   # Rule engine (URL/PAGE/BEHAVIOR) + feature extraction
│   ├── ml_inference.js            # Neural network inference
│   ├── ml_weights.json            # NN weights
│   ├── rf_inference.js            # Random forest inference
│   ├── rf_weights.json            # RF weights
│   ├── content.js                 # Content Script, page analysis + message listener
│   └── keylogger-detector.js      # MAIN-world keylogger detection
├── training/
│   ├── train_model.py             # NN training script
│   ├── train_random_forest.py     # RF training script
│   └── generate_corpus_samples.py # Corpus generation
├── test-runner.html / test-runner.js  # Test tool (Quick Test)
├── test-fetcher.js                # Test data fetching
├── corpus-samples.js / .json      # Built-in corpus (500 phishing + 500 benign)
├── _locales/                      # i18n messages (en / zh_CN)
└── icons/                         # Extension icons
```

---

## Local Development

1. Clone the repository
   ```bash
   git clone https://github.com/sunkevin-code/url-phishing-extension.git
   ```

2. Open Chrome → `chrome://extensions` → enable "Developer mode"

3. Click "Load unpacked" → select the project root

4. After editing, click the "Reload" icon on the extension card

> No `npm install` required — the extension runtime has zero dependencies, and the ML models run pure-JS inference. `package.json` is only a metadata placeholder.

---

## Testing

Built-in test tool (open `test-runner.html` inside the extension):

- **Quick Test**: runs the full `checkUrl` pipeline against the built-in corpus (500 phishing + 500 benign URLs), outputting detection rate, false-positive rate, confusion matrix, and method-contribution analysis.
- **Corpus Test**: tests against the full corpus.
- **Manual Test**: paste a custom URL list to test.

Current metrics (500+500 corpus):

| Metric | Value |
|--------|-------|
| False-positive rate (FPR) | 0.8% |
| Detection rate (DR) | 60% |

> Note: the test tool drives the full detection chain via the `CHECK_URL` message. Page/behavior/SSL layers depend on a real browser context (`tabId`), so they don't fire in pure-URL batch testing — method contribution is therefore dominated by URL rules + ML.

---

## License

Private repository. All rights reserved.
