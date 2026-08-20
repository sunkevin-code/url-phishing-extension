// Test Runner - Calls extension engine via CHECK_URL
(function() {
  "use strict";
  console.log("[TestRunner] Initializing...");

  var BUILTIN_PHISHING = typeof BUILTIN_PHISHING_LARGE !== "undefined" ? BUILTIN_PHISHING_LARGE : [];

  var BUILTIN_BENIGN = typeof BUILTIN_BENIGN_LARGE !== "undefined" ? BUILTIN_BENIGN_LARGE : [];

  var testResults = [];
  var ruleCounts = {};
  var testing = false;

  var RULE_NAMES = {
    url_ip_host: "IP Direct", url_suspicious_port: "Odd Port",
    url_long_domain: "Long Domain", url_at_symbol: "@ Symbol",
    url_double_protocol: "Dual Protocol", url_shortened: "Short URL",
    url_multiple_hyphens: "Hyphens", url_security_keywords: "Sec Keywords",
    url_suspicious_tld: "Bad TLD", url_many_subdomains: "Subdoms",
    url_hex_encoding: "Hex", url_third_party_subdomain: "3rd Party",
    url_brand_similarity: "Brand Sim", url_typosquatting: "Typosquat",
    url_homograph: "Homograph", url_data_uri: "Data URI",
    url_b64_path: "Base64", url_random_domain: "Random",
    url_service_spoof: "Svc Spoof", page_password_field: "Pwd Field",
    page_login_form: "Login", page_external_form: "Ext Form",
    page_excessive_iframes: "Iframes", page_in_iframe: "In Frame",
    page_brand_imitation: "Brand Copy", page_hidden_elements: "Hidden",
    page_few_links: "Few Links", page_external_scripts: "Ext Script",
    page_meta_redirect: "Meta Jump", page_cloaking: "Cloaking",
    page_popup_redirect: "Popup", page_fake_favicon: "Fake Icon",
    behavior_fast_redirect: "Fast Redir", behavior_many_redirects: "Multi Redir"
  };

  function log(msg) {
    console.log("[TestRunner]", msg);
    document.getElementById("statusBar").textContent = msg;
  }

  // ============================================================
  // Phishing Type Classification
  // Classifies each URL into a phishing technique category based on
  // URL features, so the test runner can report per-type detection rates.
  // ============================================================

  var PHISHING_TYPE_LABELS = {
    "ip-based": "IP Address",
    "at-symbol": "@ Symbol",
    "double-protocol": "Double Protocol",
    "data-uri": "Data URI",
    "punycode": "Punycode",
    "shortened": "Shortened URL",
    "brand-impersonation": "Brand Impersonation",
    "free-tld": "Free TLD",
    "suspicious-tld": "Suspicious TLD",
    "hosting-platform": "Hosting Platform",
    "login-phishing": "Login Phishing",
    "random-domain": "Random Domain",
    "other": "Other",
    "invalid": "Invalid"
  };

  var TYPE_BRANDS = ["google","facebook","youtube","paypal","amazon","netflix","microsoft","apple","icloud","instagram","twitter","whatsapp","telegram","discord","tiktok","linkedin","github","spotify","steam","alipay","weixin","baidu","ebay","yahoo","dropbox","adobe","shopify","stripe","chase","wellsfargo","bankofamerica","venmo","binance","coinbase","metamask","opensea","trustwallet","trezor","uphold","robinhood","chainlink","ledger","iphone"];
  var TYPE_SHORTENERS = ["bit.ly","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly","t.co","rebrand.ly","cutt.ly","shorturl.at","tiny.cc","bl.ink","rb.gy","short.link","s.id","2.gp","v.gd","0x0.st","short.cm"];
  var TYPE_FREE_TLDS = ["tk","ml","ga","cf","gq"];
  var TYPE_SUS_TLDS = ["xyz","top","work","date","men","loan","click","download","review","trade","bid","win","party","stream","racing","accountant","science","cyou","monster","quest","lol","shop","dev","cfd","live","ren"];
  var TYPE_HOSTING = ["wixstudio.com","wixsite.com","myshopify.com","wordpress.com","blogspot","weebly.com","webflow.io","squarespace.com","strikingly.com","site123.me","godaddysites.com","yolasite.com","000webhostapp.com","netlify.app","vercel.app","github.io","pages.dev","firebaseapp.com","azurewebsites.net","herokuapp.com","fly.dev","railway.app","onrender.com","glitch.me","replit.app","surge.sh","pineapple.page","qzz.io"];

  function _typeLev(a, b) {
    var m = a.length, n = b.length, dp = [];
    for (var i = 0; i <= m; i++) { dp[i] = [i]; for (var j = 0; j <= n; j++) { if (i === 0) dp[i][j] = j; else if (j > 0) { dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]); } } }
    return dp[m][n];
  }

  function _typeEnt(s) {
    var f = {}, i, e = 0;
    for (i = 0; i < s.length; i++) { var c = s[i]; f[c] = (f[c] || 0) + 1; }
    var l = s.length;
    for (var k in f) { var p = f[k] / l; e -= p * Math.log2(p); }
    return e;
  }

  function classifyPhishingType(url) {
    try {
      var u = new URL(url), h = u.hostname.toLowerCase(), full = url.toLowerCase();
      var noWWW = h.replace(/^www\./, "");
      var parts = noWWW.split(".");
      var main = parts[0];
      var tld = parts[parts.length - 1];

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return "ip-based";
      if (full.indexOf("@") > -1) return "at-symbol";
      if (/https?:\/\/.*https?:\/\//i.test(full)) return "double-protocol";
      if (full.indexOf("data:text/html") === 0 || full.indexOf("data:application") === 0) return "data-uri";
      if (h.indexOf("xn--") > -1 || /[^\x00-\x7F]/.test(h)) return "punycode";
      if (TYPE_SHORTENERS.indexOf(noWWW) > -1) return "shortened";

      // Brand impersonation: typosquatting, embedded brand, or brand-as-subdomain
      for (var i = 0; i < TYPE_BRANDS.length; i++) {
        var b = TYPE_BRANDS[i];
        if (main === b) continue;
        if (main.length === b.length && _typeLev(main, b) === 1) return "brand-impersonation";
        var flatMain = main.replace(/-/g, "");
        if (flatMain.indexOf(b) > -1 && b.length >= 4 && flatMain.length > b.length) return "brand-impersonation";
        for (var j = 0; j < parts.length - 1; j++) { if (parts[j] === b) return "brand-impersonation"; }
      }

      if (TYPE_FREE_TLDS.indexOf(tld) > -1) return "free-tld";
      if (TYPE_SUS_TLDS.indexOf(tld) > -1) return "suspicious-tld";

      for (var k = 0; k < TYPE_HOSTING.length; k++) {
        if (TYPE_HOSTING[k] === "blogspot") { if (h.indexOf(".blogspot.") > -1) return "hosting-platform"; }
        else if (h.indexOf("." + TYPE_HOSTING[k]) > -1) return "hosting-platform";
      }

      if (/login|signin|verify|secure|account|password|wallet|confirm|update/.test(full)) return "login-phishing";
      if (main.length >= 12 && _typeEnt(main) > 3.5) return "random-domain";
      return "other";
    } catch (e) { return "invalid"; }
  }

  function buildList(ph, bn) {
    var l = [];
    for (var i = 0; i < ph.length; i++) l.push({ url: ph[i], label: "phishing", type: classifyPhishingType(ph[i]) });
    for (var i = 0; i < bn.length; i++) l.push({ url: bn[i], label: "benign", type: "benign" });
    return l;
  }

  function runQuickTest() {
    if (testing) { log("Already testing"); return; }
    console.log("[TestRunner] runQuickTest() called");
    testing = true;
    clearResults();
    var all = buildList(BUILTIN_PHISHING, BUILTIN_BENIGN);
    log("Starting: " + all.length + " URLs");
    document.getElementById("btnQuickTest").disabled = true;
    toast("Testing " + all.length + " URLs...");
    testResults = [];
    ruleCounts = {};
    runBatch(all, 0);
  }

  function runBatch(all, idx) {
    if (idx >= all.length) { finish(); return; }
    var item = all[idx];
    log("Checking [" + (idx + 1) + "/" + all.length + "] " + item.url.substring(0, 50) + "...");
    chrome.runtime.sendMessage({ type: "CHECK_URL", url: item.url, tabId: -1 }).then(function(r) {
      r = r || {};
      r.label = item.label;
      r.type = item.type || "other";
      r.index = idx + 1;
      r.url = item.url;
      testResults.push(r);
      if (r.detectedRules) {
        for (var j = 0; j < r.detectedRules.length; j++) {
          var id = typeof r.detectedRules[j] === "string" ? r.detectedRules[j] : (r.detectedRules[j].id || "");
          ruleCounts[id] = (ruleCounts[id] || 0) + 1;
        }
      }
      runBatch(all, idx + 1);
    }).catch(function(e) {
      console.error("[TestRunner] Error:", e);
      testResults.push({ url: item.url, label: item.label, type: item.type || "other", index: idx + 1, score: 0, level: "safe", detectedRules: [], error: String(e) });
      runBatch(all, idx + 1);
    });
  }

  function finish() {
    testing = false;
    document.getElementById("btnQuickTest").disabled = false;
    var btnCorpus = document.getElementById("btnCorpusTest");
    if (btnCorpus) btnCorpus.disabled = false;
    log("Done: " + testResults.length + " URLs");
    renderResults();
    toast("Complete! " + testResults.length + " URLs tested.");
  }

  function testManualUrls() {
    if (testing) return;
    var t = document.getElementById("manualUrls").value.trim();
    if (!t) { toast("Paste URLs first"); return; }
    testing = true;
    clearResults();
    var lines = t.split("\n"), ph = [], bn = [], cur = "phishing";
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i].trim();
      if (!l) continue;
      if (l.toLowerCase() === "#benign" || l.toLowerCase() === "#safe") { cur = "benign"; continue; }
      if (l.toLowerCase() === "#phishing") { cur = "phishing"; continue; }
      if (cur === "benign") bn.push(l); else ph.push(l);
    }
    if (ph.length === 0 && bn.length === 0) { testing = false; toast("No valid URLs"); return; }
    var all = buildList(ph, bn);
    log("Manual test: " + all.length + " URLs");
    toast("Testing " + all.length + " URLs...");
    testResults = [];
    ruleCounts = {};
    runBatch(all, 0);
  }

  function clearResults() {
    testResults = [];
    ruleCounts = {};
    document.getElementById("mTotal").textContent = "0";
    document.getElementById("mDR").textContent = "0%";
    document.getElementById("mFPR").textContent = "0%";
    document.getElementById("mF1").textContent = "0%";
    document.getElementById("cmPanel").style.display = "none";
    var tp = document.getElementById("typePanel");
    if (tp) tp.style.display = "none";
    document.getElementById("resultsBody").innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:#999">Click "Quick Test" to call extension engine</td></tr>';
    document.getElementById("statusBar").textContent = "Ready";
  }

  function renderResults() {
    var ph = testResults.filter(function(r) { return r.label === "phishing"; });
    var bn = testResults.filter(function(r) { return r.label === "benign"; });
    var tp = ph.filter(function(r) { return r.level !== "safe"; }).length;
    var fn = ph.length - tp;
    var fp = bn.filter(function(r) { return r.level !== "safe"; }).length;
    var tn = bn.length - fp;
    var total = testResults.length;
    var dr = ph.length > 0 ? (tp / ph.length * 100) : 0;
    var fpr = bn.length > 0 ? (fp / bn.length * 100) : 0;
    var pr = (tp + fp) > 0 ? (tp / (tp + fp) * 100) : 0;
    var f1 = (pr + dr) > 0 ? (2 * pr * dr / (pr + dr)) : 0;

    document.getElementById("mTotal").textContent = total;
    document.getElementById("mDR").textContent = dr.toFixed(1) + "%";
    document.getElementById("mFPR").textContent = fpr.toFixed(1) + "%";
    document.getElementById("mF1").textContent = f1.toFixed(1) + "%";
    document.getElementById("cmTP").textContent = tp;
    document.getElementById("cmFP").textContent = fp;
    document.getElementById("cmFN").textContent = fn;
    document.getElementById("cmTN").textContent = tn;
    document.getElementById("cmAcc").textContent = total > 0 ? ((tp + tn) / total * 100).toFixed(1) + "%" : "0%";
    document.getElementById("cmPrec").textContent = pr.toFixed(1) + "%";
    document.getElementById("cmRec").textContent = dr.toFixed(1) + "%";
    document.getElementById("cmF1").textContent = f1.toFixed(1) + "%";
    document.getElementById("cmPanel").style.display = "block";

    var tbody = document.getElementById("resultsBody");
    tbody.innerHTML = "";
    if (!testResults.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:#999">No results</td></tr>';
      return;
    }
    var labels = { high: "HIGH", medium: "MEDIUM", low: "LOW", safe: "SAFE" };
    for (var i = 0; i < testResults.length; i++) {
      var r = testResults[i];
      var rc = r.label === "phishing" ? (r.level !== "safe" ? "tp" : "fn") : (r.level === "safe" ? "tn" : "fp");
      var rh = "";
      if (r.detectedRules && r.detectedRules.length) {
        rh = r.detectedRules.slice(0, 3).map(function(d) {
          var id = typeof d === "string" ? d : (d.id || "");
          var cat = id.startsWith("url_") ? "url" : id.startsWith("page_") ? "page" : "behavior";
          return '<span class="badge ' + cat + '" style="margin:1px">' + (RULE_NAMES[id] || id.replace(/_/g, " ")) + '</span>';
        }).join("");
        if (r.detectedRules.length > 3) rh += ' <span style="font-size:10px;color:#999">+' + (r.detectedRules.length - 3) + '</span>';
      }
      if (r.error) rh = '<span style="color:#F44336;font-size:10px">ERR:' + r.error + '</span>';
      var us = (r.url || "").length > 70 ? (r.url || "").substring(0, 70) + "..." : (r.url || "");
      var typeLabel = r.label === "phishing" ? (PHISHING_TYPE_LABELS[r.type] || r.type || "Other") : "-";
      tbody.innerHTML += '<tr data-label="' + r.label + '" data-result="' + rc + '">' +
        '<td>' + (r.index || i + 1) + '</td>' +
        '<td class="url-cell" title="' + (r.url || "").replace(/"/g, "&quot;") + '">' + us + '</td>' +
        '<td><span class="badge ' + (r.label === "phishing" ? "phish" : "benign") + '">' + r.label.toUpperCase() + '</span></td>' +
        '<td><span class="badge type-badge">' + typeLabel + '</span></td>' +
        '<td style="font-weight:600">' + (r.score || 0) + '</td>' +
        '<td><span class="badge ' + (r.level || "safe") + '">' + (labels[r.level] || "SAFE") + '</span></td>' +
        '<td><span class="badge ' + rc + '">' + rc.toUpperCase() + '</span></td>' +
        '<td>' + rh + '</td></tr>';
    }
    filterResults("all");
    renderTypeBreakdown();
  }

  function renderTypeBreakdown() {
    var ph = testResults.filter(function(r) { return r.label === "phishing"; });
    var byType = {};
    for (var i = 0; i < ph.length; i++) {
      var t = ph[i].type || "other";
      if (!byType[t]) byType[t] = { total: 0, detected: 0 };
      byType[t].total++;
      if (ph[i].level && ph[i].level !== "safe") byType[t].detected++;
    }
    var keys = Object.keys(byType).sort(function(a, b) { return byType[b].total - byType[a].total; });
    var tbody = document.getElementById("typeBreakdownBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (keys.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:#999">No phishing samples</td></tr>';
      return;
    }
    var totalDetected = 0, totalAll = 0;
    for (var k = 0; k < keys.length; k++) {
      var t = keys[k];
      var st = byType[t];
      var rate = st.total > 0 ? (st.detected / st.total * 100) : 0;
      totalDetected += st.detected; totalAll += st.total;
      var rateColor = rate >= 90 ? "#4CAF50" : rate >= 60 ? "#FF9800" : "#F44336";
      tbody.innerHTML += '<tr>' +
        '<td><span class="badge type-badge">' + (PHISHING_TYPE_LABELS[t] || t) + '</span></td>' +
        '<td>' + st.total + '</td>' +
        '<td>' + st.detected + '</td>' +
        '<td>' + (st.total - st.detected) + '</td>' +
        '<td style="font-weight:700;color:' + rateColor + '">' + rate.toFixed(1) + '%</td></tr>';
    }
    var overallRate = totalAll > 0 ? (totalDetected / totalAll * 100) : 0;
    tbody.innerHTML += '<tr style="border-top:2px solid #e0e0e0;font-weight:700">' +
      '<td>Overall</td><td>' + totalAll + '</td><td>' + totalDetected + '</td><td>' + (totalAll - totalDetected) + '</td>' +
      '<td style="color:#667eea">' + overallRate.toFixed(1) + '%</td></tr>';
    document.getElementById("typePanel").style.display = "block";
  }

  var curFilter = "all";
  function filterResults(type) {
    curFilter = type;
    document.querySelectorAll("#filterTabs .tab").forEach(function(b) { b.classList.remove("active"); });
    var activeTab = document.querySelector('#filterTabs .tab[data-filter="' + type + '"]');
    if (activeTab) activeTab.classList.add("active");
    document.querySelectorAll("#resultsBody tr[data-label]").forEach(function(r) {
      if (type === "all") r.style.display = "";
      else if (type === "phish") r.style.display = r.dataset.label === "phishing" ? "" : "none";
      else if (type === "benign") r.style.display = r.dataset.label === "benign" ? "" : "none";
      else r.style.display = r.dataset.result === type ? "" : "none";
    });
  }

  function loadFile(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(e) {
      document.getElementById("manualUrls").value = e.target.result;
      toast("Loaded " + file.name);
    };
    reader.readAsText(file);
  }

  function toast(msg) {
    var t = document.getElementById("toast");
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(function() { t.classList.remove("show"); }, 2500);
  }

  // ============================================================
  // Event binding (replaces blocked onclick attributes)
  // ============================================================

  function fetchFromOpenPhish() {
    if (testing) return;
    testing = true; clearResults();
    document.getElementById("btnFetchOpenPhish").disabled = true;
    log("Fetching from OpenPhish...");
    toast("Fetching from OpenPhish...");
    fetchOpenPhishFeed().then(function(urls) {
      document.getElementById("btnFetchOpenPhish").disabled = false;
      log("Fetched " + urls.length + " URLs. Starting test...");
      runFetchedTest(urls);
    }).catch(function(e) {
      document.getElementById("btnFetchOpenPhish").disabled = false;
      log("Fetch failed");
      toast("Fetch blocked by CORS. Try loading samples.json.");
      testing = false;
    });
  }

  function fetchFromPhishTank() {
    if (testing) return;
    testing = true; clearResults();
    document.getElementById("btnFetchPhishTank").disabled = true;
    log("Fetching from PhishTank...");
    toast("Fetching from PhishTank...");
    fetchPhishTankFeed().then(function(urls) {
      document.getElementById("btnFetchPhishTank").disabled = false;
      log("Fetched " + urls.length + " URLs. Starting test...");
      runFetchedTest(urls);
    }).catch(function(e) {
      document.getElementById("btnFetchPhishTank").disabled = false;
      log("Fetch failed");
      toast("PhishTank fetch failed.");
      testing = false;
    });
  }

  function runFetchedTest(urls) {
    var all = buildList(urls, BUILTIN_BENIGN_LARGE);
    log("Running test on " + all.length + " URLs");
    testResults = []; ruleCounts = {};
    runBatch(all, 0);
  }

  function runCorpusTest() {
    if (testing) return;
    var ph = typeof BUILTIN_PHISHING_LARGE !== "undefined" ? BUILTIN_PHISHING_LARGE : [];
    var bn = typeof BUILTIN_BENIGN_LARGE !== "undefined" ? BUILTIN_BENIGN_LARGE : [];
    if (ph.length === 0 && bn.length === 0) { toast("No corpus data loaded"); return; }
    testing = true; clearResults();
    document.getElementById("btnCorpusTest").disabled = true;
    log("Corpus test: " + (ph.length + bn.length) + " URLs");
    toast("Testing " + (ph.length + bn.length) + " URLs from corpus...");
    testResults = []; ruleCounts = {};
    var all = buildList(ph, bn);
    runBatch(all, 0);
  }

  function loadSamplesJson(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(e) {
      var data = loadSamplesFromJSON(e.target.result);
      if (!data) { toast("Invalid JSON file"); return; }
      document.getElementById("sampleCount").textContent = "Loaded: " + data.phishing.length + " phish + " + data.benign.length + " benign";
      if (data.phishing.length > 0 || data.benign.length > 0) {
        testing = true; clearResults();
        log("Testing " + (data.phishing.length + data.benign.length) + " URLs...");
        toast("Testing...");
        testResults = []; ruleCounts = {};
        var all = buildList(data.phishing, data.benign);
        runBatch(all, 0);
      }
    };
    reader.readAsText(file);
  }
  function bindEvents() {
    var btnQuick = document.getElementById("btnQuickTest");
    var btnClear = document.getElementById("btnClear");
    var btnManual = document.getElementById("btnManualTest");
    var fileInput = document.getElementById("fileInput");

    var btnFetchOP = document.getElementById("btnFetchOpenPhish");
    var btnFetchPT = document.getElementById("btnFetchPhishTank");
    var btnLoadSamples = document.getElementById("btnLoadSamples");
    var btnCorpus = document.getElementById("btnCorpusTest");
    var samplesInput = document.getElementById("samplesFileInput");
    if (btnFetchOP) btnFetchOP.addEventListener("click", fetchFromOpenPhish);
    if (btnFetchPT) btnFetchPT.addEventListener("click", fetchFromPhishTank);
    if (btnLoadSamples) btnLoadSamples.addEventListener("click", function() { samplesInput.click(); });
    if (btnCorpus) btnCorpus.addEventListener("click", function() { runCorpusTest(); });
    if (samplesInput) samplesInput.addEventListener("change", function() { loadSamplesJson(this.files[0]); });
    var tabs = document.querySelectorAll("#filterTabs .tab");

    if (btnQuick) btnQuick.addEventListener("click", function() { console.log("[TestRunner] QuickTest clicked"); runQuickTest(); });
    if (btnClear) btnClear.addEventListener("click", function() { testing = false; clearResults(); });
    if (btnManual) btnManual.addEventListener("click", testManualUrls);
    if (fileInput) fileInput.addEventListener("change", function() { loadFile(this.files[0]); });

    tabs.forEach(function(tab) {
      tab.addEventListener("click", function() {
        var filter = this.getAttribute("data-filter");
        if (filter) filterResults(filter);
      });
    });

    // Detect if running outside extension context
    if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage) {
      document.getElementById("extNote").innerHTML =
        '<strong style="color:#F44336">&#x26A0; Not running inside Chrome extension.</strong>' +
        '<br>Open this page via the extension popup: click the &#x1F9EA; Test button in the popup to open this test runner in extension context.' +
        '<br><span style="margin-top:4px;display:block">Or use <a href="test-harness.html" style="color:#667eea">test-harness.html</a> for standalone simulation.</span>';
      document.getElementById("testMode").textContent = "Mode: Standalone (no extension API)";
    }

    console.log("[TestRunner] Events bound. Ready.");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindEvents);
  } else {
    bindEvents();
  }
})();