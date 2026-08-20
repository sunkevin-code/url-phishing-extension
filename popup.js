// ============================================================
// Popup Script - Popup Interaction Logic
// ============================================================

let currentTabId = null;
let currentUrl = "";
let currentDomain = "";
let currentResult = null;

function withTimeout(promise, timeoutMs, fallback) {
  return Promise.race([
    promise,
    new Promise(resolve => setTimeout(() => resolve(fallback), timeoutMs))
  ]);
}

// ---------- Initialize ----------
document.addEventListener("DOMContentLoaded", async () => {
  try {
    setLoading("Getting page info...");
    const [tab] = await withTimeout(
      chrome.tabs.query({ active: true, currentWindow: true }),
      2500,
      []
    );
    if (!tab || !tab.url) {
      showError("Unable to get current page info");
      return;
    }

    currentTabId = tab.id;
    currentUrl = tab.url;
    try {
      currentDomain = new URL(tab.url).hostname.replace(/^www\./, "").toLowerCase();
    } catch (e) {}

    document.getElementById("domainDisplay").textContent = currentDomain;

    setLoading("Checking URL...");
    const result = await withTimeout(
      chrome.runtime.sendMessage({
        type: "CHECK_URL",
        url: currentUrl,
        tabId: currentTabId
      }).catch(function(e) {
        return { safe: true, score: 0, level: "safe", detectedRules: [], error: e.message };
      }),
      5000,
      { safe: true, score: 0, level: "safe", detectedRules: [], error: "Detection timed out" }
    );

    currentResult = result;
    const stats = await withTimeout(
      chrome.runtime.sendMessage({ type: "GET_STATS" }).catch(() => ({})),
      1500,
      {}
    );
    renderResult(result, stats);
  } catch (e) {
    showError(e && e.message ? e.message : "Analysis failed");
  }
});

function setLoading(text) {
  var el = document.getElementById("loadingText");
  if (el) el.textContent = text;
}

// ---------- Render ----------
function renderResult(result, stats) {
  document.getElementById("loading").style.display = "none";
  document.getElementById("result").style.display = "block";

  document.getElementById("statSafe").textContent = stats.safe || 0;
  document.getElementById("statWarn").textContent = stats.warned || 0;
  document.getElementById("statBlocked").textContent = stats.blocked || 0;
  document.getElementById("statTotal").textContent = stats.totalChecked || 0;

  const level = result.level || "safe";
  const score = result.score || 0;
  const circle = document.getElementById("scoreCircle");
  circle.className = `score-circle ${level}`;
  circle.textContent = score;

  const statusLabels = {
    safe: { text: "Safe", color: "#4CAF50" },
    low: { text: "Low Risk", color: "#FF9800" },
    medium: { text: "Medium Risk", color: "#FF5722" },
    high: { text: "High Risk", color: "#F44336" }
  };
  const label = statusLabels[level] || statusLabels.safe;
  const statusEl = document.getElementById("statusLabel");
  statusEl.textContent = label.text;
  statusEl.style.color = label.color;

  const detailsEl = document.getElementById("details");
  detailsEl.innerHTML = "";

  if (result.detectedRules && result.detectedRules.length > 0) {
    const card = document.createElement("div");
    card.className = "detail-card";
    card.innerHTML = `<h3>Detected ${result.detectedRules.length}  risk factors</h3>`;

    const rulesContainer = document.createElement("div");
    rulesContainer.className = "triggered-rules";

    const categories = {
      url: "URL Features",
      page: "Page Features",
      behavior: "Behavior Features",
      ml: "ML Signals",
      sb: "Safe Browsing",
      ssl: "SSL Signals"
    };
    const grouped = { url: [], page: [], behavior: [], ml: [], sb: [], ssl: [] };

    for (const rule of result.detectedRules) {
      if (grouped[rule.category]) {
        grouped[rule.category].push(rule.id);
      }
    }

    for (const [cat, rules] of Object.entries(grouped)) {
      if (rules.length === 0) continue;
      const catName = categories[cat] || cat;
      const div = document.createElement("div");
      div.style.marginBottom = "6px";
      div.innerHTML = `<div style="font-size:12px;font-weight:bold;color:#666;margin-bottom:4px;">${catName}</div>`;
      rules.forEach(ruleId => {
        const tag = document.createElement("span");
        tag.className = `rule-tag ${cat}`;
        tag.textContent = formatRuleName(ruleId);
        div.appendChild(tag);
      });
      rulesContainer.appendChild(div);
    }

    card.appendChild(rulesContainer);
    detailsEl.appendChild(card);
  } else if (level === "safe") {
    detailsEl.innerHTML = `<div class="no-risk">${result.error ? "Analysis fallback used" : "No risk features detected"}</div>`;
  }

  if (result.urlScore !== undefined || result.pageScore !== undefined || result.behaviorScore !== undefined) {
    const scoreCard = document.createElement("div");
    scoreCard.className = "detail-card";
    scoreCard.innerHTML = `
      <h3> Score Breakdown</h3>
      <div class="detail-item">
        <span class="label">URL Score</span>
        <span class="value ${result.urlScore >= 15 ? "risk" : "safe"}">${result.urlScore || 0}</span>
      </div>
      <div class="detail-item">
        <span class="label">Page Score</span>
        <span class="value ${result.pageScore >= 15 ? "risk" : "safe"}">${result.pageScore || 0}</span>
      </div>
      <div class="detail-item">
        <span class="label">Behavior Score</span>
        <span class="value ${result.behaviorScore >= 15 ? "risk" : "safe"}">${result.behaviorScore || 0}</span>
      </div>
      <div class="detail-item" style="border-top:1px solid #eee;padding-top:8px;margin-top:4px;">
        <span class="label" style="font-weight:bold;">Total Score</span>
        <span class="value ${level === "high" ? "risk" : level === "medium" ? "warn" : "safe"}">${score}</span>
      </div>
    `;
    detailsEl.appendChild(scoreCard);
  }
}

function formatRuleName(ruleId) {
  const nameMap = {
    url_ip_host: "IP Direct",
    url_suspicious_port: "Suspicious Port",
    url_long_domain: "Long Domain",
    url_at_symbol: "@ Symbol",
    url_double_protocol: "Dual Protocol",
    url_shortened: "Short URL",
    url_multiple_hyphens: "Many Hyphens",
    url_security_keywords: "Security Keywords",
    url_suspicious_tld: "Suspicious TLD",
    url_many_subdomains: "Many Subdomains",
    url_hex_encoding: "Hex Encoding",
    url_third_party: "Third-Party Subdomain",
    url_brand_sim: "Brand Similarity",
    url_service_spoof: "Service Spoof",
    url_random_domain: "Random Domain",
    url_typosquat: "Typosquatting",
    url_homograph: "Homograph",
    url_path_brand: "Brand in Path",
    url_suspicious_params: "Suspicious Params",
    url_http_login: "HTTP Login",
    url_suspicious_file: "Suspicious File",
    url_deep_path: "Deep Path",
    url_numeric_subdomain: "Numeric Subdomain",
    url_data_uri: "Data URI",
    url_brand_keyword_host: "Brand + Login Host",
    url_login_redirect: "Login Redirect",
    url_punycode_host: "Punycode Host",
    url_b64_path: "Encoded Path",
    url_very_long: "Very Long URL",
    ml_boost: "ML High Risk Boost",
    ml_discount: "ML Low Risk Discount",
    safe_browsing_match: "Safe Browsing Match",
    ssl_no_https: "No HTTPS",
    page_password_form: "Password Form",
    page_many_forms: "Many Forms",
    page_external_forms: "External Form",
    page_iframe_count: "Many Iframes",
    page_hidden_iframes: "Hidden Iframes",
    page_favicon_mismatch: "Favicon Mismatch",
    page_title_keywords: "Phish Title",
    page_few_links: "Few Links",
    page_broken_images: "Broken Images",
    page_popup_script: "Popup Script",
    page_no_https: "No HTTPS",
    page_sketchy_scripts: "External Scripts",
    beh_rapid_nav: "Rapid Navigation",
    beh_cross_domain: "Cross-Domain Navigation",
    KEYLOGGER: "Keylogger Detected",
    SENSITIVE_FIELD_MONITORING: "Sensitive Field Monitoring",
    FORM_SUBMIT_HOOK: "Form Submit Hook",
    BEACON_EXFIL: "Beacon Exfiltration",
    FETCH_EXFIL: "Fetch Exfiltration",
    XHR_EXFIL: "XHR Exfiltration",
    WEBSOCKET_EXFIL: "WebSocket Exfiltration"
  };
  return nameMap[ruleId] || ruleId;
}

function showError(msg) {
  document.getElementById("loading").style.display = "none";
  document.getElementById("result").style.display = "block";
  document.getElementById("details").innerHTML =
    `<div class="detail-card"><p style="color:#F44336;text-align:center;">${msg}</p></div>`;
}

// ---------- Button Events ----------
document.getElementById("btnWhitelist")?.addEventListener("click", async () => {
  const resp = await chrome.runtime.sendMessage({
    type: "ADD_CURRENT_TO_WHITELIST",
    tabId: currentTabId
  });

  if (resp?.success) {
    const btn = document.getElementById("btnWhitelist");
    btn.textContent = `Added:  ${resp.domain}`;
    btn.style.background = "#4CAF50";
    btn.style.color = "white";
    setTimeout(() => {
      btn.textContent = "Add to Whitelist";
      btn.style.background = "#E8F5E9";
      btn.style.color = "#2E7D32";
    }, 2000);
  }
});

document.getElementById("btnBlacklist")?.addEventListener("click", async () => {
  const resp = await chrome.runtime.sendMessage({
    type: "ADD_CURRENT_TO_BLACKLIST",
    tabId: currentTabId
  });

  if (resp?.success) {
    const btn = document.getElementById("btnBlacklist");
    btn.textContent = `Added:  ${resp.domain}`;
    btn.style.background = "#F44336";
    btn.style.color = "white";
    setTimeout(() => {
      btn.textContent = "Add to Blacklist";
      btn.style.background = "#FFEBEE";
      btn.style.color = "#C62828";
    }, 2000);
  }
});

document.getElementById("btnTestRunner")?.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("test-runner.html") });
});

document.getElementById("btnDashboard")?.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});

document.getElementById("btnSettings")?.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});
