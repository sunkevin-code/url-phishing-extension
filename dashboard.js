// ============================================================
// Dashboard Script - Safety Dashboard
// ============================================================

var RULE_NAMES = {};
var RULE_CATEGORIES = {};

(function() {
  var rules = {
    url_ip_host: ["url", "IP Address"],
    url_suspicious_port: ["url", "Suspicious Port"],
    url_long_domain: ["url", "Long Domain"],
    url_at_symbol: ["url", "@ Symbol"],
    url_double_protocol: ["url", "Double Protocol"],
    url_shortened: ["url", "Short URL"],
    url_multiple_hyphens: ["url", "Multiple Hyphens"],
    url_security_keywords: ["url", "Security Keywords"],
    url_suspicious_tld: ["url", "Suspicious TLD"],
    url_many_subdomains: ["url", "Many Subdomains"],
    url_hex_encoding: ["url", "Hex Encoding"],
    url_third_party_subdomain: ["url", "Third-party Subdomain"],
    url_third_party: ["url", "Third-party Subdomain"],
    url_brand_similarity: ["url", "Brand Similarity"],
    url_brand_sim: ["url", "Brand Similarity"],
    url_typosquatting: ["url", "Typosquatting"],
    url_typosquat: ["url", "Typosquatting"],
    url_homograph: ["url", "Homograph"],
    url_service_spoof: ["url", "Service Spoof"],
    url_random_domain: ["url", "Random Domain"],
    url_path_brand: ["url", "Brand in Path"],
    url_suspicious_params: ["url", "Suspicious Params"],
    url_http_login: ["url", "HTTP Login"],
    url_suspicious_file: ["url", "Suspicious File"],
    url_deep_path: ["url", "Deep Path"],
    url_numeric_subdomain: ["url", "Numeric Subdomain"],
    url_data_uri: ["url", "Data URI"],
    url_b64_path: ["url", "Base64 Path"],
    url_punycode_host: ["url", "Punycode Host"],
    url_brand_keyword_host: ["url", "Brand + Login Host"],
    url_login_redirect: ["url", "Login Redirect"],
    url_very_long: ["url", "Very Long URL"],
    page_password_form: ["page", "Password Form"],
    page_many_forms: ["page", "Many Forms"],
    page_external_forms: ["page", "External Form"],
    page_iframe_count: ["page", "Too Many iframes"],
    page_hidden_iframes: ["page", "Hidden Iframes"],
    page_favicon_mismatch: ["page", "Favicon Mismatch"],
    page_title_keywords: ["page", "Phish Title"],
    page_few_links: ["page", "Few Links"],
    page_broken_images: ["page", "Broken Images"],
    page_popup_script: ["page", "Popup Script"],
    page_no_https: ["page", "No HTTPS"],
    page_sketchy_scripts: ["page", "External Scripts"],
    beh_rapid_nav: ["behavior", "Rapid Navigation"],
    beh_cross_domain: ["behavior", "Cross-Domain Navigation"],
    ml_boost: ["ml", "ML High Risk Boost"],
    ml_discount: ["ml", "ML Low Risk Discount"],
    safe_browsing_match: ["sb", "Safe Browsing Match"],
    ssl_no_https: ["ssl", "No HTTPS"]
  };
  for (var k in rules) {
    RULE_CATEGORIES[k] = rules[k][0];
    RULE_NAMES[k] = rules[k][1];
  }
})();

document.addEventListener("DOMContentLoaded", function() {
  loadDashboard();
  setInterval(loadDashboard, 2000);
});

async function loadDashboard() {
  try {
    var statsResp = await chrome.runtime.sendMessage({ type: "GET_STATS" }).catch(function() { return null; });
    var settingsResp = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" }).catch(function() { return null; });
    var historyResp = await chrome.runtime.sendMessage({ type: "GET_DETECTION_HISTORY" }).catch(function() { return null; });
    var stats = statsResp || { totalChecked: 0, safe: 0, warned: 0, blocked: 0 };
    var settings = settingsResp || {};
    var history = historyResp || { detections: [], ruleCounts: {} };
    renderStatCards(stats);
    renderRiskBar(stats);
    renderMethodBreakdown(history);
    renderThreatList(history);
    renderEngineHealth(settings);
    renderTopRules(history);
    updateRefreshTime();
  } catch (e) {
    console.warn("Dashboard load error:", e);
  }
}

function renderStatCards(s) {
  document.getElementById("cardTotal").textContent = s.totalChecked || 0;
  document.getElementById("cardSafe").textContent = s.safe || 0;
  document.getElementById("cardWarned").textContent = s.warned || 0;
  document.getElementById("cardBlocked").textContent = s.blocked || 0;
}

function renderRiskBar(s) {
  var t = s.totalChecked || 1;
  document.getElementById("barSafe").style.width = ((s.safe || 0) / t * 100).toFixed(1) + "%";
  document.getElementById("barWarned").style.width = ((s.warned || 0) / t * 100).toFixed(1) + "%";
  document.getElementById("barBlocked").style.width = ((s.blocked || 0) / t * 100).toFixed(1) + "%";
  document.getElementById("legSafe").textContent = s.safe || 0;
  document.getElementById("legWarned").textContent = s.warned || 0;
  document.getElementById("legBlocked").textContent = s.blocked || 0;
}

function renderMethodBreakdown(h) {
  var cnt = { url: 0, page: 0, behavior: 0 };
  if (h.ruleCounts) {
    var keys = Object.keys(h.ruleCounts);
    for (var i = 0; i < keys.length; i++) {
      var cat = RULE_CATEGORIES[keys[i]] || "url";
      cnt[cat] = (cnt[cat] || 0) + h.ruleCounts[keys[i]];
    }
  }
  var t = (cnt.url + cnt.page + cnt.behavior) || 1;
  document.getElementById("barUrl").style.width = (cnt.url / t * 100).toFixed(1) + "%";
  document.getElementById("barPage").style.width = (cnt.page / t * 100).toFixed(1) + "%";
  document.getElementById("barBehavior").style.width = (cnt.behavior / t * 100).toFixed(1) + "%";
  document.getElementById("cntUrl").textContent = cnt.url;
  document.getElementById("cntPage").textContent = cnt.page;
  document.getElementById("cntBehavior").textContent = cnt.behavior;
}

function renderThreatList(h) {
  var c = document.getElementById("threatList");
  var d = h.detections || [];
  if (d.length === 0) {
    c.innerHTML = '<div class="empty-state"><div class="empty-icon" style="font-size:48px">\u{1F6E1}\uFE0F</div><p>No threats recorded</p><p style="font-size:11px;color:#bbb;margin-top:4px;">Start browsing to detect threats</p></div>';
    return;
  }
  var labels = { high: "HIGH", medium: "MEDIUM", low: "LOW" };
  var html = "";
  var items = d.slice(-20).reverse();
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    var lvl = item.level || "low";
    html += '<div class="threat-item ' + lvl + '">';
    html += '<div class="threat-domain" title="' + esc(item.url || "") + '">' + esc(item.domain || item.url || "unknown") + "</div>";
    html += '<div class="threat-level ' + lvl + '">' + (labels[lvl] || "LOW") + "</div>";
    html += '<div class="threat-time">' + fmtTime(item.timestamp) + "</div>";
    html += "</div>";
  }
  c.innerHTML = html;
}

function renderEngineHealth(s) {
  var u = document.getElementById("healthUrl");
  var p = document.getElementById("healthPage");
  var b = document.getElementById("healthBehavior");
  u.textContent = s.enableUrlDetection !== false ? "Active" : "Disabled";
  u.className = "check-status " + (s.enableUrlDetection !== false ? "on" : "off");
  p.textContent = s.enablePageDetection !== false ? "Active" : "Disabled";
  p.className = "check-status " + (s.enablePageDetection !== false ? "on" : "off");
  b.textContent = s.enableBehaviorDetection !== false ? "Active" : "Disabled";
  b.className = "check-status " + (s.enableBehaviorDetection !== false ? "on" : "off");
  var any = s.enableUrlDetection !== false || s.enablePageDetection !== false || s.enableBehaviorDetection !== false;
  document.getElementById("statusDot").className = "status-dot " + (any ? "active" : "inactive");
}

function renderTopRules(h) {
  var c = document.getElementById("topRules");
  var cnt = h.ruleCounts || {};
  var keys = Object.keys(cnt);
  if (keys.length === 0) {
    c.innerHTML = '<span style="font-size:12px;color:#bbb;">Collecting data...</span>';
    return;
  }
  keys.sort(function(a, b) { return cnt[b] - cnt[a]; });
  var top = keys.slice(0, 6);
  var html = "";
  for (var i = 0; i < top.length; i++) {
    var cat = RULE_CATEGORIES[top[i]] || "url";
    var name = RULE_NAMES[top[i]] || top[i];
    html += '<span class="rule-effect-tag ' + cat + '">' + name + " x" + cnt[top[i]] + "</span>";
  }
  c.innerHTML = html;
}

function updateRefreshTime() {
  var n = new Date();
  document.getElementById("refreshInfo").textContent = "Updated " +
    n.getHours().toString().padStart(2, "0") + ":" +
    n.getMinutes().toString().padStart(2, "0") + ":" +
    n.getSeconds().toString().padStart(2, "0");
}

document.getElementById("btnScanNow").addEventListener("click", async function() {
  var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs[0] && tabs[0].url) {
    await chrome.runtime.sendMessage({ type: "CHECK_URL", url: tabs[0].url, tabId: tabs[0].id });
    setTimeout(loadDashboard, 500);
  }
});

document.getElementById("btnOptions").addEventListener("click", function() {
  chrome.runtime.openOptionsPage();
});

function esc(s) {
  var d = document.createElement("div");
  d.textContent = s || "";
  return d.innerHTML;
}

function fmtTime(ts) {
  if (!ts) return "-";
  var d = new Date(ts);
  var n = new Date();
  var diff = n - d;
  if (diff < 60000) return "just now";
  if (diff < 3600000) return Math.floor(diff / 60000) + "m ago";
  if (diff < 86400000) return Math.floor(diff / 3600000) + "h ago";
  return (d.getMonth() + 1).toString().padStart(2, "0") + "/" + d.getDate().toString().padStart(2, "0");
}
