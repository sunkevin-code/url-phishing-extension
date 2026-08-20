// ============================================================
// Enhanced Background Service Worker
// Core Detection + Safe Browsing API + SSL Check + ML Inference
// ============================================================

import { evaluateUrlRisk, evaluateBehaviorRisk, getRiskLabel, KNOWN_DOMAINS, extractMLFeatures } from "./rules.js";
import { loadMLModel, mlPredict, isMLModelLoaded } from "./ml_inference.js";
import { loadRFModel, rfPredict, isRFModelLoaded } from "./rf_inference.js";

// ========== DomainSet ==========
class DomainSet {
  constructor(domains) {
    domains = domains || [];
    this._exact = new Set();
    this._size = 0;
    for (var i = 0; i < domains.length; i++) this.add(domains[i]);
  }
  add(domain) {
    domain = domain.toLowerCase().trim();
    if (!domain || this._exact.has(domain)) return false;
    this._exact.add(domain);
    this._size++;
    return true;
  }
  delete(domain) {
    domain = domain.toLowerCase().trim();
    if (!this._exact.has(domain)) return false;
    this._exact.delete(domain);
    this._size--;
    return true;
  }
  has(hostname) {
    hostname = hostname.toLowerCase();
    if (this._exact.has(hostname)) return true;
    var parts = hostname.split(".");
    for (var i = 0; i < parts.length - 1; i++) {
      if (this._exact.has(parts.slice(i).join("."))) return true;
    }
    return false;
  }
  includes(domain) { return this._exact.has(domain.toLowerCase().trim()); }
  toArray() { return Array.from(this._exact); }
  get length() { return this._size; }
}

// ========== Constants ==========
const STORAGE_KEYS = {
  WHITELIST: "whitelist", BLACKLIST: "blacklist", STATS: "detection_stats",
  SETTINGS: "settings", NAV_HISTORY: "nav_history", DETECTION_HISTORY: "detection_history"
};

const DEFAULT_SETTINGS = {
  enableUrlDetection: true, enablePageDetection: true, enableBehaviorDetection: true,
  warnThreshold: "medium", autoBlock: false, showNotifications: true, checkInterval: 0,
  // NEW SETTINGS
  enableSafeBrowsing: false, safeBrowsingApiKey: "",
  enableSslCheck: true, enableMLDetection: true, enableDomMonitoring: true,
  mlAlgorithm: "ensemble"
};

// ========== State ==========
let settings = { ...DEFAULT_SETTINGS };
let whitelist = new DomainSet();
let blacklist = new DomainSet();
var stats = { totalChecked: 0, blocked: 0, warned: 0, safe: 0 };
const navHistory = new Map();
let detectionHistory = { detections: [], ruleCounts: {} };
let initPromise = null;

// Safe Browsing cache (avoid hitting API repeatedly for same URL)
const safeBrowsingCache = new Map();
const SAFE_BROWSING_CACHE_TTL = 300000; // 5 minutes

// ========== Storage ==========
async function loadFromStorage() {
  const result = await chrome.storage.local.get([
    STORAGE_KEYS.WHITELIST, STORAGE_KEYS.BLACKLIST, STORAGE_KEYS.STATS, STORAGE_KEYS.SETTINGS,
    STORAGE_KEYS.DETECTION_HISTORY
  ]);
  var wl = result[STORAGE_KEYS.WHITELIST];
  var bl = result[STORAGE_KEYS.BLACKLIST];
  whitelist = new DomainSet(Array.isArray(wl) ? wl : []);
  blacklist = new DomainSet(Array.isArray(bl) ? bl : []);
  stats = result[STORAGE_KEYS.STATS] || stats;
  settings = { ...DEFAULT_SETTINGS, ...(result[STORAGE_KEYS.SETTINGS] || {}) };
  detectionHistory = result[STORAGE_KEYS.DETECTION_HISTORY] || { detections: [], ruleCounts: {} };
}

async function saveToStorage(key, data) {
  await chrome.storage.local.set({ [key]: data });
}

async function ensureInitialized() {
  if (!initPromise) {
    initPromise = (async function() {
      await loadFromStorage();
      // Await model load so checkUrl can actually use ML/RF (previously
      // fire-and-forget meant isMLModelLoaded() was still false on first check,
      // so the ML layer never contributed — a key reason "other detectors" had 0 contribution).
      await Promise.all([loadMLModel(), loadRFModel()]).catch(function(e) {
        console.warn("[Phish] model load failed:", e);
      });
      await ensureDefaultLists();
    })().catch(function(e) {
      initPromise = null;
      throw e;
    });
  }
  return initPromise;
}

async function ensureDefaultLists() {
  const defaultWhitelist = [
    "google.com","youtube.com","facebook.com","twitter.com","instagram.com",
    "linkedin.com","microsoft.com","apple.com","amazon.com","github.com",
    "stackoverflow.com","baidu.com","weixin.qq.com","alipay.com","taobao.com","jd.com"
  ];
  if (whitelist.length === 0) {
    for (var i = 0; i < defaultWhitelist.length; i++) whitelist.add(defaultWhitelist[i]);
    await saveToStorage(STORAGE_KEYS.WHITELIST, whitelist.toArray());
  }
  if (blacklist.length === 0) {
    await saveToStorage(STORAGE_KEYS.BLACKLIST, blacklist.toArray());
  }
  if (stats.totalChecked === 0) {
    await saveToStorage(STORAGE_KEYS.STATS, stats);
  }
}

function normalizeDomainFromUrl(url) {
  try { return new URL(url).hostname.replace(/^www\./, "").toLowerCase(); }
  catch { return ""; }
}

function riskLevelFromScore(score) {
  if (score >= 55) return "high";
  if (score >= 28) return "medium";
  if (score >= 10) return "low";
  return "safe";
}

function shouldWarnForLevel(level) {
  if (!settings.showNotifications || level === "safe") return false;
  const order = { low: 1, medium: 2, high: 3 };
  const threshold = settings.warnThreshold || "medium";
  return (order[level] || 0) >= (order[threshold] || 2);
}

async function updateActionIcon(tabId, level, score) {
  if (!tabId || tabId < 0) return;
  const label = getRiskLabel(level);
  try {
    await chrome.action.setIcon({ tabId: tabId, path: label.icon });
    await chrome.action.setTitle({
      tabId: tabId,
      title: "Phishing Detector: " + label.text + " (" + (score || 0) + ")"
    });
  } catch (e) {}
}

async function addListDomain(list, key, domain) {
  domain = (domain || "").toLowerCase().trim().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
  if (!domain) return { success: false, error: "Invalid domain" };
  if (!list.includes(domain)) {
    list.add(domain);
    await saveToStorage(key, list.toArray());
  }
  return { success: true, domain: domain };
}

// ========== List Checks ==========
function isWhitelisted(url) {
  try { return whitelist.has(new URL(url).hostname.replace(/^www\./, "").toLowerCase()); }
  catch { return false; }
}
function isBlacklisted(url) {
  try { return blacklist.has(new URL(url).hostname.replace(/^www\./, "").toLowerCase()); }
  catch { return false; }
}
function isKnownDomain(hostname) {
  hostname = hostname.toLowerCase().replace(/^www\./, "");
  const parts = hostname.split(".");
  for (var i = 0; i < KNOWN_DOMAINS.length; i++) {
    if (hostname === KNOWN_DOMAINS[i] || (parts.length >= 3 && hostname.endsWith("." + KNOWN_DOMAINS[i]))) {
      return true;
    }
  }
  return false;
}

// ========== Google Safe Browsing API ==========
async function checkSafeBrowsing(url) {
  if (!settings.enableSafeBrowsing || !settings.safeBrowsingApiKey) {
    return null;
  }

  // Check cache first
  const cached = safeBrowsingCache.get(url);
  if (cached && (Date.now() - cached.timestamp) < SAFE_BROWSING_CACHE_TTL) {
    return cached.result;
  }

  try {
    const apiKey = settings.safeBrowsingApiKey;
    const resp = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "phish-detector", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: url }]
          }
        })
      }
    );

    if (!resp.ok) {
      console.warn("[SB] API error:", resp.status);
      return null;
    }

    const data = await resp.json();
    const matches = data.matches || [];
    const isThreat = matches.length > 0;
    const threatTypes = matches.map(function(m) { return m.threatType; });

    const result = { isThreat: isThreat, threatTypes: threatTypes, matches: matches.length };

    // Cache result
    safeBrowsingCache.set(url, { result: result, timestamp: Date.now() });

    // Limit cache size
    if (safeBrowsingCache.size > 1000) {
      const firstKey = safeBrowsingCache.keys().next().value;
      safeBrowsingCache.delete(firstKey);
    }

    return result;
  } catch (e) {
    console.warn("[SB] Check failed:", e.message);
    return null;
  }
}

// ========== SSL Certificate Check ==========
async function checkSslCertificate(tabId) {
  if (!settings.enableSslCheck) return { valid: true, score: 0 };

  try {
    // Use chrome.webRequest or tab info for protocol check
    const tab = await chrome.tabs.get(tabId).catch(function() { return null; });
    if (!tab || !tab.url) return { valid: true, score: 0 };

    const url = new URL(tab.url);
    const protocol = url.protocol;

    if (protocol === "http:") {
      // Check if it's not localhost/dev
      const hostname = url.hostname;
      if (hostname !== "localhost" && hostname !== "127.0.0.1" && !hostname.endsWith(".local")) {
        return { valid: false, score: 20, reason: "HTTP instead of HTTPS" };
      }
    }

    // For HTTPS pages, check certificate via webRequest API
    // Note: Chrome MV3 doesn't provide direct certificate access from service workers.
    // We use the tab URL protocol as a proxy.
    if (protocol === "https:") {
      return { valid: true, score: 0 };
    }

    return { valid: true, score: 0 };
  } catch (e) {
    return { valid: true, score: 0 };
  }
}

// ========== Enhanced Core Detection ==========
async function checkUrl(tabId, url) {
  await ensureInitialized();

  if (!url || url.startsWith("chrome://") || url.startsWith("about:") ||
      url.startsWith("chrome-extension://") || url.startsWith("edge://")) {
    return { safe: true };
  }

  // Whitelist check
  if (isWhitelisted(url)) {
    // Tell the content script to stop monitoring this page so it doesn't
    // keep firing PAGE_ANALYSIS_RESULT for a site the user explicitly trusted.
    if (tabId > 0) await sendToTab(tabId, { type: "STOP_DOM_MONITORING" });
    return { safe: true, reason: "whitelist" };
  }

  // Blacklist check
  if (isBlacklisted(url)) {
    await updateStats("blocked");
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (tab) await showWarning(tabId, url, "Blacklisted domain", "high");
    return { safe: false, reason: "blacklist", level: "high" };
  }

  // ========== Multi-Layer Score ==========
  let totalScore = 0;
  let detectedRules = [];
  let urlScore = 0, pageScore = 0, behaviorScore = 0, mlScore = 0, sbScore = 0, sslScore = 0;

  // Layer 1: URL Rule-Based Detection
  if (settings.enableUrlDetection) {
    const urlResult = evaluateUrlRisk(url);
    urlScore = urlResult.score;
    detectedRules.push(...urlResult.triggered.map(function(id) { return { id: id, category: "url" }; }));
  }

  // Layer 2: Behavior Detection
  if (settings.enableBehaviorDetection && navHistory.has(tabId)) {
    const history = navHistory.get(tabId);
    const behaviorResult = evaluateBehaviorRisk(history);
    behaviorScore = behaviorResult.score;
    detectedRules.push(...behaviorResult.triggered.map(function(id) { return { id: id, category: "behavior" }; }));
  }

  // Layer 3: ML Model Inference — supports NN, RF, or ensemble.
  // ML acts as a RESCUE-ONLY gate, not an additive score. The raw 0-100
  // probability is never added to urlScore (that was the FP root cause:
  // benign sites average ~28 ML points, pushing total over the 10-pt threshold).
  if (settings.enableMLDetection && (isMLModelLoaded() || isRFModelLoaded())) {
    try {
      var mlFeatures = extractMLFeatures(url);
      // Count active features
      var nf = 0;
      for (var fi = 0; fi < mlFeatures.length; fi++) { if (mlFeatures[fi]) nf++; }

      if (nf >= 1) {
        var algo = settings.mlAlgorithm || "ensemble";
        var nnScore = null, rfScore = null;

        // Get NN score if available
        if (isMLModelLoaded() && (algo === "nn" || algo === "ensemble")) {
          var nnResult = mlPredict(mlFeatures);
          nnScore = nnResult.riskScore;
        }

        // Get RF score if available
        if (isRFModelLoaded() && (algo === "rf" || algo === "ensemble")) {
          var rfResult = rfPredict(mlFeatures);
          rfScore = rfResult.riskScore;
        }

        // Combine scores
        if (algo === "ensemble" && nnScore !== null && rfScore !== null) {
          // Ensemble: average both
          mlScore = Math.round((nnScore + rfScore) / 2);
        } else if (algo === "nn" && nnScore !== null) {
          mlScore = nnScore;
        } else if (algo === "rf" && rfScore !== null) {
          mlScore = rfScore;
        } else if (nnScore !== null) {
          mlScore = nnScore;
        } else if (rfScore !== null) {
          mlScore = rfScore;
        }
      }
    } catch (e) {
      console.warn("[ML] Inference error:", e);
    }
  }

  // Layer 4: Safe Browsing Check
  if (settings.enableSafeBrowsing && settings.safeBrowsingApiKey) {
    try {
      const sbResult = await checkSafeBrowsing(url);
      if (sbResult && sbResult.isThreat) {
        sbScore = 60; // Safe Browsing hit = very high confidence
        detectedRules.push({ id: "safe_browsing_match", category: "sb" });
        detectedRules.push({ id: "sb_" + (sbResult.threatTypes[0] || "unknown"), category: "sb" });
      }
    } catch (e) {}
  }

  // Layer 5: SSL Check (if we have a tab)
  if (settings.enableSslCheck && tabId > 0) {
    try {
      const sslResult = await checkSslCertificate(tabId);
      sslScore = sslResult.score || 0;
      if (sslResult.score > 0) {
        detectedRules.push({ id: "ssl_" + (sslResult.reason || "no_https"), category: "ssl" });
      }
    } catch (e) {}
  }

  // Combine scores. URL rules + behavior + Safe Browsing + SSL are additive,
  // but ML is a RESCUE-ONLY gate: it promotes a URL only when URL rules MISSED
  // it (urlScore < 10) while ML is very highly confident (>= 85). It promotes
  // to a FIXED "medium" level (30) rather than adding ML's full 0-100 probability,
  // which avoids over-inflating the score on ML's occasional confident-but-wrong
  // predictions (this was the source of the 12% false-positive rate).
  totalScore = Math.min(100, Math.max(0, urlScore + behaviorScore + sbScore + sslScore));

  // Known domains (capped to 9 by URL rules to prevent false positives) must
  // never be rescued by ML — otherwise a known domain like bilibili.com gets
  // its capped 9 bumped back to 30 and falsely warned.
  let _host = "";
  try { _host = new URL(url).hostname.toLowerCase(); } catch (e) {}
  if (settings.enableMLDetection && mlScore >= 85 && urlScore < 10 && !isKnownDomain(_host)) {
    // ML rescue: high-confidence phishing that the URL rules missed
    totalScore = Math.max(totalScore, 30);
    detectedRules.push({ id: "ml_rescue", category: "ml" });
  }

  // Page analysis via content script (only if not already high risk)
  if (settings.enablePageDetection && tabId > 0 && totalScore < 55) {
    const pageResult = await sendToTab(tabId, {
      type: "ANALYZE_PAGE", url: url
    });
    if (pageResult && pageResult.score > 0) {
      pageScore = pageResult.score;
      totalScore = Math.min(100, totalScore + pageScore);
      detectedRules.push(...pageResult.triggered.map(function(id) { return { id: id, category: "page" }; }));
    }

    // Start DOM monitoring on this tab
    if (settings.enableDomMonitoring) {
      await sendToTab(tabId, { type: "START_DOM_MONITORING" });
    }
  }

  // Determine risk level (same thresholds)
  let level = riskLevelFromScore(totalScore);

  // Known domains cap
  try {
    var hn = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    var parts = hn.split(".");
    for (var i = 0; i < KNOWN_DOMAINS.length; i++) {
      if (hn === KNOWN_DOMAINS[i] || (parts.length >= 3 && hn.endsWith("." + KNOWN_DOMAINS[i]))) {
        if (totalScore >= 10) {
          level = "safe";
          totalScore = Math.min(totalScore, 9);
        }
        break;
      }
    }
  } catch (e) {}

  // Record detection history
  if (level !== "safe") {
    await updateDetectionHistory(url, level, detectedRules);
  }

  await updateStats(level);

  // Handle based on risk level
  if (level === "high") {
    if (settings.autoBlock && tabId > 0) {
      try {
        await chrome.tabs.update(tabId, {
          url: chrome.runtime.getURL("blocked.html") +
               `?url=${encodeURIComponent(url)}` +
               `&rules=${encodeURIComponent(JSON.stringify(detectedRules))}` +
               `&score=${totalScore}`
        });
      } catch (e) { console.error("Block failed:", e); }
    } else if (shouldWarnForLevel(level)) {
      await showWarning(tabId, url, null, level, detectedRules, totalScore);
    }
  } else if (shouldWarnForLevel(level)) {
    await showWarning(tabId, url, null, level, detectedRules, totalScore);
  }

  // Update icon
  await updateActionIcon(tabId, level, totalScore);

  return {
    safe: level === "safe",
    level: level,
    score: totalScore,
    detectedRules: detectedRules,
    urlScore: urlScore,
    pageScore: pageScore,
    behaviorScore: behaviorScore,
    mlScore: mlScore,
    sbScore: sbScore,
    sslScore: sslScore
  };
}

// ========== Stats ==========
// Send a message to a tab's content script with a timeout guard.
// chrome.tabs.sendMessage can stay pending forever if the content script
// exists but never calls sendResponse (e.g. an exception in its listener),
// which would hang checkUrl. This wraps it with a hard timeout.
function sendToTab(tabId, message, timeoutMs) {
  return Promise.race([
    chrome.tabs.sendMessage(tabId, message),
    new Promise(function(resolve) {
      setTimeout(function() { resolve(null); }, timeoutMs || 1500);
    })
  ]).catch(function() { return null; });
}

async function updateStats(result) {
  stats.totalChecked++;
  if (result === "blocked" || result === "high") stats.blocked++;
  else if (result === "medium" || result === "low") stats.warned++;
  else if (result === "safe") stats.safe++;
  await saveToStorage(STORAGE_KEYS.STATS, stats);
  try { await chrome.runtime.sendMessage({ type: "STATS_UPDATED", stats }).catch(() => {}); } catch (e) {}
}

// ========== Detection History ==========
async function updateDetectionHistory(url, level, detectedRules) {
  if (!detectionHistory) detectionHistory = { detections: [], ruleCounts: {} };
  if (!detectionHistory.detections) detectionHistory.detections = [];
  if (!detectionHistory.ruleCounts) detectionHistory.ruleCounts = {};
  try {
    const hostname = new URL(url).hostname;
    detectionHistory.detections.push({
      domain: hostname, url: url.substring(0, 200), level: level,
      timestamp: Date.now(), rules: detectedRules ? detectedRules.map(function(r) { return r.id || r; }) : []
    });
    if (detectionHistory.detections.length > 200) {
      detectionHistory.detections = detectionHistory.detections.slice(-200);
    }
    if (detectedRules) {
      for (const rule of detectedRules) {
        const ruleId = rule.id || rule;
        detectionHistory.ruleCounts[ruleId] = (detectionHistory.ruleCounts[ruleId] || 0) + 1;
      }
    }
    await saveToStorage(STORAGE_KEYS.DETECTION_HISTORY, detectionHistory);
  } catch (e) {}
}

// ========== Warning ==========
async function showWarning(tabId, url, customReason, level, detectedRules, score) {
  const label = getRiskLabel(level);
  try {
    await sendToTab(tabId, {
      type: "SHOW_WARNING", url, level, color: label.color, reason: customReason,
      detectedRules: detectedRules || [], score: score || 0
    });
    if (settings.showNotifications) {
      await chrome.notifications.create({
        type: "basic",
        iconUrl: level === "high" ? "icons/icon128_danger.png" : "icons/icon128_warning.png",
        title: "Phishing Alert: " + label.text,
        message: level === "high" ? "High-risk page blocked: " + url.substring(0, 80) : "Warning: " + url.substring(0, 80),
        priority: 2
      }).catch(() => {});
    }
  } catch (e) {}
}

// ========== Event Listeners ==========

// Navigation completed
chrome.webNavigation.onCompleted.addListener(async function(details) {
  await ensureInitialized();
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  const url = details.url;
  if (!navHistory.has(tabId)) navHistory.set(tabId, []);
  const history = navHistory.get(tabId);
  history.push({ url: url, time: Date.now() });
  if (history.length > 10) history.shift();
  await saveToStorage(STORAGE_KEYS.NAV_HISTORY + "_" + tabId, history);
  await checkUrl(tabId, url);
}, { url: [{ schemes: ["http", "https"] }] });

// Before navigate (blacklist check)
chrome.webNavigation.onBeforeNavigate.addListener(async function(details) {
  await ensureInitialized();
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url || !url.startsWith("http")) return;
  if (isBlacklisted(url)) {
    const tabId = details.tabId;
    await updateStats("blocked");
    if (settings.autoBlock) {
      try {
        await chrome.tabs.update(tabId, {
          url: chrome.runtime.getURL("blocked.html") + "?url=" + encodeURIComponent(url) + "&reason=blacklist"
        });
      } catch (e) {}
    }
  }
});

// Message handler
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.type === "PAGE_ANALYSIS_RESULT") {
    ensureInitialized()
      .then(function() { return handlePageResult(sender.tab?.id, message); })
      .catch(function(e) { console.warn("[Phish] page result failed:", e); });
  }
  if (message.type === "CHECK_URL") {
    checkUrl(message.tabId || sender.tab?.id, message.url)
      .then(sendResponse)
      .catch(function(e) {
        console.warn("[Phish] CHECK_URL failed:", e);
        sendResponse({
          safe: true,
          level: "safe",
          score: 0,
          detectedRules: [],
          error: e && e.message ? e.message : "Detection failed"
        });
      });
    return true;
  }
  if (message.type === "GET_STATS") { sendResponse(stats); }
  if (message.type === "GET_SETTINGS") { sendResponse(settings); }
  if (message.type === "GET_WHITELIST") { sendResponse(whitelist.toArray()); }
  if (message.type === "GET_BLACKLIST") { sendResponse(blacklist.toArray()); }
  if (message.type === "GET_DETECTION_HISTORY") { sendResponse(detectionHistory); }
  if (message.type === "UPDATE_SETTINGS") {
    settings = { ...settings, ...message.settings };
    saveToStorage(STORAGE_KEYS.SETTINGS, settings);
    sendResponse({ success: true });
  }
  if (message.type === "ADD_WHITELIST") {
    addListDomain(whitelist, STORAGE_KEYS.WHITELIST, message.domain).then(function(resp) {
      sendResponse({ ...resp, whitelist: whitelist.toArray() });
    });
    return true;
  }
  if (message.type === "REMOVE_WHITELIST") {
    whitelist.delete(message.domain.toLowerCase().trim());
    saveToStorage(STORAGE_KEYS.WHITELIST, whitelist.toArray());
    sendResponse({ success: true, whitelist: whitelist.toArray() });
  }
  if (message.type === "ADD_BLACKLIST") {
    addListDomain(blacklist, STORAGE_KEYS.BLACKLIST, message.domain).then(function(resp) {
      sendResponse({ ...resp, blacklist: blacklist.toArray() });
    });
    return true;
  }
  if (message.type === "REMOVE_BLACKLIST") {
    blacklist.delete(message.domain.toLowerCase().trim());
    saveToStorage(STORAGE_KEYS.BLACKLIST, blacklist.toArray());
    sendResponse({ success: true, blacklist: blacklist.toArray() });
  }
  if (message.type === "ADD_CURRENT_TO_WHITELIST") {
    const tabId = message.tabId || sender.tab?.id;
    if (message.domain) {
      addListDomain(whitelist, STORAGE_KEYS.WHITELIST, message.domain).then(function(resp) {
        sendResponse({ ...resp, whitelist: whitelist.toArray() });
      });
      return true;
    }
    chrome.tabs.get(tabId, function(tab) {
      if (tab && tab.url) {
        addListDomain(whitelist, STORAGE_KEYS.WHITELIST, normalizeDomainFromUrl(tab.url)).then(function(resp) {
          sendResponse({ ...resp, whitelist: whitelist.toArray() });
        });
      } else {
        sendResponse({ success: false, error: "Cannot get current domain" });
      }
    });
    return true;
  }
  if (message.type === "ADD_CURRENT_TO_BLACKLIST") {
    const tabId = message.tabId || sender.tab?.id;
    if (message.domain) {
      addListDomain(blacklist, STORAGE_KEYS.BLACKLIST, message.domain).then(function(resp) {
        sendResponse({ ...resp, blacklist: blacklist.toArray() });
      });
      return true;
    }
    chrome.tabs.get(tabId, function(tab) {
      if (tab && tab.url) {
        addListDomain(blacklist, STORAGE_KEYS.BLACKLIST, normalizeDomainFromUrl(tab.url)).then(function(resp) {
          sendResponse({ ...resp, blacklist: blacklist.toArray() });
        });
      } else {
        sendResponse({ success: false, error: "Cannot get current domain" });
      }
    });
    return true;
  }
  if (message.type === "GET_ML_STATUS") {
    sendResponse({ loaded: isMLModelLoaded(), info: null });
    return true;
  }
  if (message.type === "GET_SB_CACHE_SIZE") {
    sendResponse({ size: safeBrowsingCache.size });
    return true;
  }
});

// ========== Page Result Handler ==========
async function handlePageResult(tabId, message) {
  if (!tabId) return;
  const url = message.url;
  // Whitelist check: the content script runs analyzePage() independently and
  // sends PAGE_ANALYSIS_RESULT even when checkUrl() already returned "safe"
  // via whitelist. Without this guard, whitelisted sites still show warnings.
  if (isWhitelisted(url)) return;
  let totalScore = 0;

  // URL rules
  if (settings.enableUrlDetection) {
    const urlResult = evaluateUrlRisk(url);
    totalScore += urlResult.score;
  }

  // Page score
  totalScore += (message.score || 0);

  // Determine level
  let level = riskLevelFromScore(totalScore);

  if (level === "high" || shouldWarnForLevel(level)) {
    await showWarning(tabId, url, null, level, (message.triggered || []).map(function(id) {
      return { id: id, category: "page" };
    }), totalScore);
  }
  await updateStats(level);
  await updateActionIcon(tabId, level, totalScore);
}

// ========== Initialization ==========
chrome.runtime.onInstalled.addListener(async function() {
  await ensureInitialized();
  console.log("[Phish] Enhanced background worker started");
});

chrome.runtime.onStartup.addListener(function() {
  ensureInitialized().catch(function(e) { console.warn("[Phish] startup init failed:", e); });
});

ensureInitialized().catch(function(e) { console.warn("[Phish] init failed:", e); });

// History cleanup alarm
chrome.alarms.create("cleanup_history", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener(function(alarm) {
  if (alarm.name === "cleanup_history") {
    navHistory.clear();
    console.log("[Phish] History cleaned");
  }
});

// Keep service worker alive
setInterval(function() {}, 30000);

// Storage change listener
chrome.storage.onChanged.addListener(function(changes, area) {
  if (area !== "local") return;
  if (changes[STORAGE_KEYS.WHITELIST]) {
    var arr = changes[STORAGE_KEYS.WHITELIST].newValue;
    whitelist = new DomainSet(Array.isArray(arr) ? arr : []);
  }
  if (changes[STORAGE_KEYS.BLACKLIST]) {
    var arr = changes[STORAGE_KEYS.BLACKLIST].newValue;
    blacklist = new DomainSet(Array.isArray(arr) ? arr : []);
  }
});

console.log("[Phish] Enhanced Service Worker started");
