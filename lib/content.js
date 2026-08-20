// ============================================================
// Enhanced Content Script - Page Analysis & DOM Monitoring
// ============================================================

var _pageRules = null;
var _analyzeTimeout = null;
var _lastScore = 0;
var _keyloggerFindings = [];

// Load page rules dynamically
import(chrome.runtime.getURL("lib/rules.js")).then(function(m) {
  _pageRules = m.evaluatePageRisk;
  console.log("[Phish] Page rules loaded");
});

// ========== Keylogger / Form Grabbing Detection ==========

// Inject MAIN world hook script to capture native API usage
function injectKeyloggerDetector() {
  if (document.getElementById("__aidr_keylogger_script__")) return;
  var s = document.createElement("script");
  s.id = "__aidr_keylogger_script__";
  s.src = chrome.runtime.getURL("lib/keylogger-detector.js");
  s.onload = function() { s.remove(); };
  (document.head || document.documentElement).appendChild(s);
}

// Listen for findings from the MAIN world script
window.addEventListener("message", function(event) {
  if (event.source !== window) return;
  var data = event.data;
  if (data && data.source === "aidr-keylogger" && Array.isArray(data.findings)) {
    _keyloggerFindings = data.findings;
  }
});

// Aggregate keylogger/form-grabbing findings into a risk score + triggered rules
function evaluateKeyloggerRisk() {
  var score = 0;
  var triggered = [];
  var counts = { keylogger: 0, form_submit_hook: 0, sensitive_input_monitor: 0, beacon_exfil: 0, fetch_exfil: 0, xhr_exfil: 0, websocket_exfil: 0 };
  for (var i = 0; i < _keyloggerFindings.length; i++) {
    var t = _keyloggerFindings[i].type;
    if (counts[t] !== undefined) counts[t]++;
  }

  // Keylogger: keyboard event listener on document/window — very strong signal
  if (counts.keylogger > 0) {
    score += 45;
    triggered.push("KEYLOGGER");
  }
  // Sensitive field monitoring (input/change/keyup on password/credential fields)
  if (counts.sensitive_input_monitor > 0) {
    score += 30;
    triggered.push("SENSITIVE_FIELD_MONITORING");
  }
  // Form submit interception
  if (counts.form_submit_hook > 0) {
    score += 20;
    triggered.push("FORM_SUBMIT_HOOK");
  }
  // Exfiltration channels (highest confidence — data actually leaving)
  if (counts.beacon_exfil > 0) { score += 50; triggered.push("BEACON_EXFIL"); }
  if (counts.fetch_exfil > 0) { score += 50; triggered.push("FETCH_EXFIL"); }
  if (counts.xhr_exfil > 0) { score += 40; triggered.push("XHR_EXFIL"); }
  if (counts.websocket_exfil > 0) { score += 55; triggered.push("WEBSOCKET_EXFIL"); }

  return { score: Math.min(100, score), triggered: triggered, counts: counts };
}

// ========== Page Analysis ==========

function analyzePage() {
  const url = window.location.href;
  const origin = window.location.origin;
  const result = _pageRules ? _pageRules(document, origin) : { score: 0, triggered: [] };
  // Merge keylogger/form-grabbing findings
  const kl = evaluateKeyloggerRisk();
  return {
    score: result.score + kl.score,
    triggered: result.triggered.concat(kl.triggered),
    keyloggerCounts: kl.counts,
    url: url
  };
}

// Debounced re-analysis (avoids rapid re-triggers during DOM mutations)
function scheduleReanalysis() {
  if (_analyzeTimeout) clearTimeout(_analyzeTimeout);
  _analyzeTimeout = setTimeout(function() {
    const result = analyzePage();
    if (result.score !== _lastScore) {
      _lastScore = result.score;
      if (result.score > 0) {
        chrome.runtime.sendMessage({
          type: "PAGE_ANALYSIS_RESULT",
          ...result
        }).catch(function() {});
      }
    }
  }, 500); // 500ms debounce
}

// ========== MutationObserver - Monitor DOM Changes ==========

// Watch for dynamic injection of forms, iframes, scripts, etc.
var _observer = null;

function startDomMonitoring() {
  if (_observer) return;

  _observer = new MutationObserver(function(mutations) {
    var needsReanalysis = false;

    for (var i = 0; i < mutations.length; i++) {
      var mutation = mutations[i];

      // Check added nodes
      if (mutation.addedNodes && mutation.addedNodes.length > 0) {
        for (var j = 0; j < mutation.addedNodes.length; j++) {
          var node = mutation.addedNodes[j];
          if (!node || !node.tagName) continue;

          var tag = node.tagName.toLowerCase();
          // Watch for dynamically injected forms, iframes, scripts
          if (tag === "form" || tag === "iframe" || tag === "script") {
            needsReanalysis = true;
            break;
          }

          // Check for hidden iframes (1x1, display:none)
          if (tag === "iframe") {
            var h = node.height || 0;
            var w = node.width || 0;
            if (h <= 1 || w <= 1) {
              needsReanalysis = true;
              break;
            }
          }

          // Check for password inputs
          if (tag === "input") {
            var type = (node.type || "").toLowerCase();
            if (type === "password") {
              needsReanalysis = true;
              break;
            }
          }

          // Check for added <link> favicon
          if (tag === "link") {
            var rel = (node.rel || "").toLowerCase();
            if (rel.indexOf("icon") > -1) {
              needsReanalysis = true;
              break;
            }
          }
        }
      }

      // Check attribute changes (e.g., display:none → visible, style changes)
      if (mutation.type === "attributes" && !needsReanalysis) {
        var target = mutation.target;
        if (target && target.tagName) {
          var tag2 = target.tagName.toLowerCase();
          if (tag2 === "iframe" || tag2 === "form" || tag2 === "input") {
            needsReanalysis = true;
          }
        }
      }

      if (needsReanalysis) break;
    }

    if (needsReanalysis) {
      scheduleReanalysis();
    }
  });

  // Observe the full document
  _observer.observe(document.body || document.documentElement, {
    childList: true,        // Watch for added/removed nodes
    subtree: true,          // Watch entire DOM tree
    attributes: true,       // Watch for attribute changes
    attributeFilter: ["style", "class", "src", "href", "action", "type"]
  });

  console.log("[Phish] DOM MutationObserver started");
}

// Stop DOM monitoring
function stopDomMonitoring() {
  if (_observer) {
    _observer.disconnect();
    _observer = null;
    console.log("[Phish] DOM MutationObserver stopped");
  }
}

// ========== Sensitive Field Detection ==========

function findSensitiveFields() {
  var fields = [];
  var inputs = document.querySelectorAll("input, textarea, select");

  inputs.forEach(function(input) {
    var type = (input.type || "").toLowerCase();
    var name = (input.name || "").toLowerCase();
    var id = (input.id || "").toLowerCase();
    var placeholder = (input.placeholder || "").toLowerCase();
    var autocomplete = (input.autocomplete || "").toLowerCase();

    var sensitiveTypes = ["password", "email", "tel", "creditcard", "cc-number"];
    var sensitiveNames = [
      "password", "passwd", "pwd", "creditcard", "ccnumber",
      "cardnumber", "card-number", "ssn", "socialsecurity",
      "pin", "cvv", "cvc", "bankaccount", "routing",
      "idcard", "idnumber", "phone", "mobile"
    ];

    var isSensitive = false;
    if (sensitiveTypes.indexOf(type) > -1) isSensitive = true;
    if (sensitiveNames.some(function(n) {
      return name.indexOf(n) > -1 || id.indexOf(n) > -1 ||
             placeholder.indexOf(n) > -1 || autocomplete.indexOf(n) > -1;
    })) isSensitive = true;

    if (isSensitive) {
      fields.push({
        type: type,
        name: input.name,
        id: input.id,
        placeholder: input.placeholder
      });
    }
  });

  return fields;
}

// ========== Warning Banners ==========

function _appendText(parent, text) {
  parent.appendChild(document.createTextNode(text));
}

function _ruleLabel(rule) {
  if (!rule) return "Unknown rule";
  return typeof rule === "string" ? rule : (rule.id || "Unknown rule");
}

function injectWarningBanner(level, color, reason) {
  var existing = document.getElementById("phish-detector-warning");
  if (existing) existing.remove();

  var banner = document.createElement("div");
  banner.id = "phish-detector-warning";
  banner.style.cssText = [
    "position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;",
    "background: " + color + "; color: white; padding: 12px 16px;",
    "font-family: Arial, sans-serif; font-size: 14px;",
    "display: flex; align-items: center; justify-content: space-between;",
    "box-shadow: 0 2px 8px rgba(0,0,0,0.3);",
    "animation: phishSlideDown 0.3s ease-out;"
  ].join(" ");

  var style = document.createElement("style");
  style.textContent = [
    "@keyframes phishSlideDown {",
    "  from { transform: translateY(-100%); }",
    "  to { transform: translateY(0); }",
    "}",
    "#phish-detector-warning-close {",
    "  background: rgba(255,255,255,0.2); border: none; color: white;",
    "  padding: 6px 14px; border-radius: 4px; cursor: pointer;",
    "  font-size: 13px; margin-left: 12px;",
    "}",
    "#phish-detector-warning-close:hover { background: rgba(255,255,255,0.3); }",
    "#phish-detector-whitelist-btn {",
    "  background: rgba(255,255,255,0.2); border: none; color: white;",
    "  padding: 6px 14px; border-radius: 4px; cursor: pointer;",
    "  font-size: 13px; margin-left: 8px;",
    "}",
    "#phish-detector-whitelist-btn:hover { background: rgba(255,255,255,0.3); }"
  ].join(" ");
  document.head.appendChild(style);

  var levelTextMap = { high: "High Risk", medium: "Medium Risk", low: "Low Risk" };
  var levelText = levelTextMap[level] || "Suspicious";
  var warningIcon = level === "high" ? "\u26d4" : "\u26a0\ufe0f";

  var message = document.createElement("span");
  _appendText(message, warningIcon + " ");
  var strong = document.createElement("strong");
  strong.textContent = "Phishing Detector:";
  message.appendChild(strong);
  _appendText(message, " Detected ");
  var levelSpan = document.createElement("span");
  levelSpan.style.cssText = "font-weight:bold;margin:0 4px;";
  levelSpan.textContent = levelText;
  message.appendChild(levelSpan);
  _appendText(message, " site");
  if (reason) _appendText(message, " - " + reason);
  var hostSpan = document.createElement("span");
  hostSpan.style.cssText = "margin-left:12px;opacity:0.8;font-size:12px;";
  hostSpan.textContent = window.location.hostname;
  message.appendChild(hostSpan);

  var actions = document.createElement("span");
  var whitelistBtn = document.createElement("button");
  whitelistBtn.id = "phish-detector-whitelist-btn";
  whitelistBtn.textContent = "+ Add to Whitelist";
  var closeBtn = document.createElement("button");
  closeBtn.id = "phish-detector-warning-close";
  closeBtn.textContent = "Close";
  actions.appendChild(whitelistBtn);
  actions.appendChild(closeBtn);
  banner.appendChild(message);
  banner.appendChild(actions);

  document.body.prepend(banner);

  closeBtn.addEventListener("click", function() {
    banner.remove();
  });

  whitelistBtn.addEventListener("click", async function() {
    try {
      const resp = await chrome.runtime.sendMessage({
        type: "ADD_CURRENT_TO_WHITELIST",
        domain: window.location.hostname
      });
      banner.textContent = "";
      var done = document.createElement("span");
      done.textContent = resp?.success ? "Added to whitelist. Refresh page to stop detection." : "Could not add this domain.";
      var doneClose = document.createElement("button");
      doneClose.id = "phish-detector-warning-close";
      doneClose.textContent = "Close";
      doneClose.addEventListener("click", function() { banner.remove(); });
      banner.appendChild(done);
      banner.appendChild(doneClose);
      banner.style.background = "#4CAF50";
    } catch (e) {}
  });
}

function injectBlockedOverlay(url, rules, score) {
  var existing = document.getElementById("phish-detector-blocked");
  if (existing) return;

  var overlay = document.createElement("div");
  overlay.id = "phish-detector-blocked";
  overlay.style.cssText = "position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: 2147483647; background: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; font-family: Arial, sans-serif;";

  var card = document.createElement("div");
  card.style.cssText = "text-align:center;max-width:500px;padding:40px;";

  var icon = document.createElement("div");
  icon.style.cssText = "font-size:64px;margin-bottom:20px;";
  icon.textContent = "\u26d4";
  var title = document.createElement("h1");
  title.style.cssText = "color:#F44336;font-size:24px;margin:0 0 12px 0;";
  title.textContent = "Risk Page Blocked";
  var description = document.createElement("p");
  description.style.cssText = "color:#666;font-size:14px;line-height:1.6;margin-bottom:24px;";
  description.textContent = "This page has been identified as a phishing risk and has been blocked.";
  var scoreLine = document.createElement("p");
  scoreLine.style.cssText = "color:#666;font-size:14px;line-height:1.6;margin-bottom:24px;";
  scoreLine.textContent = "Risk Score: ";
  var scoreStrong = document.createElement("strong");
  scoreStrong.style.color = "#F44336";
  scoreStrong.textContent = String(score || 0);
  scoreLine.appendChild(scoreStrong);
  _appendText(scoreLine, " / 100");
  var urlBox = document.createElement("div");
  urlBox.style.cssText = "background:#f5f5f5;padding:12px 16px;border-radius:8px;margin-bottom:24px;word-break:break-all;font-size:12px;color:#999;";
  urlBox.textContent = url || window.location.href;

  card.appendChild(icon);
  card.appendChild(title);
  card.appendChild(description);
  card.appendChild(scoreLine);
  card.appendChild(urlBox);

  if (rules && rules.length > 0) {
    var rulesBox = document.createElement("div");
    rulesBox.style.cssText = "text-align:left;margin-bottom:24px;";
    var rulesTitle = document.createElement("p");
    rulesTitle.style.cssText = "font-size:13px;color:#666;font-weight:bold;margin-bottom:8px;";
    rulesTitle.textContent = "Detected risks:";
    rulesBox.appendChild(rulesTitle);
    for (var i = 0; i < rules.length; i++) {
      var ruleRow = document.createElement("div");
      ruleRow.style.cssText = "font-size:12px;color:#888;margin:4px 0;";
      ruleRow.textContent = "\u2022 " + _ruleLabel(rules[i]);
      rulesBox.appendChild(ruleRow);
    }
    card.appendChild(rulesBox);
  }

  var actionRow = document.createElement("div");
  actionRow.style.cssText = "display:flex;gap:12px;justify-content:center;";
  var backBtn = document.createElement("button");
  backBtn.id = "phish-go-back";
  backBtn.style.cssText = "padding:10px 24px;background:#f5f5f5;border:1px solid #ddd;border-radius:6px;cursor:pointer;font-size:14px;color:#333;";
  backBtn.textContent = "Go Back";
  var ignoreBtn = document.createElement("button");
  ignoreBtn.id = "phish-ignore-risk";
  ignoreBtn.style.cssText = "padding:10px 24px;background:#F44336;border:none;border-radius:6px;cursor:pointer;font-size:14px;color:white;";
  ignoreBtn.textContent = "Ignore Risk, Continue";
  actionRow.appendChild(backBtn);
  actionRow.appendChild(ignoreBtn);
  card.appendChild(actionRow);
  overlay.appendChild(card);

  document.body.prepend(overlay);

  backBtn.addEventListener("click", function() {
    window.history.back();
  });

  ignoreBtn.addEventListener("click", function() {
    overlay.remove();
    chrome.runtime.sendMessage({
      type: "ADD_WHITELIST",
      domain: window.location.hostname
    });
  });
}

// ========== Message Listener ==========

chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  switch (message.type) {
    case "ANALYZE_PAGE":
      try {
        var result = analyzePage();
        sendResponse(result);
      } catch (e) {
        // Always respond — a thrown error here would leave the message
        // channel open forever (because of `return true` below) and hang
        // the background service worker's checkUrl.
        sendResponse({ score: 0, triggered: [], url: window.location.href });
      }
      break;

    case "SHOW_WARNING":
      if (message.level === "high") {
        injectBlockedOverlay(message.url, message.detectedRules || [], message.score || 0);
      } else {
        injectWarningBanner(message.level, message.color, message.reason);
      }
      sendResponse({ shown: true });
      break;

    case "GET_SENSITIVE_FIELDS":
      var fields = findSensitiveFields();
      sendResponse({ fields: fields, count: fields.length });
      break;

    case "GET_PAGE_INFO":
      sendResponse({
        title: document.title,
        forms: document.forms.length,
        inputs: document.querySelectorAll("input").length,
        links: document.querySelectorAll("a").length,
        scripts: document.querySelectorAll("script").length,
        iframes: document.querySelectorAll("iframe").length
      });
      break;

    case "START_DOM_MONITORING":
      startDomMonitoring();
      sendResponse({ started: true });
      break;

    case "STOP_DOM_MONITORING":
      stopDomMonitoring();
      sendResponse({ stopped: true });
      break;
  }

  // Return true only for cases that respond synchronously above is fine —
  // but we return false/undefined here so Chrome closes the channel after
  // the synchronous sendResponse. This prevents a leaked channel if a case
  // ever forgets to call sendResponse.
  return false;
});

// ========== Initialization ==========

// Inject MAIN world keylogger hook early
injectKeyloggerDetector();

// Auto-analyze page after load
setTimeout(function() {
  // Start DOM monitoring by default
  startDomMonitoring();

  var result = analyzePage();
  if (result.score > 0) {
    chrome.runtime.sendMessage({
      type: "PAGE_ANALYSIS_RESULT",
      ...result
    }).catch(function() {});
  }
}, 1000);

console.log("[Phish] Enhanced Content Script loaded (DOM monitoring active)");
