// ============================================================
// Keylogger & Form Grabbing Detector — runs in MAIN world
// Injected by content.js to hook native APIs and detect
// credential-theft patterns (keylogging + form data exfiltration).
// ============================================================
(function () {
  "use strict";

  if (window.__aidr_keylogger_installed__) return;
  window.__aidr_keylogger_installed__ = true;

  var findings = [];
  var selfOrigin = location.origin;
  var SENSITIVE_FIELD_NAMES = /password|passwd|pwd|pin|cvv|cvc|ccnumber|cardnumber|ssn|token|secret|credential|credit|account|user|email|phone/i;

  function isCrossOrigin(url) {
    try {
      if (!url) return false;
      if (url.indexOf("data:") === 0 || url.indexOf("blob:") === 0) return false;
      if (url.indexOf("http") !== 0) return false;
      var u = new URL(url, selfOrigin);
      return u.origin !== selfOrigin;
    } catch (e) { return false; }
  }

  function report(type, detail) {
    findings.push({ type: type, detail: detail || {}, ts: Date.now() });
    // Cap to avoid unbounded growth
    if (findings.length > 200) findings = findings.slice(-200);
    try {
      window.postMessage({ source: "aidr-keylogger", findings: findings }, "*");
    } catch (e) {}
  }

  function looksSensitive(data) {
    try {
      var s = String(data || "");
      if (s.length > 3000) return false; // ignore huge blobs
      return SENSITIVE_FIELD_NAMES.test(s) || /name=/.test(s) && /value=/.test(s);
    } catch (e) { return false; }
  }

  // ========== 1. Hook addEventListener for keylogger detection ==========
  var origAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    var t = String(type || "").toLowerCase();
    var self = this;
    try {
      // Keylogger: keydown/keyup/keypress on document or window
      if (t === "keydown" || t === "keyup" || t === "keypress") {
        var targetIsDoc = self === document || self === window || self === document.documentElement || self === document.body;
        if (targetIsDoc) {
          report("keylogger", { event: t, target: "document/window" });
        }
      }
      // Form grabbing: submit listener on a form
      if (t === "submit" && self && self.tagName && self.tagName.toLowerCase() === "form") {
        report("form_submit_hook", { formId: self.id || self.name || null, formAction: self.action || null });
      }
      // Input monitoring: input/change on sensitive fields
      if ((t === "input" || t === "change" || t === "keyup") && self && self.tagName) {
        var tag = self.tagName.toLowerCase();
        var name = String(self.name || self.id || self.placeholder || "").toLowerCase();
        if ((tag === "input" || tag === "textarea") && SENSITIVE_FIELD_NAMES.test(name)) {
          report("sensitive_input_monitor", { field: self.name || self.id || null });
        }
      }
    } catch (e) {}
    return origAddEventListener.apply(this, arguments);
  };

  // ========== 2. Hook onkeydown / onkeypress property setters ==========
  ["onkeydown", "onkeyup", "onkeypress"].forEach(function (prop) {
    try {
      var desc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, prop);
      if (!desc || !desc.configurable) return;
      Object.defineProperty(HTMLElement.prototype, prop, {
        configurable: true,
        get: function () { return desc.get ? desc.get.call(this) : undefined; },
        set: function (fn) {
          if (typeof fn === "function" && (this === document || this === window || this === document.body)) {
            report("keylogger", { event: prop, target: "on-property" });
          }
          if (desc.set) desc.set.call(this, fn);
        }
      });
    } catch (e) {}
  });

  // ========== 3. Hook network APIs for exfiltration detection ==========

  // navigator.sendBeacon — common exfiltration channel
  if (navigator.sendBeacon) {
    var origSendBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      try {
        if (isCrossOrigin(url) || looksSensitive(data)) {
          report("beacon_exfil", { url: String(url).slice(0, 200), crossOrigin: isCrossOrigin(url), sensitive: looksSensitive(data) });
        }
      } catch (e) {}
      return origSendBeacon(url, data);
    };
  }

  // fetch — POST/GET exfiltration
  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function (input, init) {
      try {
        var url = typeof input === "string" ? input : (input && input.url) || "";
        var method = (init && init.method) || (input && input.method) || "GET";
        var body = init && init.body;
        if (isCrossOrigin(url) && (method === "POST" || method === "PUT")) {
          var sensitive = false;
          if (typeof body === "string" && looksSensitive(body)) sensitive = true;
          if (body instanceof URLSearchParams) {
            try { sensitive = SENSITIVE_FIELD_NAMES.test(body.toString()); } catch (e) {}
          }
          if (sensitive) report("fetch_exfil", { url: String(url).slice(0, 200), method: method });
        }
      } catch (e) {}
      return origFetch.apply(this, arguments);
    };
  }

  // XMLHttpRequest — legacy exfiltration
  if (window.XMLHttpRequest) {
    var origXhrOpen = XMLHttpRequest.prototype.open;
    var origXhrSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      try {
        this.__aidr_method = String(method || "").toUpperCase();
        this.__aidr_url = String(url || "");
      } catch (e) {}
      return origXhrOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (body) {
      try {
        if (isCrossOrigin(this.__aidr_url) && (this.__aidr_method === "POST" || this.__aidr_method === "PUT")) {
          if (typeof body === "string" && looksSensitive(body)) {
            report("xhr_exfil", { url: String(this.__aidr_url).slice(0, 200), method: this.__aidr_method });
          }
        }
      } catch (e) {}
      return origXhrSend.apply(this, arguments);
    };
  }

  // WebSocket — realtime keystroke streaming
  if (window.WebSocket) {
    var origWsSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function (data) {
      try {
        if (typeof data === "string" && looksSensitive(data)) {
          report("websocket_exfil", { url: String(this.url || "").slice(0, 200) });
        }
      } catch (e) {}
      return origWsSend.apply(this, arguments);
    };
  }

  // ========== 4. Respond to content script queries ==========
  window.addEventListener("message", function (event) {
    if (event.source !== window) return;
    var data = event.data;
    if (!data || data.source !== "aidr-content") return;
    if (data.type === "GET_FINDINGS") {
      window.postMessage({ source: "aidr-keylogger", findings: findings }, "*");
    }
    if (data.type === "CLEAR_FINDINGS") {
      findings = [];
    }
  });

  // Initial report after a short delay to catch early hooks
  setTimeout(function () {
    window.postMessage({ source: "aidr-keylogger", findings: findings }, "*");
  }, 500);
})();
