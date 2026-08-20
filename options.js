// ============================================================
// Enhanced Options Script - Settings page interaction logic
// ============================================================

// ---------- State ----------
let whitelist = [];
let blacklist = [];
let settings = {};

// ---------- Init ----------
document.addEventListener("DOMContentLoaded", async () => {
  await loadData();
  renderSettings();
  renderWhitelist();
  renderBlacklist();
  bindEvents();
  checkSafeBrowsingStatus();
});

// ---------- Load Data ----------
async function loadData() {
  const result = await chrome.storage.local.get(["whitelist", "blacklist", "settings"]);
  whitelist = result.whitelist || [];
  blacklist = result.blacklist || [];
  settings = result.settings || {};
}

// ---------- Save Data ----------
async function saveLists() {
  await chrome.storage.local.set({ whitelist, blacklist });
}

// ---------- Render Settings ----------
function renderSettings() {
  // Base settings
  document.getElementById("enableUrlDetection").checked =
    settings.enableUrlDetection !== false;
  document.getElementById("enablePageDetection").checked =
    settings.enablePageDetection !== false;
  document.getElementById("enableBehaviorDetection").checked =
    settings.enableBehaviorDetection !== false;
  document.getElementById("showNotifications").checked =
    settings.showNotifications !== false;
  document.getElementById("autoBlock").checked =
    settings.autoBlock === true;
  document.getElementById("warnThreshold").value =
    settings.warnThreshold || "medium";

  // NEW: DOM Monitoring
  document.getElementById("enableDomMonitoring").checked =
    settings.enableDomMonitoring !== false;

  // NEW: SSL Check
  document.getElementById("enableSslCheck").checked =
    settings.enableSslCheck !== false;

  // NEW: ML Detection
  document.getElementById("enableMLDetection").checked =
    settings.enableMLDetection !== false;
  document.getElementById("mlAlgorithm").value =
    settings.mlAlgorithm || "ensemble";

  // NEW: Safe Browsing
  document.getElementById("enableSafeBrowsing").checked =
    settings.enableSafeBrowsing === true;
  document.getElementById("safeBrowsingApiKey").value =
    settings.safeBrowsingApiKey || "";

  // Toggle Safe Browsing API section visibility
  const sbSection = document.getElementById("safeBrowsingApiSection");
  if (sbSection) {
    sbSection.style.display = settings.enableSafeBrowsing ? "block" : "block";
  }
}

// ---------- Check Safe Browsing Status ----------
async function checkSafeBrowsingStatus() {
  const keyInput = document.getElementById("safeBrowsingApiKey");
  const statusEl = document.getElementById("sbApiStatus");
  const key = keyInput.value.trim();

  if (!key) {
    statusEl.className = "api-status info";
    statusEl.textContent = "⏸ API Key required to enable";
    return;
  }

  // Test key format (starts with AIza)
  if (key.startsWith("AIza")) {
    statusEl.className = "api-status ok";
    statusEl.textContent = "✓ API Key format correct (starts with AIza)";
  } else {
    statusEl.className = "api-status err";
    statusEl.textContent = "⚠ Invalid API Key format — Google API Keys usually start with AIza";
  }
}

// ---------- Render Whitelist ----------
function renderWhitelist() {
  const container = document.getElementById("whitelistContainer");
  if (whitelist.length === 0) {
    container.innerHTML = `<div class="empty-list">Whitelist is empty. Add trusted domains to skip detection.</div>`;
    return;
  }
  container.innerHTML = whitelist.map(domain => `
    <div class="list-item">
      <span class="domain">${escapeHtml(domain)}</span>
      <button class="remove" data-type="whitelist" data-domain="${escapeHtml(domain)}">Remove</button>
    </div>
  `).join("");
}

// ---------- Render Blacklist ----------
function renderBlacklist() {
  const container = document.getElementById("blacklistContainer");
  if (blacklist.length === 0) {
    container.innerHTML = `<div class="empty-list">Blacklist is empty. Add phishing domains to block them directly.</div>`;
    return;
  }
  container.innerHTML = blacklist.map(domain => `
    <div class="list-item">
      <span class="domain">${escapeHtml(domain)}</span>
      <button class="remove" data-type="blacklist" data-domain="${escapeHtml(domain)}">Remove</button>
    </div>
  `).join("");
}

// ---------- HTML Escape ----------
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ---------- Toast ----------
function showToast(msg, duration = 2000) {
  const toast = document.getElementById("toast");
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), duration);
}

// ---------- Save Settings to Background ----------
async function saveAndNotifySettings() {
  await chrome.storage.local.set({ settings });
  chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings }).catch(() => {});
  showToast("Settings saved");
}

// ---------- Bind Events ----------
function bindEvents() {
  // ---- Tab Switching ----
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const target = tab.dataset.tab;
      document.getElementById("whitelistTab").classList.toggle("hidden", target !== "whitelist");
      document.getElementById("blacklistTab").classList.toggle("hidden", target !== "blacklist");
    });
  });

  // ---- Settings Toggles (Basic) ----
  const baseToggleIds = [
    "enableUrlDetection", "enablePageDetection", "enableBehaviorDetection",
    "showNotifications", "autoBlock"
  ];
  baseToggleIds.forEach(id => {
    document.getElementById(id).addEventListener("change", async (e) => {
      settings[id] = e.target.checked;
      await saveAndNotifySettings();
    });
  });

  // ---- Settings Toggles (New) ----
  const newToggleIds = [
    "enableDomMonitoring", "enableSslCheck", "enableMLDetection", "enableSafeBrowsing"
  ];
  newToggleIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", async (e) => {
        settings[id] = e.target.checked;
        await saveAndNotifySettings();

        // Special handling for Safe Browsing toggle
        if (id === "enableSafeBrowsing") {
          checkSafeBrowsingStatus();
        }
      });
    }
  });

  // ---- Warning Threshold ----
  document.getElementById("warnThreshold").addEventListener("change", async (e) => {
    settings.warnThreshold = e.target.value;
    await saveAndNotifySettings();
  });

  document.getElementById("mlAlgorithm").addEventListener("change", async (e) => {
    settings.mlAlgorithm = e.target.value;
    await saveAndNotifySettings();
  });

  // ---- Safe Browsing API Key ----
  const sbKeyInput = document.getElementById("safeBrowsingApiKey");
  if (sbKeyInput) {
    // Save on blur
    sbKeyInput.addEventListener("blur", async (e) => {
      settings.safeBrowsingApiKey = e.target.value.trim();
      await saveAndNotifySettings();
      checkSafeBrowsingStatus();
    });

    // Save on Enter
    sbKeyInput.addEventListener("keypress", async (e) => {
      if (e.key === "Enter") {
        e.target.blur();
      }
    });

    // Show/hide API Key
    document.getElementById("toggleSbKey")?.addEventListener("click", () => {
      const currentType = sbKeyInput.type;
      sbKeyInput.type = currentType === "password" ? "text" : "password";
    });
  }

  // ---- Add Whitelist ----
  document.getElementById("addWhitelist").addEventListener("click", () => {
    const input = document.getElementById("whitelistInput");
    const domain = input.value.trim().toLowerCase();
    if (!domain) { showToast("Enter a domain", 1500); return; }

    if (whitelist.includes(domain)) {
      showToast("Domain already in whitelist", 1500);
      return;
    }

    whitelist.push(domain);
    saveLists().then(() => {
      renderWhitelist();
      input.value = "";
      showToast(`Added: ${domain}`);
    });
  });
  document.getElementById("whitelistInput").addEventListener("keypress", (e) => {
    if (e.key === "Enter") document.getElementById("addWhitelist").click();
  });

  // ---- Add Blacklist ----
  document.getElementById("addBlacklist").addEventListener("click", () => {
    const input = document.getElementById("blacklistInput");
    const domain = input.value.trim().toLowerCase();
    if (!domain) { showToast("Enter a domain", 1500); return; }

    if (blacklist.includes(domain)) {
      showToast("Domain already in blacklist", 1500);
      return;
    }

    blacklist.push(domain);
    saveLists().then(() => {
      renderBlacklist();
      input.value = "";
      showToast(`Added: ${domain}`);
    });
  });
  document.getElementById("blacklistInput").addEventListener("keypress", (e) => {
    if (e.key === "Enter") document.getElementById("addBlacklist").click();
  });

  // ---- Delete (Event Delegation) ----
  document.addEventListener("click", async (e) => {
    if (!e.target.classList.contains("remove")) return;

    const type = e.target.dataset.type;
    const domain = e.target.dataset.domain;

    if (type === "whitelist") {
      whitelist = whitelist.filter(w => w !== domain);
      await saveLists();
      renderWhitelist();
      showToast(`Removed: ${domain}`);
    } else if (type === "blacklist") {
      blacklist = blacklist.filter(b => b !== domain);
      await saveLists();
      renderBlacklist();
      showToast(`Removed: ${domain}`);
    }
  });

  // ---- Bulk Import ----
  function setupImport(prefix) {
    const importBtn = document.getElementById(`import${prefix}`);
    const area = document.getElementById(`import${prefix}Area`);
    const confirmBtn = document.getElementById(`confirm${prefix}Import`);
    const cancelBtn = document.getElementById(`cancel${prefix}Import`);
    const textarea = document.getElementById(`${prefix.toLowerCase()}BulkInput`);
    const list = prefix === "Whitelist" ? whitelist : blacklist;
    const renderFn = prefix === "Whitelist" ? renderWhitelist : renderBlacklist;
    const listName = prefix === "Whitelist" ? "whitelist" : "blacklist";

    importBtn.addEventListener("click", () => {
      area.classList.toggle("hidden");
    });

    confirmBtn.addEventListener("click", () => {
      const domains = textarea.value.trim().split("\n")
        .map(d => d.trim().toLowerCase())
        .filter(d => d && !list.includes(d));

      if (domains.length === 0) {
        showToast("No new domains to add", 1500);
        return;
      }

      list.push(...domains);
      saveLists().then(() => {
        renderFn();
        textarea.value = "";
        area.classList.add("hidden");
        showToast(`Added ${domains.length} domains to ${listName}`);
      });
    });

    cancelBtn.addEventListener("click", () => {
      textarea.value = "";
      area.classList.add("hidden");
    });
  }

  setupImport("Whitelist");
  setupImport("Blacklist");

  // ---- Export ----
  document.getElementById("exportWhitelist").addEventListener("click", () => {
    exportList(whitelist, "whitelist.txt");
  });
  document.getElementById("exportBlacklist").addEventListener("click", () => {
    exportList(blacklist, "blacklist.txt");
  });
}

function exportList(list, filename) {
  if (list.length === 0) {
    showToast("List is empty, nothing to export", 1500);
    return;
  }
  const blob = new Blob([list.join("\n")], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported ${list.length} domains`);
}
