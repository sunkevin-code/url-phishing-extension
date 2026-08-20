// ============================================================
// Enhanced Options Script - 设置页交互逻辑
// ============================================================

// ---------- 状态 ----------
let whitelist = [];
let blacklist = [];
let settings = {};

// ---------- 初始化 ----------
document.addEventListener("DOMContentLoaded", async () => {
  await loadData();
  renderSettings();
  renderWhitelist();
  renderBlacklist();
  bindEvents();
  checkSafeBrowsingStatus();
});

// ---------- 加载数据 ----------
async function loadData() {
  const result = await chrome.storage.local.get(["whitelist", "blacklist", "settings"]);
  whitelist = result.whitelist || [];
  blacklist = result.blacklist || [];
  settings = result.settings || {};
}

// ---------- 保存数据 ----------
async function saveLists() {
  await chrome.storage.local.set({ whitelist, blacklist });
}

// ---------- 渲染设置 ----------
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

// ---------- 检查 Safe Browsing 状态 ----------
async function checkSafeBrowsingStatus() {
  const keyInput = document.getElementById("safeBrowsingApiKey");
  const statusEl = document.getElementById("sbApiStatus");
  const key = keyInput.value.trim();

  if (!key) {
    statusEl.className = "api-status info";
    statusEl.textContent = "⏸ 需要 API Key 才能启用";
    return;
  }

  // Test key format (starts with AIza)
  if (key.startsWith("AIza")) {
    statusEl.className = "api-status ok";
    statusEl.textContent = "✓ API Key 格式正确（以 AIza 开头）";
  } else {
    statusEl.className = "api-status err";
    statusEl.textContent = "⚠ API Key 格式异常，Google API Key 通常以 AIza 开头";
  }
}

// ---------- 渲染白名单 ----------
function renderWhitelist() {
  const container = document.getElementById("whitelistContainer");
  if (whitelist.length === 0) {
    container.innerHTML = `<div class="empty-list">白名单为空，添加您信任的域名将不再被检测</div>`;
    return;
  }
  container.innerHTML = whitelist.map(domain => `
    <div class="list-item">
      <span class="domain">${escapeHtml(domain)}</span>
      <button class="remove" data-type="whitelist" data-domain="${escapeHtml(domain)}">删除</button>
    </div>
  `).join("");
}

// ---------- 渲染黑名单 ----------
function renderBlacklist() {
  const container = document.getElementById("blacklistContainer");
  if (blacklist.length === 0) {
    container.innerHTML = `<div class="empty-list">黑名单为空，添加钓鱼域名将直接拦截</div>`;
    return;
  }
  container.innerHTML = blacklist.map(domain => `
    <div class="list-item">
      <span class="domain">${escapeHtml(domain)}</span>
      <button class="remove" data-type="blacklist" data-domain="${escapeHtml(domain)}">删除</button>
    </div>
  `).join("");
}

// ---------- HTML 转义 ----------
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

// ---------- 保存设置到 background ----------
async function saveAndNotifySettings() {
  await chrome.storage.local.set({ settings });
  chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings }).catch(() => {});
  showToast("设置已保存");
}

// ---------- 绑定事件 ----------
function bindEvents() {
  // ---- Tab 切换 ----
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const target = tab.dataset.tab;
      document.getElementById("whitelistTab").classList.toggle("hidden", target !== "whitelist");
      document.getElementById("blacklistTab").classList.toggle("hidden", target !== "blacklist");
    });
  });

  // ---- 设置切换（基础） ----
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

  // ---- 设置切换（新增） ----
  const newToggleIds = [
    "enableDomMonitoring", "enableSslCheck", "enableMLDetection", "enableSafeBrowsing"
  ];
  newToggleIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", async (e) => {
        settings[id] = e.target.checked;
        await saveAndNotifySettings();

        // Safe Browsing 开关特殊处理
        if (id === "enableSafeBrowsing") {
          checkSafeBrowsingStatus();
        }
      });
    }
  });

  // ---- 警告阈值 ----
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
    // 失去焦点时保存
    sbKeyInput.addEventListener("blur", async (e) => {
      settings.safeBrowsingApiKey = e.target.value.trim();
      await saveAndNotifySettings();
      checkSafeBrowsingStatus();
    });

    // 回车保存
    sbKeyInput.addEventListener("keypress", async (e) => {
      if (e.key === "Enter") {
        e.target.blur();
      }
    });

    // 显示/隐藏 API Key
    document.getElementById("toggleSbKey")?.addEventListener("click", () => {
      const currentType = sbKeyInput.type;
      sbKeyInput.type = currentType === "password" ? "text" : "password";
    });
  }

  // ---- 添加白名单 ----
  document.getElementById("addWhitelist").addEventListener("click", () => {
    const input = document.getElementById("whitelistInput");
    const domain = input.value.trim().toLowerCase();
    if (!domain) { showToast("请输入域名", 1500); return; }

    if (whitelist.includes(domain)) {
      showToast("该域名已在白名单中", 1500);
      return;
    }

    whitelist.push(domain);
    saveLists().then(() => {
      renderWhitelist();
      input.value = "";
      showToast(`已添加: ${domain}`);
    });
  });
  document.getElementById("whitelistInput").addEventListener("keypress", (e) => {
    if (e.key === "Enter") document.getElementById("addWhitelist").click();
  });

  // ---- 添加黑名单 ----
  document.getElementById("addBlacklist").addEventListener("click", () => {
    const input = document.getElementById("blacklistInput");
    const domain = input.value.trim().toLowerCase();
    if (!domain) { showToast("请输入域名", 1500); return; }

    if (blacklist.includes(domain)) {
      showToast("该域名已在黑名单中", 1500);
      return;
    }

    blacklist.push(domain);
    saveLists().then(() => {
      renderBlacklist();
      input.value = "";
      showToast(`已添加: ${domain}`);
    });
  });
  document.getElementById("blacklistInput").addEventListener("keypress", (e) => {
    if (e.key === "Enter") document.getElementById("addBlacklist").click();
  });

  // ---- 删除（事件委托） ----
  document.addEventListener("click", async (e) => {
    if (!e.target.classList.contains("remove")) return;

    const type = e.target.dataset.type;
    const domain = e.target.dataset.domain;

    if (type === "whitelist") {
      whitelist = whitelist.filter(w => w !== domain);
      await saveLists();
      renderWhitelist();
      showToast(`已移除: ${domain}`);
    } else if (type === "blacklist") {
      blacklist = blacklist.filter(b => b !== domain);
      await saveLists();
      renderBlacklist();
      showToast(`已移除: ${domain}`);
    }
  });

  // ---- 批量导入 ----
  function setupImport(prefix) {
    const importBtn = document.getElementById(`import${prefix}`);
    const area = document.getElementById(`import${prefix}Area`);
    const confirmBtn = document.getElementById(`confirm${prefix}Import`);
    const cancelBtn = document.getElementById(`cancel${prefix}Import`);
    const textarea = document.getElementById(`${prefix.toLowerCase()}BulkInput`);
    const list = prefix === "Whitelist" ? whitelist : blacklist;
    const renderFn = prefix === "Whitelist" ? renderWhitelist : renderBlacklist;
    const listName = prefix === "Whitelist" ? "白名单" : "黑名单";

    importBtn.addEventListener("click", () => {
      area.classList.toggle("hidden");
    });

    confirmBtn.addEventListener("click", () => {
      const domains = textarea.value.trim().split("\n")
        .map(d => d.trim().toLowerCase())
        .filter(d => d && !list.includes(d));

      if (domains.length === 0) {
        showToast("没有新域名可添加", 1500);
        return;
      }

      list.push(...domains);
      saveLists().then(() => {
        renderFn();
        textarea.value = "";
        area.classList.add("hidden");
        showToast(`已批量添加 ${domains.length} 个域名到${listName}`);
      });
    });

    cancelBtn.addEventListener("click", () => {
      textarea.value = "";
      area.classList.add("hidden");
    });
  }

  setupImport("Whitelist");
  setupImport("Blacklist");

  // ---- 导出 ----
  document.getElementById("exportWhitelist").addEventListener("click", () => {
    exportList(whitelist, "whitelist.txt");
  });
  document.getElementById("exportBlacklist").addEventListener("click", () => {
    exportList(blacklist, "blacklist.txt");
  });
}

function exportList(list, filename) {
  if (list.length === 0) {
    showToast("列表为空，无需导出", 1500);
    return;
  }
  const blob = new Blob([list.join("\n")], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`已导出 ${list.length} 个域名`);
}
