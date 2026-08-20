// ============================================================
// Shared: URL Sample Generation & Feed Fetching
// Used by test-harness.html and test-runner.js
// ============================================================

// 700+ phishing URLs generated from diverse patterns
var GENERATE_PHISHING = (function() {
  var brands = ["google","facebook","youtube","paypal","amazon","netflix","microsoft","apple",
    "binance","coinbase","metamask","instagram","twitter","whatsapp","telegram","discord",
    "tiktok","snapchat","linkedin","github","spotify","dropbox","steam","epicgames","uber",
    "airbnb","twitch","reddit","pinterest","shopify","alibaba","taobao","tmall","jd","baidu",
    "weixin","qq","alipay","weibo","douyin","bilibili","zhihu","meituan","bybit","okx",
    "kucoin","opensea","uniswap","pancakeswap","hyperliquid","gmail","outlook","icloud"];
  var tlds = ["tk","ml","ga","cf","gq","xyz","top","work","date","men","loan","click",
    "download","review","trade","bid","win","party","stream","racing","accountant","science"];
  var platforms = ["wixsite.com","weebly.com","webflow.io","github.io","netlify.app",
    "vercel.app","pages.dev","firebaseapp.com","herokuapp.com","000webhostapp.com",
    "blogspot.com","wordpress.com","strikingly.com","azurewebsites.net","fly.dev",
    "railway.app","onrender.com","glitch.me","replit.app","surge.sh"];
  var paths = ["login","signin","verify","secure","account","update","confirm","auth",
    "password","reset","recover","unlock","validate","claim","bonus","airdrop","reward",
    "wallet","restore","connect","access","admin","portal","dashboard"];
  var shorteners = ["bit.ly","tinyurl.com","cutt.ly","shorturl.at","rb.gy","tiny.cc"];

  return function(n) {
    var s = Date.now();
    var rng = function(max) { s = (s * 16807) % 2147483647; return s % max; };
    var pick = function(arr, k) { var a = []; var copy = arr.slice(); for (var i=0; i<Math.min(k,copy.length); i++) { var idx = rng(copy.length); a.push(copy[idx]); copy.splice(idx,1); } return a; };
    var results = [];

    // Pattern 1: Brand typosquatting on bad TLDs
    for (var bi = 0; bi < 30; bi++) {
      var b = brands[rng(brands.length)];
      for (var ti = 0; ti < 3; ti++) {
        var t = tlds[rng(tlds.length)];
        results.push("https://www." + b + "-login." + t + "/login");
        results.push("https://" + b + "-verify." + t + "/signin");
      }
    }

    // Pattern 2: Leet substitutions
    var subs = {o:"0",i:"1",l:"1",e:"3",a:"4",s:"5",t:"7",b:"8",g:"9"};
    for (var bi = 0; bi < 25; bi++) {
      var b = brands[rng(brands.length)];
      var sb = b.split("").map(function(c) { return subs[c] || c; }).join("");
      if (sb !== b) {
        results.push("https://www." + sb + ".com/login");
        results.push("https://" + sb + "-secure.com/account");
      }
    }

    // Pattern 3: Brand on third-party platforms
    for (var bi = 0; bi < 20; bi++) {
      var b = brands[rng(brands.length)];
      for (var pi = 0; pi < 2; pi++) {
        var p = platforms[rng(platforms.length)];
        results.push("https://" + b + "-secure." + p + "/login");
        results.push("https://" + b + "-verify." + p + "/auth");
      }
    }

    // Pattern 4: IP-based hosts
    for (var bi = 0; bi < 20; bi++) {
      var b = brands[rng(brands.length)];
      var ip = Math.floor(Math.random()*223+1) + "." + Math.floor(Math.random()*256) + "." + Math.floor(Math.random()*256) + "." + Math.floor(Math.random()*256);
      results.push("http://" + ip + "/" + b + "/login");
    }

    // Pattern 5: Multi-subdomain
    for (var bi = 0; bi < 20; bi++) {
      var b = brands[rng(brands.length)];
      var t = tlds[rng(tlds.length)];
      results.push("https://" + b + ".com.login.verify." + t + "/");
      results.push("https://account." + b + ".secure.auth." + t + "/signin");
    }

    // Pattern 6: Brand + suspicious paths
    for (var bi = 0; bi < 25; bi++) {
      var b = brands[rng(brands.length)];
      var pa = paths[rng(paths.length)];
      var t = tlds[rng(tlds.length)];
      results.push("https://" + b + "-" + pa + "." + t + "/" + pa);
    }

    // Pattern 7: Hex-encoded paths
    var hex = "0123456789abcdef";
    for (var bi = 0; bi < 20; bi++) {
      var b = brands[rng(brands.length)];
      var hp = "";
      for (var i=0; i<10; i++) hp += "%" + hex[rng(16)] + hex[rng(16)];
      results.push("https://" + b + "-safe.com/login?token=" + hp);
    }

    // Pattern 8: Random long domains
    var alpha = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 60; i++) {
      var rdom = "";
      var len = 16 + rng(16);
      for (var j=0; j<len; j++) rdom += alpha[rng(36)];
      results.push("https://" + rdom + "." + tlds[rng(tlds.length)] + "/login");
    }

    // Pattern 9: Shortened URLs
    for (var i = 0; i < 30; i++) {
      var s = shorteners[rng(shorteners.length)];
      var rid = "";
      for (var j=0; j<6+rng(5); j++) rid += alpha[rng(36)];
      results.push("https://" + s + "/" + rid);
    }

    // Pattern 10: Service spoofing
    var services = ["paypal","google","facebook","apple","microsoft","amazon","netflix","binance","coinbase","metamask"];
    for (var si = 0; si < 10; si++) {
      var s = services[rng(services.length)];
      var t = tlds[rng(tlds.length)];
      results.push("https://" + s + "-service." + t + "/verify");
      results.push("https://" + s + ".account.recover." + t + "/login");
    }

    // Pattern 11: Complex nested patterns
    for (var bi = 0; bi < 15; bi++) {
      var b = brands[rng(brands.length)];
      var t = tlds[rng(tlds.length)];
      results.push("https://" + b + "-login-verify-secure." + t + "/account/auth/signin?redirect=login");
    }

    // Pattern 12: Double-subdomain random
    for (var i = 0; i < 30; i++) {
      var r1 = "", r2 = "";
      for (var j=0; j<10; j++) r1 += alpha[rng(26)];
      for (var j=0; j<8; j++) r2 += alpha[rng(36)];
      results.push("https://" + r1 + "." + r2 + "." + tlds[rng(tlds.length)] + "/verify");
    }

    // Pattern 13: IP + non-standard port
    for (var i = 0; i < 20; i++) {
      var ip = Math.floor(Math.random()*223+1) + "." + Math.floor(Math.random()*256) + "." + Math.floor(Math.random()*256) + "." + Math.floor(Math.random()*256);
      var port = [8080,8443,3000,5000,9000][rng(5)];
      results.push("http://" + ip + ":" + port + "/login");
    }

    // Pattern 14: Brand + common suffix
    for (var bi = 0; bi < 15; bi++) {
      var b = brands[rng(brands.length)];
      results.push("https://" + b + "0.com/login");
      results.push("https://" + b + "v.net/verify");
    }

    // Pattern 15: Security keywords in path
    for (var bi = 0; bi < 30; bi++) {
      var b = brands[rng(brands.length)];
      var p1 = paths[rng(paths.length)];
      var p2 = paths[rng(paths.length)];
      results.push("https://" + b + "-" + p1 + ".com/" + p2);
    }

    // Shuffle using Fisher-Yates
    for (var i = results.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var tmp = results[i]; results[i] = results[j]; results[j] = tmp;
    }

    return results.slice(0, n || 300);
  };
})();

// Generate the built-in phishing list (300 URLs)
var BUILTIN_PHISHING_LARGE = GENERATE_PHISHING(300);

// Benign URLs (100)
var BUILTIN_BENIGN_LARGE = [
  "https://www.google.com","https://www.youtube.com","https://www.facebook.com",
  "https://www.instagram.com","https://www.x.com","https://www.linkedin.com",
  "https://www.microsoft.com","https://www.apple.com","https://www.amazon.com",
  "https://www.github.com","https://www.stackoverflow.com","https://www.wikipedia.org",
  "https://www.reddit.com","https://www.netflix.com","https://www.spotify.com",
  "https://www.dropbox.com","https://www.cloudflare.com","https://www.mozilla.org",
  "https://www.nytimes.com","https://www.bbc.com","https://www.baidu.com",
  "https://www.taobao.com","https://www.jd.com","https://www.zhihu.com",
  "https://www.bilibili.com","https://www.csdn.net","https://www.163.com",
  "https://www.qq.com","https://www.sina.com.cn","https://www.sohu.com",
  "https://www.ebay.com","https://www.paypal.com","https://www.adobe.com",
  "https://www.twitch.tv","https://www.salesforce.com","https://www.oracle.com",
  "https://www.ibm.com","https://www.intel.com","https://www.cisco.com",
  "https://www.nvidia.com","https://www.amd.com","https://www.bloomberg.com",
  "https://www.reuters.com","https://www.cnn.com","https://www.theguardian.com",
  "https://www.w3.org","https://www.npmjs.com","https://pypi.org",
  "https://www.docker.com","https://www.gitlab.com","https://www.atlassian.com",
  "https://www.figma.com","https://www.notion.so","https://www.slack.com",
  "https://www.zoom.us","https://www.udemy.com","https://www.coursera.org",
  "https://www.khanacademy.org","https://www.freecodecamp.org",
  "https://www.harvard.edu","https://www.mit.edu","https://www.stanford.edu",
  "https://www.nasa.gov","https://www.nih.gov","https://www.cdc.gov",
  "https://www.who.int","https://www.un.org","https://www.worldbank.org",
  "https://www.imf.org","https://www.nationalgeographic.com","https://www.nature.com",
  "https://www.medium.com","https://www.quora.com","https://www.producthunt.com",
  "https://www.techcrunch.com","https://www.wired.com","https://www.theverge.com",
  "https://www.arstechnica.com","https://www.stackexchange.com","https://www.wikihow.com",
  "https://www.hackerrank.com","https://www.leetcode.com","https://www.geeksforgeeks.org",
  "https://www.codecademy.com","https://www.science.org","https://arxiv.org",
  "https://www.ted.com","https://www.britannica.com","https://www.merriam-webster.com",
  "https://www.imdb.com","https://www.rottentomatoes.com","https://www.goodreads.com",
  "https://www.etsy.com","https://www.kickstarter.com","https://www.indeed.com",
  "https://www.glassdoor.com","https://www.zillow.com","https://www.webmd.com"
];

// ============================================================
// Fetch functions for external feeds
// ============================================================

// Fetch from OpenPhish feed
function fetchOpenPhishFeed() {
  return fetch("https://openphish.com/feed.txt")
    .then(function(r) { return r.text(); })
    .then(function(t) {
      return t.split("\n").map(function(l) { return l.trim(); }).filter(function(l) { return l.startsWith("http"); });
    });
}

// Fetch from PhishTank (public data)
function fetchPhishTankFeed() {
  return fetch("https://data.phishtank.com/data/online-valid.json")
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var urls = [];
      var items = Array.isArray(data) ? data : (data.data || []);
      for (var i = 0; i < items.length; i++) {
        var url = items[i].url || items[i].phish_detail_url || "";
        if (url && url.startsWith("http")) urls.push(url);
      }
      return urls;
    });
}

// Load samples from a JSON file
function loadSamplesFromJSON(jsonText) {
  try {
    var data = JSON.parse(jsonText);
    return {
      phishing: data.phishing || [],
      benign: data.benign || [],
      count: (data.phishing || []).length + (data.benign || []).length
    };
  } catch(e) {
    console.error("Failed to parse samples JSON:", e);
    return null;
  }
}

// Deduplicate URLs
function dedupUrls(urls) {
  var seen = {};
  var result = [];
  for (var i = 0; i < urls.length; i++) {
    var u = urls[i].toLowerCase().trim();
    if (!seen[u]) { seen[u] = true; result.push(urls[i]); }
  }
  return result;
}

console.log("[test-fetcher.js] Loaded: " + BUILTIN_PHISHING_LARGE.length + " phishing + " + BUILTIN_BENIGN_LARGE.length + " benign URLs ready");