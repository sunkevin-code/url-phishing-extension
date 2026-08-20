// ============================================================
// Detection Rules Engine - Phishing URL Detection
// Rules: 24 URL + 12 Page + 2 Behavior = 38 total
// ============================================================

// ---------- Utility Functions ----------
function _lev(a, b) {
  var m = a.length, n = b.length, dp = [];
  for (var i = 0; i <= m; i++) { dp[i] = [i]; for (var j = 0; j <= n; j++) { if (i === 0) dp[i][j] = j; else if (j > 0) { dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]); } } }
  return dp[m][n];
}

function _ent(s) {
  var f = {}, i, c, e = 0;
  for (i = 0; i < s.length; i++) { c = s[i]; f[c] = (f[c] || 0) + 1; }
  var l = s.length;
  for (var k in f) { var p = f[k] / l; e -= p * Math.log2(p); }
  return e;
}

// Cloud vendor region pattern: ap-southeast-3, us-east-1, eu-west-2, cn-north-4, etc.
// These are legitimate AWS/Azure/Google/Alibaba/Huawei availability-zone names that
// frequently appear in otherwise-innocent CDN/cloud hostnames.
function _isCloudRegion(hostname) {
  return /(^|\.)[a-z]{2,6}-[a-z]+(-[a-z]+)?-\d{1,2}(\.|$)/i.test(hostname);
}

function _tld(hostname) {
  var parts = hostname.split(".");
  return parts.length ? parts[parts.length - 1].toLowerCase() : "";
}

// ---------- URL Feature Rules (24) ----------
export const URL_RULES = {
  IP_BASED_HOST: { id: "url_ip_host", name: "IP Direct", weight: 28,
    test: (url) => { try { return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(new URL(url).hostname); } catch { return false; } } },
  AT_SYMBOL: { id: "url_at_symbol", name: "@ Symbol", weight: 28, test: (url) => url.includes("@") },
  DOUBLE_PROTOCOL: { id: "url_double_protocol", name: "Dual Protocol", weight: 35,
    test: (url) => /https?:\/\/.*https?:\/\//i.test(url) },
  SHORTENED_URL: { id: "url_shortened", name: "Shortened URL", weight: 10,
    test: (url) => { var s=["bit.ly","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly","t.co","rebrand.ly","cutt.ly","shorturl.at","tiny.cc","bl.ink","rb.gy","short.link","s.id","2.gp","v.gd","0x0.st","short.cm"]; try { return s.indexOf(new URL(url).hostname.replace(/^www\./,"")) > -1; } catch { return false; } } },
  SECURITY_KEYWORDS: { id: "url_security_keywords", name: "Security Keywords", weight: 8,
    test: (url) => { var k=["secure","login","signin","verify","account","update","confirm","bank","paypal","password","credit","wallet","authenticate","security","unusual","suspended","claim","bonus","airdrop","reward","restore","unlock","validate","recover","reset"]; var l=url.toLowerCase(); for (var i=0;i<k.length;i++) if (l.indexOf(k[i])>-1) return true; return false; } },
  SUSPICIOUS_TLD: { id: "url_suspicious_tld", name: "Suspicious TLD", weight: 8,
    test: (url) => { var t=["xyz","top","work","date","men","loan","click","download","review","trade","bid","win","party","stream","racing","accountant","science","cyou","monster","quest","lol","shop"]; try { var h=new URL(url).hostname.toLowerCase(); var tl=_tld(h); for (var i=0;i<t.length;i++) if(tl===t[i]) return true; } catch { return false; } } },
  FREE_TLD: { id: "url_free_tld", name: "Free Domain TLD", weight: 14,
    test: (url) => { var t=["tk","ml","ga","cf","gq","dev","cfd","games"]; try { var h=new URL(url).hostname.toLowerCase(); var tl=_tld(h); for (var i=0;i<t.length;i++) if(tl===t[i]) return true; } catch { return false; } } },
  TOO_MANY_SUBDOMAINS: { id: "url_many_subdomains", name: "Many Subdomains", weight: 8,
    test: (url) => { try { return new URL(url).hostname.split(".").length > 4; } catch { return false; } } },
  MULTIPLE_HYPHENS: { id: "url_multiple_hyphens", name: "Multiple Hyphens", weight: 8,
    test: (url) => { try { var h = new URL(url).hostname; if (_isCloudRegion(h)) return false; var m = h.match(/-/g); return m && m.length >= 2; } catch { return false; } } },
  SUSPICIOUS_PORT: { id: "url_suspicious_port", name: "Suspicious Port", weight: 10,
    test: (url) => { try { var u=new URL(url); var p=u.port; if(!p||p==="80"||p==="443")return false; var l=url.toLowerCase(); var kw=["login","signin","verify","secure","account","password","admin","auth","paypal","bank"]; for(var i=0;i<kw.length;i++){if(l.indexOf(kw[i])>-1)return true;} return false; } catch { return false; } } },
  LONG_DOMAIN: { id: "url_long_domain", name: "Long Domain", weight: 15,
    test: (url) => { try { var h = new URL(url).hostname; if (_isCloudRegion(h)) return false; return h.length > 35; } catch { return false; } } },
  HEX_ENCODING: { id: "url_hex_encoding", name: "Hex Encoding", weight: 8,
    test: (url) => { var m = url.match(/%[0-9a-fA-F]{2}/g); return m && m.length > 5; } },
  THIRD_PARTY_SUBDOMAIN: { id: "url_third_party", name: "Third-party Subdomain", weight: 20,
    test: (url) => { var p=["wixstudio.com","wixsite.com","shopify.com","myshopify.com","wordpress.com","blogspot.com","weebly.com","webflow.io","squarespace.com","strikingly.com","site123.me","godaddysites.com","yolasite.com","000webhostapp.com","netlify.app","vercel.app","github.io","pages.dev","firebaseapp.com","azurewebsites.net","herokuapp.com","fly.dev","railway.app","onrender.com","glitch.me","replit.app","surge.sh"]; try { var h=new URL(url).hostname.toLowerCase(); for (var i=0;i<p.length;i++) if(h.indexOf("."+p[i])>-1) return true; } catch { return false; } } },
  BRAND_SIMILARITY: { id: "url_brand_sim", name: "Brand Similarity", weight: 15,
    test: (url) => { var ctx=["login","signin","verify","secure","account","password","wallet","authenticate","confirm","update","restore","unlock","paypal","banking"]; var l=url.toLowerCase(); var hasCtx=false; for(var ci=0;ci<ctx.length;ci++){if(l.indexOf(ctx[ci])>-1){hasCtx=true;break;}} if(!hasCtx)return false; var b=["hyperliquid","opensea","binance","coinbase","metamask","uniswap","pancakeswap","sushiswap","cryptocom","bybit","okx","kucoin","kraken","gemini","huobi","phantom","trustwallet","rainbow","facebook","instagram","whatsapp","telegram","discord","twitter","linkedin","tiktok","snapchat","youtube","gmail","outlook","microsoft","apple","icloud","netflix","amazon","paypal","steam","epicgames","roblox","spotify","taobao","tmall","alipay","weixin","weibo","douyin","baidu","qq","dropbox","uber","airbnb","twitch","adobe","shopify","salesforce","google","skype","vimeo","pinterest","tumblr","line","kakaotalk","naver","yahoo","ebay","aliexpress","walmart","target","bestbuy","tesla","nvidia","amd","intel","cisco","oracle","ibm","atlassian","notion","figma","slack","zoom","canva","surfshark","nordvpn","expressvpn","proton","ledger","trezor","uniswap","aave","compound","curve","balancer","maker","yearn"]; try { var h=new URL(url).hostname.toLowerCase().replace(/^www\./,""); var p=h.split("."), m=p[0]; if(m.length<5)return false; for (var i=0;i<b.length;i++) { var x=b[i].toLowerCase(); if(m===x)continue; if(Math.abs(m.length-x.length)>1)continue; var d=_lev(m,x); var ml=Math.max(m.length,x.length); var limit= x.length<7 ? 1 : (x.length<10 ? 1 : Math.max(1,Math.floor(ml*0.15))); if(ml>0&&d>0&&d<=limit)return true; var su={o:"0",i:"1",l:"1",e:"3",a:"4",s:"5",t:"7",b:"8",g:"9"}; var sb=""; for(var j=0;j<x.length;j++)sb+=su[x[j]]||x[j]; if(m===sb&&m.length===x.length)return true; } return false; } catch { return false; } } },
  SERVICE_SPOOF: { id: "url_service_spoof", name: "Service Spoof", weight: 15,
    test: (url) => { var b=["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","uniswap","instagram","whatsapp","telegram","discord","twitter","linkedin","spotify","steam","dropbox","alipay","weixin"]; var cc=["co.uk","com.cn","com.au","co.jp","com.br","co.in","com.sg","com.hk","co.kr","com.mx","co.nz","com.tw","com.my","co.id","com.ar"]; var official={"weixin":"qq.com","alipay":"alipay.com","amazon":"amazon.com","paypal":"paypal.com","microsoft":"microsoft.com","apple":"apple.com","google":"google.com"}; try { var h=new URL(url).hostname.toLowerCase().replace(/^www\./,""); var p=h.split("."); if(p.length>=3){for(var i=0;i<b.length;i++){var x=b[i];for(var j=0;j<p.length-2;j++){if(p[j]===x){var md=p.slice(j+1).join(".");var bo=false;for(var k=0;k<b.length;k++){if(md.indexOf(b[k]+".")===0||md===b[k]){bo=true;break;}}if(!bo){for(var c=0;c<cc.length;c++){if(md===cc[c]||md.indexOf("."+cc[c])>-1){bo=true;break;}}}if(!bo&&official[x]){if(md===official[x]||md.indexOf("."+official[x])>-1){bo=true;}}if(!bo)return true;}}}} } catch {} return false; } },
  RANDOM_DOMAIN: { id: "url_random_domain", name: "Random Domain", weight: 8,
    test: (url) => { try { var p = new URL(url).hostname.split(".")[0]; return p.length >= 12 && _ent(p) > 3.8; } catch { return false; } } },
  TYPOSQUATTING: { id: "url_typosquat", name: "Typosquatting", weight: 15,
    test: (url) => { var ctx=["login","signin","verify","secure","account","password","wallet","confirm","update","restore","unlock","paypal"]; var l=url.toLowerCase(); var hasCtx=false; for(var ci=0;ci<ctx.length;ci++){if(l.indexOf(ctx[ci])>-1){hasCtx=true;break;}} if(!hasCtx)return false; var b=["google","facebook","youtube","paypal","amazon","netflix","microsoft","apple","binance","coinbase","metamask","instagram","twitter","whatsapp","telegram","discord","tiktok","linkedin","github","spotify","steam","alipay","weixin","baidu"]; try { var h=new URL(url).hostname.toLowerCase().replace(/^www\./,""); var p=h.split("."), m=p[0]; for(var i=0;i<b.length;i++){var x=b[i];if(m===x)continue;if(m.length===x.length){var df=0;for(var j=0;j<m.length;j++)if(m[j]!==x[j])df++;if(df===1)return true;}if(Math.abs(m.length-x.length)===1){if(_lev(m,x)===1)return true;}var conf={"rn":"m","vv":"w","cl":"d","l":"1","0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","8":"b","9":"g"};var nm="";for(var j=0;j<m.length;j++){nm+=conf[m.substring(j,j+2)]!==undefined?(conf[m.substring(j,j+2)]+(j++)):m[j];}if(nm===x)return true;} } catch {} return false; } },
  HOMOGRAPH: { id: "url_homograph", name: "IDN Homograph", weight: 15,
    test: (url) => { try { return /[^\x00-\x7F]/.test(new URL(url).hostname); } catch { return false; } } },
  PATH_BRAND: { id: "url_path_brand", name: "Brand in Path", weight: 12,
    test: (url) => { var b=["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","instagram","whatsapp","telegram","discord","twitter","linkedin","spotify","steam","alipay","login","verify","signin","account","secure"]; try { var p=new URL(url).pathname.toLowerCase(); for(var i=0;i<b.length;i++)if(p.indexOf(b[i])>-1)return true; } catch {} return false; } },
  SUSPICIOUS_PARAMS: { id: "url_suspicious_params", name: "Suspicious Params", weight: 8,
    test: (url) => { var p=["token","auth","session","redirect","url","return","next","ref","callback","redir","goto","dest","target","rurl","returl","returnurl","forward","out","view","page","file","path"]; try { var q=new URL(url).search.toLowerCase(); for(var i=0;i<p.length;i++)if(q.indexOf(p[i]+"=")>-1)return true; } catch {} return false; } },
  HTTP_ON_LOGIN: { id: "url_http_login", name: "HTTP on Login", weight: 15,
    test: (url) => { var l=url.toLowerCase(); return l.indexOf("http://")===0 && (l.indexOf("login")>-1||l.indexOf("signin")>-1||l.indexOf("verify")>-1||l.indexOf("secure")>-1||l.indexOf("account")>-1) && l.indexOf("localhost")===-1 && l.indexOf("127.0.0.1")===-1; } },
  SUSPICIOUS_FILE: { id: "url_suspicious_file", name: "Suspicious File", weight: 8,
    test: (url) => { var e=[".exe",".scr",".bat",".cmd",".msi",".apk",".ipa",".zip",".rar",".js",".vbs",".ps1",".hta",".jar"]; try { var p=new URL(url).pathname.toLowerCase(); for(var i=0;i<e.length;i++)if(p.indexOf(e[i])>-1)return true; } catch {} return false; } },
  DEEP_PATH: { id: "url_deep_path", name: "Deep Path", weight: 6,
    test: (url) => { try { return new URL(url).pathname.split("/").filter(function(x){return x.length>0;}).length > 6; } catch { return false; } } },
  NUMERIC_SUBDOMAIN: { id: "url_numeric_subdomain", name: "Numeric Subdomain", weight: 8,
    test: (url) => { try { var p=new URL(url).hostname.split("."); for(var i=0;i<p.length-2;i++){if(/^\d+$/.test(p[i]))return true;} return false; } catch { return false; } } },
  DATA_URI: { id: "url_data_uri", name: "Data URI", weight: 25,
    test: (url) => { return url.toLowerCase().indexOf("data:text/html")===0 || url.toLowerCase().indexOf("data:application")===0; } },
  PUNYCODE_HOST: { id: "url_punycode_host", name: "Punycode Host", weight: 22,
    test: (url) => { try { return new URL(url).hostname.toLowerCase().indexOf("xn--") > -1; } catch { return false; } } },
  BRAND_KEYWORD_HOST: { id: "url_brand_keyword_host", name: "Brand + Login Host", weight: 18,
    test: (url) => { var brands=["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","instagram","whatsapp","telegram","discord","twitter","linkedin","alipay","weixin","github"]; var kw=["login","signin","verify","secure","account","update","confirm","support","auth","wallet","password","unlock","restore"]; try { var h=new URL(url).hostname.toLowerCase().replace(/^www\./,""); for(var i=0;i<KNOWN_DOMAINS.length;i++){if(h===KNOWN_DOMAINS[i]||h.endsWith("."+KNOWN_DOMAINS[i]))return false;} var hasBrand=false, hasKw=false; for(var b=0;b<brands.length;b++)if(h.indexOf(brands[b])>-1){hasBrand=true;break;} for(var k=0;k<kw.length;k++)if(h.indexOf(kw[k])>-1){hasKw=true;break;} return hasBrand&&hasKw; } catch { return false; } } },
  LOGIN_REDIRECT: { id: "url_login_redirect", name: "Login Redirect", weight: 18,
    test: (url) => { var kw=["login","signin","verify","account","auth","password","secure"]; var rp=["redirect","redir","return","returnurl","next","target","dest","url","continue","callback"]; try { var u=new URL(url), l=url.toLowerCase(), q=u.search.toLowerCase(); var hasKw=false, hasRedirect=false; for(var i=0;i<kw.length;i++)if(l.indexOf(kw[i])>-1){hasKw=true;break;} for(var j=0;j<rp.length;j++)if(q.indexOf(rp[j]+"=")>-1){hasRedirect=true;break;} return hasKw&&hasRedirect; } catch { return false; } } },
  BASE64ISH_PATH: { id: "url_b64_path", name: "Encoded Path", weight: 12,
    test: (url) => { try { var p=new URL(url).pathname; var m=p.match(/[A-Za-z0-9_-]{28,}={0,2}/g); return !!(m && m.length > 0); } catch { return false; } } },
  VERY_LONG_URL: { id: "url_very_long", name: "Very Long URL", weight: 8,
    test: (url) => { return typeof url === "string" && url.length > 120; } },
  BRAND_TLD_COMBO: { id: "url_brand_tld_combo", name: "Brand + Suspicious TLD", weight: 22,
    test: (url) => { var brands=["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","instagram","whatsapp","telegram","discord","twitter","linkedin","spotify","steam","alipay","weixin","github","ebay","yahoo","dropbox","adobe","shopify","stripe","venmo","chase","wellsfargo","bankofamerica","citi","hsbc"]; var tl=[".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".loan",".work",".bid",".win",".stream",".racing",".cyou",".monster",".quest",".lol"]; try { var h=new URL(url).hostname.toLowerCase().replace(/^www\./,""); var tldPart=_tld(h); var hasTl=false; for(var ti=0;ti<tl.length;ti++){if(tldPart===tl[ti]){hasTl=true;break;}} if(!hasTl)return false; var parts=h.split("."); var reg=parts.length>=2?parts[parts.length-2]:""; for(var bi=0;bi<brands.length;bi++){var b=brands[bi]; if(reg.indexOf(b)>-1 || h.indexOf(b+".")>-1){return true;}} return false; } catch { return false; } } },
  DOUBLE_ENCODING: { id: "url_double_encoding", name: "Double URL Encoding", weight: 12,
    test: (url) => { return /%25[0-9a-fA-F]{2}/.test(url); } }
};

// ---------- Page Feature Rules (12) ----------
export const PAGE_RULES = {
  PASSWORD_FORM: { id: "page_password_form", name: "Password Form", weight: 12,
    test: (doc) => { try { return doc.querySelectorAll('input[type="password"]').length > 0; } catch { return false; } } },
  MANY_FORMS: { id: "page_many_forms", name: "Many Forms", weight: 8,
    test: (doc) => { try { return doc.forms.length > 3; } catch { return false; } } },
  EXTERNAL_FORMS: { id: "page_external_forms", name: "External Form Action", weight: 15,
    test: (doc, origin) => { try { var forms=doc.forms; for(var i=0;i<forms.length;i++){var a=forms[i].action;if(a&&a.indexOf("http")===0&&a.indexOf(origin)!==0)return true;} return false; } catch { return false; } } },
  FAVICON_MISMATCH: { id: "page_favicon_mismatch", name: "Favicon Mismatch", weight: 6,
    test: (doc) => { try { var l=doc.querySelectorAll('link[rel*="icon"]'); for(var i=0;i<l.length;i++){var h=l[i].href;if(h&&h.indexOf("data:")===-1&&h.indexOf(document.location.origin)===-1)return true;} return false; } catch { return false; } } },
  IFRAME_COUNT: { id: "page_iframe_count", name: "Many Iframes", weight: 15,
    test: (doc) => { try { return doc.querySelectorAll("iframe").length > 2; } catch { return false; } } },
  HIDDEN_IFRAMES: { id: "page_hidden_iframes", name: "Hidden Iframes", weight: 18,
    test: (doc) => { try { var fr=doc.querySelectorAll("iframe"); for(var i=0;i<fr.length;i++){var s=getComputedStyle(fr[i]); if(s.display==="none"||s.visibility==="hidden"||fr[i].height<=1||fr[i].width<=1)return true;} return false; } catch { return false; } } },
  TITLE_KEYWORDS: { id: "page_title_keywords", name: "Phish Title", weight: 8,
    test: (doc) => { try { var t=(doc.title||"").toLowerCase(); var k=["login","signin","verify","secure","account","update","confirm","alert","unusual","password"]; for(var i=0;i<k.length;i++)if(t.indexOf(k[i])>-1)return true; return false; } catch { return false; } } },
  FEW_LINKS: { id: "page_few_links", name: "Few Links", weight: 5,
    test: (doc) => { try { return doc.querySelectorAll("a").length < 5; } catch { return false; } } },
  BROKEN_IMAGES: { id: "page_broken_images", name: "Broken Images", weight: 5,
    test: (doc) => { try { return doc.querySelectorAll('img[alt=""],img:not([src])').length > 3; } catch { return false; } } },
  POPUP_SCRIPT: { id: "page_popup_script", name: "Popup Script", weight: 10,
    test: (doc) => { try { var s=doc.querySelectorAll("script"); for(var i=0;i<s.length;i++){var t=s[i].textContent||"";if(t.indexOf("window.open")>-1||t.indexOf("alert(")>-1||t.indexOf("prompt(")>-1||t.indexOf("atob(")>-1||t.indexOf("eval(")>-1)return true;} return false; } catch { return false; } } },
  NO_HTTPS: { id: "page_no_https", name: "No HTTPS", weight: 20,
    test: (doc) => { try { return document.location.protocol === "http:"; } catch { return false; } } },
  SKETCHY_SCRIPTS: { id: "page_sketchy_scripts", name: "Sketchy Scripts", weight: 12,
    test: (doc) => { try { var s=document.querySelectorAll('script[src]'); for(var i=0;i<s.length;i++){var u=s[i].src;if(u&&u.indexOf(document.location.origin)!==0&&u.indexOf("cdnjs")===-1&&u.indexOf("googleapis")===-1&&u.indexOf("cloudflare")===-1&&u.indexOf("jsdelivr")===-1)return true;} return false; } catch { return false; } } }
};

// ---------- Behavior Rules (2) ----------
export const BEHAVIOR_RULES = {
  RAPID_NAVIGATION: { id: "beh_rapid_nav", name: "Rapid Navigation", weight: 10,
    test: (history) => { if (!Array.isArray(history) || history.length < 3) return false; var times = []; for (var i = 1; i < history.length; i++) { if (history[i].time && history[i-1].time) times.push(history[i].time - history[i-1].time); } if (times.length === 0) return false; var avg = times.reduce(function(a,b){return a+b;},0) / times.length; return avg < 500; } },
  CROSS_DOMAIN_FORM: { id: "beh_cross_domain", name: "Cross-Domain Form", weight: 15,
    test: (history) => { if (!Array.isArray(history) || history.length < 2) return false; var domains = []; for (var i = 0; i < history.length; i++) { try { var h = new URL(history[i].url || history[i]).hostname; domains.push(h); } catch {} } if (domains.length < 2) return false; return domains[domains.length-2] !== domains[domains.length-1]; } }
};

// ---------- Known Good Domains ----------
export const KNOWN_DOMAINS = [
  "google.com","youtube.com","facebook.com","instagram.com","twitter.com","x.com",
  "linkedin.com","microsoft.com","apple.com","amazon.com","github.com","stackoverflow.com",
  "wikipedia.org","reddit.com","netflix.com","spotify.com","dropbox.com","cloudflare.com",
  "mozilla.org","nytimes.com","bbc.com","baidu.com","taobao.com","jd.com","zhihu.com",
  "bilibili.com","csdn.net","163.com","qq.com","sina.com.cn","sohu.com","ebay.com",
  "paypal.com","adobe.com","twitch.tv","salesforce.com","oracle.com","ibm.com","intel.com",
  "cisco.com","nvidia.com","amd.com","bloomberg.com","reuters.com","cnn.com","theguardian.com",
  "w3.org","npmjs.com","pypi.org","docker.com","gitlab.com","atlassian.com","figma.com",
  "notion.so","slack.com","zoom.us","udemy.com","coursera.org","khanacademy.org","freecodecamp.org",
  "harvard.edu","mit.edu","stanford.edu","nasa.gov","nih.gov","cdc.gov","who.int","un.org",
  "worldbank.org","imf.org","nationalgeographic.com","nature.com","medium.com","quora.com",
  "producthunt.com","techcrunch.com","wired.com","theverge.com","arstechnica.com","stackexchange.com",
  "wikihow.com","hackerrank.com","leetcode.com","geeksforgeeks.org","codecademy.com","science.org",
  "arxiv.org","ted.com","britannica.com","merriam-webster.com","imdb.com","rottentomatoes.com",
  "goodreads.com","etsy.com","kickstarter.com","indeed.com","glassdoor.com","zillow.com",
  "webmd.com","shutterstock.com","flickr.com","vimeo.com","trello.com","box.com","heroku.com",
  "digitalocean.com","linode.com","aws.amazon.com","azure.microsoft.com","cloud.google.com",
  "stripe.com","shopify.com","fast.com","speedtest.net","walmart.com","target.com","bestbuy.com",
  "homedepot.com","costco.com","ikea.com","bbc.co.uk","ft.com","economist.com","wsj.com",
  "forbes.com","businessinsider.com","cnbc.com","yelp.com","tripadvisor.com","airbnb.com","booking.com",
  "mayoclinic.org","healthline.com","weather.com","openstreetmap.org","zoho.com","hubspot.com","twilio.com",
  "mailchimp.com","bitbucket.org","sourceforge.net","archlinux.org","debian.org","ubuntu.com","fedoraproject.org",
  "centos.org","redhat.com","apache.org","mysql.com","postgresql.org","mongodb.com","redis.io","sqlite.org",
  "gnome.org","kde.org","libreoffice.org","openai.com","anthropic.com","meta.com","weixin.qq.com",
  "alipay.com","tmall.com","weibo.com","douyin.com","meituan.com","bybit.com","okx.com","kraken.com","gemini.com"
];

// ============================================================
// ML Feature Extraction: 38 binary features from URL alone
// Matches training/train_model.py::extract_features()
// ============================================================

const _SHORTENERS = ["bit.ly","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly","t.co","rebrand.ly","cutt.ly","shorturl.at","tiny.cc","bl.ink","rb.gy","short.link","s.id"];
const _SUSP_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".date",".men",".loan",".click",".download",".review",".trade",".bid",".win",".ren",".party",".stream",".racing",".accountant",".science",".cyou",".monster",".quest",".lol",".live",".shop"];
const _THIRD_PARTY = ["wixstudio.com","wixsite.com","shopify.com","myshopify.com","wordpress.com","blogspot.com","weebly.com","webflow.io","squarespace.com","strikingly.com","site123.me","godaddysites.com","yolasite.com","000webhostapp.com","netlify.app","vercel.app","github.io","pages.dev","firebaseapp.com","azurewebsites.net","herokuapp.com","fly.dev","railway.app","onrender.com","glitch.me","replit.app","surge.sh"];
const _BRANDS = ["hyperliquid","opensea","binance","coinbase","metamask","uniswap","pancakeswap","sushiswap","cryptocom","bybit","okx","kucoin","kraken","gemini","huobi","phantom","trustwallet","rainbow","facebook","instagram","whatsapp","telegram","discord","twitter","linkedin","tiktok","snapchat","youtube","gmail","outlook","microsoft","apple","icloud","netflix","amazon","paypal","steam","epicgames","roblox","spotify","taobao","tmall","alipay","weixin","weibo","douyin","baidu","qq","dropbox","uber","airbnb","twitch","adobe","shopify","salesforce","google","skype","vimeo","pinterest","tumblr","line","kakaotalk","naver","yahoo","ebay","aliexpress","walmart","target","bestbuy","tesla","nvidia","amd","intel","cisco","oracle","ibm","atlassian","notion","figma","slack","zoom","canva","surfshark","nordvpn","expressvpn","proton","ledger","trezor","aave","compound","curve","balancer","maker","yearn"];
const _SEC_KEYWORDS = ["secure","login","signin","verify","account","update","confirm","bank","paypal","password","credit","wallet","authenticate","security","unusual","suspended","claim","bonus","airdrop","reward","restore","unlock","validate","recover","reset"];
const _SUSP_PARAMS = ["token","auth","session","redirect","url","return","next","ref","callback","redir","goto","dest","target","rurl","returl","returnurl","forward","out","view","page","file","path"];
const _SUSP_FILES = [".exe",".scr",".bat",".cmd",".msi",".apk",".ipa",".zip",".rar",".js",".vbs",".ps1",".hta",".jar"];
const _PATH_BRANDS = ["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","instagram","whatsapp","telegram","discord","twitter","linkedin","spotify","steam","alipay","login","verify","signin","account","secure"];
const _SPOOF_BRANDS = ["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","uniswap","instagram","whatsapp","telegram","discord","twitter","linkedin","spotify","steam","dropbox","alipay","weixin"];
const _KNOWN_MAIN = ["google","facebook","paypal","apple","microsoft","amazon","netflix","binance","coinbase","metamask","opensea","instagram","whatsapp","telegram","discord","twitter","linkedin","spotify","steam","dropbox","alipay","weixin","com","org","net","cn"];
const _TYPOSQ_BRANDS = ["google","facebook","youtube","paypal","amazon","netflix","microsoft","apple","binance","coinbase","metamask","instagram","twitter","whatsapp","telegram","discord","tiktok","linkedin","github","spotify","steam","alipay","weixin","baidu"];

/**
 * Extract all 38 binary features from a URL for ML model inference.
 * Matches the Python training script's extract_features() exactly.
 * Features 0-23: URL rules, 24-35: page features (estimated from URL),
 * 36-37: behavior features (estimated from URL).
 */
export function extractMLFeatures(url) {
  try {
    var u = new URL(url);
    var hostname = u.hostname;
    var path = u.pathname;
    var query = u.search;
    var port = u.port;
    var scheme = u.protocol.replace(":", "");
    var full_url = url.toLowerCase();
  } catch (e) {
    return new Array(38).fill(0);
  }

  var hl = hostname.toLowerCase();
  var pl = path.toLowerCase();
  var ql = query.toLowerCase();
  var f = [];

  // 0: IP_BASED_HOST
  f.push(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hl) ? 1 : 0);
  // 1: AT_SYMBOL
  f.push(url.indexOf("@") > -1 ? 1 : 0);
  // 2: DOUBLE_PROTOCOL
  f.push(/https?:\/\/.*https?:\/\//i.test(url) ? 1 : 0);
  // 3: SHORTENED_URL
  f.push(_SHORTENERS.some(function(s) { return hl.replace(/^www\./, "") === s; }) ? 1 : 0);
  // 4: SECURITY_KEYWORDS
  f.push(_SEC_KEYWORDS.some(function(k) { return full_url.indexOf(k) > -1; }) ? 1 : 0);
  // 5: SUSPICIOUS_TLD
  f.push(_SUSP_TLDS.some(function(t) { return hl.indexOf(t) > -1; }) ? 1 : 0);
  // 6: TOO_MANY_SUBDOMAINS
  f.push(hostname.split(".").length > 4 ? 1 : 0);
  // 7: MULTIPLE_HYPHENS
  f.push((hostname.match(/-/g) || []).length >= 2 ? 1 : 0);
  // 8: SUSPICIOUS_PORT
  f.push(port && port !== "" && port !== "80" && port !== "443" ? 1 : 0);
  // 9: LONG_DOMAIN
  f.push(hostname.length > 25 ? 1 : 0);
  // 10: HEX_ENCODING
  var hex = url.match(/%[0-9a-fA-F]{2}/g);
  f.push(hex && hex.length > 5 ? 1 : 0);
  // 11: THIRD_PARTY_SUBDOMAIN
  f.push(_THIRD_PARTY.some(function(tp) { return hl.indexOf("." + tp) > -1; }) ? 1 : 0);
  // 12: BRAND_SIMILARITY (Levenshtein + leet)
  var mainPart = hl.replace(/^www\./, "").split(".")[0];
  var brandSim = 0;
  for (var bi = 0; bi < _BRANDS.length; bi++) {
    var brand = _BRANDS[bi].toLowerCase();
    if (mainPart === brand) continue;
    var d = _lev(mainPart, brand);
    var ml = Math.max(mainPart.length, brand.length);
    var limit = brand.length < 6 ? 1 : Math.max(1, Math.floor(ml * 0.25));
    if (mainPart.length >= 5 && ml > 0 && d > 0 && d <= limit) { brandSim = 1; break; }
    // leet: o→0, i→1, l→1, e→3, a→4, s→5, t→7, b→8, g→9
    var leetMap = {o:"0",i:"1",l:"1",e:"3",a:"4",s:"5",t:"7",b:"8",g:"9"};
    var leet = ""; for (var lj = 0; lj < brand.length; lj++) leet += leetMap[brand[lj]] || brand[lj];
    if (mainPart.length >= 5 && mainPart === leet) { brandSim = 1; break; }
  }
  f.push(brandSim);
  // 13: SERVICE_SPOOF
  var spoof = 0;
  var parts = hl.replace(/^www\./, "").split(".");
  if (parts.length >= 3) {
    for (var si = 0; si < _SPOOF_BRANDS.length; si++) {
      var sb = _SPOOF_BRANDS[si];
      for (var sj = 0; sj < parts.length - 2; sj++) {
        if (parts[sj] === sb) {
          var md = parts.slice(sj + 1).join(".");
          var known = false;
          for (var sk = 0; sk < _KNOWN_MAIN.length; sk++) {
            if (md.indexOf(_KNOWN_MAIN[sk] + ".") === 0 || md === _KNOWN_MAIN[sk]) { known = true; break; }
          }
          if (!known) { spoof = 1; break; }
        }
      }
      if (spoof) break;
    }
  }
  f.push(spoof);
  // 14: RANDOM_DOMAIN (high entropy)
  f.push(mainPart.length >= 12 && _ent(mainPart) > 3.5 ? 1 : 0);
  // 15: TYPOSQUATTING
  var typosquat = 0;
  for (var ti = 0; ti < _TYPOSQ_BRANDS.length; ti++) {
    var tb = _TYPOSQ_BRANDS[ti];
    if (mainPart === tb) continue;
    if (mainPart.length === tb.length) {
      var diffs = 0; for (var tj = 0; tj < mainPart.length; tj++) { if (mainPart[tj] !== tb[tj]) diffs++; }
      if (diffs === 1) { typosquat = 1; break; }
    }
    if (Math.abs(mainPart.length - tb.length) === 1) {
      if (_lev(mainPart, tb) === 1) { typosquat = 1; break; }
    }
  }
  f.push(typosquat);
  // 16: HOMOGRAPH (IDN non-ASCII)
  f.push(/[^\x00-\x7F]/.test(hostname) ? 1 : 0);
  // 17: PATH_BRAND
  f.push(_PATH_BRANDS.some(function(b) { return pl.indexOf(b) > -1; }) ? 1 : 0);
  // 18: SUSPICIOUS_PARAMS
  f.push(_SUSP_PARAMS.some(function(p) { return ql.indexOf(p + "=") > -1; }) ? 1 : 0);
  // 19: HTTP_ON_LOGIN
  f.push((scheme === "http" && _SEC_KEYWORDS.some(function(k) { return full_url.indexOf(k) > -1; }) && hl.indexOf("localhost") === -1 && hl.indexOf("127.0.0.1") === -1) ? 1 : 0);
  // 20: SUSPICIOUS_FILE
  f.push(_SUSP_FILES.some(function(e) { return pl.indexOf(e) > -1; }) ? 1 : 0);
  // 21: DEEP_PATH
  f.push(path.split("/").filter(function(x) { return x.length > 0; }).length > 6 ? 1 : 0);
  // 22: NUMERIC_SUBDOMAIN
  var subParts = hostname.split(".");
  var numSub = 0;
  for (var ni = 0; ni < subParts.length - 2; ni++) { if (/^\d+$/.test(subParts[ni])) { numSub = 1; break; } }
  f.push(numSub);
  // 23: DATA_URI
  f.push((full_url.indexOf("data:text/html") === 0 || full_url.indexOf("data:application") === 0) ? 1 : 0);

  // ====== Page features (estimated from URL patterns, matching training script) ======
  // 24: PASSWORD_FORM — URL has login/signin path
  f.push((pl.indexOf("/login") > -1 || pl.indexOf("/signin") > -1 || pl.indexOf("/password") > -1 || pl.indexOf("/auth") > -1) ? 1 : 0);
  // 25: MANY_FORMS — URL has form/register/signup
  f.push((pl.indexOf("form") > -1 || pl.indexOf("survey") > -1 || pl.indexOf("register") > -1 || pl.indexOf("signup") > -1) ? 1 : 0);
  // 26: EXTERNAL_FORMS — redirect params in query
  f.push((ql.indexOf("redirect") > -1 || ql.indexOf("return") > -1) ? 1 : 0);
  // 27: FAVICON_MISMATCH — can't determine from URL alone
  f.push(0);
  // 28: IFRAME_COUNT — can't determine from URL alone
  f.push(0);
  // 29: HIDDEN_IFRAMES — can't determine from URL alone
  f.push(0);
  // 30: TITLE_KEYWORDS — phishing keywords in path/query
  f.push((_SEC_KEYWORDS.some(function(k) { return pl.indexOf(k) > -1; }) || _SEC_KEYWORDS.some(function(k) { return ql.indexOf(k) > -1; })) ? 1 : 0);
  // 31: FEW_LINKS — can't determine from URL alone
  f.push(0);
  // 32: BROKEN_IMAGES — can't determine from URL alone
  f.push(0);
  // 33: POPUP_SCRIPT — popup/redirect in path
  f.push((hl.indexOf("popup") > -1 || hl.indexOf("redirect") > -1) ? 1 : 0);
  // 34: NO_HTTPS
  f.push(scheme === "http" ? 1 : 0);
  // 35: SKETCHY_SCRIPTS — can't determine from URL alone
  f.push(0);

  // ====== Behavior features (estimated from URL patterns) ======
  // 36: RAPID_NAVIGATION — can't determine from single URL
  f.push(0);
  // 37: CROSS_DOMAIN_FORM — redirect params
  f.push(ql.indexOf("redirect") > -1 ? 1 : 0);

  return f;
}

// ============================================================
// Evaluation Functions
// ============================================================

export function evaluateUrlRisk(url) {
  var score = 0, triggered = [];
  for (var k in URL_RULES) {
    try {
      // Skip zero-weight rules (disabled net-negative contributors)
      if (URL_RULES[k].weight <= 0) continue;
      if (URL_RULES[k].test(url)) {
        score += URL_RULES[k].weight;
        triggered.push(k);
      }
    } catch (e) {}
  }
  // Combo bonuses (reduced 50% — ML model handles non-linear patterns now)
  var t = triggered;
  if (t.indexOf("SECURITY_KEYWORDS") > -1 && t.indexOf("BRAND_SIMILARITY") > -1) score += 4;
  if (t.indexOf("SECURITY_KEYWORDS") > -1 && t.indexOf("SUSPICIOUS_TLD") > -1) score += 3;
  if (t.indexOf("BRAND_SIMILARITY") > -1 && t.indexOf("SUSPICIOUS_TLD") > -1) score += 5;
  if (t.indexOf("BRAND_SIMILARITY") > -1 && t.indexOf("TOO_MANY_SUBDOMAINS") > -1) score += 3;
  if (t.indexOf("IP_BASED_HOST") > -1 && t.indexOf("SECURITY_KEYWORDS") > -1) score += 5;
  if (t.indexOf("SHORTENED_URL") > -1 && t.indexOf("SECURITY_KEYWORDS") > -1) score += 3;
  if (t.indexOf("THIRD_PARTY_SUBDOMAIN") > -1 && t.indexOf("BRAND_SIMILARITY") > -1) score += 4;
  if (t.indexOf("SERVICE_SPOOF") > -1 && t.indexOf("BRAND_SIMILARITY") > -1) score += 4;
  if (t.indexOf("TYPOSQUATTING") > -1 && t.indexOf("SECURITY_KEYWORDS") > -1) score += 3;
  if (t.indexOf("SUSPICIOUS_TLD") > -1 && t.indexOf("TOO_MANY_SUBDOMAINS") > -1) score += 2;
  if (t.indexOf("HOMOGRAPH") > -1 && t.indexOf("BRAND_SIMILARITY") > -1) score += 5;
  if (t.indexOf("NUMERIC_SUBDOMAIN") > -1 && t.indexOf("SUSPICIOUS_TLD") > -1) score += 3;
  if (t.indexOf("BRAND_KEYWORD_HOST") > -1 && t.indexOf("LOGIN_REDIRECT") > -1) score += 8;
  if (t.indexOf("BRAND_KEYWORD_HOST") > -1 && t.indexOf("SUSPICIOUS_TLD") > -1) score += 6;
  if (t.indexOf("BASE64ISH_PATH") > -1 && t.indexOf("SUSPICIOUS_PARAMS") > -1) score += 5;
  if (t.indexOf("PUNYCODE_HOST") > -1 && t.indexOf("SECURITY_KEYWORDS") > -1) score += 6;
  // Known domains cap
  try {
    var hn = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    var parts = hn.split(".");
    for (var i = 0; i < KNOWN_DOMAINS.length; i++) {
      if (hn === KNOWN_DOMAINS[i] || (parts.length >= 3 && hn.endsWith("." + KNOWN_DOMAINS[i]))) {
        if (score >= 10) score = 9;
        break;
      }
    }
  } catch (e) {}
  score = Math.min(100, Math.max(0, score));
  var level = "safe";
  if (score >= 55) level = "high";
  else if (score >= 28) level = "medium";
  else if (score >= 10) level = "low";
  return { score: score, level: level, triggered: triggered };
}

export function evaluatePageRisk(doc, origin) {
  var score = 0, triggered = [];
  for (var k in PAGE_RULES) {
    try {
      if (PAGE_RULES[k].test(doc, origin)) {
        score += PAGE_RULES[k].weight;
        triggered.push(k);
      }
    } catch (e) {}
  }
  return { score: score, triggered: triggered };
}

export function evaluateBehaviorRisk(history) {
  var score = 0, triggered = [];
  for (var k in BEHAVIOR_RULES) {
    try {
      if (BEHAVIOR_RULES[k].test(history)) {
        score += BEHAVIOR_RULES[k].weight;
        triggered.push(k);
      }
    } catch (e) {}
  }
  return { score: score, triggered: triggered };
}

export function evaluateTotalRisk(urlResult, pageResult, behaviorResult) {
  var urlScore = (urlResult && urlResult.score) || 0;
  var pageScore = (pageResult && pageResult.score) || 0;
  var behScore = (behaviorResult && behaviorResult.score) || 0;
  var total = urlScore + pageScore + behScore;
  var allTriggered = [];
  if (urlResult && urlResult.triggered) allTriggered = allTriggered.concat(urlResult.triggered.map(function(id){ return { id: id, category: "url" }; }));
  if (pageResult && pageResult.triggered) allTriggered = allTriggered.concat(pageResult.triggered.map(function(id){ return { id: id, category: "page" }; }));
  if (behaviorResult && behaviorResult.triggered) allTriggered = allTriggered.concat(behaviorResult.triggered.map(function(id){ return { id: id, category: "behavior" }; }));
  var level = "safe";
  if (total >= 55) level = "high";
  else if (total >= 28) level = "medium";
  else if (total >= 10) level = "low";
  return { score: total, level: level, triggered: allTriggered,
    urlResult: urlResult, pageResult: pageResult, behaviorResult: behaviorResult };
}

export function getRiskLabel(level) {
  var labels = {
    safe: { text: "Safe", color: "#4CAF50", icon: "icons/icon128.png" },
    low: { text: "Low Risk", color: "#FF9800", icon: "icons/icon128_warning.png" },
    medium: { text: "Medium Risk", color: "#FF5722", icon: "icons/icon128_warning.png" },
    high: { text: "High Risk", color: "#F44336", icon: "icons/icon128_danger.png" }
  };
  return labels[level] || labels.safe;
}

export function getRuleDetails(ruleId) {
  for (var k in URL_RULES) { if (URL_RULES[k].id === ruleId) return { category: "url", ...URL_RULES[k] }; }
  for (var k in PAGE_RULES) { if (PAGE_RULES[k].id === ruleId) return { category: "page", ...PAGE_RULES[k] }; }
  for (var k in BEHAVIOR_RULES) { if (BEHAVIOR_RULES[k].id === ruleId) return { category: "behavior", ...BEHAVIOR_RULES[k] }; }
  return null;
}
