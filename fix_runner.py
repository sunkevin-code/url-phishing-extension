import os
base = r"C:\Users\OseasyVM\Documents\url phishing extension"

js = r"""// Test Runner - Calls extension engine via CHECK_URL
var BUILTIN_PHISHING, BUILTIN_BENIGN, testResults, ruleCounts, testing;
BUILTIN_PHISHING=["http://paypai.com/login.php","https://accounts-google.com.verify.ngrok.io/signin","http://netflix-verify.com/account/update","https://www.facebook-com-login.tk/verify","http://secure-apple-id.verify.services/login","http://91.198.174.192/signin/amazon","http://bit.ly/3xK9mPq","https://binance.com.en-login.ml/auth","http://steamcommunlty.com/trade/offer","https://micros0ftonline.azurewebsites.net/login","http://www.paypaI.com/security","https://g00gle.com/account/recovery","http://instagram-login-help.cf/confirm","https://www.instagrama.com/login","http://faceb00k-login.ml/auth","http://secure-verify-paypal.servehttp.com/login","https://metamask-io.webflow.io/restore","http://amaz0n-prime.net/verify","https://coinbase.pro-login.xyz/verify","http://outlook-verify.ml","http://blockchaln.com/wallet/restore","https://pancake-swap.finance.claim.tk/airdrop","http://wa11et-connect.com/verify","https://dapp-interface.pages.dev/claim","http://api-bridge.000webhostapp.com/auth"];
BUILTIN_BENIGN=["https://www.google.com","https://www.youtube.com","https://www.facebook.com","https://www.instagram.com","https://www.x.com","https://www.linkedin.com","https://www.microsoft.com","https://www.apple.com","https://www.amazon.com","https://www.github.com","https://www.stackoverflow.com","https://www.wikipedia.org","https://www.reddit.com","https://www.netflix.com","https://www.spotify.com","https://www.dropbox.com","https://www.cloudflare.com","https://www.mozilla.org","https://www.nytimes.com","https://www.bbc.com","https://www.baidu.com","https://www.taobao.com","https://www.jd.com","https://www.zhihu.com","https://www.bilibili.com","https://www.csdn.net","https://www.163.com","https://www.qq.com","https://www.sina.com.cn","https://www.sohu.com"];
testResults=[];ruleCounts={};testing=false;

function log(msg){console.log("[TestRunner]",msg);document.getElementById("statusBar").textContent=msg}

function runQuickTest(){
  if(testing){log("Already testing");return}
  testing=true;clearResults();
  var all=buildList(BUILTIN_PHISHING,BUILTIN_BENIGN);
  log("Starting: "+all.length+" URLs");
  document.getElementById("btnQuickTest").disabled=true;
  toast("Testing "+all.length+" URLs...");
  testResults=[];ruleCounts={};
  runBatch(all,0);
}

function buildList(ph,bn){
  var l=[];
  for(var i=0;i<ph.length;i++)l.push({url:ph[i],label:"phishing"});
  for(var i=0;i<bn.length;i++)l.push({url:bn[i],label:"benign"});
  return l;
}

function runBatch(all,idx){
  if(idx>=all.length){finish();return}
  var item=all[idx];
  log("Checking ["+(idx+1)+"/"+all.length+"] "+item.url.substring(0,50)+"...");
  chrome.runtime.sendMessage({type:"CHECK_URL",url:item.url,tabId:-1}).then(function(r){
    r=r||{};r.label=item.label;r.index=idx+1;r.url=item.url;
    testResults.push(r);
    if(r.detectedRules){for(var j=0;j<r.detectedRules.length;j++){var id=typeof r.detectedRules[j]==="string"?r.detectedRules[j]:(r.detectedRules[j].id||"");ruleCounts[id]=(ruleCounts[id]||0)+1}}
    runBatch(all,idx+1);
  }).catch(function(e){
    console.error("[TestRunner] Error:",e);
    testResults.push({url:item.url,label:item.label,index:idx+1,score:0,level:"safe",detectedRules:[],error:String(e)});
    runBatch(all,idx+1);
  });
}

function finish(){
  testing=false;
  document.getElementById("btnQuickTest").disabled=false;
  log("Done: "+testResults.length+" URLs");
  renderResults();
  toast("Complete! "+testResults.length+" URLs tested.");
}

function testManualUrls(){
  if(testing)return;
  var t=document.getElementById("manualUrls").value.trim();
  if(!t){toast("Paste URLs first");return}
  testing=true;clearResults();
  var lines=t.split("\n"),ph=[],bn=[],cur="phishing";
  for(var i=0;i<lines.length;i++){var l=lines[i].trim();if(!l)continue;if(l.toLowerCase()==="#benign"||l.toLowerCase()==="#safe"){cur="benign";continue}if(l.toLowerCase()==="#phishing"){cur="phishing";continue}if(cur==="benign")bn.push(l);else ph.push(l)}
  if(ph.length===0&&bn.length===0){testing=false;toast("No valid URLs");return}
  var all=buildList(ph,bn);
  log("Manual test: "+all.length+" URLs");
  toast("Testing "+all.length+" URLs...");
  testResults=[];ruleCounts={};
  runBatch(all,0);
}

function clearResults(){
  testResults=[];ruleCounts={};
  document.getElementById("mTotal").textContent="0";
  document.getElementById("mDR").textContent="0%";document.getElementById("mFPR").textContent="0%";document.getElementById("mF1").textContent="0%";
  document.getElementById("cmPanel").style.display="none";
  document.getElementById("resultsBody").innerHTML='<tr><td colspan=7 style="text-align:center;padding:40px;color:#999">Click "Quick Test" to call extension engine</td></tr>';
  document.getElementById("statusBar").textContent="Ready";
}

var RULE_NAMES={url_ip_host:"IP Direct",url_suspicious_port:"Odd Port",url_long_domain:"Long Domain",url_at_symbol:"@ Symbol",url_double_protocol:"Dual Protocol",url_shortened:"Short URL",url_multiple_hyphens:"Hyphens",url_security_keywords:"Sec Keywords",url_suspicious_tld:"Bad TLD",url_many_subdomains:"Subdoms",url_hex_encoding:"Hex",url_third_party_subdomain:"3rd Party",url_brand_similarity:"Brand Sim",url_typosquatting:"Typosquat",url_homograph:"Homograph",url_data_uri:"Data URI",url_b64_path:"Base64",url_random_domain:"Random",url_service_spoof:"Svc Spoof",page_password_field:"Pwd Field",page_login_form:"Login",page_external_form:"Ext Form",page_excessive_iframes:"Iframes",page_in_iframe:"In Frame",page_brand_imitation:"Brand Copy",page_hidden_elements:"Hidden",page_few_links:"Few Links",page_external_scripts:"Ext Script",page_meta_redirect:"Meta Jump",page_cloaking:"Cloaking",page_popup_redirect:"Popup",page_fake_favicon:"Fake Icon",behavior_fast_redirect:"Fast Redir",behavior_many_redirects:"Multi Redir"};

function renderResults(){
  var ph=testResults.filter(function(r){return r.label==="phishing"});
  var bn=testResults.filter(function(r){return r.label==="benign"});
  var tp=ph.filter(function(r){return r.level!=="safe"}).length,fn=ph.length-tp;
  var fp=bn.filter(function(r){return r.level!=="safe"}).length,tn=bn.length-fp;
  var total=testResults.length;
  var dr=ph.length>0?(tp/ph.length*100):0,fpr=bn.length>0?(fp/bn.length*100):0;
  var pr=(tp+fp)>0?(tp/(tp+fp)*100):0,f1=(pr+dr)>0?(2*pr*dr/(pr+dr)):0;
  document.getElementById("mTotal").textContent=total;
  document.getElementById("mDR").textContent=dr.toFixed(1)+"%";
  document.getElementById("mFPR").textContent=fpr.toFixed(1)+"%";
  document.getElementById("mF1").textContent=f1.toFixed(1)+"%";
  document.getElementById("cmTP").textContent=tp;document.getElementById("cmFP").textContent=fp;
  document.getElementById("cmFN").textContent=fn;document.getElementById("cmTN").textContent=tn;
  document.getElementById("cmAcc").textContent=total>0?((tp+tn)/total*100).toFixed(1)+"%":"0%";
  document.getElementById("cmPrec").textContent=pr.toFixed(1)+"%";
  document.getElementById("cmRec").textContent=dr.toFixed(1)+"%";
  document.getElementById("cmF1").textContent=f1.toFixed(1)+"%";
  document.getElementById("cmPanel").style.display="block";
  var tbody=document.getElementById("resultsBody");tbody.innerHTML="";
  if(!testResults.length){tbody.innerHTML='<tr><td colspan=7 style="text-align:center;padding:40px;color:#999">No results</td></tr>';return}
  var labels={high:"HIGH",medium:"MEDIUM",low:"LOW",safe:"SAFE"};
  for(var i=0;i<testResults.length;i++){
    var r=testResults[i],rc=r.label==="phishing"?(r.level!=="safe"?"tp":"fn"):(r.level==="safe"?"tn":"fp");
    var rh="";if(r.detectedRules&&r.detectedRules.length){rh=r.detectedRules.slice(0,3).map(function(d){var id=typeof d==="string"?d:(d.id||"");var cat=id.startsWith("url_")?"url":id.startsWith("page_")?"page":"behavior";return'<span class="badge '+cat+'" style="margin:1px">'+(RULE_NAMES[id]||id.replace(/_/g," "))+'</span>'}).join("");if(r.detectedRules.length>3)rh+=' <span style="font-size:10px;color:#999">+'+String(r.detectedRules.length-3)+'</span>'}
    if(r.error)rh='<span style="color:#F44336;font-size:10px">ERR:'+r.error+'</span>';
    var us=(r.url||"").length>70?(r.url||"").substring(0,70)+"...":(r.url||"");
    tbody.innerHTML+='<tr data-label="'+r.label+'" data-result="'+rc+'"><td>'+(r.index||i+1)+'</td><td class="url-cell" title="'+(r.url||"").replace(/"/g,"&quot;")+'">'+us+'</td><td><span class="badge '+(r.label==="phishing"?"phish":"benign")+'">'+r.label.toUpperCase()+'</span></td><td style="font-weight:600">'+(r.score||0)+'</td><td><span class="badge '+(r.level||"safe")+'">'+(labels[r.level]||"SAFE")+'</span></td><td><span class="badge '+rc+'">'+rc.toUpperCase()+'</span></td><td>'+rh+'</td></tr>'
  }
  filterResults("all");
}

var curFilter="all";
function filterResults(type,btn){
  curFilter=type;document.querySelectorAll(".tab").forEach(function(b){b.classList.remove("active")});if(btn)btn.classList.add("active");
  document.querySelectorAll("#resultsBody tr[data-label]").forEach(function(r){
    if(type==="all")r.style.display="";else if(type==="phish")r.style.display=r.dataset.label==="phishing"?"":"none";else if(type==="benign")r.style.display=r.dataset.label==="benign"?"":"none";else r.style.display=r.dataset.result===type?"":"none";
  });
}

function loadFile(input){var f=input.files[0];if(!f)return;var r=new FileReader();r.onload=function(e){document.getElementById("manualUrls").value=e.target.result;toast("Loaded "+f.name)};r.readAsText(f)}
function toast(msg){var t=document.getElementById("toast");t.textContent=msg;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},2500)}
"""

with open(os.path.join(base, "test-runner.js"), "w", encoding="utf-8") as f:
    f.write(js)
print("Rewrote test-runner.js:", len(js), "chars")
