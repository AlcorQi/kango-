import{getStats,getEvents,getConfig,connectSSE,fmtTime,sevPill,safe,toast,state}from"./api.js";
let chart;
let latestIds=new Set();
async function load(){try{const s=await getStats();document.getElementById("metric-total").textContent=String(s.total_anomalies??0);document.getElementById("metric-critical").textContent=String((s.by_severity?.critical)||0);document.getElementById("metric-last").textContent=s.last_detection?fmtTime(s.last_detection):"-";const labels=Object.keys(s.by_type||{});const data=Object.values(s.by_type||{});renderChart(labels,data)}catch(e){toast(e.message||"加载统计失败","error")}
try{const res=await getEvents({page:1,size:10,sort:"detected_at:desc"});renderLatest(res.items||[])}catch(e){toast(e.message||"加载事件失败","error")}}
function renderChart(labels,data){const ctx=document.getElementById("typeChart");if(!ctx)return;const d={labels,datasets:[{label:"类型",data,backgroundColor:["#3a86ff","#ff006e","#fb5607","#8338ec","#3a506b","#06d6a0"]}]};if(chart){chart.data=d;chart.update();return}chart=new Chart(ctx,{type:"pie",data:d,options:{plugins:{legend:{labels:{color:"#e0e6f8"}}}}})}
function renderLatest(items){const tbody=document.getElementById("latest-body");if(!tbody)return;tbody.innerHTML="";items.forEach(it=>{latestIds.add(it.id);const tr=document.createElement("tr");tr.innerHTML=`<td>${fmtTime(it.detected_at)}</td><td>${sevPill(it.severity)}</td><td>${safe(it.type)}</td><td>${safe(it.message)}</td><td>${safe(it.source_file)}:${safe(it.line_number)}</td>`;tbody.appendChild(tr)})}
function onSSEAnomaly(e){if(!e||!e.id)return;const tbody=document.getElementById("latest-body");if(!tbody)return;if(latestIds.has(e.id))return;latestIds.add(e.id);const tr=document.createElement("tr");tr.innerHTML=`<td>${fmtTime(e.detected_at)}</td><td>${sevPill(e.severity)}</td><td>${safe(e.type)}</td><td>${safe(e.message)}</td><td>${safe(e.source_file||"")}</td>`;tbody.prepend(tr);tbody.querySelectorAll("tr").forEach((row,i)=>{if(i>9)row.remove()})}
document.getElementById("btn-refresh").addEventListener("click",()=>{load()});
document.addEventListener("sse:anomaly",ev=>onSSEAnomaly(ev.detail));
connectSSE();
load();
getConfig().then(c=>{const sec=(c.ui?.auto_refresh_sec)||30;setInterval(()=>{load()},sec*1000)}).catch(()=>{setInterval(()=>{load()},30000)})
