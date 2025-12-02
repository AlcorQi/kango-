import{getConfig,putConfig,toast}from"./api.js?v=2";
const DEFAULT_CONFIG={schema_version:"1.0",detection:{log_paths:[],scan_interval_sec:60,retention_days:30,retention_max_events:50000,search_mode:"mixed",enabled_detectors:["oom","kernel_panic","unexpected_reboot","fs_error","oops","deadlock"]},alerts:{enabled:false,emails:[],notify_critical:true,silent_minutes:30},ui:{auto_refresh_sec:30,page_size:20,time_format:"24h"},security:{ingest_token:"<redacted>",sse_max_clients:100}};
function renderPaths(paths){const wrap=document.getElementById("log-paths");wrap.innerHTML="";(paths||[]).forEach(p=>{const row=document.createElement("div");row.className="toolbar";const i=document.createElement("input");i.className="input";i.value=p;const b=document.createElement("button");b.className="btn";b.textContent="删除";b.addEventListener("click",()=>{row.remove()});row.appendChild(i);row.appendChild(b);wrap.appendChild(row)})}
async function load(){let c;try{c=await getConfig()}catch(e){c=DEFAULT_CONFIG;toast("未读取到配置，已应用默认值","success")}renderPaths(c.detection?.log_paths||[]);document.getElementById("scan-interval").value=c.detection?.scan_interval_sec??DEFAULT_CONFIG.detection.scan_interval_sec;document.getElementById("retention-days").value=c.detection?.retention_days??DEFAULT_CONFIG.detection.retention_days;document.getElementById("retention-max").value=c.detection?.retention_max_events??DEFAULT_CONFIG.detection.retention_max_events;document.getElementById("alerts-enabled").checked=!!(c.alerts?.enabled??DEFAULT_CONFIG.alerts.enabled);document.getElementById("alerts-email").value=(c.alerts?.emails||[])[0]||"";document.getElementById("notify-critical").checked=!!(c.alerts?.notify_critical??DEFAULT_CONFIG.alerts.notify_critical);document.getElementById("silent-minutes").value=c.alerts?.silent_minutes??DEFAULT_CONFIG.alerts.silent_minutes;document.getElementById("ui-auto-refresh").value=c.ui?.auto_refresh_sec??DEFAULT_CONFIG.ui.auto_refresh_sec;document.getElementById("ui-page-size").value=c.ui?.page_size??DEFAULT_CONFIG.ui.page_size;document.getElementById("ui-time-format").value=c.ui?.time_format??DEFAULT_CONFIG.ui.time_format;document.getElementById("sse-max").value=c.security?.sse_max_clients??DEFAULT_CONFIG.security.sse_max_clients;const mode=(c.detection?.search_mode)||DEFAULT_CONFIG.detection.search_mode;setDetectMode(mode)}
function collect(){const paths=Array.from(document.querySelectorAll("#log-paths .toolbar .input")).map(i=>i.value).filter(Boolean);const email=document.getElementById("alerts-email").value.trim();const cfg={schema_version:"1.0",detection:{log_paths:paths,scan_interval_sec:Number(document.getElementById("scan-interval").value),retention_days:Number(document.getElementById("retention-days").value),retention_max_events:Number(document.getElementById("retention-max").value),search_mode:currentDetectMode||DEFAULT_CONFIG.detection.search_mode,enabled_detectors:["oom","kernel_panic","unexpected_reboot","fs_error","oops","deadlock"]},alerts:{enabled:document.getElementById("alerts-enabled").checked,emails:email?[email]:[],notify_critical:document.getElementById("notify-critical").checked,silent_minutes:Number(document.getElementById("silent-minutes").value)},ui:{auto_refresh_sec:Number(document.getElementById("ui-auto-refresh").value),page_size:Number(document.getElementById("ui-page-size").value),time_format:document.getElementById("ui-time-format").value},security:{ingest_token:"<redacted>",sse_max_clients:Number(document.getElementById("sse-max").value)}};return cfg}
function validate(cfg){if(cfg.detection.scan_interval_sec<5||cfg.detection.scan_interval_sec>3600)return"扫描间隔需在5-3600";if(cfg.detection.retention_days<1||cfg.detection.retention_days>365)return"数据保留需在1-365";if(cfg.detection.retention_max_events<1||cfg.detection.retention_max_events>1000000)return"数据保留上限需在1-1000000";const e=cfg.alerts.emails[0];if(e&&!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e))return"邮箱格式不合法";return null}
document.getElementById("btn-add-path").addEventListener("click",()=>{const v=document.getElementById("add-path").value.trim();if(!v)return;const wrap=document.getElementById("log-paths");const row=document.createElement("div");row.className="toolbar";const i=document.createElement("input");i.className="input";i.value=v;const b=document.createElement("button");b.className="btn";b.textContent="删除";b.addEventListener("click",()=>{row.remove()});row.appendChild(i);row.appendChild(b);wrap.appendChild(row);document.getElementById("add-path").value=""});
document.getElementById("btn-save").addEventListener("click",async()=>{const cfg=collect();const err=validate(cfg);if(err){toast(err,"error");return}try{await putConfig(cfg);toast("已保存","success");await load()}catch(e){toast(e.message||"保存失败","error")}});

// 搜索 / 检测模式按钮：直接写入 config.json.detection.search_mode
let currentDetectMode=DEFAULT_CONFIG.detection.search_mode;
const modeWrap=document.getElementById("detect-modes");
const cmdEl=document.getElementById("detect-mode-command");
function setDetectMode(mode){
  currentDetectMode=mode;
  if(!modeWrap)return;
  Array.from(modeWrap.querySelectorAll("button[data-mode]")).forEach(btn=>{
    const m=btn.getAttribute("data-mode");
    if(m===mode){
      btn.classList.add("primary");
    }else{
      btn.classList.remove("primary");
    }
  });
  if(cmdEl){
    cmdEl.textContent=`当前模式：${mode}  （保存后会写入 config/config.json 的 detection.search_mode）`;
  }
}
if(modeWrap){
  modeWrap.addEventListener("click",e=>{
    const btn=e.target.closest("button[data-mode]");
    if(!btn)return;
    const mode=btn.getAttribute("data-mode");
    if(!mode)return;
    setDetectMode(mode);
  });
}

load()
