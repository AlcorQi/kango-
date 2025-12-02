const API_BASE=(typeof window!=='undefined'&&window.API_BASE)?window.API_BASE:((location&&location.port==="8000")?"/api/v1":"http://localhost:8000/api/v1");
const state={config:null,lastEventId:null};
function q(obj){const p=new URLSearchParams();Object.entries(obj||{}).forEach(([k,v])=>{if(v===undefined||v===null||v==="")return;if(Array.isArray(v))v.forEach(i=>p.append(k,i));else p.append(k,v)});return p.toString()}
async function req(path,opts){const r=await fetch(path,opts);if(!r.ok){let e;try{e=await r.json()}catch{e={status:r.status,code:"HTTP_ERROR",message:r.statusText}}throw e}return r.headers.get("content-type")?.includes("application/json")?r.json():r.text()}
async function getStats(window,hostId){return req(`${API_BASE}/stats${window||hostId?`?${q({window,host_id:hostId})}`:""}`)}
async function getHostsStats(window){return req(`${API_BASE}/hosts/stats${window?`?${q({window})}`:""}`)}
async function getEvents(params){return req(`${API_BASE}/events?${q(params)}`)}
async function getEvent(id){return req(`${API_BASE}/events/${encodeURIComponent(id)}`)}
async function getConfig(){const c=await req(`${API_BASE}/config`);state.config=c;return c}
async function putConfig(cfg){return req(`${API_BASE}/config`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(cfg)})}
async function getHosts(){return req(`${API_BASE}/hosts`)}
function connectSSE(){const es=new EventSource(`${API_BASE}/stream`);es.addEventListener("anomaly",e=>{state.lastEventId=e.lastEventId||null;try{const d=JSON.parse(e.data);document.dispatchEvent(new CustomEvent("sse:anomaly",{detail:d}))}catch{}});es.addEventListener("ping",e=>{document.dispatchEvent(new CustomEvent("sse:ping",{detail:e.data}))});es.onerror=()=>{};return es}
async function getAISuggestions(params){return req(`${API_BASE}/ai/suggestions${params?`?${q(params)}`:""}`)}
async function generateAI(payload){return req(`${API_BASE}/ai/generate`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload||{})})}
function fmtTime(s){
  try{
    const d=new Date(s);
    const fmt=(state.config?.ui?.time_format)||"24h";
    const opts={hour12:fmt==="12h"};
    return d.toLocaleString(undefined,opts)
  }catch{return s}
}
function sevPill(s){const m={critical:"critical",major:"major",minor:"minor"}[s]||"minor";return `<span class="pill ${m}">${s}</span>`}
function safe(t){return String(t??"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]))}
function toast(msg,type){const el=document.getElementById("toast");if(!el)return;el.className=type?type:"";el.textContent=msg;el.style.display=msg?"block":"none"}
export{getStats,getHostsStats,getEvents,getEvent,getConfig,putConfig,connectSSE,fmtTime,sevPill,safe,toast,state,getAISuggestions,getHosts,generateAI}
