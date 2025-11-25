import{getEvents,fmtTime,sevPill,safe,toast}from"./api.js";
let page=1,total=0,size=20,sort="detected_at:desc";
function val(id){return document.getElementById(id)?.value||""}
function checked(id){return Array.from(document.querySelectorAll(`#${id} input[type=checkbox]:checked`)).map(i=>i.value)}
async function search(){try{size=parseInt(val("q-size"),10)||20;sort=val("q-sort")||"detected_at:desc";const params={start:val("q-start")||undefined,end:val("q-end")||undefined,severity:checked("sev-group"),types:(checked("types-group").join(",")||undefined),keyword:val("q-keyword")||undefined,host_id:val("q-host")||undefined,page,size,sort};const res=await getEvents(params);total=res.total||0;render(res.items||[]);document.getElementById("page-info").textContent=`第 ${res.page} 页 · 共 ${Math.ceil((total||0)/size)||1} 页`;document.getElementById("btn-prev").disabled=res.page<=1;document.getElementById("btn-next").disabled=!res.has_next}catch(e){toast(e.message||"查询失败","error")}}
function render(items){const tbody=document.getElementById("hist-body");tbody.innerHTML="";items.forEach(it=>{const tr=document.createElement("tr");tr.innerHTML=`<td>${fmtTime(it.detected_at)}</td><td>${sevPill(it.severity)}</td><td>${safe(it.type)}</td><td>${safe(it.message)}</td><td>${safe(it.host_id||"")}</td><td>${safe(it.source_file)}:${safe(it.line_number)}</td>`;tbody.appendChild(tr)})}
document.getElementById("btn-search").addEventListener("click",()=>{page=1;search()});
document.getElementById("btn-prev").addEventListener("click",()=>{if(page>1){page--;search()}});
document.getElementById("btn-next").addEventListener("click",()=>{page++;search()});
search()
