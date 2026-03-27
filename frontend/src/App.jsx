import { useState, useEffect, useContext, createContext, useCallback, useRef } from "react";
import { supabase } from "./supabase";

const THEME = {
  bg: "#0b0d12", bgCard: "#10131a", bgCardHover: "#13161f",
  border: "#1e2330", borderBright: "#262d3d",
  accent: "#4f8ef7", accentDim: "#3a6fd4", accentGlow: "rgba(79,142,247,0.1)",
  success: "#22c55e", successGlow: "rgba(34,197,94,0.1)",
  warning: "#f59e0b", warningGlow: "rgba(245,158,11,0.1)",
  danger: "#ef4444", dangerGlow: "rgba(239,68,68,0.1)",
  purple: "#8b5cf6", purpleGlow: "rgba(139,92,246,0.1)",
  orange: "#f97316", orangeGlow: "rgba(249,115,22,0.1)",
  text: "#e2e8f0", textDim: "#4a5568", textMid: "#718096",
  sidebar: "#0b0d12", sidebarBorder: "#1e2330",
};

const TACTICS = ["Reconnaissance","Resource Development","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];
const SEVERITIES = ["Critical","High","Medium","Low","Informational"];
const sevColor = {Critical:"#ff3d55",High:"#ff7700",Medium:"#ffaa00",Low:"#00e87a",Informational:"#00d4ff"};

const TOOLS = [
  {id:"splunk",name:"Splunk",lang:"SPL",color:"#ff5733",desc:"Splunk Search Processing Language",syntax:"index=* sourcetype=* | stats count by field | where condition"},
  {id:"sentinel",name:"Microsoft Sentinel",lang:"KQL",color:"#0078d4",desc:"Kusto Query Language for Azure Sentinel",syntax:"TableName | where Condition | summarize count() by Field"},
  {id:"crowdstrike",name:"CrowdStrike",lang:"CQL",color:"#e1292b",desc:"CrowdStrike Query Language for Falcon",syntax:"#event_simpleName=ProcessRollup2 | ImageFileName=/malware/ | groupby([ComputerName])"},
  {id:"logscale",name:"Falcon LogScale",lang:"LogScale",color:"#ff6b35",desc:"Humio/LogScale query language",syntax:"#type=windowsevent EventID=4688 | ImagePath=/mimikatz/ | groupBy([ComputerName, UserName])"},
  {id:"elastic",name:"Elastic/EQL",lang:"EQL",color:"#f4bd19",desc:"Elastic Event Query Language",syntax:"process where process.name == 'cmd.exe' and process.command_line regex~ '.*malware.*'"},
  {id:"qradar",name:"IBM QRadar",lang:"AQL",color:"#054ada",desc:"Ariel Query Language for QRadar",syntax:"SELECT * FROM events WHERE LOGSOURCETYPENAME(devicetype)='WindowsAuthServer' LAST 24 HOURS"},
  {id:"chronicle",name:"Google Chronicle",lang:"YARA-L",color:"#4285f4",desc:"YARA-L 2.0 for Google Chronicle SIEM",syntax:"rule malware_detection { meta: events: $e.metadata.event_type = 'PROCESS_LAUNCH' condition: $e }"},
  {id:"tanium",name:"Tanium",lang:"Tanium Signal",color:"#00a1e0",desc:"Tanium Signals for endpoint detection",syntax:"process.name:mimikatz.exe AND process.parent.name:explorer.exe"},
  {id:"panther",name:"Panther",lang:"Python",color:"#7c3aed",desc:"Python-based detections for Panther SIEM",syntax:"def rule(event): return event.get('eventType') == 'ADMIN_LOGIN' and event.get('country') != 'US'"},
  {id:"sumo",name:"Sumo Logic",lang:"Sumo Logic",color:"#000099",desc:"Sumo Logic query language",syntax:"_sourceCategory=windows/security | where EventID=4688 | where CommandLine matches '*mimikatz*'"},
];

const S = {
  input: {width:"100%",background:"#0b0d14",border:"1px solid "+THEME.border,borderRadius:8,padding:"9px 12px",color:THEME.text,fontFamily:"inherit",fontSize:13,outline:"none",boxSizing:"border-box",transition:"border-color 0.15s"},
  textarea: {width:"100%",background:"#0b0d14",border:"1px solid "+THEME.border,borderRadius:8,padding:"9px 12px",color:THEME.text,fontFamily:"inherit",fontSize:13,outline:"none",resize:"vertical",boxSizing:"border-box",minHeight:100,transition:"border-color 0.15s"},
  btn: (v="p")=>({padding:"8px 16px",borderRadius:7,border:v==="p"?"1px solid "+THEME.accentDim:v==="d"?"1px solid "+THEME.danger+"55":v==="s"?"1px solid "+THEME.success+"55":"1px solid "+THEME.borderBright,background:v==="p"?"rgba(79,142,247,0.12)":v==="d"?"rgba(239,68,68,0.08)":v==="s"?"rgba(34,197,94,0.08)":"rgba(255,255,255,0.03)",color:v==="p"?THEME.accent:v==="d"?THEME.danger:v==="s"?THEME.success:THEME.textMid,cursor:"pointer",fontFamily:"inherit",fontSize:12,fontWeight:600,transition:"all 0.15s",whiteSpace:"nowrap"}),
  badge: (c)=>({display:"inline-flex",alignItems:"center",padding:"2px 8px",borderRadius:4,fontSize:10,fontWeight:600,background:c+"14",color:c,border:"1px solid "+c+"28"}),
  card: {background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:10,padding:20,marginBottom:16},
  cardTitle: {fontSize:13,fontWeight:700,color:THEME.text,marginBottom:16,display:"flex",alignItems:"center",gap:8,fontFamily:"'Syne',sans-serif"},
  label: {fontSize:11,color:THEME.textMid,marginBottom:5,display:"block",fontWeight:500},
  code: {background:"#080a10",border:"1px solid "+THEME.border,borderRadius:8,padding:16,fontSize:12,color:"#94b8e8",overflowX:"auto",whiteSpace:"pre-wrap",wordBreak:"break-all",fontFamily:"'JetBrains Mono','Courier New',monospace",lineHeight:1.7},
  spinner: {display:"inline-block",width:12,height:12,border:"2px solid rgba(79,142,247,0.2)",borderTop:"2px solid "+THEME.accent,borderRadius:"50%",animation:"spin 0.7s linear infinite",marginRight:7,verticalAlign:"middle"},
  tag: {display:"inline-flex",alignItems:"center",padding:"3px 9px",borderRadius:5,fontSize:11,background:"rgba(79,142,247,0.08)",color:THEME.accent,border:"1px solid rgba(79,142,247,0.2)",marginRight:4,marginBottom:4},
  divider: {height:1,background:THEME.border,margin:"18px 0"},
  flex: {display:"flex",alignItems:"center",gap:10},
  row: {display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:14},
  grid2: {display:"grid",gridTemplateColumns:"1fr 1fr",gap:16},
  grid3: {display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16},
  grid4: {display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:14},
};

const LS={get:(k,d)=>{try{const v=localStorage.getItem(k);return v?JSON.parse(v):d;}catch{return d;}},set:(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v));}catch{}},};
function uid(){return Date.now().toString(36)+Math.random().toString(36).slice(2,7);}
async function callClaude(messages,system="",max_tokens=2000){
  const res=await fetch("/api/claude",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({messages,system,max_tokens})});
  if(!res.ok){const e=await res.json().catch(()=>({}));throw new Error(e.error||"API error "+res.status);}
  const data=await res.json();return data.text||data.content?.[0]?.text||"";
}
async function callClaudeStream(messages,system="",max_tokens=2000,onChunk){
  const res=await fetch("/api/claude/stream",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({messages,system,max_tokens})});
  if(!res.ok){const e=await res.json().catch(()=>({}));throw new Error(e.error||"API error "+res.status);}
  const reader=res.body.getReader();const decoder=new TextDecoder();
  let fullText="",buffer="";
  while(true){
    const{done,value}=await reader.read();if(done)break;
    buffer+=decoder.decode(value,{stream:true});
    const lines=buffer.split("\n");buffer=lines.pop();
    for(const line of lines){
      if(line.startsWith("data: ")){
        try{const d=JSON.parse(line.slice(6));
          if(d.text){fullText+=d.text;onChunk&&onChunk(fullText);}
          if(d.done)return d.fullText||fullText;
          if(d.error)throw new Error(d.error);
        }catch(e){if(e.message&&!e.message.includes("JSON"))throw e;}
      }
    }
  }
  return fullText;
}
function Spinner(){return <span style={S.spinner}></span>;}
function StatusBar({msg,type="info"}){if(!msg)return null;const c=type==="error"?THEME.danger:type==="success"?THEME.success:THEME.accent;return <div style={{padding:"11px 15px",borderRadius:8,background:c+"0d",border:"1px solid "+c+"2a",color:c,fontSize:12,marginBottom:14,display:"flex",alignItems:"center",gap:8}}><span>{type==="error"?"!":type==="success"?"v":"i"}</span>{msg}</div>;}

// ── Skeleton Loader ───────────────────────────────────────────────────────────
function Skeleton({ width="100%", height=16, borderRadius=6, style={} }) {
  return (
    <div style={{
      width, height, borderRadius,
      background: "linear-gradient(90deg, #0d1220 25%, #141d2e 50%, #0d1220 75%)",
      backgroundSize: "200% 100%",
      animation: "shimmer 1.4s infinite",
      ...style
    }}/>
  );
}

function SkeletonCard() {
  return (
    <div style={{background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:12,padding:20,marginBottom:16}}>
      <div style={{display:"flex",justifyContent:"space-between",marginBottom:14}}>
        <Skeleton width={80} height={20} borderRadius={5}/>
        <Skeleton width={60} height={20} borderRadius={5}/>
      </div>
      <Skeleton width="70%" height={18} style={{marginBottom:10}}/>
      <Skeleton width="100%" height={13} style={{marginBottom:6}}/>
      <Skeleton width="85%" height={13} style={{marginBottom:6}}/>
      <Skeleton width="60%" height={13} style={{marginBottom:16}}/>
      <div style={{display:"flex",justifyContent:"space-between"}}>
        <Skeleton width={100} height={14} borderRadius={5}/>
        <Skeleton width={80} height={30} borderRadius={7}/>
      </div>
    </div>
  );
}

function SkeletonGrid({ count=4 }) {
  return (
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
      {Array.from({length:count}).map((_,i)=><SkeletonCard key={i}/>)}
    </div>
  );
}

function SkeletonDashboard() {
  return (
    <div>
      <div style={{background:"linear-gradient(135deg,#0a1628,#0c1220)",border:"1px solid "+THEME.borderBright,borderRadius:14,padding:"28px 32px",marginBottom:24}}>
        <Skeleton width={200} height={14} style={{marginBottom:12}}/>
        <Skeleton width="50%" height={30} style={{marginBottom:10}}/>
        <Skeleton width="70%" height={14} style={{marginBottom:6}}/>
        <Skeleton width="60%" height={14} style={{marginBottom:20}}/>
        <div style={{display:"flex",gap:10}}><Skeleton width={130} height={38} borderRadius={7}/><Skeleton width={130} height={38} borderRadius={7}/></div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:14,marginBottom:16}}>
        {[1,2,3,4].map(i=><div key={i} style={{background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:12,padding:"18px 20px"}}><Skeleton width={60} height={28} style={{marginBottom:8}}/><Skeleton width="80%" height={14}/></div>)}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        <SkeletonCard/><SkeletonCard/>
      </div>
    </div>
  );
}

function CopyBtn({text,small=false}){const[c,setC]=useState(false);return <button style={{...S.btn(),padding:small?"3px 10px":"9px 18px",fontSize:small?10:12}} onClick={()=>{navigator.clipboard.writeText(text);setC(true);setTimeout(()=>setC(false),1500)}}>{c?"Copied!":"Copy"}</button>;}

function SslCertGuide({url}){
  const base = url ? url.replace(/\/services.*/,"").replace(/\/api.*/,"") : "";
  return(
    <div style={{marginBottom:12,padding:"14px 16px",borderRadius:8,background:"rgba(255,170,0,0.07)",border:"1px solid rgba(255,170,0,0.3)"}}>
      <div style={{fontWeight:700,fontSize:12,color:THEME.warning,marginBottom:8}}>⚠ Splunk SSL Certificate Not Trusted</div>
      <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.8,marginBottom:12}}>
        Your browser blocked the connection because Splunk uses a self-signed SSL certificate.
        Fix this in <strong style={{color:THEME.text}}>3 steps</strong>:
      </div>
      <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:12}}>
        {[
          ["1","Open Splunk in a new tab",`Click the link below → browser shows "Your connection is not private" → click Advanced → Proceed to ${base||"Splunk"}`,"open"],
          ["2","Accept the certificate","Once you see the Splunk login page, the certificate is trusted. You can close that tab.","check"],
          ["3","Try pushing again","Come back here and click Push to Splunk again — it will work now.","retry"],
        ].map(([n,title,desc])=>(
          <div key={n} style={{display:"flex",gap:10,alignItems:"flex-start"}}>
            <div style={{width:20,height:20,borderRadius:"50%",background:THEME.warning+"22",border:"1px solid "+THEME.warning+"55",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:800,color:THEME.warning,flexShrink:0,marginTop:1}}>{n}</div>
            <div><div style={{fontSize:12,fontWeight:700,color:THEME.text,marginBottom:2}}>{title}</div><div style={{fontSize:11,color:THEME.textDim,lineHeight:1.5}}>{desc}</div></div>
          </div>
        ))}
      </div>
      {base&&<a href={base} target="_blank" rel="noreferrer" style={{display:"inline-flex",alignItems:"center",gap:6,padding:"7px 14px",borderRadius:6,background:THEME.warning+"15",border:"1px solid "+THEME.warning+"44",color:THEME.warning,fontSize:11,fontWeight:700,textDecoration:"none"}}>↗ Open {base} to trust certificate</a>}
    </div>
  );
}

const AuthContext = createContext(null);
function useAuth(){ return useContext(AuthContext); }
function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => { setUser(session?.user ?? null); setLoading(false); });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_e, session) => setUser(session?.user ?? null));
    return () => subscription.unsubscribe();
  }, []);
  const signUp = (e,p) => supabase.auth.signUp({email:e,password:p});
  const signIn = (e,p) => supabase.auth.signInWithPassword({email:e,password:p});
  const signOut = () => supabase.auth.signOut();
  const resetPassword = (e) => supabase.auth.resetPasswordForEmail(e);
  return <AuthContext.Provider value={{user,loading,signUp,signIn,signOut,resetPassword}}>{children}</AuthContext.Provider>;
}

function HoneycombGrid({ detections }) {
  const tacticMap = {};
  const TACTICS_LIST = ["Reconnaissance","Resource Development","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];
  TACTICS_LIST.forEach(t => { tacticMap[t] = detections.filter(d => d.tactic === t).length; });
  const max = Math.max(...Object.values(tacticMap), 1);
  const HEX_R = 44; const HEX_W = HEX_R * 2; const HEX_H = Math.sqrt(3) * HEX_R;
  const cols = 7; const rows = 2;
  const hexes = [];
  TACTICS_LIST.forEach((t, i) => {
    const col = i % cols; const row = Math.floor(i / cols);
    const x = col * (HEX_W * 0.75) + (row % 2 === 1 ? HEX_W * 0.375 : 0) + HEX_R + 10;
    const y = row * (HEX_H * 0.88) + HEX_R + 10;
    hexes.push({ tactic: t, count: tacticMap[t] || 0, x, y });
  });
  const svgW = cols * (HEX_W * 0.75) + HEX_W * 0.625 + 20;
  const svgH = rows * (HEX_H * 0.88) + HEX_H * 0.5 + 20;
  const hexPath = (cx, cy, r) => {
    const pts = Array.from({length:6}, (_,i) => {
      const a = Math.PI / 180 * (60 * i - 30);
      return `${cx + r * Math.cos(a)},${cy + r * Math.sin(a)}`;
    });
    return `M ${pts.join(" L ")} Z`;
  };
  const getColor = (count) => {
    if (count === 0) return { fill: "rgba(21,29,46,0.8)", stroke: "#1e2d45", text: "#2a3a4a" };
    const pct = count / max;
    if (pct >= 0.7) return { fill: "rgba(0,232,122,0.15)", stroke: "#00e87a", text: "#00e87a" };
    if (pct >= 0.35) return { fill: "rgba(255,170,0,0.12)", stroke: "#ffaa00", text: "#ffaa00" };
    return { fill: "rgba(0,212,255,0.1)", stroke: "#00d4ff66", text: "#00d4ff" };
  };
  const [hovered, setHovered] = useState(null);
  return (
    <div style={{...S.card, marginBottom: 0}}>
      <div style={{...S.cardTitle, marginBottom: 8}}>
        <span>⬡</span> ATT&CK Tactic Honeycomb
        <span style={{marginLeft:"auto", fontSize:10, color:THEME.textDim, fontFamily:"'JetBrains Mono',monospace", fontWeight:400}}>
          {TACTICS_LIST.filter(t=>tacticMap[t]>0).length}/{TACTICS_LIST.length} covered
        </span>
      </div>
      <div style={{fontSize:11, color:THEME.textDim, marginBottom:14, fontFamily:"'JetBrains Mono',monospace"}}>
        Hover a cell to inspect · color = coverage intensity
      </div>
      <div style={{overflowX:"auto"}}>
        <svg width={svgW} height={svgH} style={{display:"block", margin:"0 auto", minWidth: svgW}}>
          <defs>
            <filter id="hglow">
              <feGaussianBlur stdDeviation="3" result="blur"/>
              <feComposite in="SourceGraphic" in2="blur" operator="over"/>
            </filter>
          </defs>
          {hexes.map((h, i) => {
            const c = getColor(h.count);
            const isHov = hovered === i;
            const shortName = h.tactic.length > 12 ? h.tactic.split(" ").map(w=>w[0]).join("") : h.tactic.split(" ")[0];
            return (
              <g key={h.tactic} style={{cursor:"pointer"}}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}>
                <path d={hexPath(h.x, h.y, HEX_R - 2)}
                  fill={isHov ? c.stroke + "30" : c.fill}
                  stroke={isHov ? c.stroke : c.stroke}
                  strokeWidth={isHov ? 2 : 1}
                  style={{transition:"all 0.2s", filter: isHov ? "url(#hglow)" : "none"}}/>
                <text x={h.x} y={h.y - 8} textAnchor="middle" fill={c.text}
                  fontSize={h.count === 0 ? 9 : 10} fontWeight={700}
                  fontFamily="'JetBrains Mono',monospace"
                  style={{transition:"all 0.2s"}}>
                  {shortName}
                </text>
                <text x={h.x} y={h.y + 10} textAnchor="middle"
                  fill={h.count === 0 ? "#2a3a4a" : c.stroke}
                  fontSize={h.count === 0 ? 11 : 18} fontWeight={900}
                  fontFamily="'Syne',sans-serif">
                  {h.count === 0 ? "—" : h.count}
                </text>
                {h.count > 0 && (
                  <text x={h.x} y={h.y + 24} textAnchor="middle" fill={c.text}
                    fontSize={8} fontFamily="'JetBrains Mono',monospace" opacity={0.7}>
                    rule{h.count > 1 ? "s" : ""}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
      {hovered !== null && hexes[hovered] && (
        <div style={{marginTop:12, padding:"10px 14px", borderRadius:8,
          background: getColor(hexes[hovered].count).stroke + "12",
          border: "1px solid " + getColor(hexes[hovered].count).stroke + "33",
          display:"flex", alignItems:"center", justifyContent:"space-between"}}>
          <div>
            <div style={{fontSize:13, fontWeight:700, color:THEME.text, fontFamily:"'Syne',sans-serif"}}>{hexes[hovered].tactic}</div>
            <div style={{fontSize:11, color:THEME.textDim, fontFamily:"'JetBrains Mono',monospace", marginTop:2}}>
              {hexes[hovered].count === 0 ? "No detections — coverage gap" : `${hexes[hovered].count} detection${hexes[hovered].count > 1 ? "s" : ""} built`}
            </div>
          </div>
          <span style={{...S.badge(hexes[hovered].count === 0 ? THEME.danger : getColor(hexes[hovered].count).stroke)}}>
            {hexes[hovered].count === 0 ? "GAP" : Math.round(hexes[hovered].count / max * 100) + "%"}
          </span>
        </div>
      )}
      <div style={{display:"flex", gap:16, marginTop:14, flexWrap:"wrap"}}>
        {[["#00e87a","Strong (3+ rules)"],["#ffaa00","Partial (1–2 rules)"],["#00d4ff","Minimal (1 rule)"],["#2a3a4a","Gap (0 rules)"]].map(([c,l])=>(
          <div key={l} style={{display:"flex", alignItems:"center", gap:6}}>
            <div style={{width:10, height:10, borderRadius:2, background:c, opacity:0.8}}/>
            <span style={{fontSize:10, color:THEME.textDim, fontFamily:"'JetBrains Mono',monospace"}}>{l}</span>
          </div>
        ))}
      </div>
      {/* ── Gap row ── */}
      {TACTICS_LIST.filter(t=>tacticMap[t]===0).length>0&&(
        <div style={{marginTop:12,paddingTop:12,borderTop:"1px solid "+THEME.border}}>
          <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
            <span style={{fontSize:11,fontWeight:500,color:THEME.textMid,flexShrink:0}}>Gaps:</span>
            {TACTICS_LIST.filter(t=>tacticMap[t]===0).map(t=>(
              <span key={t} style={{display:"inline-flex",alignItems:"center",padding:"2px 8px",borderRadius:4,background:"rgba(239,68,68,0.07)",border:"1px solid rgba(239,68,68,0.2)",fontSize:10,color:"#f87171",fontWeight:500}}>
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function OnboardingModal({ user, onComplete }) {
  const [step, setStep] = useState(1);
  const [siem, setSiem] = useState(null);
  const [goal, setGoal] = useState(null);
  const SIEMS = [
    {id:"splunk",name:"Splunk",color:"#ff5733",icon:"🔴"},
    {id:"sentinel",name:"Sentinel",color:"#0078d4",icon:"🔵"},
    {id:"crowdstrike",name:"CrowdStrike",color:"#e1292b",icon:"🦅"},
    {id:"elastic",name:"Elastic",color:"#f4bd19",icon:"🟡"},
    {id:"logscale",name:"LogScale",color:"#ff6b35",icon:"🟠"},
    {id:"qradar",name:"QRadar",color:"#054ada",icon:"🔷"},
    {id:"chronicle",name:"Chronicle",color:"#4285f4",icon:"🌐"},
    {id:"tanium",name:"Tanium",color:"#00a1e0",icon:"🔹"},
    {id:"panther",name:"Panther",color:"#7c3aed",icon:"🟣"},
    {id:"sumo",name:"Sumo Logic",color:"#000099",icon:"📊"},
  ];
  const GOALS = [
    {id:"build",icon:"🔨",title:"Build Detections",desc:"Create production-ready detection rules using the ADS framework",tab:"builder",color:THEME.accent},
    {id:"hunt",icon:"🎯",title:"Hunt Threats",desc:"Investigate alerts, triage events, and track threat actors",tab:"triage",color:THEME.danger},
    {id:"simulate",icon:"⚡",title:"Simulate Attacks",desc:"Generate adversary campaigns and map them against your existing detection coverage",tab:"adversary",color:THEME.purple},
  ];
  function complete() {
    LS.set("onboarding_done", true);
    LS.set("onboarding_siem", siem);
    LS.set("onboarding_goal", goal);
    LS.set("getting_started", {
      built_detection: false,
      ran_simulation: false,
      checked_intel: false,
      enabled_autopilot: false,
    });
    onComplete(siem, goal);
  }
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.92)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:2000,backdropFilter:"blur(8px)"}}>
      <div style={{background:"linear-gradient(145deg,#0c1220,#080d18)",border:"1px solid "+THEME.borderBright,borderRadius:20,padding:"40px 44px",width:"100%",maxWidth:560,boxShadow:"0 32px 80px rgba(0,0,0,0.9)"}}>
        {/* Progress dots */}
        <div style={{display:"flex",justifyContent:"center",gap:8,marginBottom:32}}>
          {[1,2,3].map(s=>(
            <div key={s} style={{width:s===step?24:8,height:8,borderRadius:4,background:s<=step?THEME.accent:THEME.border,transition:"all 0.3s"}}/>
          ))}
        </div>

        {/* Step 1 — SIEM picker */}
        {step===1&&(
          <div>
            <div style={{textAlign:"center",marginBottom:28}}>
              <div style={{fontSize:32,marginBottom:12}}>👋</div>
              <div style={{fontSize:22,fontWeight:900,color:THEME.text,marginBottom:8}}>Welcome to <span style={{color:THEME.accent}}>DetectIQ</span></div>
              <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.7}}>Let's personalize your experience. Which SIEM do you primarily use?</div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:28}}>
              {SIEMS.map(s=>(
                <div key={s.id} onClick={()=>setSiem(s.id)}
                  style={{padding:"10px 14px",borderRadius:10,border:"1px solid "+(siem===s.id?s.color:THEME.border),background:siem===s.id?s.color+"12":"rgba(255,255,255,0.02)",cursor:"pointer",display:"flex",alignItems:"center",gap:10,transition:"all 0.15s"}}
                  onMouseEnter={e=>{if(siem!==s.id){e.currentTarget.style.borderColor=s.color+"44";e.currentTarget.style.background=s.color+"08";}}}
                  onMouseLeave={e=>{if(siem!==s.id){e.currentTarget.style.borderColor=THEME.border;e.currentTarget.style.background="rgba(255,255,255,0.02)";}}}
                >
                  <span style={{fontSize:16}}>{s.icon}</span>
                  <span style={{fontSize:12,fontWeight:600,color:siem===s.id?s.color:THEME.text}}>{s.name}</span>
                  {siem===s.id&&<span style={{marginLeft:"auto",fontSize:12,color:s.color}}>✓</span>}
                </div>
              ))}
            </div>
            <button style={{...S.btn("p"),width:"100%",padding:"12px",fontSize:14,justifyContent:"center",display:"flex",opacity:siem?1:0.4}} onClick={()=>siem&&setStep(2)} disabled={!siem}>
              Continue →
            </button>
            <div style={{textAlign:"center",marginTop:12}}>
              <span style={{fontSize:11,color:THEME.textDim,cursor:"pointer"}} onClick={()=>{setSiem("splunk");setStep(2);}}>Skip for now</span>
            </div>
          </div>
        )}

        {/* Step 2 — Goal picker */}
        {step===2&&(
          <div>
            <div style={{textAlign:"center",marginBottom:28}}>
              <div style={{fontSize:32,marginBottom:12}}>🎯</div>
              <div style={{fontSize:22,fontWeight:900,color:THEME.text,marginBottom:8}}>What's your main goal?</div>
              <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.7}}>We'll guide you to the right tools first.</div>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:10,marginBottom:28}}>
              {GOALS.map(g=>(
                <div key={g.id} onClick={()=>setGoal(g.id)}
                  style={{padding:"16px 20px",borderRadius:12,border:"1px solid "+(goal===g.id?g.color:THEME.border),background:goal===g.id?g.color+"10":"rgba(255,255,255,0.02)",cursor:"pointer",display:"flex",alignItems:"center",gap:16,transition:"all 0.15s"}}
                  onMouseEnter={e=>{if(goal!==g.id){e.currentTarget.style.borderColor=g.color+"44";e.currentTarget.style.background=g.color+"06";}}}
                  onMouseLeave={e=>{if(goal!==g.id){e.currentTarget.style.borderColor=THEME.border;e.currentTarget.style.background="rgba(255,255,255,0.02)";}}}
                >
                  <div style={{width:44,height:44,borderRadius:10,background:g.color+"18",border:"1px solid "+g.color+"33",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,flexShrink:0}}>{g.icon}</div>
                  <div style={{flex:1}}>
                    <div style={{fontSize:14,fontWeight:700,color:goal===g.id?g.color:THEME.text,marginBottom:3}}>{g.title}</div>
                    <div style={{fontSize:11,color:THEME.textDim,lineHeight:1.5}}>{g.desc}</div>
                  </div>
                  {goal===g.id&&<span style={{fontSize:18,color:g.color}}>✓</span>}
                </div>
              ))}
            </div>
            <div style={{display:"flex",gap:10}}>
              <button style={{...S.btn(),padding:"12px",fontSize:13,flex:"0 0 80px"}} onClick={()=>setStep(1)}>← Back</button>
              <button style={{...S.btn("p"),padding:"12px",fontSize:14,flex:1,justifyContent:"center",display:"flex",opacity:goal?1:0.4}} onClick={()=>goal&&setStep(3)} disabled={!goal}>
                Continue →
              </button>
            </div>
          </div>
        )}

        {/* Step 3 — Ready */}
        {step===3&&(()=>{
          const g = GOALS.find(x=>x.id===goal);
          const s = SIEMS.find(x=>x.id===siem);
          return (
            <div style={{textAlign:"center"}}>
              <div style={{fontSize:48,marginBottom:16}}>🚀</div>
              <div style={{fontSize:22,fontWeight:900,color:THEME.text,marginBottom:8}}>You're all set!</div>
              <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,marginBottom:28,maxWidth:380,margin:"0 auto 28px"}}>
                Your workspace is configured for <span style={{color:s?.color||THEME.accent,fontWeight:700}}>{s?.name||"your SIEM"}</span>.
                We'll take you straight to <span style={{color:g?.color||THEME.accent,fontWeight:700}}>{g?.title}</span> to get started.
              </div>
              <div style={{background:"rgba(0,212,255,0.05)",border:"1px solid rgba(0,212,255,0.15)",borderRadius:12,padding:"16px 20px",marginBottom:28,textAlign:"left"}}>
                <div style={{fontSize:11,fontWeight:700,color:THEME.accentDim,letterSpacing:"0.1em",marginBottom:12}}>YOUR GETTING STARTED CHECKLIST</div>
                {[
                  {icon:"🔨",text:"Build your first detection"},
                  {icon:"🎯",text:"Run an attack simulation"},
                  {icon:"🌐",text:"Check the live threat feed"},
                  {icon:"🤖",text:"Enable Detection Autopilot"},
                ].map(item=>(
                  <div key={item.text} style={{display:"flex",alignItems:"center",gap:10,padding:"6px 0",borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
                    <span>{item.icon}</span>
                    <span style={{fontSize:12,color:THEME.textMid}}>{item.text}</span>
                    <span style={{marginLeft:"auto",fontSize:10,color:THEME.textDim}}>pending</span>
                  </div>
                ))}
              </div>
              <button style={{...S.btn("p"),width:"100%",padding:"14px",fontSize:14,justifyContent:"center",display:"flex"}} onClick={complete}>
                Let's go → {g?.title}
              </button>
            </div>
          );
        })()}
      </div>
    </div>
  );
}

function LoginModal({ onClose, onDemo }) {
  const { signIn, signUp, resetPassword } = useAuth();
  const [mode, setMode] = useState("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState({ text: "", type: "info" });
  async function handleSubmit() {
    setMsg({ text: "", type: "info" });
    if (!email.trim()) { setMsg({ text: "Email is required.", type: "error" }); return; }
    if (mode === "reset") {
      setLoading(true);
      try {
        const res = await fetch("/api/send-reset-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to send email");
        setMsg({ text: "Reset email sent! Check your inbox.", type: "success" });
      } catch(e) {
        // Fallback to Supabase default
        const { error } = await resetPassword(email);
        if (error) setMsg({ text: "Could not send reset email. Please try again.", type: "error" });
        else setMsg({ text: "Reset email sent! Check your inbox.", type: "success" });
      }
      setLoading(false);
      return;
    }
    if (!password) { setMsg({ text: "Password is required.", type: "error" }); return; }
    if (mode === "signup" && password !== confirm) { setMsg({ text: "Passwords do not match.", type: "error" }); return; }
    if (mode === "signup" && password.length < 8) { setMsg({ text: "Password must be at least 8 characters.", type: "error" }); return; }
    setLoading(true);
    if (mode === "signup") {
      const { error } = await signUp(email, password);
      setLoading(false);
      if (error) setMsg({ text: error.message, type: "error" });
      else {
        setMsg({ text: "Account created! You can now sign in.", type: "success" });
        fetch("/api/auth/welcome-email",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,name:email.split("@")[0]})}).catch(()=>{});
      }
    } else {
      const { error } = await signIn(email, password);
      setLoading(false);
      if (error) setMsg({ text: error.message, type: "error" });
      else onClose();
    }
  }
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.8)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:1000,backdropFilter:"blur(6px)"}} onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div style={{background:"linear-gradient(145deg,#0c1220,#080d18)",border:"1px solid "+THEME.borderBright,borderRadius:16,padding:36,width:"100%",maxWidth:420,boxShadow:"0 32px 80px rgba(0,0,0,0.7)"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{display:"flex",justifyContent:"center",marginBottom:12}}><DetectIQLogo size="lg"/></div>
          <div style={{fontSize:13,color:THEME.textMid}}>{mode==="signin"?"Welcome back":"Create your account"}</div>
        </div>
        <div style={{marginBottom:14}}><label style={S.label}>Email</label><input style={S.input} type="email" value={email} onChange={e=>setEmail(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleSubmit()} placeholder="you@example.com" autoFocus/></div>
        {mode!=="reset"&&<div style={{marginBottom:14}}><label style={S.label}>Password</label><input style={S.input} type="password" value={password} onChange={e=>setPassword(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleSubmit()} placeholder={mode==="signup"?"Min 8 characters":"Your password"}/></div>}
        {mode==="signup"&&<div style={{marginBottom:14}}><label style={S.label}>Confirm Password</label><input style={S.input} type="password" value={confirm} onChange={e=>setConfirm(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleSubmit()} placeholder="Repeat password"/></div>}
        {msg.text&&<StatusBar msg={msg.text} type={msg.type}/>}
        <button style={{...S.btn("p"),width:"100%",padding:"12px",fontSize:13,marginBottom:12,justifyContent:"center",display:"flex",alignItems:"center"}} onClick={handleSubmit} disabled={loading}>{loading&&<Spinner/>}{mode==="signin"?"Sign In":mode==="signup"?"Create Account":"Send Reset Email"}</button>
        <div style={{textAlign:"center",fontSize:12,color:THEME.textDim,marginBottom:14}}>
          {mode==="signin"&&<><span style={{color:THEME.accent,cursor:"pointer"}} onClick={()=>{setMode("signup");setMsg({text:"",type:"info"});}}>Create account</span><span style={{margin:"0 10px",color:THEME.border}}>|</span><span style={{color:THEME.accent,cursor:"pointer"}} onClick={()=>{setMode("reset");setMsg({text:"",type:"info"});}}>Forgot password?</span></>}
          {mode!=="signin"&&<span style={{color:THEME.accent,cursor:"pointer"}} onClick={()=>{setMode("signin");setMsg({text:"",type:"info"});}}>Back to sign in</span>}
        </div>
        <div style={{borderTop:"1px solid "+THEME.border,paddingTop:16,textAlign:"center"}}>
          <button style={{...S.btn(),width:"100%",padding:"10px",fontSize:12}} onClick={onDemo}>Try Demo Mode (no account needed)</button>
        </div>
      </div>
    </div>
  );
}

async function fetchDetectionsFromDB(userId) {
  const { data, error } = await supabase.from("detections").select("*").eq("user_id", userId).order("created_at", { ascending: false });
  if (error) throw error;
  return data.map(d => ({id:d.id,name:d.name,query:d.query,tool:d.tool,tactic:d.tactic,severity:d.severity,description:d.description,tags:d.tags||[],score:d.score||0,created:d.created_at,queryType:d.tool,threat:d.description}));
}
async function saveDetectionToDB(userId, det) {
  const { data, error } = await supabase.from("detections").insert([{user_id:userId,name:det.name,query:det.query,tool:det.queryType||det.tool,tactic:det.tactic,severity:det.severity||"Medium",description:det.threat||det.description||"",tags:det.tags||[],score:det.score||0}]).select().single();
  if (error) throw error;
  return { ...det, id: data.id };
}
async function deleteDetectionFromDB(id) { const { error } = await supabase.from("detections").delete().eq("id", id); if (error) throw error; }
async function updateDetectionInDB(det) { const { error } = await supabase.from("detections").update({name:det.name,query:det.query,score:det.score,tactic:det.tactic,severity:det.severity,tags:det.tags||[]}).eq("id", det.id); if (error) throw error; }

const MITRE_USECASES = [
  // ── RECONNAISSANCE ──────────────────────────────────────────────────────────
  {id:"uc001",tactic:"Reconnaissance",technique:"T1595.001",name:"Active Scanning — IP Ranges",description:"Detect systematic scanning of IP ranges from external sources.",queryType:"KQL",severity:"Medium",tool:"sentinel",difficulty:"Intermediate",query:"CommonSecurityLog\n| where DeviceAction == 'Deny'\n| summarize ScanCount=count(), Ports=make_set(DestinationPort) by SourceIP, bin(TimeGenerated, 5m)\n| where ScanCount > 50 and array_length(Ports) > 10",walkthrough:{story:"Attackers enumerate your IP space before launching targeted attacks. Tools like Masscan or Shodan are used to fingerprint open services.",tune:"Adjust ScanCount threshold based on your baseline firewall deny rate. Internal scanners should be whitelisted by IP.",fp:"Legitimate vulnerability scanners (Qualys, Nessus) from known IPs. Add their IPs to an exclusion list.",related:["uc002","uc003"]}},
  {id:"uc002",tactic:"Reconnaissance",technique:"T1592.002",name:"Host Software Discovery via Web",description:"Detect web crawlers probing for software versions and tech stack.",queryType:"SPL",severity:"Low",tool:"splunk",difficulty:"Beginner",query:"index=web sourcetype=access_combined\n| where match(useragent, '(?i)(nmap|masscan|nikto|sqlmap|dirbuster|gobuster|zgrab)')\n| stats count by src_ip, useragent, uri\n| sort -count",walkthrough:{story:"Attackers use scanning tools to identify web frameworks, CMS versions, and vulnerable plugins before targeting your web apps.",tune:"Add your own internal scanner user agents to the exclusion list. Focus on external IPs.",fp:"Security team running authorized scans. Exclude known scanner IPs from the detection.",related:["uc001","uc003"]}},
  {id:"uc003",tactic:"Reconnaissance",technique:"T1596",name:"Search Open Technical Databases",description:"Detect unusual DNS lookups suggesting OSINT gathering on your infrastructure.",queryType:"KQL",severity:"Low",tool:"sentinel",difficulty:"Beginner",query:"DnsEvents\n| where QueryType in ('MX','NS','TXT','SOA','AXFR')\n| where ClientIP !in (trusted_resolvers)\n| summarize count() by ClientIP, QueryType, bin(TimeGenerated, 1h)\n| where count_ > 20",walkthrough:{story:"DNS reconnaissance reveals mail servers, name servers, and SPF records. AXFR attempts indicate zone transfer attacks.",tune:"Build a list of trusted DNS resolvers and exclude them. Alert on AXFR attempts immediately.",fp:"Legitimate monitoring tools and DNS health checkers. Whitelist known monitoring IPs.",related:["uc001","uc002"]}},

  // ── RESOURCE DEVELOPMENT ────────────────────────────────────────────────────
  {id:"uc004",tactic:"Resource Development",technique:"T1583.001",name:"Acquire Infrastructure — Domains",description:"Detect newly registered lookalike domains targeting your organization.",queryType:"SPL",severity:"Medium",tool:"splunk",difficulty:"Advanced",query:"index=dns\n| lookup domainage_lookup domain AS query OUTPUT domain_age\n| where domain_age < 30\n| where match(query, '(?i)(yourcompany|yourdomain|brandname)')\n| stats count by query, domain_age, src_ip",walkthrough:{story:"Attackers register lookalike domains (company-login.com) for phishing campaigns weeks before launching attacks.",tune:"Replace 'yourcompany' with your actual brand names. Integrate with a domain monitoring service for proactive alerting.",fp:"Legitimate new domains registered by your own organization. Maintain an allowlist of new domains you register.",related:["uc005","uc006"]}},
  {id:"uc005",tactic:"Resource Development",technique:"T1587.001",name:"Develop Capabilities — Malware",description:"Detect staging of malware on internal systems before deployment.",queryType:"CQL",severity:"High",tool:"crowdstrike",difficulty:"Advanced",query:"#event_simpleName=ProcessRollup2\n| ImageFileName=/mshta.exe|regsvr32.exe|rundll32.exe/i\n| CommandLine=/scrobj|javascript|vbscript|http/i\n| groupby([ComputerName, UserName, CommandLine])\n| sort(count, order=desc)",walkthrough:{story:"Attackers use living-off-the-land binaries to stage malware. MSHTA and RegSvr32 are commonly abused for initial staging.",tune:"Baseline legitimate use of these binaries in your environment. Many are used by legitimate software installers.",fp:"Software installers and update mechanisms use these binaries. Build a baseline of known-good command patterns.",related:["uc004","uc006"]}},
  {id:"uc006",tactic:"Resource Development",technique:"T1588.002",name:"Obtain Tool — Remote Access",description:"Detect download and staging of remote access tools not in your approved list.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Intermediate",query:"DeviceNetworkEvents\n| where RemoteUrl has_any ('anydesk.com','teamviewer.com','screenconnect.com','ngrok.io','serveo.net')\n| where InitiatingProcessFileName !in (approved_tools)\n| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName",walkthrough:{story:"Attackers download and install remote access tools to maintain persistence after initial compromise.",tune:"Maintain an approved list of remote access tools allowed in your environment. Alert on all others.",fp:"IT help desk legitimately uses TeamViewer or AnyDesk. Maintain an approved tool list and whitelist those processes.",related:["uc004","uc005"]}},

  // ── INITIAL ACCESS ──────────────────────────────────────────────────────────
  {id:"uc007",tactic:"Initial Access",technique:"T1566.001",name:"Spearphishing Attachment",description:"Detect malicious email attachments with weaponized file types.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Beginner",query:"index=email sourcetype=mail_logs attachment_name=*\n| eval ext=lower(mvindex(split(attachment_name,'.'), -1))\n| where ext IN ('exe','vbs','js','hta','doc','xls','zip','iso','img','lnk')\n| stats count by src_user, attachment_name, subject\n| where count < 3 | sort -count",walkthrough:{story:"Spearphishing with malicious attachments is the #1 initial access vector. Attackers craft targeted emails with weaponized Office docs, ISOs, or LNK files.",tune:"Adjust file extension list based on what your organization actually uses. Add PS1, MSI, and HTA if not blocked by email gateway.",fp:"Legitimate business attachments like ZIP files and macros. Consider allowlisting specific senders for business-critical file types.",related:["uc008","uc009"]}},
  {id:"uc008",tactic:"Initial Access",technique:"T1566.002",name:"Spearphishing Link",description:"Detect clicks on malicious links in emails leading to credential harvesting.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Beginner",query:"EmailUrlInfo\n| where Url has_any ('bit.ly','tinyurl','t.co','rebrand.ly')\n| join kind=inner EmailEvents on NetworkMessageId\n| where DeliveryAction == 'Delivered'\n| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Url, Subject",walkthrough:{story:"Attackers use URL shorteners and newly-registered domains to bypass email filters. Clicking the link leads to credential phishing or drive-by malware.",tune:"Expand the URL shortener list. Consider integrating with a threat intelligence feed for real-time malicious URL detection.",fp:"Marketing emails legitimately use URL shorteners. Add known marketing domains to an exclusion list.",related:["uc007","uc009"]}},
  {id:"uc009",tactic:"Initial Access",technique:"T1190",name:"Exploit Public-Facing Application",description:"Detect exploitation attempts against internet-facing applications.",queryType:"KQL",severity:"Critical",tool:"sentinel",difficulty:"Intermediate",query:"SecurityEvent\n| where EventID == 4625\n| summarize FailCount=count() by IpAddress, Account, bin(TimeGenerated, 5m)\n| where FailCount > 10 | order by FailCount desc",walkthrough:{story:"Attackers exploit unpatched vulnerabilities in VPNs, web apps, and remote access solutions. Log4Shell, ProxyLogon, and Fortinet CVEs are common examples.",tune:"Lower the threshold for critical systems. Consider geo-blocking countries you don't operate in.",fp:"Legitimate users forgetting passwords will trigger this. Focus on external IPs and accounts that don't exist in your directory.",related:["uc007","uc010"]}},
  {id:"uc010",tactic:"Initial Access",technique:"T1078",name:"Valid Account Abuse",description:"Detect use of valid credentials from anomalous locations or unusual times.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Intermediate",query:"index=auth sourcetype=okta OR sourcetype=azure_ad action=success\n| stats count dc(src_ip) as ip_count by user\n| where ip_count > 5\n| join user [search index=auth action=success | stats latest(_time) as last_login by user]\n| eval hours_since=round((now()-last_login)/3600,1)",walkthrough:{story:"Compromised credentials from phishing or password spraying allow attackers to blend in as legitimate users. Impossible travel and new device alerts are key signals.",tune:"Integrate with your identity provider. Add impossible travel detection by comparing login geolocations.",fp:"VPN users will appear from multiple IPs. Travel and remote work legitimately triggers this. Correlate with HR data.",related:["uc009","uc011"]}},
  {id:"uc011",tactic:"Initial Access",technique:"T1133",name:"External Remote Services",description:"Detect unusual VPN or RDP connections from unexpected geolocations.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Beginner",query:"SigninLogs\n| where AppDisplayName has_any ('VPN','Remote Desktop','Citrix')\n| where LocationDetails.countryOrRegion !in (allowed_countries)\n| project TimeGenerated, UserPrincipalName, IPAddress, LocationDetails, AppDisplayName",walkthrough:{story:"Attackers use legitimate VPN and remote access services to gain foothold. Access from unusual countries is a key indicator.",tune:"Build and maintain your allowed countries list. Alert immediately on access from high-risk countries.",fp:"Business travelers and remote workers. Consider requiring MFA step-up for access from new countries.",related:["uc009","uc010"]}},

  // ── EXECUTION ───────────────────────────────────────────────────────────────
  {id:"uc012",tactic:"Execution",technique:"T1059.001",name:"PowerShell Encoded Commands",description:"Detect PowerShell with base64 encoded commands.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Beginner",query:"index=wineventlog EventCode=4688 process_name='powershell.exe'\n| where match(process_command_line, '(?i)-enc|-encodedcommand|-e\\s+[A-Za-z0-9+/]{20,}')\n| table _time, user, host, process_command_line | head 100",walkthrough:{story:"Encoded PowerShell is the most common obfuscation technique for malicious payloads. Attackers base64-encode commands to bypass simple string matching.",tune:"Enable PowerShell Script Block Logging (Event 4104) for full command visibility. Also check for -EncodedCommand with short strings.",fp:"Some legitimate software uses encoded PowerShell. Build a baseline of known-good hashes and command patterns.",related:["uc013","uc014"]}},
  {id:"uc013",tactic:"Execution",technique:"T1059.001",name:"PowerShell Download Cradle",description:"Detect PowerShell downloading payloads from the internet.",queryType:"CQL",severity:"High",tool:"crowdstrike",difficulty:"Beginner",query:"#event_simpleName=ProcessRollup2\n| CommandLine=/DownloadString|DownloadFile|WebClient|Invoke-WebRequest|IWR|wget|curl/i\n| CommandLine=/http/\n| ImageFileName=/powershell/i\n| groupby([ComputerName, UserName, CommandLine])\n| sort(count, order=desc)",walkthrough:{story:"Download cradles pull malicious payloads from attacker-controlled servers. This is stage 2 of many attacks after initial phishing.",tune:"Alert on any PowerShell making external HTTP calls. Combine with network proxy logs for full visibility.",fp:"Windows Update, package managers, and admin scripts legitimately use WebClient. Whitelist known-good URLs.",related:["uc012","uc014"]}},
  {id:"uc014",tactic:"Execution",technique:"T1059.003",name:"Suspicious CMD Shell",description:"Detect suspicious Windows Command Shell usage for recon and movement.",queryType:"EQL",severity:"Medium",tool:"elastic",difficulty:"Beginner",query:"process where process.name == 'cmd.exe'\n  and process.command_line regex~ '.*(net user|net localgroup|whoami|ipconfig /all|systeminfo|tasklist|netstat -ano).*'\n  and not user.name in ('SYSTEM','LOCAL SERVICE')",walkthrough:{story:"CMD is used by attackers for quick reconnaissance after initial access. Commands like whoami, ipconfig, and net user are classic post-exploitation discovery.",tune:"Consider the parent process — cmd.exe spawned by Office apps or email clients is highly suspicious.",fp:"IT administrators and help desk staff run these commands regularly. Correlate with the user's role and time of day.",related:["uc012","uc015"]}},
  {id:"uc015",tactic:"Execution",technique:"T1059.005",name:"VBScript Execution",description:"Detect VBScript files executed via wscript or cscript.",queryType:"LogScale",severity:"High",tool:"logscale",difficulty:"Intermediate",query:"#type=windowsevent EventID=4688\n| ImagePath=/wscript.exe|cscript.exe/i\n| CommandLine=/.vbs|.vbe/i\n| !CommandLine=/\\windows\\system32/i\n| groupBy([ComputerName, UserName, CommandLine])",walkthrough:{story:"VBScript is commonly delivered via phishing attachments and HTML smuggling. WScript and CScript execute the scripts silently.",tune:"Block VBScript execution via GPO (Software Restriction Policies) in most environments. This detection is your backstop.",fp:"Legacy applications and admin scripts use VBScript. Maintain an inventory of legitimate VBS scripts.",related:["uc014","uc016"]}},
  {id:"uc016",tactic:"Execution",technique:"T1047",name:"WMI Execution",description:"Detect WMI used for remote command execution.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Intermediate",query:"SecurityEvent\n| where EventID == 4688\n| where Process has 'wmiprvse.exe' or CommandLine has 'wmic'\n| where CommandLine has_any ('process call create','os get','computersystem get')\n| project TimeGenerated, Account, Computer, CommandLine",walkthrough:{story:"WMI is abused for lateral movement and persistence. It's a trusted Windows component making it hard to block outright.",tune:"Enable WMI activity logging. Focus on remote WMI calls (from non-local IPs) and unusual process creation via WMI.",fp:"System management tools like SCCM and monitoring agents heavily use WMI. Whitelist known management server IPs.",related:["uc015","uc017"]}},
  {id:"uc017",tactic:"Execution",technique:"T1569.002",name:"Service Execution",description:"Detect services created and immediately executed for payload delivery.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Intermediate",query:"index=wineventlog EventCode=7045\n| join ComputerName [search index=wineventlog EventCode=7036 Message='*running*']\n| where ServiceFileName !match('(?i)(windows|microsoft|program files)')\n| table _time, ComputerName, ServiceName, ServiceFileName",walkthrough:{story:"PsExec and similar tools create temporary services to execute payloads on remote systems. Service creation followed immediately by execution is a red flag.",tune:"Correlate EventID 7045 (service install) with 7036 (service state change) within 60 seconds for high-fidelity alerts.",fp:"Legitimate software installers create services. Focus on services with unusual paths like Temp or AppData.",related:["uc016","uc018"]}},

  // ── PERSISTENCE ─────────────────────────────────────────────────────────────
  {id:"uc018",tactic:"Persistence",technique:"T1547.001",name:"Registry Run Key",description:"Detect modifications to Windows Registry autorun keys.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Beginner",query:"index=wineventlog EventCode=13\n| where match(registry_path, '(?i)CurrentVersion\\\\Run')\n| where NOT match(registry_value_data, '(?i)(windows|microsoft|adobe|google|mozilla)')\n| table _time, user, registry_path, registry_value_name, registry_value_data",walkthrough:{story:"Registry Run keys are the most classic persistence mechanism. Malware adds itself here to survive reboots.",tune:"Build a baseline of known-good Run key entries. Alert on any NEW entries not in your baseline.",fp:"Many legitimate applications add Run keys. Focus on entries pointing to unusual paths like Temp, AppData, or ProgramData.",related:["uc019","uc020"]}},
  {id:"uc019",tactic:"Persistence",technique:"T1053.005",name:"Scheduled Task Creation",description:"Detect creation of scheduled tasks by non-system accounts.",queryType:"KQL",severity:"Medium",tool:"sentinel",difficulty:"Beginner",query:"SecurityEvent\n| where EventID in (4698, 4702)\n| extend TaskAction = extract('<Command>([^<]+)</Command>', 1, EventData)\n| where TaskAction !has '\\Windows\\'\n| project TimeGenerated, Account, Computer, TaskAction",walkthrough:{story:"Scheduled tasks are popular for persistence and lateral movement. Attackers create tasks pointing to malware in unusual directories.",tune:"Alert on tasks pointing to non-standard paths (Temp, AppData, user directories). Also alert on tasks with encoded commands.",fp:"Many legitimate applications create scheduled tasks. Focus on tasks created by non-system accounts pointing to unusual locations.",related:["uc018","uc020"]}},
  {id:"uc020",tactic:"Persistence",technique:"T1543.003",name:"Malicious Service Installation",description:"Detect Windows service installations from unusual paths.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Beginner",query:"SecurityEvent\n| where EventID == 7045\n| where SubjectUserName !in ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE')\n| where ServiceFileName !startswith 'C:\\Windows\\'\n| project TimeGenerated, SubjectUserName, ServiceName, ServiceFileName",walkthrough:{story:"Malicious services provide persistence and can run as SYSTEM. Attackers install services pointing to malware dropped in writable directories.",tune:"Alert on services installed from Temp, AppData, or user home directories. These are almost never legitimate.",fp:"Third-party software installs services from Program Files. Focus on services outside standard installation directories.",related:["uc018","uc019"]}},
  {id:"uc021",tactic:"Persistence",technique:"T1136.001",name:"Local Account Creation",description:"Detect creation of new local user accounts.",queryType:"SPL",severity:"Medium",tool:"splunk",difficulty:"Beginner",query:"index=wineventlog EventCode=4720\n| stats count by src_user, user, host\n| where NOT match(src_user, '(?i)(system|administrator)')\n| sort -count",walkthrough:{story:"Attackers create backdoor local accounts to maintain persistent access even if primary credentials are changed.",tune:"Any local account creation outside of your standard provisioning process should be investigated. Correlate with your ITSM system.",fp:"Helpdesk creating temporary accounts for troubleshooting. Ensure all account creation goes through your official process.",related:["uc020","uc022"]}},
  {id:"uc022",tactic:"Persistence",technique:"T1098",name:"Account Manipulation",description:"Detect modifications to existing accounts including group membership changes.",queryType:"CQL",severity:"High",tool:"crowdstrike",difficulty:"Intermediate",query:"#event_simpleName=UserAccountModified OR #event_simpleName=GroupMemberAdded\n| UserName!=SYSTEM\n| groupby([ComputerName, UserName, TargetUserName, #event_simpleName])\n| sort(count, order=desc)",walkthrough:{story:"Attackers add their compromised accounts to privileged groups for escalation. Adding to Domain Admins or Administrators is a critical signal.",tune:"Alert immediately on additions to Domain Admins, Enterprise Admins, and local Administrators groups.",fp:"Legitimate helpdesk group membership changes. Correlate with your change management system.",related:["uc021","uc023"]}},
  {id:"uc023",tactic:"Persistence",technique:"T1505.003",name:"Web Shell",description:"Detect web shell deployment and execution on web servers.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Advanced",query:"index=web sourcetype=iis OR sourcetype=apache\n| where match(cs_uri_stem, '(?i)(\.php|\.asp|\.aspx|\.jsp)')\n| where match(cs_uri_query, '(?i)(cmd=|exec=|shell=|system=|passthru=|eval=)')\n| stats count by c_ip, cs_uri_stem, cs_uri_query\n| where count > 1",walkthrough:{story:"Web shells are server-side scripts giving attackers persistent remote access through web requests. They're hard to detect as they blend with normal web traffic.",tune:"Combine with file integrity monitoring on web directories. Alert on new PHP/ASPX files created in web root.",fp:"Some legitimate applications use query parameters that look like shell commands. Review the specific URIs in context.",related:["uc022","uc024"]}},

  // ── PRIVILEGE ESCALATION ────────────────────────────────────────────────────
  {id:"uc024",tactic:"Privilege Escalation",technique:"T1055",name:"Process Injection",description:"Detect process injection including DLL injection and process hollowing.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Advanced",query:"index=sysmon EventCode=8\n| where TargetImage != SourceImage\n| where NOT match(SourceImage, '(?i)(antivirus|defender|edr|crowdstrike)')\n| stats count by SourceImage, TargetImage, GrantedAccess\n| where count < 5",walkthrough:{story:"Process injection allows code execution in the context of another process to evade detection and escalate privileges. Mimikatz injects into LSASS to dump credentials.",tune:"Requires Sysmon with CreateRemoteThread logging. Focus on injections into high-value processes like lsass.exe, winlogon.exe, and browsers.",fp:"Security tools and debuggers legitimately inject into processes. Whitelist your EDR and security tool processes.",related:["uc025","uc026"]}},
  {id:"uc025",tactic:"Privilege Escalation",technique:"T1548.002",name:"UAC Bypass",description:"Detect UAC bypass techniques via auto-elevation.",queryType:"EQL",severity:"High",tool:"elastic",difficulty:"Advanced",query:"process where event.type == 'start'\n  and process.parent.name == 'eventvwr.exe'\n  and not process.executable regex~ 'C:\\\\Windows\\\\(System32|SysWOW64)\\\\.*\\.exe'",walkthrough:{story:"UAC bypass allows execution with elevated privileges without the UAC prompt. Event Viewer, fodhelper, and cmstp are commonly abused.",tune:"Monitor the specific parent processes known for UAC bypass: eventvwr.exe, fodhelper.exe, cmstp.exe, sdclt.exe.",fp:"This is very low false-positive — legitimate processes spawned by eventvwr.exe outside System32 are extremely rare.",related:["uc024","uc026"]}},
  {id:"uc026",tactic:"Privilege Escalation",technique:"T1068",name:"Exploit Kernel Vulnerability",description:"Detect exploitation of kernel vulnerabilities for privilege escalation.",queryType:"LogScale",severity:"Critical",tool:"logscale",difficulty:"Advanced",query:"#type=windowsevent EventID=4688\n| ImagePath=/cmd.exe|powershell.exe/i\n| ParentImagePath=/explorer.exe/i\n| IntegrityLevel=System\n| groupBy([ComputerName, UserName, ImagePath, CommandLine])",walkthrough:{story:"Kernel exploits like PrintNightmare, EternalBlue, and HiveNightmare allow attackers to go from low-privileged user to SYSTEM.",tune:"Alert on ANY process running as SYSTEM that was spawned from a user-interactive process. This is almost always malicious.",fp:"Extremely rare false positives. Some Windows Update processes run as SYSTEM spawned from user sessions.",related:["uc024","uc025"]}},
  {id:"uc027",tactic:"Privilege Escalation",technique:"T1078.002",name:"Domain Account Abuse",description:"Detect domain admin accounts used interactively on workstations.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Intermediate",query:"SecurityEvent\n| where EventID == 4624 and LogonType == 2\n| where TargetUserName has_any (domain_admin_list)\n| where Computer !in (domain_controllers)\n| project TimeGenerated, TargetUserName, Computer, IpAddress",walkthrough:{story:"Domain admin accounts should only be used on domain controllers. Interactive use on workstations exposes credentials to theft via LSASS dumping.",tune:"Maintain a list of domain admin accounts. Alert on any interactive (Type 2) logon on non-DC systems.",fp:"Helpdesk using DA accounts for workstation administration. Enforce the tiered administration model to prevent this.",related:["uc026","uc028"]}},

  // ── DEFENSE EVASION ─────────────────────────────────────────────────────────
  {id:"uc028",tactic:"Defense Evasion",technique:"T1070.001",name:"Event Log Clearing",description:"Detect clearing of Windows Security or System event logs.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Beginner",query:"index=wineventlog EventCode IN (1102, 104)\n| table _time, host, user, Message\n| eval alert='CRITICAL: Log cleared by '+user",walkthrough:{story:"Log clearing is a classic anti-forensics technique. Attackers clear logs to remove evidence of their activities before or after an attack.",tune:"This is near-zero false-positive. Any log clearing outside of an approved maintenance window should be treated as a critical incident.",fp:"Automated log management scripts. Ensure all log clearing goes through change management and is done via approved tools only.",related:["uc029","uc030"]}},
  {id:"uc029",tactic:"Defense Evasion",technique:"T1562.001",name:"Security Tool Disabled",description:"Detect attempts to disable AV, EDR, or firewall.",queryType:"KQL",severity:"Critical",tool:"sentinel",difficulty:"Beginner",query:"SecurityEvent\n| where EventID == 7045\n| where ServiceName has_any ('WindowsDefender','MsMpEng','Sense','CrowdStrike','Carbon')\n| project TimeGenerated, SubjectUserName, ServiceName",walkthrough:{story:"Disabling security tools is typically done immediately after initial access to prepare for the main attack phase. This is a critical alert requiring immediate response.",tune:"Add all your security tool service names. Also monitor registry modifications to Windows Defender exclusion keys.",fp:"Security team during authorized testing. Ensure all security tool changes are tracked in your change management system.",related:["uc028","uc030"]}},
  {id:"uc030",tactic:"Defense Evasion",technique:"T1027",name:"Obfuscated Scripts",description:"Detect execution of heavily obfuscated scripts.",queryType:"SPL",severity:"Medium",tool:"splunk",difficulty:"Intermediate",query:"index=sysmon EventCode=1\n| where match(CommandLine, '(?i)(frombase64|iex |invoke-expression|char\\(|\\[convert\\]|\\[string\\])')\n| stats count by ParentImage, Image, CommandLine\n| where count < 3",walkthrough:{story:"Script obfuscation hides malicious intent from signature-based detection. Multiple layers of encoding and string manipulation are used.",tune:"Enable PowerShell Script Block Logging (4104) for the actual decoded content. Combine with AMSI telemetry.",fp:"Some legitimate PowerShell management scripts use encoding. Focus on commands that also contact external URLs or modify the registry.",related:["uc028","uc031"]}},
  {id:"uc031",tactic:"Defense Evasion",technique:"T1036",name:"Masquerading",description:"Detect processes masquerading as legitimate Windows binaries.",queryType:"EQL",severity:"High",tool:"elastic",difficulty:"Intermediate",query:"process where process.name in ('svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe')\n  and not process.executable regex~ 'C:\\\\Windows\\\\(System32|SysWOW64)\\\\.*'",walkthrough:{story:"Attackers name their malware after legitimate system processes to avoid suspicion. A 'svchost.exe' running from AppData is malicious.",tune:"Build a whitelist of expected paths for each system process. Any deviation is suspicious.",fp:"Near-zero false positives. These processes should ONLY run from System32 or SysWOW64.",related:["uc030","uc032"]}},
  {id:"uc032",tactic:"Defense Evasion",technique:"T1218",name:"Signed Binary Proxy Execution",description:"Detect abuse of signed Windows binaries (LOLBins) for execution.",queryType:"CQL",severity:"High",tool:"crowdstrike",difficulty:"Intermediate",query:"#event_simpleName=ProcessRollup2\n| ImageFileName=/regsvr32.exe|rundll32.exe|mshta.exe|certutil.exe|msiexec.exe/i\n| CommandLine=/http:|scrobj|javascript|\\\\[0-9]/i\n| groupby([ComputerName, UserName, CommandLine])",walkthrough:{story:"LOLBins are trusted, signed Windows binaries abused to execute malicious code. They bypass application whitelisting and are trusted by security tools.",tune:"Each LOLBin has specific abuse patterns. RegSvr32 with HTTP, CertUtil with -decode, MSHTA with script URLs are key patterns.",fp:"Some legitimate software uses these patterns. Baseline your environment and focus on new or unusual invocations.",related:["uc031","uc033"]}},
  {id:"uc033",tactic:"Defense Evasion",technique:"T1055.012",name:"Process Hollowing",description:"Detect process hollowing used to hide malicious code in legitimate processes.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Advanced",query:"index=sysmon EventCode=1\n| where ParentImage matches '(?i)(explorer\\.exe|winword\\.exe|excel\\.exe)'\n| where Image matches '(?i)(svchost|lsass|cmd|powershell)\\.exe'\n| where NOT match(Image, 'C:\\\\Windows\\\\System32')",walkthrough:{story:"Process hollowing creates a suspended legitimate process, replaces its memory with malicious code, then resumes execution. The malicious code runs under a trusted process name.",tune:"Requires Sysmon. Focus on suspicious parent-child process relationships especially Office apps spawning system processes.",fp:"Some macro-heavy Office documents legitimately spawn cmd.exe for automation. Context and command line analysis is key.",related:["uc032","uc034"]}},

  // ── CREDENTIAL ACCESS ───────────────────────────────────────────────────────
  {id:"uc034",tactic:"Credential Access",technique:"T1003.001",name:"LSASS Memory Dump",description:"Detect credential dumping from LSASS memory.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Intermediate",query:"index=sysmon EventCode=10 TargetImage='*lsass.exe'\n| where GrantedAccess IN ('0x1010','0x1410','0x1fffff','0x147a','0x1038','0x40')\n| table _time, SourceImage, GrantedAccess, CallTrace",walkthrough:{story:"LSASS stores credentials in memory. Mimikatz and similar tools open LSASS with specific access rights to extract password hashes and Kerberos tickets.",tune:"Requires Sysmon with LSASS access monitoring. The GrantedAccess values are specific to credential dumping tools.",fp:"Security tools and Windows processes legitimately access LSASS. Whitelist your AV/EDR processes and known Windows system processes.",related:["uc035","uc036"]}},
  {id:"uc035",tactic:"Credential Access",technique:"T1110.001",name:"Password Brute Force",description:"Detect brute force authentication attacks with high failure rates.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Beginner",query:"SecurityEvent\n| where EventID == 4625\n| summarize FailCount=count() by IpAddress, Account, bin(TimeGenerated, 10m)\n| where FailCount > 20 | order by FailCount desc",walkthrough:{story:"Brute force attacks try many passwords against one account. Password spraying tries one password against many accounts to avoid lockout.",tune:"Also implement a low-and-slow spray detection: 1 failed login against 50+ accounts from the same IP within an hour.",fp:"Users forgetting passwords will generate some failures. Focus on external IPs and accounts that don't exist in your directory.",related:["uc034","uc036"]}},
  {id:"uc036",tactic:"Credential Access",technique:"T1558.003",name:"Kerberoasting",description:"Detect TGS ticket requests for offline cracking of service account passwords.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Advanced",query:"index=wineventlog EventCode=4769\n| where TicketEncryptionType='0x17' AND ServiceName != 'krbtgt'\n| stats count by src_ip, ServiceName, Account\n| where count > 3",walkthrough:{story:"Kerberoasting requests service tickets encrypted with the service account's password hash, then cracks them offline. RC4 encryption (0x17) is the target.",tune:"RC4 Kerberos encryption should be disabled in modern environments. Any RC4 TGS request is suspicious.",fp:"Legacy applications require RC4 Kerberos. If you have them, whitelist their specific service names.",related:["uc034","uc035"]}},
  {id:"uc037",tactic:"Credential Access",technique:"T1552.001",name:"Credentials in Files",description:"Detect processes searching for credential files and password-containing configs.",queryType:"EQL",severity:"High",tool:"elastic",difficulty:"Intermediate",query:"process where process.name in ('findstr.exe','grep','type','cat')\n  and process.command_line regex~ '.*(password|passwd|credentials|secret|apikey|connection_string).*'\n  and not user.name in ('SYSTEM')",walkthrough:{story:"Attackers search file systems for credentials stored in config files, scripts, and documentation. Finding one password often leads to more through credential reuse.",tune:"Also monitor access to known sensitive files: web.config, .env, connection strings, password managers.",fp:"Developers and admins legitimately search for configuration parameters. Context is key — focus on users without a development role.",related:["uc036","uc038"]}},
  {id:"uc038",tactic:"Credential Access",technique:"T1187",name:"Forced Authentication",description:"Detect forced NTLM authentication used to capture credential hashes.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Advanced",query:"SecurityEvent\n| where EventID == 4648\n| where TargetServerName !has 'localhost' and TargetServerName !has '127.0.0.1'\n| summarize count() by SubjectUserName, TargetServerName, IpAddress\n| where count_ > 5",walkthrough:{story:"Responder and similar tools capture NTLM hashes by forcing authentication to attacker-controlled servers. Hashes are then cracked or relayed.",tune:"Enable NTLM auditing. Combine with network detection for outbound SMB to unusual external IPs.",fp:"Some applications use NTLM for authentication. Focus on authentication attempts to non-standard servers or external IPs.",related:["uc037","uc039"]}},
  {id:"uc039",tactic:"Credential Access",technique:"T1606.002",name:"Golden SAML",description:"Detect forged SAML assertions used to access cloud resources.",queryType:"KQL",severity:"Critical",tool:"sentinel",difficulty:"Advanced",query:"SigninLogs\n| where AuthenticationDetails has 'SAMLToken'\n| where IPAddress !in (known_idp_ips)\n| where ResultType == 0\n| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, AuthenticationDetails",walkthrough:{story:"Golden SAML forges SAML assertions using the stolen ADFS signing certificate. Attackers can authenticate as any user to any cloud service without knowing passwords.",tune:"Monitor for ADFS certificate exports. Combine with Azure AD sign-in logs showing unusual SAML authentications.",fp:"Legitimate SAML authentications from your IdP IPs. Whitelist your ADFS and Azure AD Connect servers.",related:["uc038","uc040"]}},

  // ── DISCOVERY ───────────────────────────────────────────────────────────────
  {id:"uc040",tactic:"Discovery",technique:"T1046",name:"Network Port Scan",description:"Detect internal network scanning indicating lateral movement preparation.",queryType:"SPL",severity:"Medium",tool:"splunk",difficulty:"Beginner",query:"index=network sourcetype=firewall\n| bucket _time span=1m\n| stats dc(dest_port) as port_count, dc(dest_ip) as host_count by src_ip, _time\n| where port_count > 20 OR host_count > 15",walkthrough:{story:"Internal port scans indicate an attacker is mapping your network after initial compromise to find targets for lateral movement.",tune:"Adjust thresholds based on your network baseline. Segment your network — scans crossing segments are particularly suspicious.",fp:"Legitimate vulnerability scanners and network monitoring tools. Whitelist scanner IPs or create a separate rule with lower severity.",related:["uc041","uc042"]}},
  {id:"uc041",tactic:"Discovery",technique:"T1082",name:"System Information Discovery",description:"Detect bulk system information enumeration.",queryType:"CQL",severity:"Low",tool:"crowdstrike",difficulty:"Beginner",query:"#event_simpleName=ProcessRollup2\n| ImageFileName=/systeminfo.exe|ipconfig.exe|hostname.exe|whoami.exe|nltest.exe/i\n| !ParentImageFileName=/cmd.exe|powershell.exe/i\n| groupby([ComputerName, UserName, ImageFileName])",walkthrough:{story:"Post-compromise reconnaissance includes gathering system info to understand the environment, domain structure, and available privileges.",tune:"Focus on these commands running in sequence within a short timeframe — that indicates automated post-exploitation.",fp:"IT staff and monitoring agents run these commands regularly. Focus on unusual users or times of day.",related:["uc040","uc042"]}},
  {id:"uc042",tactic:"Discovery",technique:"T1018",name:"Remote System Discovery",description:"Detect network enumeration commands used to discover remote systems.",queryType:"SPL",severity:"Medium",tool:"splunk",difficulty:"Beginner",query:"index=wineventlog EventCode=4688\n| where match(process_command_line, '(?i)(net view|nmap|arp -a|ping -n|nslookup|nbtscan)')\n| stats count by user, host, process_command_line\n| where count < 5",walkthrough:{story:"Attackers enumerate domain computers, file shares, and network resources to identify high-value targets for lateral movement.",tune:"Combine multiple discovery commands into a single rule — an attacker running 5+ discovery commands within 10 minutes is a strong signal.",fp:"IT admins performing network documentation or troubleshooting. Correlate with helpdesk tickets.",related:["uc040","uc041"]}},
  {id:"uc043",tactic:"Discovery",technique:"T1069",name:"Permission Group Discovery",description:"Detect enumeration of privileged groups to identify targets for escalation.",queryType:"KQL",severity:"Low",tool:"sentinel",difficulty:"Intermediate",query:"SecurityEvent\n| where EventID in (4798, 4799)\n| summarize count() by SubjectUserName, Computer, bin(TimeGenerated, 5m)\n| where count_ > 10",walkthrough:{story:"Attackers enumerate group memberships to find accounts with elevated privileges that can be targeted for credential theft or impersonation.",tune:"Combine with domain LDAP query monitoring. Bulk LDAP queries for group memberships are a strong indicator.",fp:"Directory synchronization tools and HR systems enumerate groups regularly. Whitelist known sync service accounts.",related:["uc042","uc044"]}},
  {id:"uc044",tactic:"Discovery",technique:"T1087.002",name:"Domain Account Discovery",description:"Detect bulk enumeration of domain user accounts.",queryType:"SPL",severity:"Medium",tool:"splunk",difficulty:"Intermediate",query:"index=wineventlog EventCode=4661\n| where ObjectType='SAM_USER' OR ObjectType='SAM_GROUP'\n| stats dc(ObjectName) as enum_count by SubjectUserName, src_ip\n| where enum_count > 50",walkthrough:{story:"Domain account enumeration identifies targets for spearphishing, password spraying, and privilege escalation. LDAP and SAM enumeration are primary methods.",tune:"Enable SAM object access auditing. Combine with LDAP query logging on domain controllers.",fp:"Active Directory management tools enumerate users by design. Whitelist management tool service accounts.",related:["uc043","uc045"]}},
  {id:"uc045",tactic:"Discovery",technique:"T1135",name:"Network Share Discovery",description:"Detect enumeration of network shares for data staging and lateral movement.",queryType:"KQL",severity:"Medium",tool:"sentinel",difficulty:"Beginner",query:"SecurityEvent\n| where EventID == 5140\n| where ShareName !in ('\\\\*\\IPC$','\\\\*\\NETLOGON','\\\\*\\SYSVOL')\n| summarize ShareCount=dcount(ShareName) by SubjectUserName, IpAddress, bin(TimeGenerated, 10m)\n| where ShareCount > 10",walkthrough:{story:"Network share enumeration identifies data repositories for theft and paths for lateral movement using tools like net view and SMB scanning.",tune:"Alert on access to multiple shares in a short period, especially ADMIN$ and C$ from non-admin workstations.",fp:"Backup agents and DLP tools access many shares. Whitelist known backup service accounts.",related:["uc044","uc046"]}},

  // ── LATERAL MOVEMENT ────────────────────────────────────────────────────────
  {id:"uc046",tactic:"Lateral Movement",technique:"T1021.001",name:"RDP Lateral Movement",description:"Detect suspicious RDP connections between internal hosts.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Beginner",query:"SecurityEvent\n| where EventID == 4624 and LogonType == 10\n| where IpAddress !in ('127.0.0.1','::1')\n| summarize RDPCount=count() by IpAddress, Account, Computer\n| where RDPCount > 3",walkthrough:{story:"RDP is the most common lateral movement method. Attackers hop from system to system using stolen credentials.",tune:"Implement RDP jumpbox architecture. Alert on RDP connections from workstations to other workstations — this should never happen in a well-configured environment.",fp:"Helpdesk RDP to workstations is normal. Focus on workstation-to-workstation RDP and unusual time-of-day patterns.",related:["uc047","uc048"]}},
  {id:"uc047",tactic:"Lateral Movement",technique:"T1550.002",name:"Pass-the-Hash",description:"Detect NTLM authentication from unexpected workstations.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Advanced",query:"index=wineventlog EventCode=4624 LogonType=3\n| where AuthenticationPackageName='NTLM' AND WorkstationName != ComputerName\n| stats count by SubjectUserName, IpAddress, WorkstationName",walkthrough:{story:"Pass-the-Hash uses captured NTLM hashes to authenticate without knowing the plaintext password. It's undetectable by most antivirus tools.",tune:"Implement Restricted Admin mode and Credential Guard to prevent PtH. This detection is your backstop when defenses fail.",fp:"Some legacy applications and services use NTLM. Focus on high-privilege accounts and admin accounts using NTLM.",related:["uc046","uc048"]}},
  {id:"uc048",tactic:"Lateral Movement",technique:"T1021.002",name:"SMB Lateral Movement",description:"Detect SMB-based lateral movement including PsExec and admin share access.",queryType:"LogScale",severity:"High",tool:"logscale",difficulty:"Intermediate",query:"#type=windowsevent EventID=5140\n| ShareName=ADMIN$ OR ShareName=C$\n| !IpAddress=127.0.0.1\n| groupBy([ComputerName, SubjectUserName, IpAddress, ShareName])\n| sort(count, order=desc)",walkthrough:{story:"Admin shares (ADMIN$, C$) are used by PsExec, wmiexec, and similar tools for lateral movement. They should only be accessed by authorized admins from known IPs.",tune:"Implement firewall rules restricting SMB to management systems only. Alert on any admin share access from workstations.",fp:"Windows Update, SCCM, and file servers legitimately access admin shares. Maintain a whitelist of authorized management IPs.",related:["uc046","uc047"]}},
  {id:"uc049",tactic:"Lateral Movement",technique:"T1563.002",name:"RDP Session Hijacking",description:"Detect RDP session hijacking used to take over existing user sessions.",queryType:"EQL",severity:"Critical",tool:"elastic",difficulty:"Advanced",query:"process where process.name == 'tscon.exe'\n  and process.command_line regex~ '.*/dest.*RDP-Tcp.*'\n  and user.name != 'SYSTEM'",walkthrough:{story:"tscon.exe can hijack any active RDP session without knowing credentials. SYSTEM privilege is required, making this a post-escalation technique.",tune:"tscon.exe should only run as SYSTEM for legitimate session management. Any user-initiated tscon.exe with RDP parameters is malicious.",fp:"Near-zero false positives. This is a very specific technique with almost no legitimate use.",related:["uc046","uc050"]}},
  {id:"uc050",tactic:"Lateral Movement",technique:"T1534",name:"Internal Spearphishing",description:"Detect internal phishing campaigns from compromised accounts.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Intermediate",query:"EmailEvents\n| where SenderFromDomain == tostring(split(RecipientEmailAddress,'@')[1])\n| where Subject has_any ('password','urgent','invoice','wire transfer','verify')\n| where DeliveryAction == 'Delivered'\n| summarize count() by SenderFromAddress, Subject",walkthrough:{story:"Compromised internal accounts send phishing emails to colleagues. These are highly effective as users trust internal senders.",tune:"Monitor for internal accounts sending emails with phishing keywords, especially to finance and executive users.",fp:"Legitimate internal security awareness training. Coordinate with your phishing simulation vendor to exclude test campaigns.",related:["uc049","uc051"]}},

  // ── COLLECTION ──────────────────────────────────────────────────────────────
  {id:"uc051",tactic:"Collection",technique:"T1056.001",name:"Keylogging",description:"Detect keylogger installation and execution.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Advanced",query:"index=sysmon EventCode=7\n| where match(ImageLoaded, '(?i)(pynput|keyboard|keyhook|getasynckeystate|setwindowshookex)')\n| stats count by Image, ImageLoaded, ComputerName",walkthrough:{story:"Keyloggers capture credentials and sensitive data entered by users. They're often embedded in RATs and post-exploitation frameworks.",tune:"Requires Sysmon with image load events. Also monitor for unusual DLLs being loaded by browser and Office processes.",fp:"Accessibility software and some legitimate applications use keyboard hooks. Baseline known-good keyboard hook users.",related:["uc052","uc053"]}},
  {id:"uc052",tactic:"Collection",technique:"T1560.001",name:"Archive Collected Data",description:"Detect use of archiving tools to stage data for exfiltration.",queryType:"CQL",severity:"Medium",tool:"crowdstrike",difficulty:"Beginner",query:"#event_simpleName=ProcessRollup2\n| ImageFileName=/7z.exe|winrar.exe|zip.exe|rar.exe/i\n| CommandLine=/-p|-password/i\n| groupby([ComputerName, UserName, CommandLine])",walkthrough:{story:"Attackers compress and encrypt data before exfiltration to reduce transfer size and bypass DLP. Password-protected archives are a strong signal.",tune:"Alert on archiving with passwords from unusual locations. Also monitor for large archives created in user temp directories.",fp:"Legitimate use of password-protected archives for secure file transfer. Focus on unusual file paths and large archive sizes.",related:["uc051","uc053"]}},
  {id:"uc053",tactic:"Collection",technique:"T1005",name:"Data from Local System",description:"Detect mass file access suggesting data staging before exfiltration.",queryType:"KQL",severity:"Medium",tool:"sentinel",difficulty:"Intermediate",query:"DeviceFileEvents\n| where FolderPath has_any ('\\Temp\\','\\AppData\\Local\\Temp\\')\n| where FileName endswith_any ('.zip','.rar','.7z','.tar','.gz')\n| summarize FileCount=count() by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 10m)\n| where FileCount > 20",walkthrough:{story:"Before exfiltration, attackers stage collected data in temp directories. Large numbers of files appearing in temp folders is a key signal.",tune:"Combine with file size monitoring. A few large files in temp are more suspicious than many small ones.",fp:"Software installers create temp files. Focus on archives specifically and correlate with subsequent network connections.",related:["uc052","uc054"]}},
  {id:"uc054",tactic:"Collection",technique:"T1114.001",name:"Local Email Collection",description:"Detect access to email archives and PST files for data theft.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Intermediate",query:"index=sysmon EventCode=11\n| where match(TargetFilename, '(?i)(\.pst|\.ost|\.mbox)')\n| where NOT match(Image, '(?i)(outlook|thunderbird|exchange)')\n| stats count by Image, TargetFilename, ComputerName",walkthrough:{story:"Email archives contain valuable business intelligence, credentials, and communication data. Non-email processes accessing PST files is suspicious.",tune:"Requires Sysmon file creation events. Monitor for PST files being copied to unusual locations or accessed by unknown processes.",fp:"Backup software accesses PST files. Whitelist your backup agent processes.",related:["uc053","uc055"]}},

  // ── COMMAND AND CONTROL ─────────────────────────────────────────────────────
  {id:"uc055",tactic:"Command and Control",technique:"T1071.001",name:"HTTP C2 Beaconing",description:"Detect regular interval HTTP beaconing to C2 infrastructure.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Advanced",query:"index=proxy\n| bucket _time span=1h\n| stats count, stdev(bytes) as stdev_b by src_ip, dest_host, _time\n| eval beacon=if(stdev_b < 200 AND count > 10, 'HIGH', 'LOW')\n| where beacon='HIGH'",walkthrough:{story:"C2 frameworks like Cobalt Strike, Metasploit, and custom implants beacon at regular intervals. Low variance in packet size and timing is the key indicator.",tune:"Reduce the stdev threshold for high-confidence alerts. Also check for domain fronting (Host header != SNI) as a beaconing indicator.",fp:"Legitimate monitoring agents and update checkers beacon regularly. Build a baseline of known-good beaconing applications.",related:["uc056","uc057"]}},
  {id:"uc056",tactic:"Command and Control",technique:"T1572",name:"DNS Tunneling",description:"Detect DNS tunneling for covert C2 communication.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Advanced",query:"DnsEvents\n| where QueryType == 'TXT' or strlen(Name) > 50\n| summarize QueryCount=count(), AvgLen=avg(strlen(Name)) by ClientIP, bin(TimeGenerated, 1h)\n| where QueryCount > 100 or AvgLen > 40",walkthrough:{story:"DNS tunneling encodes data in DNS queries to bypass firewall controls. Unusually long subdomains and high TXT query rates are key indicators.",tune:"Implement DNS security solutions (DNSBL, Cisco Umbrella). DNS queries over 63 characters per label are inherently suspicious.",fp:"Some CDNs and certificate validation use long DNS names. Focus on the combination of high volume AND long names.",related:["uc055","uc057"]}},
  {id:"uc057",tactic:"Command and Control",technique:"T1095",name:"Non-Standard Port C2",description:"Detect C2 communication over non-standard ports.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Intermediate",query:"index=network sourcetype=firewall action=allow\n| where NOT dest_port IN (80,443,22,25,53,8080,8443,3389,445)\n| where NOT match(dest_ip, '^(10\\.|172\\.1[6-9]\\.|192\\.168\\.)')\n| stats count dc(dest_port) as ports by src_ip, dest_ip\n| where ports > 3",walkthrough:{story:"Attackers use unusual ports to avoid network detection. Cobalt Strike commonly uses non-standard ports for its HTTPS listener.",tune:"Implement egress filtering to block non-standard outbound ports. This detection catches what slips through.",fp:"Legitimate applications using non-standard ports. Inventory all applications requiring non-standard port access and whitelist them.",related:["uc055","uc058"]}},
  {id:"uc058",tactic:"Command and Control",technique:"T1219",name:"Remote Access Tool",description:"Detect installation of unauthorized remote access tools.",queryType:"EQL",severity:"Medium",tool:"elastic",difficulty:"Beginner",query:"process where process.name in ('teamviewer.exe','anydesk.exe','ngrok.exe','screenconnect.exe','ultraviewer.exe')\n  and not process.code_signature.trusted == true\n  and not process.code_signature.subject_name regex~ 'TeamViewer|AnyDesk'",walkthrough:{story:"Attackers install remote access tools as persistent backdoors. Unsigned or unrecognized RATs are a clear indicator of compromise.",tune:"Maintain an approved RAT list and alert on any not in the list. Also monitor for ngrok and similar tunneling tools which are almost never legitimate.",fp:"IT help desk uses approved RATs. Maintain a strict approved-tools policy and alert on everything else.",related:["uc057","uc059"]}},
  {id:"uc059",tactic:"Command and Control",technique:"T1102",name:"Web Service C2",description:"Detect C2 communication hiding behind legitimate web services.",queryType:"KQL",severity:"Medium",tool:"sentinel",difficulty:"Advanced",query:"DeviceNetworkEvents\n| where RemoteUrl has_any ('pastebin.com','github.com/raw','githubusercontent.com','gist.github.com','hastebin.com')\n| where InitiatingProcessFileName !in ('code.exe','git.exe','browser.exe')\n| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName",walkthrough:{story:"Attackers abuse legitimate services like Pastebin, GitHub, and Slack for C2 to blend in with normal traffic and avoid domain-based detection.",tune:"Focus on non-browser processes accessing these services. A PowerShell script downloading from raw.githubusercontent.com is suspicious.",fp:"Developer tools and update mechanisms use GitHub APIs. Whitelist known developer tools accessing GitHub.",related:["uc058","uc060"]}},

  // ── EXFILTRATION ────────────────────────────────────────────────────────────
  {id:"uc060",tactic:"Exfiltration",technique:"T1041",name:"Large Data Exfiltration",description:"Detect large outbound transfers to external destinations.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Beginner",query:"index=network sourcetype=firewall action=allow\n| where NOT match(dest_ip, '^(10\\.|172\\.1[6-9]\\.|192\\.168\\.)')\n| stats sum(bytes_out) as total_bytes by src_ip, dest_ip\n| where total_bytes > 100000000\n| eval MB=round(total_bytes/1024/1024,2) | sort -MB",walkthrough:{story:"Large data exfiltration transfers gigabytes of data to attacker-controlled servers. This is the final stage of a data theft attack.",tune:"Adjust the threshold based on normal large transfers in your environment. 100MB is a starting point — tune up or down.",fp:"Software updates, cloud backups, and video uploads generate large transfers. Whitelist known update servers and cloud backup destinations.",related:["uc061","uc062"]}},
  {id:"uc061",tactic:"Exfiltration",technique:"T1048",name:"Exfiltration Over Alternative Protocol",description:"Detect data exfiltration over DNS, ICMP, or other covert channels.",queryType:"LogScale",severity:"High",tool:"logscale",difficulty:"Advanced",query:"#type=dns\n| QueryName=/.{50,}/\n| type=TXT\n| groupBy([ClientIP, QueryName])\n| count > 50\n| sort(count, order=desc)",walkthrough:{story:"DNS exfiltration encodes data in DNS queries to bypass DLP and firewall controls. Each DNS query can carry up to 253 bytes.",tune:"Implement DNS monitoring and block TXT queries to non-authoritative external DNS servers. Establish DNS query rate baselines.",fp:"Some cloud services use long DNS names for routing. Focus on high-volume long-subdomain TXT queries to unknown domains.",related:["uc060","uc062"]}},
  {id:"uc062",tactic:"Exfiltration",technique:"T1567",name:"Exfiltration to Cloud Storage",description:"Detect data uploads to cloud storage services.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Beginner",query:"DeviceNetworkEvents\n| where RemoteUrl has_any ('dropbox.com','drive.google.com','onedrive.live.com','wetransfer.com','mega.nz','box.com')\n| where SentBytes > 10000000\n| summarize TotalSent=sum(SentBytes) by DeviceName, InitiatingProcessAccountName, RemoteUrl",walkthrough:{story:"Cloud storage services are increasingly used for exfiltration as they blend with normal traffic and are hard to block without impacting productivity.",tune:"Implement CASB controls to monitor and limit uploads to unsanctioned cloud storage. Alert on unusually large uploads.",fp:"Legitimate business use of cloud storage. Implement a policy defining approved cloud storage and alert on unapproved services.",related:["uc060","uc061"]}},
  {id:"uc063",tactic:"Exfiltration",technique:"T1020",name:"Automated Exfiltration",description:"Detect automated bulk exfiltration scripts running at regular intervals.",queryType:"SPL",severity:"High",tool:"splunk",difficulty:"Advanced",query:"index=network sourcetype=firewall\n| bucket _time span=15m\n| stats sum(bytes_out) as bytes by src_ip, dest_ip, _time\n| eventstats stdev(bytes) as stdev by src_ip, dest_ip\n| where stdev < 1000 AND bytes > 1000000\n| eval beacon_score=round(1/(stdev+1)*bytes/1000000,2)",walkthrough:{story:"Automated exfiltration runs scripts that transfer data at regular intervals to evade volume-based detection. Low variance in transfer size is the key signal.",tune:"This requires a statistical baseline of your normal outbound traffic patterns. Run for 2 weeks before enabling alerts.",fp:"Scheduled backups and sync jobs have low variance by design. Whitelist known backup and sync destinations.",related:["uc060","uc062"]}},

  // ── IMPACT ──────────────────────────────────────────────────────────────────
  {id:"uc064",tactic:"Impact",technique:"T1486",name:"Ransomware Encryption",description:"Detect ransomware mass encryption via shadow copy deletion.",queryType:"SPL",severity:"Critical",tool:"splunk",difficulty:"Beginner",query:"index=wineventlog (EventCode=4688 OR EventCode=1)\n| where match(process_command_line, '(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled no|wbadmin.*delete)')\n| table _time, host, user, process_command_line",walkthrough:{story:"Ransomware deletes shadow copies before encrypting to prevent easy recovery. This detection catches the critical pre-encryption step.",tune:"This is near-zero false-positive. Immediately isolate any host triggering this detection. Have your IR plan ready.",fp:"Disk management utilities. Extremely rare in normal operations — any match should be treated as a critical incident.",related:["uc065","uc066"]}},
  {id:"uc065",tactic:"Impact",technique:"T1490",name:"Shadow Copy Deletion",description:"Detect deletion of Windows Volume Shadow Copies.",queryType:"CQL",severity:"Critical",tool:"crowdstrike",difficulty:"Beginner",query:"#event_simpleName=ProcessRollup2\n| ImageFileName=/vssadmin.exe|wbadmin.exe|wmic.exe/i\n| CommandLine=/delete/i\n| groupby([ComputerName, UserName, CommandLine])",walkthrough:{story:"Shadow Copy deletion is the most reliable ransomware pre-cursor indicator. Almost no legitimate software deletes ALL shadow copies.",tune:"Alert on deletion of ALL shadow copies. Deletion of a specific copy may be legitimate backup management.",fp:"Some backup solutions delete old shadow copies as part of rotation. Verify with your backup team before tuning this out.",related:["uc064","uc066"]}},
  {id:"uc066",tactic:"Impact",technique:"T1485",name:"Data Destruction",description:"Detect mass file deletion or secure wiping tools.",queryType:"EQL",severity:"Critical",tool:"elastic",difficulty:"Intermediate",query:"process where process.name in ('sdelete.exe','eraser.exe','cipher.exe','format.exe','del.exe')\n  and process.command_line regex~ '.*/p|/w|/s|/q.*'\n  and not user.name == 'SYSTEM'",walkthrough:{story:"Data destruction attacks permanently delete data to cause maximum damage. Wiping tools and format commands are the primary indicators.",tune:"Combine with file system monitoring to detect mass deletions. Alert on deletion of more than 1000 files within 5 minutes.",fp:"Secure disposal of decommissioned systems. Ensure data destruction is done only through approved change management processes.",related:["uc064","uc067"]}},
  {id:"uc067",tactic:"Impact",technique:"T1499",name:"Endpoint Denial of Service",description:"Detect resource exhaustion attacks targeting endpoint availability.",queryType:"KQL",severity:"High",tool:"sentinel",difficulty:"Intermediate",query:"Perf\n| where CounterName in ('% Processor Time','Available MBytes','Disk Write Bytes/sec')\n| where (CounterName == '% Processor Time' and CounterValue > 95)\n    or (CounterName == 'Available MBytes' and CounterValue < 100)\n| summarize avg(CounterValue) by Computer, CounterName, bin(TimeGenerated, 5m)",walkthrough:{story:"Resource exhaustion attacks consume CPU, memory, or disk to make systems unavailable. Crypto miners and fork bombs are common examples.",tune:"Set thresholds based on your normal baseline. Critical servers may legitimately use 95% CPU during batch jobs.",fp:"Legitimate high-load operations like batch processing, backups, and database operations. Correlate with scheduled job logs.",related:["uc064","uc066"]}},
  {id:"uc068",tactic:"Impact",technique:"T1496",name:"Resource Hijacking",description:"Detect unauthorized cryptocurrency mining using system resources.",queryType:"SPL",severity:"Medium",tool:"splunk",difficulty:"Beginner",query:"index=sysmon EventCode=1\n| where match(CommandLine, '(?i)(xmrig|minerd|cpuminer|stratum\\+tcp|pool\\.minexmr|cryptonight)')\n| table _time, host, user, Image, CommandLine",walkthrough:{story:"Crypto miners are installed to monetize compromised systems. They consume CPU/GPU resources and often communicate with mining pools.",tune:"Also monitor for high sustained CPU usage by unknown processes. Block known mining pool domains at the proxy/DNS level.",fp:"Near-zero false positives. Crypto mining on corporate systems is almost never legitimate.",related:["uc067","uc069"]}},
  {id:"uc069",tactic:"Impact",technique:"T1531",name:"Account Access Removal",description:"Detect mass account lockouts or deletion suggesting destructive attack.",queryType:"KQL",severity:"Critical",tool:"sentinel",difficulty:"Intermediate",query:"SecurityEvent\n| where EventID in (4725, 4726, 4740)\n| summarize ActionCount=count(), AffectedUsers=dcount(TargetUserName) by SubjectUserName, bin(TimeGenerated, 5m)\n| where AffectedUsers > 10",walkthrough:{story:"Destructive attackers lock out or delete accounts to maximize damage and prevent recovery. This is often the final stage of a destructive attack.",tune:"Alert immediately on bulk account changes. Any single account modifying more than 10 user accounts in 5 minutes is highly anomalous.",fp:"User provisioning scripts run by IT. Ensure all bulk user operations are done by known service accounts from known IPs.",related:["uc064","uc068"]}},
];

function ToolSelector({selected, onSelect}){
  return(
    <div style={{marginBottom:18}}>
      <label style={S.label}>Target SIEM / Security Tool</label>
      <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
        {TOOLS.map(t=>(
          <div key={t.id} onClick={()=>onSelect(t)}
            style={{padding:"8px 14px",borderRadius:8,border:"1px solid "+(selected?.id===t.id?t.color+"88":THEME.border),background:selected?.id===t.id?t.color+"12":"rgba(255,255,255,0.02)",cursor:"pointer",transition:"all 0.15s"}}>
            <div style={{fontSize:12,fontWeight:700,color:selected?.id===t.id?t.color:THEME.textMid}}>{t.name}</div>
            <div style={{fontSize:10,color:THEME.textDim,marginTop:1}}>{t.lang}</div>
          </div>
        ))}
      </div>
      {selected&&<div style={{marginTop:10,padding:"10px 14px",background:"#02040a",borderRadius:8,border:"1px solid "+selected.color+"33"}}>
        <span style={{fontSize:11,color:selected.color,fontWeight:700}}>{selected.name} ({selected.lang})</span>
        <span style={{fontSize:11,color:THEME.textDim,marginLeft:10}}>{selected.desc}</span>
      </div>}
    </div>
  );
}

// ── HelpBox: collapsible inline documentation panel ──────────────────────────
function HelpBox({ title="How it works", items=[], color=THEME.accent }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{marginBottom:14,border:"1px solid "+color+"22",borderRadius:8,overflow:"hidden"}}>
      <div onClick={()=>setOpen(o=>!o)} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"9px 14px",cursor:"pointer",background:color+"07",userSelect:"none"}}>
        <div style={{display:"flex",alignItems:"center",gap:7}}>
          <span style={{fontSize:13}}>📖</span>
          <span style={{fontSize:12,fontWeight:600,color}}>{title}</span>
        </div>
        <span style={{fontSize:11,color,opacity:0.7}}>{open?"▲ Hide":"▼ Show"}</span>
      </div>
      {open&&(
        <div style={{padding:"12px 14px",background:color+"04",display:"flex",flexDirection:"column",gap:8}}>
          {items.map((item,i)=>(
            <div key={i} style={{display:"flex",gap:10,alignItems:"flex-start"}}>
              <span style={{fontSize:14,flexShrink:0,marginTop:1}}>{item.icon}</span>
              <div>
                <div style={{fontSize:12,fontWeight:600,color:THEME.text,marginBottom:2}}>{item.title}</div>
                <div style={{fontSize:11,color:THEME.textMid,lineHeight:1.6}}>{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SectionHeader({ icon, title, color = THEME.accent, children }) {
  return (
    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:20,paddingBottom:16,borderBottom:"1px solid "+THEME.border}}>
      <div style={{display:"flex",alignItems:"center",gap:10}}>
        <span style={{fontSize:16,opacity:0.8}}>{icon}</span>
        <span style={{fontSize:17,fontWeight:700,color:THEME.text,letterSpacing:"-0.02em",fontFamily:"'Syne',sans-serif"}}>{title}</span>
      </div>
      <div style={{display:"flex",alignItems:"center",gap:8}}>{children}</div>
    </div>
  );
}

function StatCard({ value, label, icon, color = THEME.accent, sub }) {
  return (
    <div style={{background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:10,padding:"18px 20px",position:"relative",overflow:"hidden"}}>
      <div style={{position:"absolute",top:14,right:16,fontSize:18,opacity:0.25}}>{icon}</div>
      <div style={{fontSize:26,fontWeight:800,color:THEME.text,letterSpacing:"-0.02em",lineHeight:1}}>{value}</div>
      <div style={{fontSize:12,color:THEME.textMid,marginTop:5,fontWeight:500}}>{label}</div>
      {sub && <div style={{fontSize:11,color:THEME.textDim,marginTop:3}}>{sub}</div>}
      <div style={{position:"absolute",bottom:0,left:0,width:"3px",height:"100%",background:color,borderRadius:"0 0 0 10px",opacity:0.7}}/>
    </div>
  );
}

// ── External Enrichment Tools ─────────────────────────────────────────────────
const ENRICH_TOOLS=[
  {cat:"🔗 URL & Domain",color:"#00d4ff",tools:[
    {name:"URLScan.io",url:"https://urlscan.io/search/#*",desc:"Scan and analyse URLs for malicious content"},
    {name:"VirusTotal URL",url:"https://www.virustotal.com/gui/home/url",desc:"Multi-AV URL and domain reputation check"},
    {name:"URLVoid",url:"https://www.urlvoid.com/",desc:"Website reputation and blacklist checker"},
    {name:"PhishTank",url:"https://phishtank.org/",desc:"Community phishing URL database"},
  ]},
  {cat:"🌐 IP & Domain Rep",color:"#7c55ff",tools:[
    {name:"AbuseIPDB",url:"https://www.abuseipdb.com/",desc:"IP address abuse reports and reputation"},
    {name:"Shodan",url:"https://www.shodan.io/",desc:"Internet-connected device search and exposure"},
    {name:"GreyNoise",url:"https://viz.greynoise.io/",desc:"Internet background noise and mass scanner IPs"},
    {name:"IPVoid",url:"https://www.ipvoid.com/",desc:"IP reputation, DNSBL, and geolocation lookup"},
    {name:"MXToolbox",url:"https://mxtoolbox.com/SuperTool.aspx",desc:"DNS, blacklist, and mail server diagnostics"},
  ]},
  {cat:"📧 Email & Headers",color:"#ffaa00",tools:[
    {name:"MXToolbox Header",url:"https://mxtoolbox.com/EmailHeaders.aspx",desc:"Parse and analyze email message headers"},
    {name:"Google Admin Toolbox",url:"https://toolbox.googleapps.com/apps/messageheader/",desc:"Google's email header analyzer"},
    {name:"EmailRep",url:"https://emailrep.io/",desc:"Email address reputation and risk score"},
    {name:"hunter.io",url:"https://hunter.io/email-verifier",desc:"Verify email addresses and find breached accounts"},
  ]},
  {cat:"🦠 File & Hash",color:"#ff3d55",tools:[
    {name:"VirusTotal Hash",url:"https://www.virustotal.com/gui/home/search",desc:"Multi-engine malware scan by file hash"},
    {name:"MalwareBazaar",url:"https://bazaar.abuse.ch/",desc:"Malware sample database by hash, tag, or signature"},
    {name:"Hybrid Analysis",url:"https://www.hybrid-analysis.com/",desc:"Free malware sandbox with MITRE ATT&CK mapping"},
    {name:"Any.run",url:"https://app.any.run/",desc:"Interactive malware sandbox — watch execution live"},
    {name:"Joe Sandbox",url:"https://www.joesandbox.com/",desc:"Deep file analysis and behavioral sandbox"},
  ]},
  {cat:"🔍 OSINT & Threat Intel",color:"#00e87a",tools:[
    {name:"MITRE ATT&CK",url:"https://attack.mitre.org/techniques/",desc:"Official MITRE technique database and TTPs"},
    {name:"OTX AlienVault",url:"https://otx.alienvault.com/",desc:"Open threat intelligence — IOCs and pulses"},
    {name:"ThreatFox",url:"https://threatfox.abuse.ch/",desc:"IOC sharing database — IPs, domains, hashes"},
    {name:"Robtex",url:"https://www.robtex.com/",desc:"DNS and IP routing intelligence and relationships"},
  ]},
];
function ExternalEnrichTools({tactic,technique,name}){
  const[open,setOpen]=useState(false);
  return(
    <div style={{marginTop:16,border:"1px solid "+THEME.border,borderRadius:8,overflow:"hidden"}}>
      <div onClick={()=>setOpen(o=>!o)} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"10px 14px",cursor:"pointer",background:"rgba(255,255,255,0.02)"}}
        onMouseEnter={e=>e.currentTarget.style.background="rgba(255,255,255,0.04)"}
        onMouseLeave={e=>e.currentTarget.style.background="rgba(255,255,255,0.02)"}>
        <div style={{fontSize:11,fontWeight:700,color:THEME.textMid,letterSpacing:"0.08em"}}>🔬 EXTERNAL ENRICHMENT TOOLS</div>
        <span style={{fontSize:11,color:THEME.textDim,transform:open?"rotate(90deg)":"rotate(0deg)",display:"inline-block",transition:"transform 0.15s"}}>›</span>
      </div>
      {open&&(
        <div style={{padding:"12px 14px",display:"grid",gap:12}}>
          {ENRICH_TOOLS.map(cat=>(
            <div key={cat.cat}>
              <div style={{fontSize:10,fontWeight:800,color:cat.color,letterSpacing:"0.1em",marginBottom:7}}>{cat.cat}</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                {cat.tools.map(t=>(
                  <a key={t.name} href={t.url} target="_blank" rel="noopener noreferrer" title={t.desc}
                    style={{display:"inline-flex",alignItems:"center",gap:5,padding:"5px 11px",borderRadius:6,background:"rgba(255,255,255,0.03)",border:"1px solid "+THEME.border,color:THEME.textMid,textDecoration:"none",fontSize:11,transition:"all 0.12s"}}
                    onMouseEnter={e=>{e.currentTarget.style.background="rgba(255,255,255,0.07)";e.currentTarget.style.color=cat.color;e.currentTarget.style.borderColor=cat.color+"55";}}
                    onMouseLeave={e=>{e.currentTarget.style.background="rgba(255,255,255,0.03)";e.currentTarget.style.color=THEME.textMid;e.currentTarget.style.borderColor=THEME.border;}}>
                    {t.name} <span style={{fontSize:9,opacity:0.5}}>↗</span>
                  </a>
                ))}
              </div>
            </div>
          ))}
          <div style={{fontSize:10,color:THEME.textDim,marginTop:4}}>Tip: copy IOCs (IPs, hashes, domains) from your detection query above and paste into these tools for manual enrichment.</div>
        </div>
      )}
    </div>
  );
}

// ── Tabbed ADS View ───────────────────────────────────────────────────────────
function ADSResult({ ads, threat, tactic, tool, onSave, detName, setDetName, severity, beginner, onSendToTriage }) {
  const [activeTab, setActiveTab] = useState("overview");
  // Active query — starts as original, gets improved by Score/Enrich/ML actions
  const [activeQuery, setActiveQuery] = useState(()=>ads.detection_query||"");
  const [queryModified, setQueryModified] = useState(false);
  const [applyingFix, setApplyingFix] = useState(false);
  // Score tab
  const [scoreData, setScoreData] = useState(null);
  const [scoring, setScoring] = useState(false);
  const [scoreErr, setScoreErr] = useState("");
  // Enrich tab
  const [enrichData, setEnrichData] = useState(null);
  const [enriching, setEnriching] = useState(false);
  const [enrichErr, setEnrichErr] = useState("");
  // ML/UBA/RBA tab
  const [mlData, setMlData] = useState(null);
  const [mlLoading, setMlLoading] = useState(false);
  const [mlErr, setMlErr] = useState("");
  // Blast Radius tab
  const [blastData, setBlastData] = useState(null);
  const [blasting, setBlasting] = useState(false);
  const [blastErr, setBlastErr] = useState("");
  // AI False Positive tab
  const [fpAiData, setFpAiData] = useState(null);
  const [fpAiLoading, setFpAiLoading] = useState(false);
  const [fpAiErr, setFpAiErr] = useState("");
  // Defend tab (Honeytoken + DNS Sinkhole)
  const [defendSubTab, setDefendSubTab] = useState("honey");
  const [honeytokenData, setHoneytokenData] = useState(null);
  const [honeytokenLoading, setHoneytokenLoading] = useState(false);
  const [honeytokenErr, setHoneytokenErr] = useState("");
  const [sinkholeData, setSinkholeData] = useState(null);
  const [sinkholeLoading, setSinkholeLoading] = useState(false);
  const [sinkholeErr, setSinkholeErr] = useState("");
  // LOTL tab
  const [lotlData, setLotlData] = useState(null);
  const [lotlLoading, setLotlLoading] = useState(false);
  const [lotlErr, setLotlErr] = useState("");
  const [mlSubTab, setMlSubTab] = useState("ml");
  // Workflow tab
  const [workflowData, setWorkflowData] = useState(null);
  const [workflowLoading, setWorkflowLoading] = useState(false);
  const [workflowErr, setWorkflowErr] = useState("");
  const [workflowSubTab, setWorkflowSubTab] = useState("visual");
  // Deploy tab
  const [deploySubTab, setDeploySubTab] = useState("test");
  const [testResult, setTestResult] = useState(null);
  const [testLoading, setTestLoading] = useState(false);
  const [playbookContent, setPlaybookContent] = useState("");
  const [generatingPlaybook, setGeneratingPlaybook] = useState(false);
  const [ticketContent, setTicketContent] = useState("");
  const [generatingTicket, setGeneratingTicket] = useState(false);
  const [sigmaContent, setSigmaContent] = useState("");
  const [loadingSigma, setLoadingSigma] = useState(false);
  const [pushResult, setPushResult] = useState("");
  const [pushing, setPushing] = useState(false);
  const [showCurlCmd, setShowCurlCmd] = useState(false);
  const [splunkUrl, setSplunkUrl] = useState(LS.get("splunk_url",""));
  const [splunkToken, setSplunkToken] = useState(LS.get("splunk_token",""));
  const [splunkAuthMode, setSplunkAuthMode] = useState(LS.get("splunk_auth_mode","token"));
  const [splunkUser, setSplunkUser] = useState(LS.get("splunk_user",""));
  const [splunkPass, setSplunkPass] = useState(LS.get("splunk_pass",""));
  const [elasticUrl, setElasticUrl] = useState(LS.get("elastic_url",""));
  const [elasticToken, setElasticToken] = useState(LS.get("elastic_token",""));
  const [soarUrl, setSoarUrl] = useState(LS.get("soar_url",""));
  const [soarToken, setSoarToken] = useState(LS.get("soar_token",""));
  if (!ads) return null;

  // Poll async job until done or error (max 90s, polls every 1.5s)
  async function pollJob(jobId, maxWaitMs=90000) {
    const interval=1500, start=Date.now();
    while(Date.now()-start<maxWaitMs){
      await new Promise(r=>setTimeout(r,interval));
      const r=await fetch(`/api/jobs/${jobId}`);
      const d=await r.json();
      if(d.status==="done") return d.result;
      if(d.status==="error") throw new Error(d.error||"Job failed");
      // still queued/active — keep polling
    }
    throw new Error("Request timed out — please try again.");
  }

  // Build a det object — always uses activeQuery so improvements flow through to Deploy
  function buildDet() {
    return { id: "builder-preview", name: detName||threat.slice(0,60), threat, tactic, queryType: tool.lang, tool: tool.id, query: activeQuery, severity, ads };
  }

  function applyQuery(newQuery, label) {
    if(!newQuery) return;
    setActiveQuery(newQuery);
    setQueryModified(true);
    setActiveTab("query");
  }

  async function fixQueryFromScore() {
    if (!scoreData) return;
    setApplyingFix(true);
    try {
      const issues = [...(scoreData.weaknesses||[]), ...(scoreData.recommendations||[])].join("\n- ");
      const improved = await callClaudeStream(
        [{ role:"user", content:`You are a detection engineer. Improve this ${tool.lang} query by fixing these specific issues:\n\n${issues}\n\nOriginal query:\n${activeQuery}\n\nReturn ONLY the improved ${tool.lang} query. No explanation, no markdown.` }],
        "Expert detection engineer. Return only the query.",
        2000
      );
      applyQuery(improved.trim(), "score-fix");
    } catch(e) { setScoreErr("Fix failed: "+e.message); }
    setApplyingFix(false);
  }

  async function fixQueryFromEnrich() {
    if (!enrichData) return;
    setApplyingFix(true);
    try {
      const context = [
        enrichData.gap_warning ? "Coverage gap to fix: "+enrichData.gap_warning : "",
        enrichData.quick_win ? "Quick win to apply: "+enrichData.quick_win : "",
        enrichData.adjacent_detections?.length ? "Extend coverage for: "+enrichData.adjacent_detections.map(d=>d.name).join(", ") : ""
      ].filter(Boolean).join("\n");
      const improved = await callClaudeStream(
        [{ role:"user", content:`Improve this ${tool.lang} detection query to address these gaps:\n\n${context}\n\nOriginal query:\n${activeQuery}\n\nReturn ONLY the improved ${tool.lang} query. No explanation, no markdown.` }],
        "Expert detection engineer. Return only the query.",
        2000
      );
      applyQuery(improved.trim(), "enrich-fix");
    } catch(e) { setEnrichErr("Fix failed: "+e.message); }
    setApplyingFix(false);
  }

  async function runTest() {
    setTestLoading(true); setTestResult(null); setActiveTab("deploy"); setDeploySubTab("test");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/test", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ name:det.name, query:det.query, queryType:det.queryType, tool:det.tool, tactic:det.tactic, severity:det.severity, threat:det.threat }) });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setTestResult(data);
    } catch(e) { setTestResult({ error: e.message }); }
    setTestLoading(false);
  }

  async function runPlaybook() {
    setGeneratingPlaybook(true); setPlaybookContent(""); setActiveTab("deploy"); setDeploySubTab("playbook");
    const det = buildDet();
    try {
      const txt = await callClaudeStream([{ role:"user", content:`Short IR playbook for: ${det.name} (${det.tactic}, ${det.severity})\n\nKeep each section to 2-3 bullet points max, one line each:\n1. TRIAGE (verify TP)\n2. ENRICH (IPs/users/hashes to check)\n3. CONTAIN\n4. ERADICATE\n5. ESCALATE WHEN\n6. FP FILTERS\n7. PSEUDO-CODE (5 lines max)` }],
        "Expert SOC analyst and SOAR engineer writing incident response playbooks.", 2000,
        (partial) => setPlaybookContent(partial));
      setPlaybookContent(txt);
    } catch(e) { setPlaybookContent("Error: "+e.message); }
    setGeneratingPlaybook(false);
  }

  async function runTicket() {
    setGeneratingTicket(true); setTicketContent(""); setActiveTab("deploy"); setDeploySubTab("ticket");
    const det = buildDet();
    try {
      const txt = await callClaude([{ role:"user", content:`Write a brief JIRA ticket for deploying: ${det.name} (${det.severity}/${det.tactic}/${det.queryType})\n\nSections (2-3 lines each max): Summary, Description, Acceptance Criteria, Test Steps, Rollback.` }], "SOC engineer.", 1000);
      setTicketContent(txt);
    } catch(e) { setTicketContent("Error: "+e.message); }
    setGeneratingTicket(false);
  }

  async function runSigmaAI() {
    setLoadingSigma(true); setSigmaContent(""); setActiveTab("deploy"); setDeploySubTab("sigma");
    const det = buildDet();
    try {
      const res = await fetch("/api/sigma/export", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ detection:{ name:det.name, query:det.query, tactic:det.tactic, technique:ads.mitre_id||"", severity:det.severity, queryType:det.queryType, tool:det.tool, threat:det.threat } }) });
      const data = await res.json();
      setSigmaContent(data.sigma || ("Error: "+(data.error||"Sigma export failed.")));
    } catch(e) { setSigmaContent("Error: "+e.message); }
    setLoadingSigma(false);
  }

  async function runBlast() {
    setBlasting(true); setBlastErr(""); setBlastData(null); setActiveTab("blast");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/blast-radius",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:det.name,query:det.query,queryType:tool.lang,tactic,severity})});
      const data = await res.json(); if(data.error) throw new Error(data.error); setBlastData(data);
    } catch(e) { setBlastErr(e.message); }
    setBlasting(false);
  }

  async function runFpAi() {
    setFpAiLoading(true); setFpAiErr(""); setFpAiData(null); setActiveTab("aitp");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/false-positives",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:det.name,query:det.query,queryType:tool.lang,tactic})});
      const data = await res.json(); if(data.error) throw new Error(data.error); setFpAiData(data);
    } catch(e) { setFpAiErr(e.message); }
    setFpAiLoading(false);
  }

  async function runHoneytoken() {
    setHoneytokenLoading(true); setHoneytokenErr(""); setHoneytokenData(null); setActiveTab("defend"); setDefendSubTab("honey");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/honeytoken",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:det.name,query:det.query,queryType:tool.lang,tactic,threat})});
      const data = await res.json(); if(data.error) throw new Error(data.error); setHoneytokenData(data);
    } catch(e) { setHoneytokenErr(e.message); }
    setHoneytokenLoading(false);
  }

  async function runSinkhole() {
    setSinkholeLoading(true); setSinkholeErr(""); setSinkholeData(null); setActiveTab("defend"); setDefendSubTab("sinkhole");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/dns-sinkhole",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:det.name,query:det.query,tactic,threat})});
      const data = await res.json(); if(data.error) throw new Error(data.error); setSinkholeData(data);
    } catch(e) { setSinkholeErr(e.message); }
    setSinkholeLoading(false);
  }

  async function runLotl() {
    setLotlLoading(true); setLotlErr(""); setLotlData(null); setActiveTab("lotl");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/lotl-coverage",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:det.name,tactic,queryType:tool.lang})});
      const data = await res.json(); if(data.error) throw new Error(data.error); setLotlData(data);
    } catch(e) { setLotlErr(e.message); }
    setLotlLoading(false);
  }

  async function runML() {
    setMlLoading(true); setMlErr(""); setMlData(null); setActiveTab("ml");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/ml-enhance", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ name:det.name, query:det.query, queryType:tool.lang, tactic, severity, threat }) });
      const init = await res.json();
      if (init.error) throw new Error(init.error);
      const data = init.jobId ? await pollJob(init.jobId) : init;
      setMlData(data);
    } catch(e) { setMlErr(e.message); }
    setMlLoading(false);
  }

  async function runWorkflow() {
    setWorkflowLoading(true); setWorkflowErr(""); setWorkflowData(null); setActiveTab("workflow");
    const det = buildDet();
    try {
      const res = await fetch("/api/detection/workflow", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ name:det.name, query:det.query, queryType:tool.lang, tactic, severity, threat, mitre_id:ads.mitre_id||"" }) });
      const init = await res.json();
      if (init.error) throw new Error(init.error);
      const data = init.jobId ? await pollJob(init.jobId) : init;
      setWorkflowData(data);
    } catch(e) { setWorkflowErr(e.message); }
    setWorkflowLoading(false);
  }

  function isOnPremUrl(url) {
    if (!url) return false;
    try { const h = new URL(url).hostname; return h==="localhost"||h==="127.0.0.1"||h.endsWith(".local")||/^10\./.test(h)||/^192\.168\./.test(h)||/^172\.(1[6-9]|2\d|3[01])\./.test(h); } catch { return false; }
  }

  async function pushToSplunk() {
    if (!splunkUrl||(!splunkToken&&splunkAuthMode==="token")||(!splunkUser&&splunkAuthMode==="basic")) { setPushResult("error:Fill in Splunk URL and credentials first."); return; }
    LS.set("splunk_url",splunkUrl); LS.set("splunk_token",splunkToken); LS.set("splunk_auth_mode",splunkAuthMode); LS.set("splunk_user",splunkUser); LS.set("splunk_pass",splunkPass);
    setPushing(true); setPushResult("");
    const det = buildDet();
    try {
      // Always proxy through server — it handles self-signed certs with rejectUnauthorized:false
      const res = await fetch("/api/siem/push/splunk", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ url:splunkUrl, token:splunkToken, authMode:splunkAuthMode, username:splunkUser, password:splunkPass, name:det.name, query:det.query, severity:det.severity, description:det.threat||"", tactic:det.tactic, queryType:det.queryType }) });
      const data = await res.json();
      if(data.success){ setPushResult("success:"+data.message); }
      else {
        const isLocalDns = data.error&&(data.error.includes("EAI_AGAIN")||data.error.includes("ENOTFOUND")||data.error.includes("getaddrinfo"));
        if(isLocalDns){ setShowCurlCmd(true); setPushResult("error:LOCAL_NET"); }
        else setPushResult("error:"+(data.error||"Push failed."));
      }
    } catch(e) { setPushResult("error:"+e.message); }
    setPushing(false);
  }

  async function pushToElastic() {
    if (!elasticUrl||!elasticToken) { setPushResult("error:Fill in Kibana URL and API key first."); return; }
    LS.set("elastic_url",elasticUrl); LS.set("elastic_token",elasticToken);
    setPushing(true); setPushResult("");
    const det = buildDet();
    try {
      if (isOnPremUrl(elasticUrl)) {
        const sev = det.severity==="critical"?"critical":det.severity==="high"?"high":det.severity==="medium"?"medium":"low";
        const langMap = {kql:"kuery",eql:"eql",esql:"esql"}; const lang = langMap[det.queryType?.toLowerCase()]||"kuery";
        const rule = { name:det.name, description:det.threat||det.name, risk_score:sev==="critical"?99:sev==="high"?73:sev==="medium"?47:21, severity:sev, type:"query", query:det.query||"", language:lang, index:["logs-*","*"], enabled:false };
        const res = await fetch(`${elasticUrl.replace(/\/$/,"")}/api/detection_engine/rules`, { method:"POST", headers:{"Authorization":`ApiKey ${elasticToken}`,"Content-Type":"application/json","kbn-xsrf":"detectiq"}, body:JSON.stringify(rule) });
        if (res.ok) setPushResult("success:Rule created in Elastic Security (disabled for review).");
        else if (res.status===409) setPushResult("success:Rule already exists in Elastic.");
        else setPushResult("error:Elastic returned "+res.status);
      } else {
        const res = await fetch("/api/siem/push/elastic", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ url:elasticUrl, token:elasticToken, name:det.name, query:det.query, severity:det.severity, description:det.threat||det.name, tactic:det.tactic, queryType:det.queryType }) });
        const data = await res.json();
        setPushResult(data.success ? "success:"+data.message : "error:"+(data.error||"Push failed."));
      }
    } catch(e) { setPushResult("error:"+e.message); }
    setPushing(false);
  }

  async function pushToSOAR() {
    if (!soarUrl) { setPushResult("error:Fill in SOAR webhook URL first."); return; }
    LS.set("soar_url",soarUrl); LS.set("soar_token",soarToken);
    setPushing(true); setPushResult("");
    const det = buildDet();
    try {
      const res = await fetch("/api/siem/push/soar", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ url:soarUrl, token:soarToken, payload:{ source:"DetectIQ", event_type:"detection_push", detection:{ id:det.id, name:det.name, tactic:det.tactic, severity:det.severity, query_type:det.queryType, tool:det.tool, query:det.query, description:det.threat||"", mitre_id:ads.mitre_id||"", summary:ads.summary||"" }, timestamp:new Date().toISOString() } }) });
      const data = await res.json();
      setPushResult(data.success ? "success:"+data.message : "error:"+(data.error||"SOAR push failed."));
    } catch(e) { setPushResult("error:"+e.message); }
    setPushing(false);
  }

  async function runScore() {
    setScoring(true); setScoreErr(""); setScoreData(null); setActiveTab("score");
    try {
      const res = await fetch("/api/detection/quality-score", {
        method: "POST", headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ name: detName||threat.slice(0,60), query: ads.detection_query||"", queryType: tool.lang, tactic, severity })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setScoreData(data);
    } catch(e) { setScoreErr(e.message); }
    setScoring(false);
  }

  async function runEnrich() {
    setEnriching(true); setEnrichErr(""); setEnrichData(null); setActiveTab("enrich");
    try {
      const prompt = `You are a detection engineer advisor. Give a SHORT, actionable enrichment for this detection.

Detection: ${detName||threat.slice(0,60)}
Tactic: ${tactic}
Severity: ${severity}
MITRE ID: ${ads.mitre_id||"unknown"}

Return ONLY valid JSON:
{
  "attack_path_summary": "one sentence, max 12 words",
  "next_tactics": ["tactic1","tactic2"],
  "adjacent_detections": [{"name":"short name","why":"6 words max"},{"name":"short name","why":"6 words max"}],
  "high_value_targets": "3-5 asset types, comma separated",
  "cvss_score": "N/A",
  "quick_win": "one action, max 10 words",
  "gap_warning": "one sentence, max 12 words"
}`;
      const result = await callClaude([{role:"user",content:prompt}],"Expert detection engineer. Return ONLY valid JSON.",1200);
      const m = result.match(/\{[\s\S]*\}/);
      if (!m) throw new Error("Could not parse enrichment");
      const cleaned = m[0].replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,"").replace(/\\(?!["\\/bfnrtu])/g,"\\\\");
      setEnrichData(JSON.parse(cleaned));
    } catch(e) { setEnrichErr(e.message); }
    setEnriching(false);
  }

  const tabs = [
    { id:"overview",  label:"Overview",       icon:"📋" },
    { id:"behaviors", label:"Behaviors",      icon:"👁"  },
    { id:"query",     label:"Query",          icon:"⚡"  },
    { id:"fp",        label:"False Positives",icon:"🔇"  },
    { id:"tuning",    label:"Tuning",         icon:"🎛"  },
    { id:"refs",      label:"References",     icon:"📎"  },
    { id:"score",     label:"Score",          icon:"🏅"  },
    { id:"enrich",    label:"Enrich",         icon:"🔍"  },
    { id:"ml",        label:"ML/UBA/RBA",     icon:"🧠"  },
    { id:"blast",     label:"Blast Radius",   icon:"💥"  },
    { id:"aitp",      label:"False Positives",icon:"⚠️"  },
    { id:"lotl",      label:"LOTL",           icon:"🔧"  },
    { id:"workflow",  label:"Workflow",       icon:"⚡"  },
    { id:"deploy",    label:"Deploy",         icon:"🚀"  },
  ];

  return (
    <div style={S.card}>
      {/* Summary header */}
      <div style={{background:"linear-gradient(135deg,rgba(0,212,255,0.06),rgba(124,85,255,0.04))",border:"1px solid "+THEME.borderBright,borderRadius:10,padding:"16px 20px",marginBottom:16}}>
        <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",flexWrap:"wrap",gap:12}}>
          <div>
            <div style={{fontSize:10,fontWeight:800,color:THEME.accentDim,letterSpacing:"0.15em",marginBottom:4}}>ATTACK DETECTION STRATEGY</div>
            <div style={{fontSize:17,fontWeight:900,color:THEME.text,marginBottom:8}}>{ads.technique_name || threat.slice(0,50)}</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {ads.mitre_id&&<span style={S.badge(THEME.accent)}>{ads.mitre_id}</span>}
              <span style={S.badge(sevColor[severity]||THEME.textDim)}>{severity}</span>
              <span style={S.badge(tool.color)}>{tool.lang}</span>
              <span style={{...S.badge(THEME.textDim)}}>{tactic}</span>
            </div>
          </div>
          <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
            <input style={{...S.input,width:170}} value={detName} onChange={e=>setDetName(e.target.value)} placeholder="Detection name..."/>
            <button style={{...S.btn(),padding:"7px 11px",fontSize:11}} onClick={runScore} disabled={scoring}>{scoring?<><Spinner/>...</>:"🏅 Score"}</button>
            <button style={{...S.btn(),padding:"7px 11px",fontSize:11}} onClick={runEnrich} disabled={enriching}>{enriching?<><Spinner/>...</>:"🔍 Enrich"}</button>
            <button style={{...S.btn(),padding:"7px 11px",fontSize:11}} onClick={runML} disabled={mlLoading}>{mlLoading?<><Spinner/>...</>:"🧠 ML/UBA"}</button>
            <button style={{...S.btn(),padding:"7px 11px",fontSize:11,borderColor:"rgba(255,80,80,0.4)",color:"#ff8080"}} onClick={runBlast} disabled={blasting}>{blasting?<><Spinner/>...</>:"💥 Blast"}</button>
            <button style={{...S.btn(),padding:"7px 11px",fontSize:11,borderColor:"rgba(255,170,0,0.4)",color:THEME.warning}} onClick={runFpAi} disabled={fpAiLoading}>{fpAiLoading?<><Spinner/>...</>:"⚠️ FP"}</button>
            <button style={{...S.btn(),padding:"7px 11px",fontSize:11,borderColor:"rgba(0,232,122,0.4)",color:THEME.success}} onClick={runLotl} disabled={lotlLoading}>{lotlLoading?<><Spinner/>...</>:"🔧 LOTL"}</button>
            <button style={{...S.btn(),padding:"7px 11px",fontSize:11}} onClick={runWorkflow} disabled={workflowLoading}>{workflowLoading?<><Spinner/>...</>:"⚡ Workflow"}</button>
            <div style={{marginLeft:"auto",display:"flex",gap:8}}>
              <button style={{...S.btn(),padding:"7px 16px",fontSize:12,borderColor:THEME.purple+"55",color:THEME.purple,fontWeight:600}} onClick={()=>setActiveTab("deploy")}>🚀 Deploy</button>
              <button style={{...S.btn("s"),padding:"7px 18px",fontSize:12}} onClick={onSave}>Save</button>
            </div>
          </div>
        </div>
        {/* One-line summary */}
        {ads.summary&&<div style={{marginTop:12,fontSize:13,color:THEME.textMid,lineHeight:1.6,borderTop:"1px solid "+THEME.border,paddingTop:10}}>{ads.summary}</div>}
      </div>

      {/* Tabs */}
      <div style={{display:"flex",gap:4,marginBottom:14,borderBottom:"1px solid "+THEME.border,paddingBottom:0}}>
        {tabs.map(t=>(
          <button key={t.id} onClick={()=>setActiveTab(t.id)}
            style={{padding:"8px 14px",borderRadius:"7px 7px 0 0",border:"1px solid "+(activeTab===t.id?THEME.accentDim+"66":"transparent"),borderBottom:activeTab===t.id?"1px solid "+THEME.bg:"1px solid transparent",background:activeTab===t.id?"linear-gradient(135deg,rgba(0,212,255,0.08),rgba(0,212,255,0.04))":"transparent",color:activeTab===t.id?THEME.accent:THEME.textDim,cursor:"pointer",fontFamily:"inherit",fontSize:11,fontWeight:activeTab===t.id?700:500,transition:"all 0.15s",marginBottom:-1}}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{minHeight:140}}>
        {activeTab==="overview"&&<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap"}}>{ads.attack_overview||"No overview available."}</div>}

        {activeTab==="behaviors"&&(
          <div>
            <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap",marginBottom:16}}>{ads.observable_behaviors||"No behaviors listed."}</div>
            {/* Simulated log events */}
            {ads.simulated_events&&ads.simulated_events.length>0&&(
              <div>
                <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.15em",marginBottom:10}}>SIMULATED LOG EVENTS</div>
                {ads.simulated_events.map((evt,i)=>(
                  <div key={i} style={{background:"#02040a",border:"1px solid "+THEME.warning+"22",borderRadius:8,padding:12,marginBottom:8,position:"relative"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                      <span style={{...S.badge(THEME.warning),fontSize:9}}>EVENT {i+1}</span>
                      <div style={{display:"flex",gap:6}}>
                        <CopyBtn text={evt} small={true}/>
                        {onSendToTriage&&<button style={{...S.btn(),padding:"3px 10px",fontSize:10}} onClick={()=>onSendToTriage(evt)}>Send to Triage</button>}
                      </div>
                    </div>
                    <div style={{fontSize:11,color:"#7dd3fc",fontFamily:"monospace",lineHeight:1.7,whiteSpace:"pre-wrap"}}>{evt}</div>
                  </div>
                ))}
              </div>
            )}
            {beginner&&<div style={{marginTop:10,padding:"10px 14px",background:THEME.warningGlow,border:"1px solid "+THEME.warning+"33",borderRadius:8,fontSize:12,color:THEME.warning}}><b>Beginner tip:</b> These are what the attack looks like in your logs. The simulated events help you test your detection rule before going live.</div>}
          </div>
        )}

        {activeTab==="query"&&(
          <div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <span style={{fontSize:11,color:tool.color,fontWeight:700}}>{tool.name} — {tool.lang}</span>
                {queryModified&&<span style={{fontSize:9,fontWeight:800,padding:"2px 8px",borderRadius:4,background:"rgba(0,255,136,0.12)",border:"1px solid rgba(0,255,136,0.3)",color:THEME.success}}>✓ IMPROVED</span>}
              </div>
              <div style={{display:"flex",gap:6}}>
                {queryModified&&<button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>{setActiveQuery(ads.detection_query||"");setQueryModified(false);}}>↩ Reset to original</button>}
                <CopyBtn text={activeQuery}/>
              </div>
            </div>
            {queryModified&&(
              <div style={{marginBottom:10,padding:"8px 12px",background:"rgba(0,255,136,0.05)",border:"1px solid rgba(0,255,136,0.2)",borderRadius:7,fontSize:11,color:THEME.success}}>
                ✓ Query improved — this version will be used when pushing to Splunk/Elastic/SOAR.
              </div>
            )}
            <textarea style={{...S.textarea,minHeight:180,fontFamily:"monospace",fontSize:12}} value={activeQuery} onChange={e=>{setActiveQuery(e.target.value);setQueryModified(e.target.value!==ads.detection_query);}}/>
            {beginner&&<div style={{marginTop:10,padding:"10px 14px",background:THEME.accentGlow,border:"1px solid "+THEME.accentDim+"33",borderRadius:8,fontSize:12,color:THEME.accent}}><b>Beginner tip:</b> Copy this query and paste it directly into {tool.name}.</div>}
          </div>
        )}

        {activeTab==="fp"&&<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap"}}>{ads.false_positive_guidance||"No false positive guidance available."}</div>}
        {activeTab==="tuning"&&<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap"}}>{ads.tuning_tips||"No tuning tips available."}</div>}
        {activeTab==="refs"&&<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap"}}>{ads.references||"No references available."}</div>}

        {activeTab==="score"&&(
          <div>
            {scoring&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Analyzing detection quality...</div>}
            {scoreErr&&<div style={{color:THEME.danger,fontSize:13}}>{scoreErr}</div>}
            {!scoring&&!scoreData&&!scoreErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🏅 Score" to analyze this detection's quality.</div>}
            {scoreData&&(
              <div>
                {/* Overall score */}
                <div style={{display:"flex",alignItems:"center",gap:16,marginBottom:20,padding:"16px 20px",background:"rgba(0,212,255,0.04)",border:"1px solid "+THEME.borderBright,borderRadius:10}}>
                  <div style={{fontSize:42,fontWeight:900,color:scoreData.overall>=80?THEME.success:scoreData.overall>=60?THEME.warning:THEME.danger,lineHeight:1}}>{scoreData.overall}</div>
                  <div>
                    <div style={{fontSize:10,fontWeight:800,letterSpacing:"0.12em",color:THEME.textDim,marginBottom:2}}>OVERALL QUALITY SCORE</div>
                    <div style={{fontSize:12,color:THEME.textMid}}>{scoreData.overall>=80?"Strong detection":scoreData.overall>=60?"Acceptable — needs tuning":"Needs significant improvement"}</div>
                  </div>
                  <div style={{flex:1,height:8,background:THEME.border,borderRadius:4,overflow:"hidden",marginLeft:8}}>
                    <div style={{width:scoreData.overall+"%",height:"100%",background:scoreData.overall>=80?THEME.success:scoreData.overall>=60?THEME.warning:THEME.danger,borderRadius:4,transition:"width 0.6s ease"}}/>
                  </div>
                </div>
                {/* Breakdown */}
                {scoreData.breakdown&&(
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
                    {Object.entries(scoreData.breakdown).map(([k,v])=>(
                      <div key={k} style={{padding:"10px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                          <span style={{fontSize:11,color:THEME.textMid,textTransform:"capitalize"}}>{k.replace(/_/g," ")}</span>
                          <span style={{fontSize:13,fontWeight:700,color:v.score>=80?THEME.success:v.score>=60?THEME.warning:THEME.danger}}>{v.score}</span>
                        </div>
                        <div style={{height:4,background:THEME.border,borderRadius:2,marginBottom:6}}>
                          <div style={{width:v.score+"%",height:"100%",background:v.score>=80?THEME.success:v.score>=60?THEME.warning:THEME.danger,borderRadius:2}}/>
                        </div>
                        <div style={{fontSize:11,color:THEME.textDim,lineHeight:1.5}}>{v.notes}</div>
                      </div>
                    ))}
                  </div>
                )}
                {/* Strengths / Weaknesses / Recs */}
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10}}>
                  {scoreData.strengths?.length>0&&(
                    <div style={{padding:"10px 14px",background:"rgba(0,255,136,0.04)",border:"1px solid rgba(0,255,136,0.15)",borderRadius:8}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.success,letterSpacing:"0.1em",marginBottom:8}}>STRENGTHS</div>
                      {scoreData.strengths.map((s,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,marginBottom:4,paddingLeft:8,borderLeft:"2px solid "+THEME.success+"44"}}>✓ {s}</div>)}
                    </div>
                  )}
                  {scoreData.weaknesses?.length>0&&(
                    <div style={{padding:"10px 14px",background:"rgba(255,61,85,0.04)",border:"1px solid rgba(255,61,85,0.15)",borderRadius:8}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.danger,letterSpacing:"0.1em",marginBottom:8}}>WEAKNESSES</div>
                      {scoreData.weaknesses.map((w,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,marginBottom:4,paddingLeft:8,borderLeft:"2px solid "+THEME.danger+"44"}}>⚠ {w}</div>)}
                    </div>
                  )}
                  {scoreData.recommendations?.length>0&&(
                    <div style={{padding:"10px 14px",background:"rgba(124,85,255,0.04)",border:"1px solid rgba(124,85,255,0.15)",borderRadius:8}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.1em",marginBottom:8}}>RECOMMENDATIONS</div>
                      {scoreData.recommendations.map((r,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,marginBottom:4,paddingLeft:8,borderLeft:"2px solid "+THEME.purple+"44"}}>→ {r}</div>)}
                    </div>
                  )}
                </div>
                {/* Apply fixes CTA */}
                {(scoreData.weaknesses?.length>0||scoreData.recommendations?.length>0)&&(
                  <div style={{marginTop:14,padding:"12px 16px",background:"rgba(0,255,136,0.05)",border:"1px solid rgba(0,255,136,0.2)",borderRadius:8,display:"flex",alignItems:"center",justifyContent:"space-between",gap:12}}>
                    <div>
                      <div style={{fontSize:12,fontWeight:700,color:THEME.success,marginBottom:2}}>✨ Auto-fix the query</div>
                      <div style={{fontSize:11,color:THEME.textDim}}>Rewrite the {tool.lang} query applying all {scoreData.weaknesses?.length||0} weaknesses and {scoreData.recommendations?.length||0} recommendations. The improved query will be used when pushing to Splunk/Elastic.</div>
                    </div>
                    <button style={{...S.btn("p"),padding:"9px 20px",fontSize:12,whiteSpace:"nowrap",flexShrink:0}} onClick={fixQueryFromScore} disabled={applyingFix}>{applyingFix?<><Spinner/>Rewriting...</>:"✨ Apply Fixes to Query"}</button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab==="enrich"&&(
          <div>
            {enriching&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Enriching with threat intelligence...</div>}
            {enrichErr&&<div style={{color:THEME.danger,fontSize:13}}>{enrichErr}</div>}
            {!enriching&&!enrichData&&!enrichErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🔍 Enrich" to add threat context and coverage gaps.</div>}
            {enrichData&&(
              <div style={{display:"grid",gap:12}}>
                {enrichData.attack_path_summary&&(
                  <div style={{padding:"12px 16px",background:"rgba(0,212,255,0.04)",border:"1px solid "+THEME.borderBright,borderRadius:8}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.12em",marginBottom:6}}>KILL CHAIN POSITION</div>
                    <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.6}}>{enrichData.attack_path_summary}</div>
                  </div>
                )}
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                  {enrichData.next_tactics?.length>0&&(
                    <div style={{padding:"12px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.12em",marginBottom:8}}>NEXT LIKELY TACTICS</div>
                      {enrichData.next_tactics.map((t,i)=><div key={i} style={{fontSize:12,color:THEME.textMid,marginBottom:4,display:"flex",alignItems:"center",gap:6}}><span style={{color:THEME.warning,fontSize:10}}>→</span>{t}</div>)}
                    </div>
                  )}
                  {enrichData.high_value_targets&&(
                    <div style={{padding:"12px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.danger,letterSpacing:"0.12em",marginBottom:8}}>HIGH VALUE TARGETS AT RISK</div>
                      <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{enrichData.high_value_targets}</div>
                    </div>
                  )}
                </div>
                {enrichData.adjacent_detections?.length>0&&(
                  <div style={{padding:"12px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.12em",marginBottom:8}}>ADJACENT DETECTIONS TO BUILD</div>
                    {enrichData.adjacent_detections.map((d,i)=>(
                      <div key={i} style={{marginBottom:8,paddingLeft:10,borderLeft:"2px solid "+THEME.purple+"44"}}>
                        <div style={{fontSize:12,fontWeight:700,color:THEME.text}}>{d.name}</div>
                        <div style={{fontSize:11,color:THEME.textDim}}>{d.why}</div>
                      </div>
                    ))}
                  </div>
                )}
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                  {enrichData.quick_win&&(
                    <div style={{padding:"12px 16px",background:"rgba(0,255,136,0.04)",border:"1px solid rgba(0,255,136,0.15)",borderRadius:8}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.success,letterSpacing:"0.12em",marginBottom:6}}>QUICK WIN</div>
                      <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{enrichData.quick_win}</div>
                    </div>
                  )}
                  {enrichData.gap_warning&&(
                    <div style={{padding:"12px 16px",background:"rgba(255,61,85,0.04)",border:"1px solid rgba(255,61,85,0.15)",borderRadius:8}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.danger,letterSpacing:"0.12em",marginBottom:6}}>COVERAGE GAP</div>
                      <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{enrichData.gap_warning}</div>
                    </div>
                  )}
                </div>
                {/* Apply enrich improvements CTA */}
                {(enrichData.gap_warning||enrichData.quick_win)&&(
                  <div style={{marginTop:14,padding:"12px 16px",background:"rgba(0,255,136,0.05)",border:"1px solid rgba(0,255,136,0.2)",borderRadius:8,display:"flex",alignItems:"center",justifyContent:"space-between",gap:12}}>
                    <div>
                      <div style={{fontSize:12,fontWeight:700,color:THEME.success,marginBottom:2}}>✨ Apply enrichment to query</div>
                      <div style={{fontSize:11,color:THEME.textDim}}>Rewrite the {tool.lang} query to fix the coverage gap{enrichData.quick_win?" and apply the quick win":""}. Improved version will be used when deploying.</div>
                    </div>
                    <button style={{...S.btn("p"),padding:"9px 20px",fontSize:12,whiteSpace:"nowrap",flexShrink:0}} onClick={fixQueryFromEnrich} disabled={applyingFix}>{applyingFix?<><Spinner/>Rewriting...</>:"✨ Apply to Query"}</button>
                  </div>
                )}
              </div>
            )}
            {/* External Enrichment Tools — always shown */}
            <ExternalEnrichTools tactic={tactic} technique={ads?.mitre_id} name={detName}/>
          </div>
        )}

        {activeTab==="ml"&&(
          <div>
            {mlLoading&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Generating ML/UBA/RBA enhancements...</div>}
            {mlErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{mlErr}</div>}
            {!mlLoading&&!mlData&&!mlErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🧠 ML/UBA" to generate ML-enhanced queries, UBA baselines, and risk scoring rules.</div>}
            {mlData&&(
              <div>
                {/* Sub-tabs */}
                <div style={{display:"flex",gap:4,marginBottom:16,flexWrap:"wrap"}}>
                  {[["ml","🤖 ML Query"],["uba","👤 UBA"],["rba","⚠️ Risk Rules"],["factors","📊 Risk Factors"]].map(([id,label])=>(
                    <button key={id} onClick={()=>setMlSubTab(id)}
                      style={{padding:"6px 14px",borderRadius:6,border:"1px solid "+(mlSubTab===id?THEME.accent+"88":"transparent"),background:mlSubTab===id?"rgba(0,212,255,0.08)":"rgba(255,255,255,0.02)",color:mlSubTab===id?THEME.accent:THEME.textDim,cursor:"pointer",fontFamily:"inherit",fontSize:11,fontWeight:mlSubTab===id?700:400}}>
                      {label}
                    </button>
                  ))}
                </div>

                {mlSubTab==="ml"&&(
                  <div>
                    <div style={{padding:"10px 14px",background:"rgba(0,212,255,0.04)",border:"1px solid "+THEME.borderBright,borderRadius:8,marginBottom:12}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.12em",marginBottom:4}}>ML APPROACH</div>
                      <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.6}}>{mlData.ml_approach}</div>
                    </div>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{fontSize:11,color:THEME.textDim}}>ML-Enhanced Query — <span style={{color:THEME.success}}>{mlData.anomaly_threshold}</span></span>
                      <div style={{display:"flex",gap:6}}><CopyBtn text={mlData.ml_query||""}/><button style={{...S.btn("p"),padding:"4px 10px",fontSize:10,opacity:mlData.ml_query?1:0.4,cursor:mlData.ml_query?"pointer":"default"}} onClick={()=>mlData.ml_query&&applyQuery(mlData.ml_query,"ml")}>Use This Query ↑</button></div>
                    </div>
                    <div style={S.code}>{mlData.ml_query||"No query generated."}</div>
                    {mlData.ml_explanation&&<div style={{marginTop:10,fontSize:12,color:THEME.textMid,lineHeight:1.7,padding:"10px 14px",background:"rgba(255,255,255,0.02)",borderRadius:8}}>{mlData.ml_explanation}</div>}
                    <div style={{marginTop:10,display:"flex",gap:12,fontSize:11,color:THEME.textDim}}>
                      <span>Baseline window: <span style={{color:THEME.warning}}>{mlData.baseline_window}</span></span>
                    </div>
                  </div>
                )}

                {mlSubTab==="uba"&&(
                  <div>
                    <div style={{padding:"10px 14px",background:"rgba(124,85,255,0.04)",border:"1px solid "+THEME.purple+"33",borderRadius:8,marginBottom:12}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.12em",marginBottom:4}}>UBA BEHAVIORAL PATTERN</div>
                      <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.6}}>{mlData.uba_pattern}</div>
                    </div>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{fontSize:11,color:THEME.textDim}}>UBA-Focused Query (baselines per user/entity)</span>
                      <div style={{display:"flex",gap:6}}><CopyBtn text={mlData.uba_query||""}/><button style={{...S.btn("p"),padding:"4px 10px",fontSize:10,opacity:mlData.uba_query?1:0.4,cursor:mlData.uba_query?"pointer":"default"}} onClick={()=>mlData.uba_query&&applyQuery(mlData.uba_query,"uba")}>Use This Query ↑</button></div>
                    </div>
                    <div style={S.code}>{mlData.uba_query||"No UBA query generated."}</div>
                  </div>
                )}

                {mlSubTab==="rba"&&(
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12,padding:"12px 16px",background:"rgba(255,170,0,0.04)",border:"1px solid rgba(255,170,0,0.2)",borderRadius:8}}>
                      <div style={{fontSize:36,fontWeight:900,color:mlData.risk_score>=70?THEME.danger:mlData.risk_score>=40?THEME.warning:THEME.success}}>{mlData.risk_score}</div>
                      <div>
                        <div style={{fontSize:10,fontWeight:800,letterSpacing:"0.12em",color:THEME.textDim}}>RISK SCORE</div>
                        <div style={{fontSize:12,color:THEME.textMid}}>Splunk ES Risk Framework contribution</div>
                      </div>
                    </div>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{fontSize:11,color:THEME.textDim}}>Risk Modifier Rule (adds to Splunk ES risk index — deploy alongside main detection)</span>
                      <div style={{display:"flex",gap:6}}><CopyBtn text={mlData.risk_modifier_rule||""}/><button style={{...S.btn("p"),padding:"4px 10px",fontSize:10,opacity:mlData.risk_modifier_rule?1:0.4,cursor:mlData.risk_modifier_rule?"pointer":"default"}} onClick={()=>mlData.risk_modifier_rule&&applyQuery(mlData.risk_modifier_rule,"rba")}>Use This Query ↑</button></div>
                    </div>
                    <div style={S.code}>{mlData.risk_modifier_rule||"No risk rule generated."}</div>
                  </div>
                )}

                {mlSubTab==="factors"&&(
                  <div>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.12em",marginBottom:12}}>RISK FACTORS ({mlData.risk_factors?.length||0} identified)</div>
                    {(mlData.risk_factors||[]).map((f,i)=>(
                      <div key={i} style={{display:"flex",gap:10,alignItems:"flex-start",padding:"10px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8,marginBottom:8}}>
                        <div style={{width:22,height:22,borderRadius:"50%",background:THEME.warning+"22",border:"1px solid "+THEME.warning+"44",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:THEME.warning,flexShrink:0}}>{i+1}</div>
                        <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{f}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab==="blast"&&(
          <div>
            {blasting&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Estimating blast radius across org sizes...</div>}
            {blastErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{blastErr}</div>}
            {!blasting&&!blastData&&!blastErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "💥 Blast" to estimate how many alerts this detection generates before deploying.</div>}
            {blastData&&(
              <div>
                <div style={{marginBottom:16,padding:"12px 16px",background:"rgba(255,80,80,0.04)",border:"1px solid rgba(255,80,80,0.2)",borderRadius:8}}>
                  <div style={{fontSize:10,fontWeight:800,color:"#ff8080",letterSpacing:"0.12em",marginBottom:4}}>ALERT FATIGUE RISK — {blastData.alert_fatigue_risk||"Unknown"}</div>
                  <div style={{fontSize:12,color:THEME.textMid}}>{blastData.benchmark}</div>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:10,marginBottom:16}}>
                  {(blastData.estimates||[]).map((e,i)=>(
                    <div key={i} style={{padding:"14px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+(e.noise_level==="Very High"?THEME.danger:e.noise_level==="High"?THEME.warning:e.noise_level==="Medium"?"rgba(0,212,255,0.3)":THEME.success)+"44",borderRadius:8}}>
                      <div style={{fontSize:16,fontWeight:800,color:e.noise_level==="Very High"?THEME.danger:e.noise_level==="High"?THEME.warning:e.noise_level==="Medium"?THEME.accent:THEME.success}}>{e.daily_alerts} <span style={{fontSize:11,fontWeight:400,color:THEME.textDim}}>alerts/day</span></div>
                      <div style={{fontSize:11,fontWeight:700,color:THEME.text,marginTop:2}}>{e.endpoints}</div>
                      <div style={{fontSize:10,color:THEME.textDim,marginTop:2}}>FP rate: {e.fp_rate} · Noise: {e.noise_level}</div>
                      <div style={{fontSize:10,color:THEME.textMid,marginTop:6,paddingTop:6,borderTop:"1px solid "+THEME.border}}>{e.recommendation}</div>
                    </div>
                  ))}
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
                  <div style={{padding:"10px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:4}}>PEAK HOURS</div>
                    <div style={{fontSize:12,color:THEME.textMid}}>{blastData.peak_hours}</div>
                  </div>
                  <div style={{padding:"10px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:4}}>TOP LOG SOURCES</div>
                    <div style={{fontSize:12,color:THEME.textMid}}>{(blastData.top_log_sources||[]).join(", ")}</div>
                  </div>
                </div>
                <div style={{padding:"12px 16px",background:"rgba(255,170,0,0.04)",border:"1px solid rgba(255,170,0,0.2)",borderRadius:8}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.1em",marginBottom:6}}>TUNING RECOMMENDATION</div>
                  <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{blastData.tuning_recommendation}</div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab==="aitp"&&(
          <div>
            {fpAiLoading&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Analyzing detection for false positive scenarios...</div>}
            {fpAiErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{fpAiErr}</div>}
            {!fpAiLoading&&!fpAiData&&!fpAiErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "⚠️ FP Check" to get AI analysis of false positive scenarios and ready-to-paste exclusions.</div>}
            {fpAiData&&(
              <div>
                <div style={{display:"flex",gap:10,alignItems:"center",marginBottom:16,padding:"12px 16px",background:fpAiData.safe_to_deploy?"rgba(0,232,122,0.05)":"rgba(255,170,0,0.05)",border:"1px solid "+(fpAiData.safe_to_deploy?THEME.success:THEME.warning)+"44",borderRadius:8}}>
                  <div style={{fontSize:22}}>{fpAiData.safe_to_deploy?"✅":"⚠️"}</div>
                  <div>
                    <div style={{fontSize:12,fontWeight:700,color:fpAiData.safe_to_deploy?THEME.success:THEME.warning}}>{fpAiData.safe_to_deploy?"Safe to Deploy":"Tune Before Deploying"}</div>
                    <div style={{fontSize:11,color:THEME.textMid}}>{fpAiData.deploy_recommendation} · Overall FP rate: {fpAiData.overall_fp_rate}</div>
                  </div>
                </div>
                <div style={{marginBottom:14}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.12em",marginBottom:10}}>FALSE POSITIVE SCENARIOS ({(fpAiData.scenarios||[]).length})</div>
                  {(fpAiData.scenarios||[]).map((s,i)=>(
                    <div key={i} style={{marginBottom:10,padding:"12px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                        <div style={{fontSize:12,fontWeight:700,color:THEME.text}}>{s.title}</div>
                        <span style={{...S.badge(s.likelihood==="High"?THEME.danger:s.likelihood==="Medium"?THEME.warning:THEME.success),fontSize:9}}>{s.likelihood} likelihood</span>
                      </div>
                      <div style={{fontSize:11,color:THEME.textMid,marginBottom:6}}>{s.description} · <span style={{color:THEME.textDim}}>Affects: {s.affected_roles}</span></div>
                      {s.exclusion_query&&<div style={{...S.code,fontSize:10,padding:"6px 10px"}}>{s.exclusion_query}</div>}
                    </div>
                  ))}
                </div>
                <div style={{marginBottom:10}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.12em"}}>EXCLUSION TEMPLATE — paste at end of detection</div>
                    <CopyBtn text={fpAiData.exclusion_template||""}/>
                  </div>
                  <div style={S.code}>{fpAiData.exclusion_template||"No template generated."}</div>
                </div>
                <div style={{padding:"10px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:4}}>RECOMMENDED WHITELIST FIELDS</div>
                  <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>{(fpAiData.recommended_whitelist_fields||[]).map((f,i)=><span key={i} style={S.badge(THEME.accent)}>{f}</span>)}</div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab==="lotl"&&(
          <div>
            {lotlLoading&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Mapping LOTL binary coverage for {tactic}...</div>}
            {lotlErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{lotlErr}</div>}
            {!lotlLoading&&!lotlData&&!lotlErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🔧 LOTL" to see all Living-off-the-Land binaries relevant to this tactic with detection queries for each.</div>}
            {lotlData&&(
              <div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
                  <div style={{padding:"12px 16px",background:"rgba(0,232,122,0.04)",border:"1px solid rgba(0,232,122,0.2)",borderRadius:8}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.success,letterSpacing:"0.1em",marginBottom:4}}>COVERAGE GAP</div>
                    <div style={{fontSize:12,color:THEME.textMid}}>{lotlData.coverage_gap_summary}</div>
                  </div>
                  <div style={{padding:"12px 16px",background:"rgba(0,212,255,0.04)",border:"1px solid "+THEME.borderBright,borderRadius:8}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.1em",marginBottom:4}}>QUICK WIN</div>
                    <div style={{fontSize:12,color:THEME.textMid}}>{lotlData.quick_win}</div>
                  </div>
                </div>
                <div style={{marginBottom:10}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.12em",marginBottom:10}}>PRIORITY ORDER</div>
                  <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:14}}>{(lotlData.priority_order||[]).map((b,i)=><span key={i} style={{...S.badge(i===0?THEME.danger:i===1?THEME.warning:THEME.accent),fontSize:10}}>#{i+1} {b}</span>)}</div>
                </div>
                {(lotlData.lolbins||[]).map((b,i)=>(
                  <div key={i} style={{marginBottom:10,border:"1px solid "+THEME.border,borderRadius:8,overflow:"hidden"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 14px",background:"rgba(255,255,255,0.02)"}}>
                      <div style={{display:"flex",alignItems:"center",gap:10}}>
                        <span style={{fontFamily:"monospace",fontSize:12,fontWeight:700,color:THEME.text}}>{b.name}</span>
                        <span style={S.badge(b.risk==="High"?THEME.danger:b.risk==="Medium"?THEME.warning:THEME.success)}>{b.risk}</span>
                        <span style={{fontSize:10,color:THEME.textDim}}>{b.prevalence}</span>
                      </div>
                      <div style={{display:"flex",gap:6}}>
                        <CopyBtn text={b.query||""}/>
                        <button style={{...S.btn("p"),padding:"3px 10px",fontSize:10}} onClick={()=>b.query&&applyQuery(b.query,"lotl")}>Use ↑</button>
                      </div>
                    </div>
                    <div style={{padding:"8px 14px",borderTop:"1px solid "+THEME.border}}>
                      <div style={{fontSize:11,color:THEME.textMid,marginBottom:6}}>{b.abuse}</div>
                      <div style={{...S.code,fontSize:10,padding:"6px 10px"}}>{b.query}</div>
                    </div>
                  </div>
                ))}
                <div style={{marginTop:10,fontSize:11,color:THEME.textDim}}>Reference: <a href="https://lolbas-project.github.io/" target="_blank" rel="noopener noreferrer" style={{color:THEME.accent}}>LOLBAS Project ↗</a> · <a href="https://gtfobins.github.io/" target="_blank" rel="noopener noreferrer" style={{color:THEME.accent}}>GTFOBins ↗</a></div>
              </div>
            )}
          </div>
        )}

        {activeTab==="defend"&&(
          <div>
            <div style={{display:"flex",gap:6,marginBottom:16}}>
              {[{id:"honey",label:"🍯 Honeytokens"},{id:"sinkhole",label:"🕳 DNS Sinkhole"}].map(t=>(
                <button key={t.id} onClick={()=>setDefendSubTab(t.id)} style={{padding:"6px 14px",borderRadius:6,border:"1px solid "+(defendSubTab===t.id?THEME.purple+"88":"transparent"),background:defendSubTab===t.id?"rgba(124,85,255,0.1)":"transparent",color:defendSubTab===t.id?THEME.purple:THEME.textDim,cursor:"pointer",fontFamily:"inherit",fontSize:11,fontWeight:defendSubTab===t.id?700:400}}>{t.label}</button>
              ))}
            </div>

            {defendSubTab==="honey"&&(
              <div>
                {honeytokenLoading&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Designing honeytoken traps...</div>}
                {honeytokenErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{honeytokenErr}</div>}
                {!honeytokenLoading&&!honeytokenData&&!honeytokenErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🍯 Honey" to generate honeytoken traps that give 100% confidence alerts when triggered.</div>}
                {honeytokenData&&(
                  <div>
                    <div style={{marginBottom:14,padding:"12px 16px",background:"rgba(124,85,255,0.04)",border:"1px solid "+THEME.purple+"33",borderRadius:8}}>
                      <div style={{fontSize:12,color:THEME.textMid,marginBottom:4}}>{honeytokenData.coverage_benefit}</div>
                      <div style={{fontSize:11,color:THEME.textDim}}>Canary tokens: <a href={honeytokenData.canarytoken_url} target="_blank" rel="noopener noreferrer" style={{color:THEME.accent}}>canarytokens.org ↗</a></div>
                    </div>
                    {(honeytokenData.tokens||[]).map((t,i)=>(
                      <div key={i} style={{marginBottom:12,border:"1px solid "+THEME.border,borderRadius:8,overflow:"hidden"}}>
                        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 14px",background:"rgba(255,255,255,0.02)"}}>
                          <div>
                            <div style={{fontSize:12,fontWeight:700,color:THEME.text}}>{t.type}</div>
                            <div style={{fontSize:10,color:THEME.textDim}}>{t.platform} · Alert confidence: <span style={{color:THEME.success}}>{t.alert_confidence}</span></div>
                          </div>
                          <span style={S.badge(THEME.success)}>100% confidence</span>
                        </div>
                        <div style={{padding:"10px 14px",borderTop:"1px solid "+THEME.border}}>
                          <div style={{fontSize:11,color:THEME.textMid,marginBottom:8}}>{t.description}</div>
                          <div style={{fontSize:10,fontWeight:700,color:THEME.textDim,marginBottom:4}}>DEPLOY CMD</div>
                          <div style={{...S.code,fontSize:10,padding:"6px 10px",marginBottom:8}}>{t.deployment_cmd}</div>
                          <div style={{fontSize:10,fontWeight:700,color:THEME.textDim,marginBottom:4}}>DETECTION QUERY</div>
                          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                            <span style={{fontSize:10,color:THEME.textDim}}></span>
                            <div style={{display:"flex",gap:6}}><CopyBtn text={t.detection_query||""}/><button style={{...S.btn("p"),padding:"3px 10px",fontSize:10}} onClick={()=>t.detection_query&&applyQuery(t.detection_query,"honey")}>Use ↑</button></div>
                          </div>
                          <div style={S.code}>{t.detection_query}</div>
                        </div>
                      </div>
                    ))}
                    {honeytokenData.deployment_guide&&(
                      <div style={{padding:"12px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                        <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:6}}>DEPLOYMENT GUIDE</div>
                        <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.7}}>{honeytokenData.deployment_guide}</div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {defendSubTab==="sinkhole"&&(
              <div>
                {sinkholeLoading&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Generating DNS sinkhole configurations...</div>}
                {sinkholeErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{sinkholeErr}</div>}
                {!sinkholeLoading&&!sinkholeData&&!sinkholeErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🕳 Sinkhole" to generate RPZ zone files, Pi-hole lists, and Windows DNS configs for this threat.</div>}
                {sinkholeData&&(
                  <div>
                    <div style={{marginBottom:14}}>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.12em",marginBottom:8}}>INFERRED DOMAINS TO BLOCK ({(sinkholeData.inferred_domains||[]).length})</div>
                      <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>{(sinkholeData.inferred_domains||[]).map((d,i)=><span key={i} style={{...S.badge(THEME.danger),fontFamily:"monospace",fontSize:10}}>{d}</span>)}</div>
                    </div>
                    {[
                      {label:"Pi-hole Blocklist",key:"pihole_blocklist",color:THEME.success},
                      {label:"BIND9 RPZ Zone",key:"bind9_rpz",color:THEME.warning},
                      {label:"Windows DNS RPZ",key:"windows_dns_rpz",color:THEME.accent},
                      {label:"Unbound Config",key:"unbound_conf",color:THEME.purple},
                      {label:"Sinkhole Detection Query",key:"sinkhole_detection_query",color:THEME.danger},
                    ].map(({label,key,color})=>(
                      <div key={key} style={{marginBottom:10}}>
                        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                          <span style={{fontSize:10,fontWeight:800,color,letterSpacing:"0.1em"}}>{label}</span>
                          <div style={{display:"flex",gap:6}}>
                            <CopyBtn text={sinkholeData[key]||""}/>
                            {key==="sinkhole_detection_query"&&<button style={{...S.btn("p"),padding:"3px 10px",fontSize:10}} onClick={()=>sinkholeData[key]&&applyQuery(sinkholeData[key],"sinkhole")}>Use ↑</button>}
                          </div>
                        </div>
                        <div style={{...S.code,fontSize:10,padding:"8px 12px",whiteSpace:"pre-wrap"}}>{sinkholeData[key]||"Not generated."}</div>
                      </div>
                    ))}
                    {sinkholeData.deployment_steps&&(
                      <div style={{padding:"12px 14px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8}}>
                        <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:8}}>DEPLOYMENT STEPS</div>
                        {(sinkholeData.deployment_steps||[]).map((s,i)=><div key={i} style={{fontSize:12,color:THEME.textMid,marginBottom:4}}>{s}</div>)}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab==="workflow"&&(
          <div>
            {workflowLoading&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/> Designing automated response workflow...</div>}
            {workflowErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{workflowErr}</div>}
            {!workflowLoading&&!workflowData&&!workflowErr&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "⚡ Workflow" to generate an automated SOAR response workflow for this detection.</div>}
            {workflowData&&(
              <div>
                <div style={{marginBottom:14,padding:"12px 16px",background:"rgba(0,212,255,0.04)",border:"1px solid "+THEME.borderBright,borderRadius:8}}>
                  <div style={{fontSize:13,fontWeight:700,color:THEME.text,marginBottom:4}}>{workflowData.workflow_name}</div>
                  <div style={{fontSize:12,color:THEME.textMid}}>{workflowData.description}</div>
                  {workflowData.key_integrations?.length>0&&(
                    <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:8}}>
                      {workflowData.key_integrations.map((k,i)=><span key={i} style={S.badge(THEME.purple)}>{k}</span>)}
                    </div>
                  )}
                </div>

                {/* Sub-tabs */}
                <div style={{display:"flex",gap:4,marginBottom:14}}>
                  {[["visual","🔀 Visual"],["n8n","n8n JSON"],["xsoar","XSOAR"],["tines","Tines"]].map(([id,label])=>(
                    <button key={id} onClick={()=>setWorkflowSubTab(id)}
                      style={{padding:"6px 14px",borderRadius:6,border:"1px solid "+(workflowSubTab===id?THEME.accent+"88":"transparent"),background:workflowSubTab===id?"rgba(0,212,255,0.08)":"rgba(255,255,255,0.02)",color:workflowSubTab===id?THEME.accent:THEME.textDim,cursor:"pointer",fontFamily:"inherit",fontSize:11,fontWeight:workflowSubTab===id?700:400}}>
                      {label}
                    </button>
                  ))}
                </div>

                {workflowSubTab==="visual"&&(
                  <div style={{overflowX:"auto",paddingBottom:8}}>
                    {(() => {
                      const steps = workflowData.steps || [];
                      const edges = workflowData.edges || [];
                      const iconMap = { webhook:"🔔", code:"{}", globe:"🌐", ai:"🤖", merge:"⇄", decision:"◆", email:"✉", http:"🌐" };
                      const typeColor = { trigger:THEME.success, http:THEME.accent, ai:THEME.purple, transform:"#ff9900", decision:THEME.warning, notify:"#00ccff" };
                      // Group steps into columns for layout
                      const colOrder = ["trigger","extract","enrich1","enrich2","llm_analyze","merge","decision","block_action","update_siem","llm_report","notify","log_no_action"];
                      const ordered = colOrder.filter(id=>steps.find(s=>s.id===id)).map(id=>steps.find(s=>s.id===id));
                      const rest = steps.filter(s=>!colOrder.includes(s.id));
                      const allSteps = [...ordered,...rest];
                      return (
                        <div style={{display:"flex",alignItems:"flex-start",gap:0,minWidth:800,position:"relative"}}>
                          {allSteps.map((step,i)=>{
                            const color = typeColor[step.type]||THEME.textDim;
                            const isDecision = step.type==="decision";
                            return (
                              <div key={step.id} style={{display:"flex",alignItems:"center",flexShrink:0}}>
                                <div style={{display:"flex",flexDirection:"column",alignItems:"center"}}>
                                  <div style={{width:110,padding:"10px 8px",background:"rgba(255,255,255,0.04)",border:"1px solid "+color+"66",borderRadius:isDecision?0:8,transform:isDecision?"rotate(2deg)":"none",marginBottom:4,cursor:"default"}} title={step.description}>
                                    <div style={{fontSize:18,textAlign:"center",marginBottom:4}}>{iconMap[step.icon]||"⬡"}</div>
                                    <div style={{fontSize:10,fontWeight:700,color:color,textAlign:"center",lineHeight:1.3,marginBottom:2}}>{step.label}</div>
                                    {step.sublabel&&<div style={{fontSize:9,color:THEME.textDim,textAlign:"center",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:95}}>{step.sublabel}</div>}
                                  </div>
                                </div>
                                {i<allSteps.length-1&&<div style={{width:24,height:1,background:THEME.borderBright,flexShrink:0,position:"relative"}}><div style={{position:"absolute",right:-2,top:-4,fontSize:10,color:THEME.textDim}}>›</div></div>}
                              </div>
                            );
                          })}
                        </div>
                      );
                    })()}
                    <div style={{marginTop:16,display:"flex",gap:8,flexWrap:"wrap"}}>
                      {[["trigger","Trigger",THEME.success],["http","HTTP/API",THEME.accent],["ai","AI/LLM",THEME.purple],["transform","Transform","#ff9900"],["decision","Decision",THEME.warning],["notify","Notify","#00ccff"]].map(([t,label,color])=>(
                        <span key={t} style={{fontSize:10,color:color,display:"flex",alignItems:"center",gap:4}}><span style={{width:8,height:8,borderRadius:"50%",background:color,display:"inline-block"}}></span>{label}</span>
                      ))}
                    </div>
                    {/* Step details */}
                    <div style={{marginTop:16,display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                      {(workflowData.steps||[]).map(step=>(
                        <div key={step.id} style={{padding:"8px 12px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:6}}>
                          <div style={{fontSize:11,fontWeight:700,color:THEME.text,marginBottom:2}}>{step.label}</div>
                          <div style={{fontSize:11,color:THEME.textDim,lineHeight:1.5}}>{step.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {workflowSubTab==="n8n"&&(
                  <div>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{fontSize:11,color:THEME.textDim}}>Import this JSON into n8n (File → Import Workflow)</span>
                      <div style={{display:"flex",gap:6}}>
                        <CopyBtn text={JSON.stringify(workflowData.n8n_workflow||{name:workflowData.workflow_name,nodes:[],connections:{}},null,2)}/>
                        <button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>{const b=new Blob([JSON.stringify(workflowData.n8n_workflow||{name:workflowData.workflow_name,nodes:[],connections:{}},null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="detectiq-workflow.json";a.click();}}>⬇ Download</button>
                      </div>
                    </div>
                    <div style={S.code}>{JSON.stringify(workflowData.n8n_workflow||{name:workflowData.workflow_name,nodes:[],connections:{}},null,2)}</div>
                  </div>
                )}

                {workflowSubTab==="xsoar"&&(
                  <div>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{fontSize:11,color:THEME.textDim}}>Cortex XSOAR / Splunk SOAR playbook pseudocode</span>
                      <CopyBtn text={workflowData.xsoar_pseudocode||""}/>
                    </div>
                    <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap",padding:14,background:"#02040a",borderRadius:8,border:"1px solid "+THEME.border}}>{workflowData.xsoar_pseudocode||"No XSOAR config generated."}</div>
                  </div>
                )}

                {workflowSubTab==="tines"&&(
                  <div>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{fontSize:11,color:THEME.textDim}}>Tines story implementation guidance</span>
                      <CopyBtn text={workflowData.tines_description||""}/>
                    </div>
                    <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap",padding:14,background:"#02040a",borderRadius:8,border:"1px solid "+THEME.border}}>{workflowData.tines_description||"No Tines config generated."}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab==="deploy"&&(
          <div>
            {/* Query being deployed */}
            <div style={{marginBottom:14,padding:"10px 14px",background:queryModified?"rgba(0,255,136,0.05)":"rgba(255,255,255,0.02)",border:"1px solid "+(queryModified?"rgba(0,255,136,0.25)":THEME.border),borderRadius:8,display:"flex",alignItems:"flex-start",gap:10}}>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:10,fontWeight:800,letterSpacing:"0.1em",color:queryModified?THEME.success:THEME.textDim,marginBottom:4}}>{queryModified?"✓ IMPROVED QUERY WILL BE DEPLOYED":"ORIGINAL QUERY WILL BE DEPLOYED"}</div>
                <div style={{fontSize:11,fontFamily:"monospace",color:THEME.textMid,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{activeQuery.slice(0,120)}{activeQuery.length>120?"...":""}</div>
              </div>
              <button style={{...S.btn(),padding:"4px 10px",fontSize:10,flexShrink:0}} onClick={()=>setActiveTab("query")}>View / Edit ↗</button>
            </div>
            {/* Sub-tab row */}
            <div style={{display:"flex",gap:4,marginBottom:14,flexWrap:"wrap"}}>
              {[["test","🧪 Test"],["playbook","🎭 Playbook"],["ticket","🎫 Ticket"],["sigma","∑ Sigma AI"],["splunk","Splunk"],["elastic","Elastic"],["soar","SOAR"]].map(([id,label])=>(
                <button key={id} onClick={()=>setDeploySubTab(id)}
                  style={{padding:"6px 12px",borderRadius:6,border:"1px solid "+(deploySubTab===id?THEME.purple+"88":"transparent"),background:deploySubTab===id?"rgba(124,85,255,0.1)":"rgba(255,255,255,0.02)",color:deploySubTab===id?THEME.purple:THEME.textDim,cursor:"pointer",fontFamily:"inherit",fontSize:11,fontWeight:deploySubTab===id?700:400}}>
                  {label}
                </button>
              ))}
            </div>

            {/* BETA badge row */}
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:16}}>
              <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={runTest} disabled={testLoading}>{testLoading?<><Spinner/>Testing...</>:"🧪 Test Detection"}</button>
              <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={runPlaybook} disabled={generatingPlaybook}>{generatingPlaybook?<><Spinner/>Generating...</>:"🎭 Playbook"}</button>
              <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={runTicket} disabled={generatingTicket}>{generatingTicket?<><Spinner/>Generating...</>:"🎫 Create Ticket"}</button>
              <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={runSigmaAI} disabled={loadingSigma}>{loadingSigma?<><Spinner/>Exporting...</>:"∑ Sigma AI"}</button>
              <div style={{borderLeft:"1px solid "+THEME.border,margin:"0 4px"}}/>
              <button style={{...S.btn(),padding:"7px 14px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={()=>setDeploySubTab("splunk")}>Push to Splunk</button>
              <button style={{...S.btn(),padding:"7px 14px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={()=>setDeploySubTab("elastic")}>Push to Elastic</button>
              <button style={{...S.btn(),padding:"7px 14px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={()=>setDeploySubTab("soar")}>Push to SOAR</button>
            </div>

            {pushResult&&(pushResult.includes("LOCAL_NET")
              ? <div style={{marginBottom:12,padding:"12px 16px",background:"rgba(255,170,0,0.07)",border:"1px solid rgba(255,170,0,0.3)",borderRadius:8}}>
                  <div style={{fontSize:12,fontWeight:700,color:THEME.warning,marginBottom:4}}>⚠ Splunk is on your local network</div>
                  <div style={{fontSize:11,color:THEME.textMid,lineHeight:1.6}}>The cloud server can't resolve <code style={{color:THEME.accent}}>{splunkUrl}</code> — <code>.local</code> hostnames only work on your Mac's network.<br/>Use the <b>curl command below</b> — run it in your Mac terminal to push directly from your machine.</div>
                </div>
              : pushResult.includes("SSL_CERT:")
                ? <SslCertGuide url={pushResult.replace(/.*SSL_CERT:/,"")}/>
                : <div style={{marginBottom:12}}><StatusBar msg={pushResult.split(/:(.+)/)[1]||pushResult} type={pushResult.startsWith("success")?"success":"error"}/></div>
            )}

            {/* 🧪 Test */}
            {deploySubTab==="test"&&(
              <div>
                {testLoading&&<div style={{textAlign:"center",padding:24,color:THEME.textDim}}><Spinner/> Running detection test...</div>}
                {!testLoading&&!testResult&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🧪 Test Detection" to validate your detection logic.</div>}
                {testResult?.error&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8}}>{testResult.error}</div>}
                {testResult&&!testResult.error&&(
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:14,padding:"14px 18px",background:testResult.passed?"rgba(0,255,136,0.05)":"rgba(255,61,85,0.05)",border:"1px solid "+(testResult.passed?THEME.success+"33":THEME.danger+"33"),borderRadius:10}}>
                      <div style={{fontSize:28}}>{testResult.passed?"✅":"❌"}</div>
                      <div>
                        <div style={{fontSize:14,fontWeight:700,color:testResult.passed?THEME.success:THEME.danger}}>{testResult.passed?"Detection Passed":"Detection Issues Found"}</div>
                        <div style={{fontSize:12,color:THEME.textMid,marginTop:2}}>{testResult.summary}</div>
                      </div>
                    </div>
                    {testResult.issues?.length>0&&<div style={{marginBottom:12}}>{testResult.issues.map((iss,i)=><div key={i} style={{fontSize:12,color:THEME.warning,padding:"6px 10px",background:"rgba(255,170,0,0.05)",borderRadius:6,marginBottom:4}}>⚠ {iss}</div>)}</div>}
                    {testResult.suggestions?.length>0&&<div>{testResult.suggestions.map((s,i)=><div key={i} style={{fontSize:12,color:THEME.textMid,padding:"6px 10px",background:"rgba(255,255,255,0.02)",borderRadius:6,marginBottom:4,borderLeft:"2px solid "+THEME.accent+"44"}}>→ {s}</div>)}</div>}
                  </div>
                )}
              </div>
            )}

            {/* 🎭 Playbook */}
            {deploySubTab==="playbook"&&(
              <div>
                {generatingPlaybook&&<div style={{textAlign:"center",padding:24,color:THEME.textDim}}><Spinner/> Generating IR playbook...</div>}
                {!generatingPlaybook&&!playbookContent&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🎭 Playbook" to generate a SOAR response playbook.</div>}
                {playbookContent&&<div style={{fontSize:12,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap",padding:14,background:"#02040a",borderRadius:8,border:"1px solid "+THEME.border}}><div style={{display:"flex",justifyContent:"flex-end",marginBottom:8}}><CopyBtn text={playbookContent}/></div>{playbookContent}</div>}
              </div>
            )}

            {/* 🎫 Ticket */}
            {deploySubTab==="ticket"&&(
              <div>
                {generatingTicket&&<div style={{textAlign:"center",padding:24,color:THEME.textDim}}><Spinner/> Generating JIRA/ServiceNow ticket...</div>}
                {!generatingTicket&&!ticketContent&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "🎫 Create Ticket" to generate a deployment ticket.</div>}
                {ticketContent&&<div style={{fontSize:12,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap",padding:14,background:"#02040a",borderRadius:8,border:"1px solid "+THEME.border}}><div style={{display:"flex",justifyContent:"flex-end",marginBottom:8}}><CopyBtn text={ticketContent}/></div>{ticketContent}</div>}
              </div>
            )}

            {/* ∑ Sigma AI */}
            {deploySubTab==="sigma"&&(
              <div>
                {loadingSigma&&<div style={{textAlign:"center",padding:24,color:THEME.textDim}}><Spinner/> Generating Sigma rule...</div>}
                {!loadingSigma&&!sigmaContent&&<div style={{textAlign:"center",padding:32,color:THEME.textDim,fontSize:13}}>Click "∑ Sigma AI" to export as a Sigma rule.</div>}
                {sigmaContent&&(
                  <div style={{position:"relative"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{fontSize:11,color:THEME.textDim}}>Sigma Rule (YAML)</span>
                      <div style={{display:"flex",gap:6}}>
                        <CopyBtn text={sigmaContent}/>
                        <button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>{const b=new Blob([sigmaContent],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=(detName||"detection").replace(/\s+/g,"_")+".yml";a.click();}}>⬇ Download</button>
                      </div>
                    </div>
                    <div style={S.code}>{sigmaContent}</div>
                  </div>
                )}
              </div>
            )}

            {/* Splunk */}
            {deploySubTab==="splunk"&&(
              <div style={{display:"grid",gap:10}}>
                <div style={{fontSize:11,color:THEME.textDim}}>Push this detection as a Splunk saved search / alert.</div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}>
                  <span style={{fontSize:11,color:THEME.textMid,width:80}}>Auth Mode</span>
                  <select style={{...S.input,flex:1}} value={splunkAuthMode} onChange={e=>setSplunkAuthMode(e.target.value)}>
                    <option value="token">Bearer Token</option>
                    <option value="basic">Username / Password</option>
                  </select>
                </div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:80}}>Splunk URL</span><input style={{...S.input,flex:1}} value={splunkUrl} onChange={e=>setSplunkUrl(e.target.value)} placeholder="https://your-splunk:8089"/></div>
                {splunkAuthMode==="token"
                  ? <div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:80}}>Token</span><input style={{...S.input,flex:1}} type="password" value={splunkToken} onChange={e=>setSplunkToken(e.target.value)} placeholder="Splunk HEC/API token"/></div>
                  : <><div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:80}}>Username</span><input style={{...S.input,flex:1}} value={splunkUser} onChange={e=>setSplunkUser(e.target.value)} placeholder="admin"/></div><div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:80}}>Password</span><input style={{...S.input,flex:1}} type="password" value={splunkPass} onChange={e=>setSplunkPass(e.target.value)}/></div></>
                }
                <button style={{...S.btn("p"),padding:"9px 20px",alignSelf:"flex-start"}} onClick={pushToSplunk} disabled={pushing}>{pushing?<><Spinner/>Pushing...</>:"Push to Splunk"}</button>
                {/* curl fallback */}
                <div style={{marginTop:4}}>
                  <div onClick={()=>setShowCurlCmd(o=>!o)} style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer",padding:"6px 0"}}>
                    <span style={{fontSize:10,color:THEME.textDim,transform:showCurlCmd?"rotate(90deg)":"rotate(0deg)",display:"inline-block",transition:"transform 0.15s"}}>›</span>
                    <span style={{fontSize:11,color:THEME.textDim}}>📋 Copy as curl command <span style={{color:THEME.warning}}>(run this on your Mac if Splunk is local)</span></span>
                  </div>
                  {showCurlCmd&&(()=>{
                    const det=buildDet();const q=(det.query||"").replace(/'/g,"'\\''");
                    const authFlag=splunkAuthMode==="basic"?`-u '${splunkUser||"admin"}:${splunkPass||"password"}'`:`-H 'Authorization: Bearer ${splunkToken||"<token>"}'`;
                    const url=(splunkUrl||"https://splunk:8089").replace(/\/$/,"");
                    const name=(det.name||"detection").replace(/'/g,"'\\''");
                    const cmd=`#!/bin/bash\nSPLUNK_QUERY='${q}'\n\ncurl -k -X POST '${url}/services/saved/searches' \\\n  ${authFlag} \\\n  --data-urlencode "name=${name}" \\\n  --data-urlencode "search=$SPLUNK_QUERY" \\\n  -d 'is_scheduled=1' \\\n  -d 'cron_schedule=*/15 * * * *' \\\n  -d 'dispatch.earliest_time=-15m' \\\n  -d 'dispatch.latest_time=now'`;
                    return(<div style={{position:"relative",marginTop:4}}>
                      <div style={{fontSize:10,color:THEME.textDim,marginBottom:4}}>Save as <code>push.sh</code>, then run: <code>chmod +x push.sh && ./push.sh</code></div>
                      <pre style={{...S.code,fontSize:10,lineHeight:1.6,whiteSpace:"pre-wrap",wordBreak:"break-all",paddingRight:60}}>{cmd}</pre>
                      <button style={{position:"absolute",top:28,right:6,...S.btn("p"),padding:"4px 10px",fontSize:10}} onClick={()=>navigator.clipboard.writeText(cmd)}>Copy</button>
                    </div>);
                  })()}</div>
              </div>
            )}

            {/* Elastic */}
            {deploySubTab==="elastic"&&(
              <div style={{display:"grid",gap:10}}>
                <div style={{fontSize:11,color:THEME.textDim}}>Push this detection as a Kibana detection rule.</div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:80}}>Kibana URL</span><input style={{...S.input,flex:1}} value={elasticUrl} onChange={e=>setElasticUrl(e.target.value)} placeholder="https://your-kibana:5601"/></div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:80}}>API Key</span><input style={{...S.input,flex:1}} type="password" value={elasticToken} onChange={e=>setElasticToken(e.target.value)} placeholder="base64 of id:api_key"/></div>
                <button style={{...S.btn("p"),padding:"9px 20px",alignSelf:"flex-start"}} onClick={pushToElastic} disabled={pushing}>{pushing?<><Spinner/>Pushing...</>:"Push to Elastic"}</button>
              </div>
            )}

            {/* SOAR */}
            {deploySubTab==="soar"&&(
              <div style={{display:"grid",gap:10}}>
                <div style={{fontSize:11,color:THEME.textDim}}>Send this detection as a webhook payload to your SOAR platform (Splunk SOAR, XSOAR, Tines, n8n, etc).</div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:100}}>Webhook URL</span><input style={{...S.input,flex:1}} value={soarUrl} onChange={e=>setSoarUrl(e.target.value)} placeholder="https://your-soar/webhook/..."/></div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:11,color:THEME.textMid,width:100}}>Token (opt)</span><input style={{...S.input,flex:1}} type="password" value={soarToken} onChange={e=>setSoarToken(e.target.value)} placeholder="Optional bearer token"/></div>
                <button style={{...S.btn("p"),padding:"9px 20px",alignSelf:"flex-start"}} onClick={pushToSOAR} disabled={pushing}>{pushing?<><Spinner/>Pushing...</>:"Push to SOAR"}</button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Detection Builder ─────────────────────────────────────────────────────────
const TACTIC_KEYWORDS={
  "Reconnaissance":["scan","recon","nmap","sweep","port scan","network scan","ip range","fingerprint","enumerat","shodan","censys","probe"],
  "Resource Development":["c2 infra","domain reg","phishing kit","malware dev","exploit kit","stage infra"],
  "Initial Access":["phishing","spearphish","exploit public","drive-by","supply chain","watering hole","external service","vpn exploit","rdp exploit","initial access"],
  "Execution":["powershell","cmd.exe","wscript","cscript","scheduled task","wmi exec","rundll","regsvr32","mshta","command exec","script exec","invoke-","shellcode"],
  "Persistence":["registry run","startup","autorun","scheduled task","service install","cron","persistence","boot","logon script","winlogon"],
  "Privilege Escalation":["privilege esc","uac bypass","token impersonat","sudo","suid","juicypotato","printspoofer","escalat","privesc","admin access","local admin"],
  "Defense Evasion":["obfuscat","encode","base64","lolbas","timestomp","clear log","disable av","amsi","etw bypass","process inject","masquerad","unhook","packer"],
  "Credential Access":["lsass","mimikatz","credential dump","password spray","brute force","kerberoast","pass-the-hash","pth","golden ticket","ntlm","hashcat","secretsdump","credential"],
  "Discovery":["net user","whoami","ipconfig","systeminfo","net group","ldap query","bloodhound","sharphound","adrecon","net localgroup","tasklist","netstat","discovery"],
  "Lateral Movement":["psexec","wmiexec","lateral","remote service","dcom","smb exec","rdp lateral","move laterally","pass-the-ticket"],
  "Collection":["keylog","screenshot","clipboard","archive","zip collect","data collect","email collect","browser history","stage data"],
  "Command and Control":["c2","beacon","cobalt strike","dns tunnel","http tunnel","reverse shell","c&c","cobaltstrike","metasploit","empire","command and control","implant"],
  "Exfiltration":["exfil","data theft","exfiltrat","ftp upload","data leak","dns exfil","http post data","upload sensitive"],
  "Impact":["ransomware","encrypt file","shadow copy","disk wipe","defac","dos attack","ddos","destruct","wiper","delete backup","data destroy"],
};
const SEVERITY_KEYWORDS={
  "Critical":["ransomware","shadow copy","domain admin","domain controller","dc compromise","golden ticket","encrypt file","disk wipe","wiper"],
  "High":["lsass","mimikatz","privilege esc","c2","beacon","psexec","credential dump","kerberoast","lateral movement","cobalt","pass-the-hash","reverse shell"],
  "Medium":["phishing","brute force","password spray","recon","scan","discovery","scheduled task","persistence","registry"],
  "Low":["whoami","systeminfo","ipconfig","net user","tasklist","netstat","ping","nslookup"],
};
function inferTacticAndSeverity(text){
  const t=text.toLowerCase();
  let bestTactic=null,bestScore=0;
  for(const[tac,kws] of Object.entries(TACTIC_KEYWORDS)){
    const score=kws.filter(k=>t.includes(k)).length;
    if(score>bestScore){bestScore=score;bestTactic=tac;}
  }
  let bestSev="Medium";
  for(const[sev,kws] of Object.entries(SEVERITY_KEYWORDS)){
    if(kws.some(k=>t.includes(k))){bestSev=sev;break;}
  }
  return{tactic:bestTactic,severity:bestSev};
}

function DetectionBuilder({onSave, onSendToTriage, prefill}){
  const[threat,setThreat]=useState("");
  const[logSample,setLogSample]=useState("");
  const[selectedTool,setSelectedTool]=useState(TOOLS[0]);
  const[tactic,setTactic]=useState("Execution");
  const[stage,setStage]=useState(0);
  const[ads,setAds]=useState(null);
  const[schema,setSchema]=useState([]);
  const[loading,setLoading]=useState(false);
  const[err,setErr]=useState("");
  const[detName,setDetName]=useState("");
  const[severity,setSeverity]=useState("Medium");
  const[beginner,setBeginner]=useState(false);
  const[viewMode,setViewMode]=useState("ads");
  const[streamTokens,setStreamTokens]=useState(0);
  const[tacticAuto,setTacticAuto]=useState(false);
  const[severityAuto,setSeverityAuto]=useState(false);

  useEffect(()=>{
    if(prefill?.scenario){
      setThreat(prefill.scenario);
      if(prefill.tactic){setTactic(prefill.tactic);setTacticAuto(false);}
    }
  },[prefill]);

  // Auto-detect tactic + severity from threat text (debounced 500ms)
  useEffect(()=>{
    if(!threat.trim()||threat.length<8)return;
    const timer=setTimeout(()=>{
      const{tactic:t,severity:s}=inferTacticAndSeverity(threat);
      if(t){setTactic(t);setTacticAuto(true);}
      setSeverity(s);setSeverityAuto(true);
    },500);
    return()=>clearTimeout(timer);
  },[threat]);

  async function extractSchema(s){if(!s.trim())return[];try{const t=await callClaude([{role:"user",content:"Extract field names from this log. Return ONLY a JSON array of strings.\n"+s}],"",300);const m=t.match(/\[[\s\S]*\]/);return m?JSON.parse(m[0]):[];}catch{return[];}}

  async function runPipeline(){
    if(!threat.trim()){setErr("Enter a threat scenario.");return;}
    setErr("");setLoading(true);setAds(null);
    try{
      setStage(1);
      const fields=logSample?await extractSchema(logSample):[];
      setSchema(fields);
      const hint=fields.length?"Use these exact field names: "+fields.join(", "):"";
      setStage(2);

      const adsPrompt = `Generate an Attack Detection Strategy (ADS) for this threat. Be concise throughout.

Threat: ${threat}
MITRE Tactic: ${tactic}
Target SIEM: ${selectedTool.name} (${selectedTool.lang})
${hint}

Return ONLY valid JSON:
{
  "technique_name": "short name",
  "mitre_id": "T####",
  "summary": "one sentence",
  "attack_overview": "2-3 sentences total",
  "observable_behaviors": "3-4 bullet points, one line each",
  "simulated_events": ["1-2 realistic log entries for ${selectedTool.name}"],
  "detection_query": "production-ready ${selectedTool.lang} query",
  "false_positive_guidance": "2-3 scenarios, one line each",
  "tuning_tips": "2-3 tips, one line each",
  "references": "MITRE URL + 1-2 technique IDs"
}`;

      setStreamTokens(0);
      const result = await callClaudeStream([{role:"user",content:adsPrompt}], "Expert detection engineer. Return ONLY valid JSON, no markdown.", 5000,
        (partial)=>setStreamTokens(partial.length)
      );
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if(!jsonMatch) throw new Error("Could not parse response. Try again.");
      let adsData;
      try { adsData = JSON.parse(jsonMatch[0]); }
      catch(_){
        // fix common Claude JSON issues: bad escapes, control chars, trailing commas
        const fixed = jsonMatch[0]
          .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,"")
          .replace(/,\s*([\]}])/g,"$1")
          .replace(/(?<!\\)\\(?!["\\/bfnrtu])/g,"\\\\");
        adsData = JSON.parse(fixed);
      }
      setAds(adsData);
      setDetName(adsData.technique_name || "Detect " + threat.slice(0,40));
      setStage(3);
    }catch(e){setErr("Pipeline failed: "+e.message);setStage(0);}
    setLoading(false);
  }

  function handleSave(){
    if(!ads)return;
    onSave({id:uid(),name:detName||"Detect "+threat.slice(0,40),threat,tactic,queryType:selectedTool.lang,tool:selectedTool.id,query:ads.detection_query||"",severity,schema,score:0,tags:[tactic,selectedTool.lang],ads,created:new Date().toISOString()});
    alert("Saved to library!");
  }

  const stageColors=[THEME.textDim,THEME.accent,THEME.purple,THEME.success];

  return(
    <div>
      <SectionHeader icon="🔨" title="AI Detection Builder" color={THEME.accent}>
        <div style={S.flex}>
          <div style={{display:"flex",alignItems:"center",gap:8,padding:"6px 12px",borderRadius:8,border:"1px solid "+(beginner?THEME.warning+"66":THEME.border),background:beginner?THEME.warningGlow:"transparent",cursor:"pointer",transition:"all 0.2s"}} onClick={()=>setBeginner(!beginner)}>
            <div style={{width:28,height:16,borderRadius:8,background:beginner?THEME.warning:THEME.border,transition:"background 0.2s",position:"relative"}}>
              <div style={{width:12,height:12,borderRadius:"50%",background:"#fff",position:"absolute",top:2,left:beginner?14:2,transition:"left 0.2s"}}/>
            </div>
            <span style={{fontSize:11,fontWeight:700,color:beginner?THEME.warning:THEME.textDim}}>Beginner Mode</span>
          </div>
          <span style={S.badge(THEME.accent)}>ADS Framework</span>
        </div>
      </SectionHeader>
      <HelpBox title="Builder Quick Reference" color={THEME.accent} items={[
        {icon:"🎯",title:"Threat Scenario",desc:"Describe the attack behavior in plain English (e.g. 'Mimikatz LSASS dump via cmd.exe'). The more specific, the better the query. Include process names, tactics, or known malware if relevant."},
        {icon:"📋",title:"Log Sample",desc:"Paste a real log line from your SIEM. DetectIQ will ground the query in your actual field names and data structure, avoiding generic templates that need heavy tuning."},
        {icon:"🏅",title:"Score",desc:"Rates the detection on specificity, coverage, FP risk, and data source quality (1-10). Aim for 7+."},
        {icon:"🧠",title:"ML/UBA",desc:"Generates a behavioral baseline rule that catches anomalies instead of static IOCs — harder for attackers to evade. Also produces Risk Scores and RBA rules."},
        {icon:"💥",title:"Blast Radius",desc:"Estimates how many alerts per day this rule would generate across different org sizes. Run this before deploying to avoid alert fatigue."},
        {icon:"⚠️",title:"False Positive Estimator",desc:"AI predicts the most common legitimate activities that would trigger this rule, and generates exclusion logic to suppress them."},
        {icon:"🔧",title:"LOTL",desc:"Living-off-the-Land coverage — generates detections for built-in OS tools (PowerShell, WMI, certutil) that attackers abuse to blend in."},
      ]}/>

      <div style={S.card}>
        <ToolSelector selected={selectedTool} onSelect={setSelectedTool}/>
        <div style={S.grid2}>
          <div><label style={S.label}>Threat Scenario</label><textarea style={{...S.textarea,minHeight:80}} value={threat} onChange={e=>setThreat(e.target.value)} placeholder="e.g. Mimikatz LSASS credential dumping, PowerShell encoded execution..."/></div>
          <div><label style={S.label}>Log Sample (optional)</label><textarea style={{...S.textarea,minHeight:80}} value={logSample} onChange={e=>setLogSample(e.target.value)} placeholder={"Paste a real "+selectedTool.name+" log to ground the query"}/></div>
        </div>
        <div style={{...S.grid2,marginTop:12}}>
          <div>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <label style={{...S.label,marginBottom:0}}>MITRE Tactic</label>
              {tacticAuto&&<span style={{fontSize:9,fontWeight:700,padding:"1px 7px",borderRadius:4,background:"rgba(0,212,255,0.12)",border:"1px solid rgba(0,212,255,0.3)",color:THEME.accent}}>AUTO</span>}
            </div>
            <select style={S.input} value={tactic} onChange={e=>{setTactic(e.target.value);setTacticAuto(false);}}>{TACTICS.map(t=><option key={t}>{t}</option>)}</select>
          </div>
          <div>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <label style={{...S.label,marginBottom:0}}>Severity</label>
              {severityAuto&&<span style={{fontSize:9,fontWeight:700,padding:"1px 7px",borderRadius:4,background:"rgba(255,170,0,0.12)",border:"1px solid rgba(255,170,0,0.3)",color:THEME.warning}}>AUTO</span>}
            </div>
            <select style={S.input} value={severity} onChange={e=>{setSeverity(e.target.value);setSeverityAuto(false);}}>{SEVERITIES.map(s=><option key={s}>{s}</option>)}</select>
          </div>
        </div>
        {schema.length>0&&<div style={{marginTop:10}}><label style={S.label}>Schema Fields</label><div style={{display:"flex",flexWrap:"wrap"}}>{schema.map(f=><span key={f} style={S.tag}>{f}</span>)}</div></div>}

        {stage>0&&(
          <div style={{marginTop:14,display:"flex",gap:6}}>
            {["Analysis","ADS Generation","Complete"].map((s,i)=>(
              <div key={s} style={{flex:1,padding:"6px 10px",borderRadius:7,background:stage>i?stageColors[i+1]+"15":"rgba(255,255,255,0.02)",border:"1px solid "+(stage>i?stageColors[i+1]+"44":THEME.border),textAlign:"center",fontSize:11,color:stage>i?stageColors[i+1]:THEME.textDim,fontWeight:stage>i?700:400,transition:"all 0.3s"}}>
                {stage>i?"✓ ":stage===i+1?<Spinner/>:""}{s}
              </div>
            ))}
          </div>
        )}
        <div style={{marginTop:14,display:"flex",alignItems:"center",gap:12}}>
          <button style={{...S.btn("p"),padding:"11px 26px",fontSize:13}} onClick={runPipeline} disabled={loading}>{loading&&<Spinner/>}{loading?`Generating ADS... (${streamTokens} chars)`:"Generate ADS"}</button>
          {stage===3&&<span style={{fontSize:12,color:THEME.success,fontWeight:700}}>ADS ready!</span>}
        </div>
        {err&&<StatusBar msg={err} type="error"/>}
      </div>

      {ads&&(
        <>
          <div style={{display:"flex",gap:6,marginBottom:12}}>
            <button style={{...S.btn(viewMode==="ads"?"p":""),padding:"7px 14px",fontSize:11}} onClick={()=>setViewMode("ads")}>ADS View</button>
            <button style={{...S.btn(viewMode==="raw"?"p":""),padding:"7px 14px",fontSize:11}} onClick={()=>setViewMode("raw")}>Raw Query Only</button>
          </div>
          {viewMode==="ads"&&<ADSResult ads={ads} threat={threat} tactic={tactic} tool={selectedTool} onSave={handleSave} detName={detName} setDetName={setDetName} severity={severity} beginner={beginner} onSendToTriage={onSendToTriage}/>}
          {viewMode==="raw"&&<div style={S.card}><div style={{...S.row,marginBottom:14}}><div style={S.cardTitle}><span>⚡</span> {selectedTool.lang} Query</div><div style={S.flex}><CopyBtn text={ads.detection_query||""}/><button style={S.btn("s")} onClick={handleSave}>Save</button></div></div><div style={S.code}>{ads.detection_query||""}</div></div>}
        </>
      )}
    </div>
  );
}

// ── Attack Simulator ──────────────────────────────────────────────────────────
function AttackSimulator({ onSendToTriage, onSendToBuilder, prefill }) {
  const[scenario,setScenario]=useState("");
  const[selectedTool,setSelectedTool]=useState(TOOLS[0]);
  const[tactic,setTactic]=useState("Execution");
  const[events,setEvents]=useState(null);
  const[loading,setLoading]=useState(false);
  const[err,setErr]=useState("");
  const[sentEvents,setSentEvents]=useState({});
  const[activeLog,setActiveLog]=useState(null);
  const[copyMode,setCopyMode]=useState("raw");
  const[streamTokens,setStreamTokens]=useState(0);
  const[tacticAuto,setTacticAuto]=useState(false);

  useEffect(()=>{
    if(prefill?.scenario){setScenario(prefill.scenario);if(prefill.tactic){setTactic(prefill.tactic);setTacticAuto(false);}}
  },[prefill]);

  useEffect(()=>{
    if(!scenario.trim()||scenario.length<8)return;
    const timer=setTimeout(()=>{
      const{tactic:t}=inferTacticAndSeverity(scenario);
      if(t){setTactic(t);setTacticAuto(true);}
    },500);
    return()=>clearTimeout(timer);
  },[scenario]);

  const QUICK_SCENARIOS=[
    {label:"Mimikatz LSASS Dump",tactic:"Credential Access"},
    {label:"PowerShell Encoded Payload",tactic:"Execution"},
    {label:"RDP Brute Force",tactic:"Credential Access"},
    {label:"PsExec Lateral Movement",tactic:"Lateral Movement"},
    {label:"Ransomware Shadow Copy Delete",tactic:"Impact"},
    {label:"DNS Tunneling C2",tactic:"Command and Control"},
    {label:"DCSync Attack",tactic:"Credential Access"},
    {label:"Registry Persistence",tactic:"Persistence"},
    {label:"WMI Remote Execution",tactic:"Execution"},
    {label:"Kerberoasting",tactic:"Credential Access"},
    {label:"LOLBAS CertUtil Download",tactic:"Defense Evasion"},
    {label:"Pass-the-Hash NTLM",tactic:"Lateral Movement"},
  ];

  // Per-platform log format instructions
  const LOG_FORMAT_HINTS = {
    splunk: `Generate Splunk-style logs. Each log_event must be formatted EXACTLY like real Splunk search results:
index=wineventlog sourcetype=WinEventLog:Security EventCode=4688 ComputerName=CORP-PC01 SubjectUserName=jsmith ProcessName=C:/Windows/System32/cmd.exe ParentProcessName=C:/Windows/explorer.exe CommandLine="cmd.exe /c whoami" _time=2024-01-15T14:23:01.342Z
Use real Splunk field names: index, sourcetype, EventCode, ComputerName, SubjectUserName, ProcessName, CommandLine, _time, src_ip, dest_ip, bytes, action`,

    sentinel: `Generate Microsoft Sentinel KQL table rows. Each log_event must look like a real Sentinel table row:
TimeGenerated: 2024-01-15T14:23:01.342Z | Computer: CORP-PC01 | EventID: 4688 | Account: CORP\\jsmith | Process: cmd.exe | CommandLine: cmd.exe /c whoami | ParentProcess: explorer.exe | IpAddress: 10.10.1.45 | LogonType: 3
Use real Sentinel table fields from SecurityEvent, DeviceProcessEvents, SigninLogs, DeviceNetworkEvents`,

    crowdstrike: `Generate CrowdStrike Falcon event format. Each log_event must look like real Falcon telemetry:
#event_simpleName=ProcessRollup2 timestamp=1705329781342 ComputerName=CORP-PC01 UserName=jsmith UserSid=S-1-5-21-... ImageFileName=\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe CommandLine="cmd.exe /c whoami" ParentBaseFileName=explorer.exe MD5HashData=abc123... SHA256HashData=def456...
Use real CrowdStrike field names: #event_simpleName, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, MD5HashData`,

    logscale: `Generate Falcon LogScale (Humio) format. Each log_event must look like real LogScale output:
@timestamp=2024-01-15T14:23:01.342Z #type=windowsevent EventID=4688 ComputerName=CORP-PC01 UserName=CORP\\jsmith ImagePath=C:/Windows/System32/cmd.exe CommandLine="cmd.exe /c whoami" ParentImagePath=C:/Windows/explorer.exe IntegrityLevel=High
Use real LogScale fields with # prefixed type fields`,

    elastic: `Generate Elastic ECS (Elastic Common Schema) format. Each log_event must be a real ECS JSON-style record:
{"@timestamp":"2024-01-15T14:23:01.342Z","event.category":"process","event.type":"start","host.name":"CORP-PC01","user.name":"jsmith","process.name":"cmd.exe","process.command_line":"cmd.exe /c whoami","process.parent.name":"explorer.exe","process.pid":4821,"process.executable":"C:/Windows/System32/cmd.exe"}
Use proper ECS field names: event.category, event.type, host.name, user.name, process.name, process.command_line`,

    qradar: `Generate IBM QRadar AQL event format. Each log_event must look like a real QRadar event:
sourceip=10.10.1.45 destinationip=10.10.1.10 username=CORP\\jsmith eventname="Windows: Process Created" devicetype=WindowsAuthServer magnitude=7 credibility=10 severity=8 starttime=1705329781342 EventID=4688 ProcessName=cmd.exe CommandLine="cmd.exe /c whoami"
Use real QRadar field names: sourceip, destinationip, username, eventname, magnitude, severity, EventID`,

    chronicle: `Generate Google Chronicle YARA-L compatible event format. Each log_event must look like real Chronicle UDM:
metadata.event_timestamp: 2024-01-15T14:23:01.342Z | metadata.event_type: PROCESS_LAUNCH | principal.hostname: CORP-PC01 | principal.user.userid: jsmith | target.process.file.full_path: C:/Windows/System32/cmd.exe | target.process.command_line: cmd.exe /c whoami | src.ip: 10.10.1.45
Use real Chronicle UDM fields: metadata.event_type, principal.hostname, target.process, src.ip`,

    tanium: `Generate Tanium Signal event format. Each log_event must look like real Tanium Signals output:
timestamp=2024-01-15T14:23:01.342Z computer_name=CORP-PC01 user_name=CORP\\jsmith process_name=cmd.exe process_command_line="cmd.exe /c whoami" parent_process_name=explorer.exe process_id=4821 parent_process_id=1234 file_path=C:/Windows/System32/cmd.exe hash_md5=abc123
Use Tanium field names: computer_name, user_name, process_name, process_command_line, parent_process_name`,

    panther: `Generate Panther Python rule compatible log format. Each log_event must look like a real JSON event Panther would receive:
{"timestamp":"2024-01-15T14:23:01.342Z","eventType":"PROCESS_CREATED","hostName":"CORP-PC01","userName":"jsmith","processName":"cmd.exe","commandLine":"cmd.exe /c whoami","parentProcess":"explorer.exe","processId":4821,"sourceIPAddress":"10.10.1.45","severity":"HIGH","ruleId":"aws_root_activity"}
Use JSON format with Panther-compatible field names`,

    sumo: `Generate Sumo Logic log format. Each log_event must look like real Sumo Logic parsed output:
_sourceCategory=windows/security _sourceName=WinEventLog:Security _collector=CORP-PC01 EventCode=4688 TimeGenerated=2024-01-15T14:23:01.342Z AccountName=jsmith ProcessName=cmd.exe CommandLine="cmd.exe /c whoami" ParentProcessName=explorer.exe IpAddress=10.10.1.45
Use Sumo Logic field names: _sourceCategory, _sourceName, EventCode, AccountName, ProcessName, CommandLine`,
  };

  async function simulate(){
    if(!scenario.trim()){setErr("Enter an attack scenario.");return;}
    setErr("");setLoading(true);setEvents(null);setSentEvents({});setActiveLog(null);

    const formatHint = LOG_FORMAT_HINTS[selectedTool.id] || LOG_FORMAT_HINTS.splunk;

    try{
      const prompt=`You are a security expert generating realistic SIEM log data for detection engineering training.

Attack scenario: ${scenario}
SIEM Platform: ${selectedTool.name} (${selectedTool.lang})
MITRE Tactic: ${tactic}

CRITICAL LOG FORMAT REQUIREMENT:
${formatHint}

Return ONLY valid JSON with NO backslashes except in log_event strings where they are absolutely required:
{
  "attack_name": "specific name of this attack technique",
  "mitre_id": "T####.###",
  "mitre_tactic": "${tactic}",
  "summary": "2 sentences describing exactly what the attacker does",
  "timeline": [
    {
      "time_offset": "T+0s",
      "stage": "MITRE tactic name",
      "description": "specific action taken by attacker",
      "log_event": "EXACT ${selectedTool.name} format log entry with realistic field values - follow the format example above precisely",
      "key_fields": ["field1: suspicious_value", "field2: suspicious_value"],
      "why_suspicious": "one sentence explaining why this specific log entry indicates malicious activity"
    }
  ],
  "iocs": ["specific IOC 1", "specific IOC 2", "specific IOC 3", "specific IOC 4"],
  "detection_hint": "specific ${selectedTool.lang} field and value to alert on",
  "hunt_query": "one-line ${selectedTool.lang} search query to find this activity"
}

Generate exactly 5 timeline steps. Each log_event must be 100% realistic ${selectedTool.name} format.`;

      setStreamTokens(0);
      const result=await callClaudeStream([{role:"user",content:prompt}],"Expert SIEM engineer and red teamer. Return ONLY valid JSON.",4000,
        (partial)=>setStreamTokens(partial.length)
      );
      const m=result.match(/\{[\s\S]*\}/);
      if(!m) throw new Error("Could not parse response.");

      // Nuclear JSON fixer
      function fixJson(s){
        let out="";let inStr=false;let i=0;
        while(i<s.length){
          const ch=s[i];
          if(ch==='"'&&(i===0||s[i-1]!=="\\")){inStr=!inStr;}
          if(inStr&&ch==="\\"){
            const next=s[i+1];
            if(next&&'"\\/bfnrtu'.includes(next)){out+=ch+next;i+=2;}
            else{out+="\\\\";i++;}
          }else{out+=ch;i++;}
        }
        return out;
      }
      let parsed;
      try{parsed=JSON.parse(m[0]);}
      catch(e){
        try{parsed=JSON.parse(fixJson(m[0]));}
        catch(e2){throw new Error("Could not parse simulation response. Try again.");}
      }
      setEvents(parsed);
      setActiveLog(0);
    }catch(e){setErr("Simulation failed: "+e.message);}
    setLoading(false);
  }

  function sendToTriage(logEvent,idx){
    onSendToTriage(logEvent);
    setSentEvents(p=>({...p,[idx]:true}));
  }

  const STAGE_COLOR={"Initial Access":THEME.danger,"Execution":"#ff7700","Persistence":THEME.warning,"Privilege Escalation":"#ffcc00","Defense Evasion":THEME.purple,"Credential Access":"#ff55aa","Discovery":THEME.accent,"Lateral Movement":"#00aaff","Collection":"#00ccaa","Command and Control":THEME.success,"Exfiltration":"#88ff00","Impact":THEME.danger};

  const activeStep = events?.timeline?.[activeLog];

  return(
    <div>
      <SectionHeader icon="🎯" title="Attack Simulator" color={THEME.danger}>
        <div style={S.flex}>
          <span style={S.badge(THEME.danger)}>Real Log Formats</span>
          <span style={S.badge(selectedTool.color)}>{selectedTool.lang}</span>
        </div>
      </SectionHeader>

      <div style={S.card}>
        {/* Quick scenarios */}
        <label style={S.label}>Quick Scenarios</label>
        <div style={{display:"flex",flexWrap:"wrap",gap:6,marginBottom:16}}>
          {QUICK_SCENARIOS.map(q=>(
            <div key={q.label} onClick={()=>{setScenario(q.label);setTactic(q.tactic);}}
              style={{padding:"5px 11px",borderRadius:7,border:"1px solid "+(scenario===q.label?THEME.danger+"66":THEME.border),background:scenario===q.label?THEME.dangerGlow:"rgba(255,255,255,0.02)",cursor:"pointer",fontSize:11,fontWeight:600,color:scenario===q.label?THEME.danger:THEME.textMid,transition:"all 0.15s"}}>
              {q.label}
            </div>
          ))}
        </div>

        <ToolSelector selected={selectedTool} onSelect={setSelectedTool}/>

        <div style={S.grid2}>
          <div>
            <label style={S.label}>Attack Scenario</label>
            <textarea style={{...S.textarea,minHeight:70}} value={scenario} onChange={e=>setScenario(e.target.value)} placeholder="e.g. Mimikatz LSASS credential dumping on Windows Server 2022..."/>
          </div>
          <div>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <label style={{...S.label,marginBottom:0}}>MITRE Tactic</label>
              {tacticAuto&&<span style={{fontSize:9,fontWeight:700,padding:"1px 7px",borderRadius:4,background:"rgba(0,212,255,0.12)",border:"1px solid rgba(0,212,255,0.3)",color:THEME.accent}}>AUTO</span>}
            </div>
            <select style={S.input} value={tactic} onChange={e=>{setTactic(e.target.value);setTacticAuto(false);}}>{TACTICS.map(t=><option key={t}>{t}</option>)}</select>
          </div>
        </div>

        <div style={{marginTop:14,display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
          <button style={{...S.btn("d"),padding:"11px 26px",fontSize:13}} onClick={simulate} disabled={loading}>{loading&&<Spinner/>}{loading?`Simulating... (${streamTokens} chars)`:"Simulate Attack"}</button>
          {events&&<button style={{...S.btn(),padding:"11px 20px",fontSize:12}} onClick={()=>onSendToBuilder(scenario,tactic)}>Build Detection for This</button>}
        </div>
        {err&&<StatusBar msg={err} type="error"/>}
      </div>

      {events&&(
        <div>
          {/* Attack summary card */}
          <div style={{...S.card,borderColor:THEME.danger+"33",background:"linear-gradient(135deg,rgba(255,61,85,0.05),rgba(255,61,85,0.02))"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:12,marginBottom:12}}>
              <div>
                <div style={{fontSize:10,fontWeight:800,color:THEME.danger,letterSpacing:"0.15em",marginBottom:4}}>ATTACK SIMULATION — {selectedTool.name}</div>
                <div style={{fontSize:17,fontWeight:900,color:THEME.text,marginBottom:6}}>{events.attack_name}</div>
                <div style={S.flex}>
                  <span style={S.badge(THEME.danger)}>{events.mitre_id}</span>
                  <span style={S.badge(THEME.orange)}>{events.mitre_tactic}</span>
                  <span style={S.badge(selectedTool.color)}>{selectedTool.lang}</span>
                </div>
              </div>
              <CopyBtn text={events.timeline?.map(s=>`[${s.time_offset}] ${s.stage}\n${s.log_event}`).join("\n\n")||""}/>
            </div>
            <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.7,marginBottom:12}}>{events.summary}</div>

            {/* IOCs */}
            {events.iocs?.length>0&&(
              <div style={{marginBottom:12}}>
                <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.12em",marginBottom:6}}>IOCs</div>
                <div style={{display:"flex",flexWrap:"wrap"}}>{events.iocs.map((ioc,i)=><span key={i} style={S.tag}>{ioc}</span>)}</div>
              </div>
            )}

            {/* Detection hint + Hunt query */}
            <div style={S.grid2}>
              {events.detection_hint&&<div style={{padding:"10px 14px",background:THEME.successGlow,border:"1px solid "+THEME.success+"33",borderRadius:8,fontSize:12,color:THEME.success,lineHeight:1.6}}><span style={{fontWeight:800}}>Detection hint: </span>{events.detection_hint}</div>}
              {events.hunt_query&&<div style={{padding:"10px 14px",background:"rgba(124,85,255,0.06)",border:"1px solid "+THEME.purple+"33",borderRadius:8,fontSize:11,color:THEME.purple,fontFamily:"monospace",lineHeight:1.6,position:"relative"}}>
                <div style={{fontSize:9,fontWeight:800,color:THEME.purple,letterSpacing:"0.1em",marginBottom:4,fontFamily:"inherit"}}>HUNT QUERY</div>
                {events.hunt_query}
                <div style={{position:"absolute",top:6,right:6}}><CopyBtn text={events.hunt_query} small={true}/></div>
              </div>}
            </div>
          </div>

          {/* Timeline nav */}
          <div style={{display:"flex",gap:3,marginBottom:12,overflowX:"auto",padding:"2px 0"}}>
            {events.timeline?.map((step,i)=>{
              const c=STAGE_COLOR[step.stage]||THEME.accent;
              return(
                <div key={i} onClick={()=>setActiveLog(i)}
                  style={{flex:1,minWidth:80,padding:"8px 6px",borderRadius:8,border:"1px solid "+(activeLog===i?c+"66":THEME.border),background:activeLog===i?c+"12":"rgba(255,255,255,0.01)",cursor:"pointer",textAlign:"center",transition:"all 0.15s",flexShrink:0}}>
                  <div style={{fontSize:9,fontWeight:800,color:activeLog===i?c:THEME.textDim,marginBottom:3}}>{step.time_offset}</div>
                  <div style={{fontSize:8,color:activeLog===i?c:THEME.textDim,lineHeight:1.3}}>{step.stage?.split(" ").slice(0,2).join(" ")}</div>
                </div>
              );
            })}
          </div>

          {/* Active log detail */}
          {activeStep&&(
            <div style={{...S.card,borderLeft:"3px solid "+(STAGE_COLOR[activeStep.stage]||THEME.accent)+"66"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:12,flexWrap:"wrap",gap:8}}>
                <div style={S.flex}>
                  <span style={S.badge(STAGE_COLOR[activeStep.stage]||THEME.accent)}>{activeStep.stage}</span>
                  <span style={{fontSize:13,fontWeight:700,color:THEME.text}}>{activeStep.description}</span>
                </div>
                <span style={{fontSize:11,color:THEME.textDim,fontFamily:"monospace"}}>{activeStep.time_offset}</span>
              </div>

              {/* Log event — the main output */}
              <div style={{marginBottom:12}}>
                <div style={{fontSize:10,fontWeight:800,color:selectedTool.color,letterSpacing:"0.12em",marginBottom:6}}>
                  {selectedTool.name} LOG EVENT
                </div>
                <div style={{position:"relative"}}>
                  <div style={{...S.code,background:"#020408",borderColor:selectedTool.color+"22",fontSize:11,lineHeight:1.9,minHeight:60}}>
                    {activeStep.log_event}
                  </div>
                  <div style={{position:"absolute",top:8,right:8,display:"flex",gap:6}}>
                    <CopyBtn text={activeStep.log_event||""} small={true}/>
                    <button style={{...S.btn(sentEvents[activeLog]?"s":""),padding:"3px 10px",fontSize:10}} onClick={()=>sendToTriage(activeStep.log_event,activeLog)}>
                      {sentEvents[activeLog]?"Sent!":"Triage"}
                    </button>
                  </div>
                </div>
              </div>

              {/* Key suspicious fields */}
              {activeStep.key_fields?.length>0&&(
                <div style={{marginBottom:10}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.1em",marginBottom:6}}>KEY SUSPICIOUS FIELDS</div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                    {activeStep.key_fields.map((f,i)=>(
                      <div key={i} style={{padding:"4px 10px",borderRadius:6,background:"rgba(255,170,0,0.08)",border:"1px solid rgba(255,170,0,0.2)",fontSize:11,color:THEME.warning,fontFamily:"monospace"}}>{f}</div>
                    ))}
                  </div>
                </div>
              )}

              {/* Why suspicious */}
              {activeStep.why_suspicious&&(
                <div style={{padding:"8px 12px",background:"rgba(255,61,85,0.05)",border:"1px solid rgba(255,61,85,0.15)",borderRadius:7,fontSize:12,color:"#ff8899",lineHeight:1.6}}>
                  <span style={{fontWeight:800,color:THEME.danger}}>Why suspicious: </span>{activeStep.why_suspicious}
                </div>
              )}

              {/* Step nav */}
              <div style={{display:"flex",justifyContent:"space-between",marginTop:14,paddingTop:12,borderTop:"1px solid "+THEME.border}}>
                <button style={{...S.btn(),padding:"6px 14px",fontSize:11}} onClick={()=>setActiveLog(Math.max(0,activeLog-1))} disabled={activeLog===0}>Previous</button>
                <span style={{fontSize:11,color:THEME.textDim,alignSelf:"center"}}>Event {activeLog+1} of {events.timeline?.length}</span>
                <button style={{...S.btn("p"),padding:"6px 14px",fontSize:11}} onClick={()=>setActiveLog(Math.min((events.timeline?.length||1)-1,activeLog+1))} disabled={activeLog===(events.timeline?.length||1)-1}>Next</button>
              </div>
            </div>
          )}

          {/* All events list */}
          <div style={S.card}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.15em",marginBottom:12}}>ALL EVENTS — {selectedTool.name}</div>
            {events.timeline?.map((step,i)=>{
              const c=STAGE_COLOR[step.stage]||THEME.accent;
              return(
                <div key={i} style={{marginBottom:10,cursor:"pointer"}} onClick={()=>setActiveLog(i)}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                    <span style={{fontSize:10,color:THEME.textDim,fontFamily:"monospace",minWidth:40}}>{step.time_offset}</span>
                    <span style={S.badge(c)}>{step.stage}</span>
                    <span style={{fontSize:11,color:THEME.textMid}}>{step.description}</span>
                    <div style={{marginLeft:"auto",display:"flex",gap:5}}>
                      <CopyBtn text={step.log_event||""} small={true}/>
                      <button style={{...S.btn(sentEvents[i]?"s":""),padding:"2px 8px",fontSize:9}} onClick={e=>{e.stopPropagation();sendToTriage(step.log_event,i);}}>{sentEvents[i]?"Sent!":"Triage"}</button>
                    </div>
                  </div>
                  <div style={{...S.code,fontSize:10,lineHeight:1.6,background:"#02040a",borderColor:c+"18",padding:"8px 10px",borderLeft:"2px solid "+c+"44"}}>{step.log_event}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Atomic Tests ──────────────────────────────────────────────────────────────
const ATOMIC_TACTICS=["All","Command and Control","Credential Access","Defense Evasion","Discovery","Execution","Exfiltration","Impact","Initial Access","Lateral Movement","Persistence","Privilege Escalation","Collection"];
const ATOMIC_PLATFORMS=["All","windows","linux","macos"];

function AtomicTests({onBuildOn,onImport}){
  const toast=useToast();
  const[tests,setTests]=useState([]);
  const[loading,setLoading]=useState(true);
  const[error,setError]=useState(null);
  const[tactic,setTactic]=useState("All");
  const[platform,setPlatform]=useState("All");
  const[search,setSearch]=useState("");
  const[expanded,setExpanded]=useState(null);
  const[generating,setGenerating]=useState(null);
  // per-test run mode: "simulate"|"agent"|"paste"
  const[runMode,setRunMode]=useState({});
  // simulation results keyed by test.id
  const[simResults,setSimResults]=useState({});
  const[simulating,setSimulating]=useState(null);
  // agent
  const[agentKey]=useState(()=>localStorage.getItem("atomic_agent_key")||(()=>{const k=crypto.randomUUID();localStorage.setItem("atomic_agent_key",k);return k;})());
  const[agentJobs,setAgentJobs]=useState({});// jobId keyed by test.id
  const[jobPollers,setJobPollers]=useState({});
  // paste logs
  const[pasteLogs,setPasteLogs]=useState({});
  const[pasteAnalysis,setPasteAnalysis]=useState({});
  const[analyzingPaste,setAnalyzingPaste]=useState(null);

  useEffect(()=>{
    setLoading(true);
    const params=new URLSearchParams();
    if(tactic!=="All")params.set("tactic",tactic);
    if(platform!=="All")params.set("platform",platform);
    if(search)params.set("search",search);
    fetch("/api/atomic-tests?"+params)
      .then(r=>r.json())
      .then(d=>{setTests(d.tests||[]);setLoading(false);})
      .catch(e=>{setError(e.message);setLoading(false);});
  },[tactic,platform,search]);

  async function generateDetection(test, extraContext=""){
    setGenerating(test.id);
    const scenario=`${test.technique_id} - ${test.technique_name}: ${test.test_name}\n\n${test.description}\n\nExecutor: ${test.executor_name}\nAttacker command:\n${test.resolved_command||test.command}${test.cleanup_command?"\n\nCleanup:\n"+test.cleanup_command:""}${extraContext?"\n\n"+extraContext:""}`;
    onBuildOn?.(scenario, test.tactic);
    toast?.("Opened in Detection Builder","success");
    setGenerating(null);
  }

  async function runSimulate(test){
    setSimulating(test.id);
    try{
      const res=await fetch("/api/atomic/simulate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({technique_id:test.technique_id,technique_name:test.technique_name,test_name:test.test_name,description:test.description,command:test.resolved_command||test.command,executor_name:test.executor_name,platforms:test.platforms})});
      const data=await res.json();
      if(data.error)throw new Error(data.error);
      setSimResults(p=>({...p,[test.id]:data}));
    }catch(e){toast?.("Simulation failed: "+e.message,"error");}
    setSimulating(null);
  }

  async function runOnAgent(test){
    try{
      const res=await fetch("/api/atomic/jobs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({test_id:test.id,command:test.resolved_command||test.command,cleanup_command:test.cleanup_command,executor_name:test.executor_name,platform:test.platforms[0]||"windows",agent_key:agentKey})});
      const data=await res.json();
      if(data.error)throw new Error(data.error);
      setAgentJobs(p=>({...p,[test.id]:{job_id:data.job_id,status:"pending"}}));
      toast?.("Job queued — agent will pick it up","success");
      // poll for result
      const poller=setInterval(async()=>{
        const r=await fetch("/api/atomic/jobs/"+data.job_id).then(x=>x.json());
        setAgentJobs(p=>({...p,[test.id]:r}));
        if(r.status==="completed"||r.status==="failed"){clearInterval(poller);setJobPollers(p=>{const n={...p};delete n[test.id];return n;});}
      },3000);
      setJobPollers(p=>({...p,[test.id]:poller}));
    }catch(e){toast?.("Agent job failed: "+e.message,"error");}
  }

  async function analyzePasteLogs(test){
    const logs=pasteLogs[test.id];
    if(!logs?.trim())return;
    setAnalyzingPaste(test.id);
    try{
      const res=await fetch("/api/ai",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({messages:[{role:"user",content:`Analyze these logs from running ATT&CK test ${test.technique_id} - ${test.test_name}:\n\n${logs}\n\nIdentify: key event IDs, suspicious fields, process names, detection opportunities. Be concise and specific.`}],system:"You are a detection engineering expert analyzing security logs.",maxTokens:800})});
      const data=await res.json();
      setPasteAnalysis(p=>({...p,[test.id]:data.text||data.content||"No analysis returned"}));
    }catch(e){toast?.("Analysis failed: "+e.message,"error");}
    setAnalyzingPaste(null);
  }

  const tacticColor={
    "Execution":THEME.warning,"Credential Access":THEME.danger,"Defense Evasion":THEME.purple,
    "Discovery":THEME.accent,"Persistence":THEME.orange,"Privilege Escalation":THEME.danger,
    "Lateral Movement":THEME.warning,"Impact":THEME.danger,"Initial Access":THEME.danger,
    "Command and Control":THEME.purple,"Exfiltration":THEME.orange,"Collection":THEME.accent,
  };

  return(
    <div>
      <SectionHeader icon="⚛" title="Atomic Tests">
        <span style={{fontSize:11,padding:"3px 10px",borderRadius:5,background:"rgba(239,68,68,0.08)",border:"1px solid rgba(239,68,68,0.2)",color:"#f87171",fontWeight:500}}>Red Canary</span>
        <span style={{fontSize:12,color:THEME.textDim}}>Real attack procedures → instant detection generation</span>
      </SectionHeader>

      {/* Filters */}
      <div style={{...S.card,marginBottom:16}}>
        <div style={{display:"flex",gap:10,flexWrap:"wrap",alignItems:"center"}}>
          <input style={{...S.input,flex:1,minWidth:180,padding:"7px 12px"}} placeholder="Search technique, name, description..." value={search} onChange={e=>setSearch(e.target.value)}/>
          <select style={{...S.input,width:200}} value={tactic} onChange={e=>setTactic(e.target.value)}>
            {ATOMIC_TACTICS.map(t=><option key={t}>{t}</option>)}
          </select>
          <select style={{...S.input,width:130}} value={platform} onChange={e=>setPlatform(e.target.value)}>
            {ATOMIC_PLATFORMS.map(p=><option key={p}>{p.charAt(0).toUpperCase()+p.slice(1)}</option>)}
          </select>
          {tests.length>0&&<span style={{fontSize:11,color:THEME.textMid,whiteSpace:"nowrap"}}>{tests.length} tests</span>}
        </div>
      </div>

      {/* Results */}
      {loading?(
        <div style={{...S.card,textAlign:"center",padding:48}}>
          <Spinner/><span style={{color:THEME.textMid,marginLeft:10,fontSize:13}}>Fetching from Red Canary GitHub...</span>
        </div>
      ):error?(
        <div style={{...S.card,textAlign:"center",padding:48,color:THEME.danger}}>{error}</div>
      ):(
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          {tests.map(test=>{
            const isOpen=expanded===test.id;
            const tc=tacticColor[test.tactic]||THEME.textMid;
            return(
              <div key={test.id} style={{...S.card,marginBottom:0,borderColor:isOpen?THEME.borderBright:THEME.border,transition:"border-color 0.15s"}}>
                {/* Header row */}
                <div style={{display:"flex",alignItems:"center",gap:10,cursor:"pointer"}} onClick={()=>setExpanded(isOpen?null:test.id)}>
                  <span style={{fontSize:11,fontFamily:"monospace",fontWeight:700,color:tc,background:tc+"12",border:"1px solid "+tc+"30",borderRadius:5,padding:"2px 8px",flexShrink:0}}>{test.technique_id}</span>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:13,fontWeight:600,color:THEME.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{test.test_name}</div>
                    <div style={{fontSize:11,color:THEME.textMid}}>{test.technique_name}</div>
                  </div>
                  <div style={{display:"flex",gap:6,alignItems:"center",flexShrink:0}}>
                    {test.platforms.map(p=>(
                      <span key={p} style={{fontSize:10,color:THEME.textDim,background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:4,padding:"1px 6px"}}>{p}</span>
                    ))}
                    {test.elevation_required&&<span style={{fontSize:10,color:THEME.warning,background:THEME.warning+"10",border:"1px solid "+THEME.warning+"30",borderRadius:4,padding:"1px 6px"}}>admin</span>}
                    <span style={{fontSize:10,color:THEME.textDim,marginLeft:4}}>{isOpen?"▲":"▼"}</span>
                  </div>
                </div>

                {/* Expanded */}
                {isOpen&&(
                  <div style={{marginTop:12,paddingTop:12,borderTop:"1px solid "+THEME.border}}>
                    {test.description&&<p style={{fontSize:12,color:THEME.textMid,lineHeight:1.7,marginBottom:12}}>{test.description}</p>}

                    {/* Executor badge */}
                    {test.executor_name&&(
                      <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}>
                        <span style={{fontSize:10,color:THEME.textDim}}>Executor:</span>
                        <span style={{fontSize:10,fontWeight:600,color:THEME.accent,background:THEME.accent+"10",border:"1px solid "+THEME.accent+"25",borderRadius:4,padding:"1px 7px",fontFamily:"monospace"}}>{test.executor_name}</span>
                      </div>
                    )}

                    {/* Input arguments */}
                    {test.input_args?.length>0&&(
                      <div style={{marginBottom:12}}>
                        <div style={{fontSize:11,color:THEME.textDim,fontWeight:600,marginBottom:6}}>Input Arguments</div>
                        <div style={{display:"flex",flexDirection:"column",gap:4}}>
                          {test.input_args.map(arg=>(
                            <div key={arg.name} style={{display:"flex",alignItems:"baseline",gap:8,fontSize:11}}>
                              <code style={{color:THEME.accent,fontFamily:"monospace",flexShrink:0}}>#{"{"+arg.name+"}"}</code>
                              <span style={{color:THEME.textMid,flex:1}}>{arg.description}</span>
                              <span style={{color:THEME.textDim,fontFamily:"monospace",background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:3,padding:"0 5px"}}>{arg.default||"—"}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Resolved command (with defaults filled in) */}
                    {(test.resolved_command||test.command)&&(
                      <div style={{marginBottom:12}}>
                        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                          <div style={{fontSize:11,color:THEME.textDim,fontWeight:600}}>
                            {test.resolved_command?"Resolved Command":"Attack Command"}
                          </div>
                          {test.resolved_command&&<span style={{fontSize:10,color:THEME.success,background:THEME.success+"10",border:"1px solid "+THEME.success+"25",borderRadius:3,padding:"0 5px"}}>defaults applied</span>}
                        </div>
                        <pre style={{...S.code,fontSize:11,whiteSpace:"pre-wrap",wordBreak:"break-all",margin:0,padding:"10px 12px"}}>{test.resolved_command||test.command}</pre>
                      </div>
                    )}

                    {/* Raw command if different */}
                    {test.resolved_command&&test.command&&(
                      <details style={{marginBottom:12}}>
                        <summary style={{fontSize:11,color:THEME.textDim,cursor:"pointer",marginBottom:4}}>Raw template</summary>
                        <pre style={{...S.code,fontSize:10,whiteSpace:"pre-wrap",wordBreak:"break-all",margin:"4px 0 0",padding:"8px 12px",opacity:0.7}}>{test.command}</pre>
                      </details>
                    )}

                    {/* Cleanup command */}
                    {test.cleanup_command&&(
                      <div style={{marginBottom:12}}>
                        <div style={{fontSize:11,color:THEME.textDim,fontWeight:600,marginBottom:4}}>Cleanup Command</div>
                        <pre style={{...S.code,fontSize:11,whiteSpace:"pre-wrap",wordBreak:"break-all",margin:0,padding:"10px 12px",borderColor:THEME.success+"33"}}>{test.cleanup_command}</pre>
                      </div>
                    )}

                    {/* 3-mode run panel */}
                    <div style={{marginTop:4,borderTop:"1px solid "+THEME.border,paddingTop:12}}>
                      {/* Mode tabs */}
                      <div style={{display:"flex",gap:6,marginBottom:12}}>
                        {[["simulate","🤖 AI Simulate"],["agent","💻 Run on Agent"],["paste","📋 Paste Logs"]].map(([m,label])=>(
                          <button key={m} onClick={()=>setRunMode(p=>({...p,[test.id]:p[test.id]===m?null:m}))}
                            style={{fontSize:11,padding:"5px 12px",borderRadius:6,border:"1px solid "+(runMode[test.id]===m?THEME.accent:THEME.border),background:runMode[test.id]===m?THEME.accent+"15":"transparent",color:runMode[test.id]===m?THEME.accent:THEME.textMid,cursor:"pointer",fontFamily:"inherit",fontWeight:runMode[test.id]===m?600:400,transition:"all 0.12s"}}>
                            {label}
                          </button>
                        ))}
                        <button style={{...S.btn("p"),padding:"5px 14px",fontSize:11,marginLeft:"auto"}} disabled={!!generating} onClick={()=>generateDetection(test)}>
                          {generating===test.id?<><Spinner/>Opening...</>:"Generate Detection →"}
                        </button>
                      </div>

                      {/* Mode A: AI Simulate */}
                      {runMode[test.id]==="simulate"&&(
                        <div style={{background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:8,padding:14}}>
                          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
                            <span style={{fontSize:12,fontWeight:600,color:THEME.text}}>AI-simulated execution output</span>
                            <button style={{...S.btn("p"),padding:"5px 14px",fontSize:11}} onClick={()=>runSimulate(test)} disabled={simulating===test.id}>
                              {simulating===test.id?<><Spinner/>Simulating...</>:"Run Simulation"}
                            </button>
                          </div>
                          {simResults[test.id]?(()=>{
                            const s=simResults[test.id];
                            return(
                              <div style={{display:"flex",flexDirection:"column",gap:10}}>
                                {s.what_happens&&<div><div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:3}}>WHAT HAPPENS</div><p style={{fontSize:12,color:THEME.textMid,lineHeight:1.7,margin:0}}>{s.what_happens}</p></div>}
                                {s.process_tree?.length>0&&<div><div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:3}}>PROCESS TREE</div>{s.process_tree.map((p,i)=><div key={i} style={{fontSize:11,fontFamily:"monospace",color:THEME.text,padding:"2px 0"}}>{p}</div>)}</div>}
                                {s.event_logs?.length>0&&<div><div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:4}}>EXPECTED EVENT LOGS</div>{s.event_logs.map((e,i)=>(
                                  <div key={i} style={{background:THEME.bg,border:"1px solid "+THEME.border,borderRadius:6,padding:"8px 10px",marginBottom:4}}>
                                    <div style={{display:"flex",gap:8,marginBottom:4}}>
                                      <span style={{fontSize:10,fontWeight:700,color:THEME.accent,fontFamily:"monospace"}}>Event {e.event_id}</span>
                                      <span style={{fontSize:10,color:THEME.textDim}}>{e.source}</span>
                                    </div>
                                    <div style={{fontSize:11,color:THEME.textMid,marginBottom:4}}>{e.description}</div>
                                    {e.key_fields&&<div style={{display:"flex",flexWrap:"wrap",gap:4}}>{Object.entries(e.key_fields).map(([k,v])=><span key={k} style={{fontSize:9,fontFamily:"monospace",background:THEME.accent+"10",border:"1px solid "+THEME.accent+"25",borderRadius:3,padding:"1px 6px",color:THEME.accent}}>{k}={String(v)}</span>)}</div>}
                                  </div>
                                ))}</div>}
                                {s.detection_signals?.length>0&&<div><div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:4}}>DETECTION SIGNALS</div>{s.detection_signals.map((sig,i)=><div key={i} style={{fontSize:11,fontFamily:"monospace",color:THEME.success,padding:"2px 0"}}>→ {sig}</div>)}</div>}
                                {s.artifacts?.length>0&&<div><div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:4}}>ARTIFACTS CREATED</div>{s.artifacts.map((a,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,padding:"1px 0"}}>• {a}</div>)}</div>}
                                {s.cleanup_result&&<div style={{background:THEME.success+"08",border:"1px solid "+THEME.success+"25",borderRadius:6,padding:"8px 10px"}}><div style={{fontSize:10,color:THEME.success,fontWeight:600,marginBottom:2}}>AUTO-CLEANUP</div><div style={{fontSize:11,color:THEME.textMid}}>{s.cleanup_result}</div></div>}
                                <button style={{...S.btn("p"),padding:"6px 14px",fontSize:11,alignSelf:"flex-start"}} onClick={()=>generateDetection(test,`AI Simulation signals:\n${s.detection_signals?.join("\n")}\n\nEvent IDs: ${s.event_logs?.map(e=>e.event_id).join(", ")}`)}>Build Detection from Simulation →</button>
                              </div>
                            );
                          })():<div style={{fontSize:12,color:THEME.textDim,textAlign:"center",padding:16}}>Click "Run Simulation" — AI will generate expected process tree, event logs, and detection signals without executing anything real.</div>}
                        </div>
                      )}

                      {/* Mode B: Agent */}
                      {runMode[test.id]==="agent"&&(()=>{
                        const job=agentJobs[test.id];
                        return(
                          <div style={{background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:8,padding:14}}>
                            <div style={{fontSize:12,fontWeight:600,color:THEME.text,marginBottom:8}}>Run on your test machine</div>
                            <div style={{fontSize:11,color:THEME.textMid,lineHeight:1.7,marginBottom:10}}>Install the DetectIQ agent on a <strong style={{color:THEME.warning}}>dedicated test VM only</strong> — never on production. The agent picks up jobs, runs them, auto-cleans up, and sends logs back here.</div>
                            <div style={{marginBottom:10}}>
                              <div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:4}}>YOUR AGENT KEY</div>
                              <code style={{fontSize:11,fontFamily:"monospace",color:THEME.accent,background:THEME.accent+"10",border:"1px solid "+THEME.accent+"25",borderRadius:4,padding:"4px 10px",display:"block",wordBreak:"break-all"}}>{agentKey}</code>
                            </div>
                            <div style={{display:"flex",gap:8,marginBottom:12}}>
                              <a href={`/api/atomic/agent-script?platform=windows&key=${agentKey}`} download="detectiq-agent.ps1" style={{...S.btn(),padding:"5px 12px",fontSize:11,textDecoration:"none",display:"inline-flex",alignItems:"center",gap:4}}>⬇ Windows Agent (.ps1)</a>
                              <a href={`/api/atomic/agent-script?platform=linux&key=${agentKey}`} download="detectiq-agent.sh" style={{...S.btn(),padding:"5px 12px",fontSize:11,textDecoration:"none",display:"inline-flex",alignItems:"center",gap:4}}>⬇ Linux Agent (.sh)</a>
                            </div>
                            {!job?(
                              <button style={{...S.btn("p"),padding:"6px 16px",fontSize:12}} onClick={()=>runOnAgent(test)}>Queue Job on Agent</button>
                            ):(
                              <div>
                                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                                  <span style={{width:8,height:8,borderRadius:"50%",background:job.status==="completed"?THEME.success:job.status==="failed"?THEME.danger:THEME.warning,display:"inline-block"}}/>
                                  <span style={{fontSize:12,fontWeight:600,color:THEME.text,textTransform:"capitalize"}}>{job.status}</span>
                                  {(job.status==="pending"||job.status==="running")&&<><Spinner/><span style={{fontSize:11,color:THEME.textMid}}>waiting for agent...</span></>}
                                </div>
                                {job.output&&<div style={{marginBottom:8}}><div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:3}}>OUTPUT</div><pre style={{...S.code,fontSize:11,whiteSpace:"pre-wrap",padding:"8px 12px",maxHeight:200,overflowY:"auto"}}>{job.output}</pre></div>}
                                {job.cleanup_output&&<div style={{marginBottom:8}}><div style={{fontSize:10,color:THEME.success,fontWeight:600,marginBottom:3}}>CLEANUP OUTPUT</div><pre style={{...S.code,fontSize:11,whiteSpace:"pre-wrap",padding:"8px 12px",borderColor:THEME.success+"33"}}>{job.cleanup_output}</pre></div>}
                                {job.error&&<div style={{fontSize:11,color:THEME.danger,marginBottom:8}}>Error: {job.error}</div>}
                                {job.status==="completed"&&<button style={{...S.btn("p"),padding:"6px 14px",fontSize:11}} onClick={()=>generateDetection(test,"Real execution output:\n"+job.output)}>Build Detection from Output →</button>}
                              </div>
                            )}
                          </div>
                        );
                      })()}

                      {/* Mode C: Paste Logs */}
                      {runMode[test.id]==="paste"&&(
                        <div style={{background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:8,padding:14}}>
                          <div style={{fontSize:12,fontWeight:600,color:THEME.text,marginBottom:6}}>Paste logs from your own test run</div>
                          <div style={{fontSize:11,color:THEME.textMid,marginBottom:8}}>Run the test manually on your lab machine, then paste the resulting SIEM logs, event viewer output, or terminal output here.</div>
                          <textarea value={pasteLogs[test.id]||""} onChange={e=>setPasteLogs(p=>({...p,[test.id]:e.target.value}))}
                            style={{...S.input,width:"100%",height:120,fontFamily:"monospace",fontSize:11,resize:"vertical",padding:"8px 10px"}}
                            placeholder="Paste Windows Event logs, Sysmon output, auditd logs, terminal output..."/>
                          <div style={{display:"flex",gap:8,marginTop:8}}>
                            <button style={{...S.btn("p"),padding:"6px 14px",fontSize:11}} disabled={analyzingPaste===test.id||!pasteLogs[test.id]?.trim()} onClick={()=>analyzePasteLogs(test)}>
                              {analyzingPaste===test.id?<><Spinner/>Analyzing...</>:"Analyze Logs"}
                            </button>
                            {pasteAnalysis[test.id]&&<button style={{...S.btn(),padding:"6px 14px",fontSize:11}} onClick={()=>generateDetection(test,"Real log analysis:\n"+pasteAnalysis[test.id])}>Build Detection →</button>}
                          </div>
                          {pasteAnalysis[test.id]&&(
                            <div style={{marginTop:10,fontSize:12,color:THEME.textMid,lineHeight:1.7,background:THEME.bg,border:"1px solid "+THEME.border,borderRadius:6,padding:"10px 12px",whiteSpace:"pre-wrap"}}>{pasteAnalysis[test.id]}</div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          {tests.length===0&&<div style={{...S.card,textAlign:"center",padding:40,color:THEME.textMid}}>No tests found for these filters.</div>}
        </div>
      )}
    </div>
  );
}

function UseCaseRepository({onImport, onBuildOn}){
  const[search,setSearch]=useState("");const[tactic,setTactic]=useState("All");const[sev,setSev]=useState("All");const[tool,setTool]=useState("All");const[diff,setDiff]=useState("All");const[selected,setSelected]=useState(null);
  useEffect(()=>{const p=new URLSearchParams(window.location.search);const id=p.get("id");if(id){const u=MITRE_USECASES.find(x=>x.id===id);if(u)setSelected(u);}},[]);
  useEffect(()=>{if(window.location.pathname==="/usecases"){window.history.replaceState({},"",selected?"/usecases?id="+selected.id:"/usecases");}},[selected]);
  const[stixData,setStixData]=useState([]);const[stixLoading,setStixLoading]=useState(true);
  useEffect(()=>{
    fetch("/api/mitre/techniques").then(r=>r.json()).then(d=>{
      if(d.techniques&&d.techniques.length)setStixData(d.techniques);
    }).catch(()=>{}).finally(()=>setStixLoading(false));
  },[]);
  const[imported,setImported]=useState({});const[walkTab,setWalkTab]=useState("story");
  const _staticIds=new Set(MITRE_USECASES.map(u=>u.technique));
  const allCases=[...MITRE_USECASES,...stixData.filter(t=>!_staticIds.has(t.technique))];
  const filtered=allCases.filter(u=>
    (!search||u.name.toLowerCase().includes(search.toLowerCase())||u.description.toLowerCase().includes(search.toLowerCase())||u.technique.toLowerCase().includes(search.toLowerCase()))
    &&(tactic==="All"||u.tactic===tactic)
    &&(sev==="All"||u.severity===sev)
    &&(tool==="All"||u.tool===tool)
    &&(diff==="All"||u.difficulty===diff)
  );
  function doImport(uc){onImport({...uc,id:uid(),score:0,created:new Date().toISOString(),tags:[uc.tactic,uc.queryType,uc.technique]});setImported(p=>({...p,[uc.id]:true}));}
  const toolObj=TOOLS.reduce((a,t)=>{a[t.id]=t;return a;},{});
  const diffColor={Beginner:THEME.success,Intermediate:THEME.warning,Advanced:THEME.danger};
  const WALK_TABS=[{id:"story",label:"Attack Story"},{id:"tune",label:"Tuning Guide"},{id:"fp",label:"False Positives"},{id:"related",label:"Related Rules"}];
  return(
    <div>
      <SectionHeader icon="📚" title="MITRE ATT&CK Use Case Repository" color={THEME.purple}>
        <span style={S.badge(THEME.accent)}>{stixLoading?"Loading...":filtered.length+" / "+allCases.length+" rules"}</span>
      </SectionHeader>
      <div style={S.card}>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          <input style={{...S.input,flex:1,minWidth:180}} value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search by name, T#### technique ID, or description..."/>
          <select style={{...S.input,width:190}} value={tactic} onChange={e=>setTactic(e.target.value)}><option>All</option>{TACTICS.map(t=><option key={t}>{t}</option>)}</select>
          <select style={{...S.input,width:120}} value={sev} onChange={e=>setSev(e.target.value)}><option>All</option>{SEVERITIES.map(s=><option key={s}>{s}</option>)}</select>
          <select style={{...S.input,width:150}} value={tool} onChange={e=>setTool(e.target.value)}><option>All</option>{TOOLS.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}</select>
          <select style={{...S.input,width:140}} value={diff} onChange={e=>setDiff(e.target.value)}><option>All</option><option>Beginner</option><option>Intermediate</option><option>Advanced</option></select>
        </div>
      </div>
      <div style={S.grid2}>
        {filtered.map(uc=>{const t=toolObj[uc.tool];const isSelected=selected?.id===uc.id;return(
          <div key={uc.id} style={{...S.card,cursor:"pointer",borderColor:isSelected?THEME.accent:THEME.border}} onClick={()=>setSelected(isSelected?null:uc)}>
            <div style={S.row}>
              <div style={S.flex}>
                <span style={S.badge(sevColor[uc.severity]||THEME.textDim)}>{uc.severity}</span>
                {t&&<span style={{...S.badge(t.color),fontSize:10}}>{t.lang}</span>}
                {uc.difficulty&&<span style={{...S.badge(diffColor[uc.difficulty]||THEME.textDim),fontSize:9}}>{uc.difficulty}</span>}
              </div>
              <span style={{fontSize:11,color:THEME.accent,fontWeight:800,fontFamily:"monospace"}}>{uc.technique}</span>
            </div>
            <div style={{fontSize:14,fontWeight:700,marginBottom:6,color:THEME.text}}>{uc.name}</div>
            <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6,marginBottom:12}}>{uc.description}</div>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:8}}>
              <span style={{fontSize:11,color:THEME.textDim}}>{uc.tactic}</span>
              <div style={S.flex}>
                {onBuildOn&&<button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={e=>{e.stopPropagation();onBuildOn(uc.name+" — "+uc.description,uc.tactic);}}>Build on This</button>}
                <button style={S.btn(imported[uc.id]?"s":"p")} onClick={e=>{e.stopPropagation();doImport(uc);}}>{imported[uc.id]?"Imported!":"Import Rule"}</button>
              </div>
            </div>

            {isSelected&&(
              <div onClick={e=>e.stopPropagation()}>
                <div style={S.divider}/>
                {uc.query?(
                  <>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.accentDim,letterSpacing:"0.12em",marginBottom:8}}>DETECTION QUERY</div>
                  <div style={{position:"relative",marginBottom:14}}>
                    <div style={S.code}>{uc.query}</div>
                    <div style={{position:"absolute",top:8,right:8}}><CopyBtn text={uc.query}/></div>
                  </div>
                  </>
):(  
                  <div style={{background:"rgba(0,212,255,0.03)",border:"1px dashed "+THEME.accentDim,borderRadius:8,padding:16,marginBottom:14,textAlign:"center"}}>
                    <div style={{fontSize:12,color:THEME.textMid,marginBottom:12}}>No pre-built query — generate one with AI.</div>
                    <div style={{display:"flex",gap:8,justifyContent:"center",flexWrap:"wrap"}}>
                      {onBuildOn&&<button style={{...S.btn("p"),padding:"7px 14px",fontSize:11}} onClick={()=>onBuildOn(uc.name+" — "+uc.description,uc.tactic)}>🔨 Build Detection</button>}
                      {uc.url&&<a href={uc.url} target="_blank" rel="noreferrer" style={{...S.btn(),padding:"7px 14px",fontSize:11,textDecoration:"none",display:"inline-flex",alignItems:"center"}}>🔗 MITRE ATT&CK</a>}
                    </div>
                  </div>
)}

                {/* Walkthrough tabs */}
                {uc.walkthrough&&(
                  <div style={{background:"#03060d",border:"1px solid "+THEME.border,borderRadius:10,padding:16}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.12em",marginBottom:12}}>WALKTHROUGH</div>
                    <div style={{display:"flex",gap:4,marginBottom:14,borderBottom:"1px solid "+THEME.border,paddingBottom:0}}>
                      {WALK_TABS.map(wt=>(
                        <button key={wt.id} onClick={()=>setWalkTab(wt.id)}
                          style={{padding:"6px 12px",borderRadius:"6px 6px 0 0",border:"1px solid "+(walkTab===wt.id?THEME.purple+"66":"transparent"),borderBottom:walkTab===wt.id?"1px solid #03060d":"1px solid transparent",background:walkTab===wt.id?"rgba(124,85,255,0.08)":"transparent",color:walkTab===wt.id?THEME.purple:THEME.textDim,cursor:"pointer",fontFamily:"inherit",fontSize:11,fontWeight:walkTab===wt.id?700:500,marginBottom:-1}}>
                          {wt.label}
                        </button>
                      ))}
                    </div>
                    <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8}}>
                      {walkTab==="story"&&<div>{uc.walkthrough.story}</div>}
                      {walkTab==="tune"&&<div>{uc.walkthrough.tune}</div>}
                      {walkTab==="fp"&&<div>{uc.walkthrough.fp}</div>}
                      {walkTab==="related"&&<div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                        {uc.walkthrough.related?.map(rid=>{
                          const rel=MITRE_USECASES.find(u=>u.id===rid);
                          return rel?<div key={rid} style={{padding:"6px 12px",borderRadius:7,background:THEME.purple+"10",border:"1px solid "+THEME.purple+"33",fontSize:12,color:THEME.purple,cursor:"pointer"}} onClick={()=>setSelected(rel)}>{rel.name}</div>:null;
                        })}
                      </div>}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );})}
      </div>
      {filtered.length===0&&<div style={{...S.card,textAlign:"center",color:THEME.textDim,padding:50}}><div style={{fontSize:36,marginBottom:12}}>📚</div>No rules match your filters.</div>}
    </div>
  );
}


function QueryTranslator({prefill}){
  const[inputQuery,setInputQuery]=useState("");
  const[fromTool,setFromTool]=useState(TOOLS[0]);
  useEffect(()=>{if(prefill?.query){setInputQuery(prefill.query);const t=TOOLS.find(t=>t.id===prefill.tool);if(t)setFromTool(t);}},[prefill]);
  const[toTool,setToTool]=useState(TOOLS[1]);
  const[result,setResult]=useState("");
  const[loading,setLoading]=useState(false);
  const[err,setErr]=useState("");
  // Analyze panel
  const[analyzeMode,setAnalyzeMode]=useState(null); // null | "score" | "enrich" | "ml"
  const[analyzeData,setAnalyzeData]=useState(null);
  const[analyzing,setAnalyzing]=useState(false);

  async function translate(){if(!inputQuery.trim()){setErr("Paste a query first.");return;}setErr("");setLoading(true);setResult("");try{await callClaudeStream([{role:"user",content:"Translate this "+fromTool.lang+" query to "+toTool.lang+" for "+toTool.name+". Preserve all logic. Return ONLY the translated query.\n\n"+inputQuery}],"Expert in all SIEM query languages.",2000,(partial)=>setResult(partial));}catch(e){setErr("Translation failed: "+e.message);}setLoading(false);}

  async function analyzeQuery(mode){
    if(!inputQuery.trim()){setErr("Paste a query first.");return;}
    setAnalyzeMode(mode); setAnalyzeData(null); setAnalyzing(true); setErr("");
    try{
      if(mode==="score"){
        const res=await fetch("/api/detection/quality-score",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:"Query Analysis",query:inputQuery,queryType:fromTool.lang,tactic:"Unknown",severity:"Medium"})});
        const data=await res.json(); if(data.error)throw new Error(data.error); setAnalyzeData(data);
      } else if(mode==="enrich"){
        const txt=await callClaude([{role:"user",content:`Enrich this ${fromTool.lang} detection query.\n\nQuery:\n${inputQuery}\n\nReturn ONLY valid JSON:\n{"attack_path_summary":"...","next_tactics":["tactic1"],"adjacent_detections":[{"name":"...","why":"..."}],"high_value_targets":"...","quick_win":"...","gap_warning":"..."}`}],"Expert detection engineer. Return ONLY valid JSON.",1200);
        const m=txt.match(/\{[\s\S]*\}/); if(m)setAnalyzeData(JSON.parse(m[0].replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,"").replace(/\\(?!["\\/bfnrtu])/g,"\\\\")));
      } else if(mode==="ml"){
        const res=await fetch("/api/detection/ml-enhance",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:"Query Analysis",query:inputQuery,queryType:fromTool.lang,tactic:"Unknown",severity:"Medium",threat:""})});
        const init=await res.json(); if(init.error)throw new Error(init.error);
        const data=init.jobId?await pollJob(init.jobId):init; setAnalyzeData(data);
      }
    }catch(e){setErr("Analysis failed: "+e.message);}
    setAnalyzing(false);
  }

  return(
    <div>
      <SectionHeader icon="🔄" title="Query Translator" color={THEME.purple}><span style={S.badge(THEME.purple)}>10 Platforms</span></SectionHeader>
      <HelpBox title="Query Translator Quick Reference" color={THEME.purple} items={[
        {icon:"🔄",title:"What it does",desc:"Converts detection queries between SIEM and EDR platforms — Splunk SPL, Sentinel KQL, Elastic EQL, CrowdStrike CQL, Chronicle YARA-L, QRadar AQL, and more. AI handles field name mapping and syntax differences."},
        {icon:"📋",title:"How to use it",desc:"Select your source platform, paste the query, select the target platform, and click Translate. The output is ready to copy into your target SIEM."},
        {icon:"⚠️",title:"Field mismatches",desc:"Some fields don't exist on every platform (e.g. 'process_name' in Splunk vs 'ProcessName' in Sentinel). The translator flags these so you can review and adjust before deploying."},
        {icon:"💡",title:"Tip",desc:"For best results, translate one logical query at a time. Complex multi-search or sub-search queries may need manual review after translation."},
      ]}/>
      <div style={S.card}>
        <div style={{display:"flex",gap:12,alignItems:"flex-end",marginBottom:18,flexWrap:"wrap"}}>
          <div style={{flex:1,minWidth:160}}><label style={S.label}>From</label><select style={S.input} value={fromTool.id} onChange={e=>setFromTool(TOOLS.find(t=>t.id===e.target.value))}>{TOOLS.map(t=><option key={t.id} value={t.id}>{t.name} ({t.lang})</option>)}</select></div>
          <button style={{...S.btn(),padding:"10px 18px",fontSize:18}} onClick={()=>{const tmp=fromTool;setFromTool(toTool);setToTool(tmp);}}>⇄</button>
          <div style={{flex:1,minWidth:160}}><label style={S.label}>To</label><select style={S.input} value={toTool.id} onChange={e=>setToTool(TOOLS.find(t=>t.id===e.target.value))}>{TOOLS.map(t=><option key={t.id} value={t.id}>{t.name} ({t.lang})</option>)}</select></div>
        </div>
        <div style={S.grid2}>
          <div><label style={S.label}>Source ({fromTool.lang})</label><textarea style={{...S.textarea,minHeight:200,fontFamily:"monospace",fontSize:12}} value={inputQuery} onChange={e=>setInputQuery(e.target.value)} placeholder={"Paste your "+fromTool.lang+" query here..."}/></div>
          <div><label style={S.label}>Translated ({toTool.lang})</label>{result?<div style={{position:"relative"}}><div style={{...S.code,minHeight:200}}>{result}</div><div style={{position:"absolute",top:8,right:8}}><CopyBtn text={result}/></div></div>:<div style={{...S.textarea,minHeight:200,display:"flex",alignItems:"center",justifyContent:"center",color:THEME.textDim,fontSize:13,fontStyle:"italic"}}>Translation will appear here...</div>}</div>
        </div>
        <div style={{marginTop:14,display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
          <button style={{...S.btn("p"),padding:"10px 22px"}} onClick={translate} disabled={loading}>{loading&&<Spinner/>}{loading?"Translating...":"Translate Query"}</button>
          <div style={{borderLeft:"1px solid "+THEME.border,height:24,margin:"0 4px"}}/>
          <span style={{fontSize:11,color:THEME.textDim}}>Analyze source query:</span>
          <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={()=>analyzeQuery("score")} disabled={analyzing&&analyzeMode==="score"}>{analyzing&&analyzeMode==="score"?<><Spinner/>Scoring...</>:"🏅 Score"}</button>
          <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={()=>analyzeQuery("enrich")} disabled={analyzing&&analyzeMode==="enrich"}>{analyzing&&analyzeMode==="enrich"?<><Spinner/>Enriching...</>:"🔍 Enrich"}</button>
          <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={()=>analyzeQuery("ml")} disabled={analyzing&&analyzeMode==="ml"}>{analyzing&&analyzeMode==="ml"?<><Spinner/>Generating...</>:"🧠 ML/UBA"}</button>
        </div>
        {err&&<StatusBar msg={err} type="error"/>}
      </div>

      {/* Analysis results */}
      {analyzeData&&analyzeMode==="score"&&(
        <div style={S.card}>
          <div style={{...S.row,marginBottom:14}}><div style={S.cardTitle}><span>🏅</span> Quality Score</div><span style={{fontSize:28,fontWeight:900,color:analyzeData.overall>=80?THEME.success:analyzeData.overall>=60?THEME.warning:THEME.danger}}>{analyzeData.overall}/100</span></div>
          {analyzeData.breakdown&&<div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>{Object.entries(analyzeData.breakdown).map(([k,v])=><div key={k} style={{padding:"8px 12px",background:"rgba(255,255,255,0.02)",borderRadius:7,border:"1px solid "+THEME.border}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}><span style={{fontSize:11,color:THEME.textMid,textTransform:"capitalize"}}>{k.replace(/_/g," ")}</span><span style={{fontWeight:700,color:v.score>=80?THEME.success:v.score>=60?THEME.warning:THEME.danger,fontSize:12}}>{v.score}</span></div><div style={{fontSize:10,color:THEME.textDim}}>{v.notes}</div></div>)}</div>}
          {analyzeData.recommendations?.length>0&&<div>{analyzeData.recommendations.map((r,i)=><div key={i} style={{fontSize:12,color:THEME.textMid,padding:"5px 10px",borderLeft:"2px solid "+THEME.purple+"44",marginBottom:4}}>→ {r}</div>)}</div>}
        </div>
      )}
      {analyzeData&&analyzeMode==="enrich"&&(
        <div style={S.card}>
          <div style={{...S.cardTitle,marginBottom:14}}><span>🔍</span> Threat Enrichment</div>
          {analyzeData.attack_path_summary&&<div style={{marginBottom:10,fontSize:13,color:THEME.textMid,padding:"10px 14px",background:"rgba(0,212,255,0.04)",borderRadius:8,border:"1px solid "+THEME.borderBright}}>{analyzeData.attack_path_summary}</div>}
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
            {analyzeData.quick_win&&<div style={{padding:"10px 14px",background:"rgba(0,255,136,0.04)",borderRadius:8,border:"1px solid rgba(0,255,136,0.15)"}}><div style={{fontSize:10,fontWeight:800,color:THEME.success,marginBottom:4}}>QUICK WIN</div><div style={{fontSize:12,color:THEME.textMid}}>{analyzeData.quick_win}</div></div>}
            {analyzeData.gap_warning&&<div style={{padding:"10px 14px",background:"rgba(255,61,85,0.04)",borderRadius:8,border:"1px solid rgba(255,61,85,0.15)"}}><div style={{fontSize:10,fontWeight:800,color:THEME.danger,marginBottom:4}}>COVERAGE GAP</div><div style={{fontSize:12,color:THEME.textMid}}>{analyzeData.gap_warning}</div></div>}
          </div>
        </div>
      )}
      {analyzeData&&analyzeMode==="ml"&&(
        <div style={S.card}>
          <div style={{...S.cardTitle,marginBottom:14}}><span>🧠</span> ML/UBA Enhancement</div>
          <div style={{fontSize:12,color:THEME.textMid,marginBottom:10,padding:"8px 12px",background:"rgba(0,212,255,0.04)",borderRadius:7}}>{analyzeData.ml_approach}</div>
          <label style={S.label}>ML-Enhanced Query</label>
          <div style={{position:"relative"}}><div style={S.code}>{analyzeData.ml_query}</div><div style={{position:"absolute",top:8,right:8}}><CopyBtn text={analyzeData.ml_query||""}/></div></div>
          {analyzeData.risk_modifier_rule&&<><label style={{...S.label,marginTop:12}}>Risk Modifier Rule</label><div style={{position:"relative"}}><div style={S.code}>{analyzeData.risk_modifier_rule}</div><div style={{position:"absolute",top:8,right:8}}><CopyBtn text={analyzeData.risk_modifier_rule||""}/></div></div></>}
        </div>
      )}
    </div>
  );
}

function DetectionExplainer({prefill}){
  const[query,setQuery]=useState(()=>{if(window.location.pathname!=="/explainer")return "";const p=new URLSearchParams(window.location.search);return p.get("query")||"";});
  const[tool,setTool]=useState(()=>{const p=new URLSearchParams(window.location.search);return TOOLS.find(t=>t.id===p.get("tool"))||TOOLS[0];});
  const[result,setResult]=useState("");const[loading,setLoading]=useState(false);const[err,setErr]=useState("");
  useEffect(()=>{if(query&&window.location.pathname==="/explainer"){window.history.replaceState({},"","/explainer?query="+encodeURIComponent(query)+"&tool="+tool.id);}},[query,tool.id]);
  useEffect(()=>{if(prefill?.query){setQuery(prefill.query);const t=TOOLS.find(t=>t.id===prefill.tool);if(t)setTool(t);}},[prefill]);
  async function explain(){if(!query.trim()){setErr("Paste a query first.");return;}setErr("");setLoading(true);setResult("");try{await callClaudeStream([{role:"user",content:"Analyze and explain this "+tool.lang+" detection query.\n\n1. PLAIN ENGLISH SUMMARY\n2. LOGIC BREAKDOWN\n3. WHAT IT DETECTS\n4. MITRE ATT&CK techniques\n5. FALSE POSITIVE RISKS\n6. IMPROVEMENT SUGGESTIONS\n\nQuery:\n"+query}],"Expert SOC analyst.",2000,(partial)=>setResult(partial));}catch(e){setErr("Error: "+e.message);}setLoading(false);}
  return(
    <div>
      <SectionHeader icon="🔍" title="Detection Explainer" color={THEME.warning}><span style={S.badge(THEME.warning)}>AI Analysis</span></SectionHeader>
      <HelpBox title="Detection Explainer Quick Reference" color={THEME.warning} items={[
        {icon:"🔍",title:"What it does",desc:"Paste any detection query and AI breaks it down line by line — explaining what each field, function, and condition does in plain English. Great for onboarding new analysts or reviewing inherited rules."},
        {icon:"🏅",title:"Quality Score",desc:"After explaining the query, AI rates it 1–10 on specificity, coverage, FP risk, and data source quality. A score below 5 usually means the rule needs tuning."},
        {icon:"🛠",title:"Improvement suggestions",desc:"AI identifies weaknesses (e.g. missing field filters, over-broad wildcards) and suggests specific improvements you can copy back into the Builder."},
        {icon:"💡",title:"Tip",desc:"Use this on inherited or legacy rules from other teams to quickly understand what they cover — and whether they're still relevant."},
      ]}/>
      <div style={S.card}>
        <div style={{marginBottom:16}}><label style={S.label}>Platform</label><div style={{display:"flex",flexWrap:"wrap",gap:8}}>{TOOLS.map(t=><div key={t.id} onClick={()=>setTool(t)} style={{padding:"6px 12px",borderRadius:7,border:"1px solid "+(tool.id===t.id?t.color+"88":THEME.border),background:tool.id===t.id?t.color+"12":"transparent",cursor:"pointer",fontSize:12,fontWeight:700,color:tool.id===t.id?t.color:THEME.textDim,transition:"all 0.15s"}}>{t.name}</div>)}</div></div>
        <label style={S.label}>Query to Explain</label>
        <textarea style={{...S.textarea,minHeight:160,fontFamily:"monospace",fontSize:12,marginBottom:14}} value={query} onChange={e=>setQuery(e.target.value)} placeholder={"Paste any "+tool.lang+" query..."}/>
        <button style={{...S.btn("p"),padding:"10px 22px"}} onClick={explain} disabled={loading}>{loading&&<Spinner/>}{loading?"Analyzing...":"Explain This Detection"}</button>
        {err&&<StatusBar msg={err} type="error"/>}
      </div>
      {result&&<div style={S.card}><div style={{...S.row,marginBottom:14}}><div style={S.cardTitle}><span>💡</span> Analysis</div><CopyBtn text={result}/></div><div style={{fontSize:13,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap"}}>{result}</div></div>}
    </div>
  );
}

function DetectionLibrary({detections, onDelete, onUpdate, onBuildOn, onSendToTriage, onExplain, onTranslate}){
  const toast = useToast();
  const[search,setSearch]=useState("");
  const[ft,setFt]=useState("All");
  const[fc,setFc]=useState("All");
  const[selected,setSelected]=useState(null);
  useEffect(()=>{if(!detections.length)return;const p=new URLSearchParams(window.location.search);const id=p.get("id");if(id){const d=detections.find(x=>x.id===id);if(d)setSelected(d);}},[detections.length]);
  useEffect(()=>{if(window.location.pathname==="/library"){window.history.replaceState({},"",selected?"/library?id="+selected.id:"/library");}},[selected]);
  const[scoring,setScoring]=useState(null);
  const[scoreResult,setScoreResult]=useState("");
  const[enriching,setEnriching]=useState(null);
  const[enrichData,setEnrichData]=useState({});
  const[pushModal,setPushModal]=useState(null);
  const[pushing,setPushing]=useState(false);
  const[pushResult,setPushResult]=useState("");
  const[ticketModal,setTicketModal]=useState(null);
  const[ticketContent,setTicketContent]=useState("");
  const[generatingTicket,setGeneratingTicket]=useState(false);
  const[splunkUrl,setSplunkUrl]=useState(LS.get("splunk_url",""));
  const[splunkToken,setSplunkToken]=useState(LS.get("splunk_token",""));
  const[splunkUser,setSplunkUser]=useState(LS.get("splunk_user",""));
  const[splunkPass,setSplunkPass]=useState(LS.get("splunk_pass",""));
  const[splunkAuthMode,setSplunkAuthMode]=useState(LS.get("splunk_auth_mode","token")); // "token" | "basic"
  const[dataReqs,setDataReqs]=useState(null);
  const[loadingDataReqs,setLoadingDataReqs]=useState(false);
  const[indexOverride,setIndexOverride]=useState("");
  const[sourcetypeOverride,setSourcetypeOverride]=useState("");
  const[elasticUrl,setElasticUrl]=useState(LS.get("elastic_url",""));
  const[elasticToken,setElasticToken]=useState(LS.get("elastic_token",""));
  const[soarUrl,setSoarUrl]=useState(LS.get("soar_url",""));
  const[soarToken,setSoarToken]=useState(LS.get("soar_token",""));
  const[githubToken,setGithubToken]=useState(LS.get("github_token",""));
  const[githubRepo,setGithubRepo]=useState(LS.get("github_repo",""));
  const[sigmaModal,setSigmaModal]=useState(null);
  const[sigmaContent,setSigmaContent]=useState("");
  const[loadingSigma,setLoadingSigma]=useState(false);
  const[logscaleUrl,setLogscaleUrl]=useState(LS.get("logscale_url",""));
  const[logscaleToken,setLogscaleToken]=useState(LS.get("logscale_token",""));
  const[logscaleRepo,setLogscaleRepo]=useState(LS.get("logscale_repo",""));
  const[sumoUrl,setSumoUrl]=useState(LS.get("sumo_url",""));
  const[sumoAccessId,setSumoAccessId]=useState(LS.get("sumo_access_id",""));
  const[sumoAccessKey,setSumoAccessKey]=useState(LS.get("sumo_access_key",""));
  const[generatedRule,setGeneratedRule]=useState("");
  const[generatingRule,setGeneratingRule]=useState(false);
  const [testModal, setTestModal] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [testLoading, setTestLoading] = useState(false);
  const[bulkSelected,setBulkSelected]=useState(new Set());
  const[bulkMode,setBulkMode]=useState(false);
  const[importing,setImporting]=useState(false);
  const[importMsg,setImportMsg]=useState("");
  const[versionHistory,setVersionHistory]=useState({});
  const[loadingVersions,setLoadingVersions]=useState(null);
  const[showVersions,setShowVersions]=useState(null);
  const[saveVersionNote,setSaveVersionNote]=useState("");
  const[savingVersion,setSavingVersion]=useState(false);
  const[playbookModal,setPlaybookModal]=useState(null);
  const[playbookContent,setPlaybookContent]=useState("");
  const[generatingPlaybook,setGeneratingPlaybook]=useState(false);
  const[scoreModal,setScoreModal]=useState(null);
  const[qualityResult,setQualityResult]=useState(null);
  const[scoringDet,setScoringDet]=useState(null);
  const[diffModal,setDiffModal]=useState(null);

  const filtered=detections.filter(d=>
    (!search||d.name.toLowerCase().includes(search.toLowerCase())||d.threat?.toLowerCase().includes(search.toLowerCase()))
    &&(ft==="All"||d.queryType===ft||d.tool===ft)
    &&(fc==="All"||d.tactic===fc)
  );
  const toolObj=TOOLS.reduce((a,t)=>{a[t.id]=t;return a;},{});

  const ATTACK_CHAIN = {
    "Reconnaissance":     {next:["Resource Development","Initial Access"], color:"#ff6688"},
    "Resource Development":{next:["Initial Access"], color:"#aa88ff"},
    "Initial Access":     {next:["Execution","Persistence"], color:THEME.danger},
    "Execution":          {next:["Persistence","Privilege Escalation","Defense Evasion"], color:"#ff7700"},
    "Persistence":        {next:["Privilege Escalation","Defense Evasion"], color:THEME.warning},
    "Privilege Escalation":{next:["Defense Evasion","Credential Access"], color:"#ffcc00"},
    "Defense Evasion":    {next:["Credential Access","Discovery"], color:THEME.purple},
    "Credential Access":  {next:["Discovery","Lateral Movement"], color:"#ff55aa"},
    "Discovery":          {next:["Lateral Movement","Collection"], color:THEME.accent},
    "Lateral Movement":   {next:["Collection","Command and Control"], color:"#00aaff"},
    "Collection":         {next:["Command and Control","Exfiltration"], color:"#00ccaa"},
    "Command and Control":{next:["Exfiltration","Impact"], color:THEME.success},
    "Exfiltration":       {next:["Impact"], color:"#88ff00"},
    "Impact":             {next:[], color:THEME.danger},
  };

  async function scoreDetectionQuick(det){
    setScoring(det.id);setScoreResult("");
    try{const txt=await callClaude([{role:"user",content:"Score this detection 1-10. Give score and 3 improvements.\n\nName: "+det.name+"\nType: "+det.queryType+"\nQuery:\n"+det.query}],"Expert detection engineer.",1000);
    setScoreResult(txt);const m=txt.match(/(\d+)\s*\/\s*10/);if(m)onUpdate({...det,score:parseInt(m[1])});}
    catch(e){setScoreResult("Error: "+e.message);}
    setScoring(null);
  }

  async function enrichDetection(det){
    setEnriching(det.id);
    try{
      const cveMatch = det.name.match(/CVE-\d{4}-\d+/i) || det.threat?.match(/CVE-\d{4}-\d+/i);
      const prompt = `You are a detection engineer advisor. Give a SHORT, actionable enrichment for this detection.

Detection: ${det.name}
Tactic: ${det.tactic}
Severity: ${det.severity}
${cveMatch ? "CVE: "+cveMatch[0] : ""}

Return ONLY valid JSON:
{
  "attack_path_summary": "one sentence: where this fits in the kill chain",
  "next_tactics": ["tactic1","tactic2"],
  "adjacent_detections": [
    {"name":"detection name","why":"one line why you need this too"},
    {"name":"detection name","why":"one line why you need this too"}
  ],
  "high_value_targets": "comma-separated list of assets most at risk (e.g. Domain Controllers, VPN gateways)",
  "cvss_score": "${cveMatch ? 'look up '+cveMatch[0]+' CVSS score, return number like 9.8' : 'N/A'}",
  "quick_win": "one specific thing to do RIGHT NOW to improve this detection",
  "gap_warning": "one sentence about what attack variation this detection MISSES"
}`;
      const result = await callClaude([{role:"user",content:prompt}],"Expert detection engineer. Return ONLY valid JSON.",1200);
      const m = result.match(/\{[\s\S]*\}/);
      if(m){
        const cleaned = m[0].replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,"").replace(/\\(?!["\\/bfnrtu])/g,"\\\\");
        setEnrichData(p=>({...p,[det.id]:JSON.parse(cleaned)}));
      }
    }catch(e){setEnrichData(p=>({...p,[det.id]:{error:"Enrichment failed: "+e.message}}));}
    setEnriching(null);
  }

  // ── Parse indexes/sourcetypes from SPL query ─────────────────────────────
  function parseQueryDataRefs(query){
    if(!query) return {indexes:[],sourcetypes:[]};
    const idxMatches = [...query.matchAll(/index\s*=\s*["']?(\S+?)["']?(?:\s|$|\))/gi)].map(m=>m[1].replace(/['"]/g,""));
    const stMatches = [
      ...[...query.matchAll(/sourcetype\s*=\s*["']?([^\s,)]+)["']?/gi)].map(m=>m[1].replace(/['"]/g,"")),
      ...(query.match(/sourcetype\s+IN\s*\(([^)]+)\)/i)?.[1]||"").split(",").map(s=>s.trim().replace(/['"]/g,"")).filter(Boolean)
    ];
    return {indexes:[...new Set(idxMatches)],sourcetypes:[...new Set(stMatches)]};
  }

  async function analyzeDataRequirements(det,platform="splunk"){
    setLoadingDataReqs(true);setDataReqs(null);
    try{
      const res=await fetch("/api/siem/data-requirements",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:det.name,query:det.query,queryType:det.queryType,tactic:det.tactic,severity:det.severity,platform})});
      const data=await res.json();
      if(data.error) setDataReqs({error:data.error});
      else {
        setDataReqs(data);
        if(data.indexes?.length) setIndexOverride(data.indexes.join(", "));
        if(data.sourcetypes?.length) setSourcetypeOverride(data.sourcetypes.join(", "));
      }
    }catch(e){setDataReqs({error:e.message});}
    setLoadingDataReqs(false);
  }

  // ── Real push functions ───────────────────────────────────────────────────
  function isOnPremUrl(url){
    if(!url) return false;
    try{
      const h = new URL(url).hostname;
      return h==="localhost"||h==="127.0.0.1"||h.endsWith(".local")||
        /^10\./.test(h)||/^192\.168\./.test(h)||/^172\.(1[6-9]|2\d|3[01])\./.test(h);
    }catch{return false;}
  }

  async function pushToSplunk(det){
    const url = splunkUrl || prompt("Splunk URL (e.g. https://your-splunk:8089):");
    if(splunkAuthMode==="basic"){
      if(!url||!splunkUser||!splunkPass){setPushResult("error:Splunk URL, username and password required.");return;}
    } else {
      if(!url||!splunkToken){setPushResult("error:Splunk URL and token required.");return;}
    }
    LS.set("splunk_url",url);
    setSplunkUrl(url);
    setPushing(true);setPushResult("");
    try{
      if(isOnPremUrl(url)){
        // On-prem: call directly from browser (server can't reach local hostnames)
        const sev = det.severity==="critical"?"1":det.severity==="high"?"2":det.severity==="medium"?"3":"4";
        const body = new URLSearchParams({
          name: det.name,
          search: det.query||"",
          "dispatch.earliest_time":"-24h@h",
          "dispatch.latest_time":"now",
          "alert_type":"number of events",
          "alert_comparator":"greater than",
          "alert_threshold":"0",
          "alert.severity": sev,
          "is_scheduled":"1",
          "cron_schedule":"*/15 * * * *",
          "description": det.threat||det.description||""
        });
        const authHeader = splunkAuthMode==="basic"
          ? "Basic "+btoa(`${splunkUser}:${splunkPass}`)
          : `Bearer ${splunkToken}`;
        const res = await fetch(`${url.replace(/\/$/,"")}/services/saved/searches`,{
          method:"POST",
          headers:{"Authorization":authHeader,"Content-Type":"application/x-www-form-urlencoded"},
          body:body.toString()
        });
        if(res.ok||res.status===201){
          setPushResult("success:Detection pushed to Splunk (on-prem) as saved search.");
        } else {
          const txt = await res.text().catch(()=>"");
          if(res.status===409) setPushResult("success:Saved search already exists in Splunk (no change needed).");
          else if(res.status===401) setPushResult("error:Splunk rejected the token — check it has saved search creation rights.");
          else setPushResult("error:Splunk returned "+res.status+(txt?": "+txt.slice(0,200):""));
        }
      } else {
        // Cloud/remote: proxy through backend
        const res = await fetch("/api/siem/push/splunk",{
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({url,token:splunkToken,authMode:splunkAuthMode,username:splunkUser,password:splunkPass,name:det.name,query:det.query,severity:det.severity,description:det.threat||det.description||"",tactic:det.tactic,queryType:det.queryType})
        });
        const data = await res.json();
        if(data.success) setPushResult("success:"+data.message);
        else setPushResult("error:"+(data.error||"Push failed. Check your Splunk URL and credentials."));
      }
    }catch(e){
      const isSelfSignedUrl = splunkUrl && (splunkUrl.includes(".local") || splunkUrl.includes("192.168") || splunkUrl.includes("10.") || splunkUrl.includes("localhost"));
      if(e.message.includes("Failed to fetch")||e.message.includes("NetworkError")){
        if(isSelfSignedUrl){
          setPushResult("error:SSL_CERT:"+splunkUrl);
        } else {
          setPushResult("error:Could not reach Splunk. If CORS is blocking, add DetectIQ's origin to Splunk's web.conf: crossOriginSharingPolicy = *");
        }
      } else {
        setPushResult("error:"+e.message);
      }
    }
    setPushing(false);
  }

  async function pushToElastic(det){
    const url = elasticUrl || prompt("Kibana URL (e.g. https://your-kibana:5601):");
    const token = elasticToken || prompt("Elastic API key (format: base64 of id:api_key):");
    if(!url||!token){setPushResult("error:Kibana URL and API key required.");return;}
    LS.set("elastic_url",url);LS.set("elastic_token",token);
    setElasticUrl(url);setElasticToken(token);
    setPushing(true);setPushResult("");
    try{
      if(isOnPremUrl(url)){
        // On-prem: call directly from browser
        const sev = det.severity==="critical"?"critical":det.severity==="high"?"high":det.severity==="medium"?"medium":"low";
        const langMap = {kql:"kuery",eql:"eql",esql:"esql"};
        const lang = langMap[det.queryType?.toLowerCase()]||"kuery";
        const rule = {name:det.name,description:det.threat||det.description||det.name,risk_score:sev==="critical"?99:sev==="high"?73:sev==="medium"?47:21,severity:sev,type:"query",query:det.query||"",language:lang,index:["logs-*","*"],enabled:false};
        const res = await fetch(`${url.replace(/\/$/,"")}/api/detection_engine/rules`,{
          method:"POST",
          headers:{"Authorization":`ApiKey ${token}`,"Content-Type":"application/json","kbn-xsrf":"detectiq"},
          body:JSON.stringify(rule)
        });
        if(res.ok||res.status===200){
          setPushResult("success:Detection rule created in Elastic Security (on-prem, disabled for review).");
        } else {
          const txt = await res.text().catch(()=>"");
          if(res.status===409) setPushResult("success:Rule already exists in Elastic (no change needed).");
          else if(res.status===401) setPushResult("error:Elastic rejected the API key — ensure it has Security write permissions.");
          else setPushResult("error:Elastic returned "+res.status+(txt?": "+txt.slice(0,200):""));
        }
      } else {
        // Cloud/remote: proxy through backend
        const res = await fetch("/api/siem/push/elastic",{
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({url,token,name:det.name,query:det.query,severity:det.severity,description:det.threat||det.description||det.name,tactic:det.tactic,queryType:det.queryType})
        });
        const data = await res.json();
        if(data.success) setPushResult("success:"+data.message);
        else setPushResult("error:"+(data.error||"Push failed. Check your Kibana URL and API key."));
      }
    }catch(e){
      if(e.message.includes("Failed to fetch")||e.message.includes("NetworkError")){
        setPushResult("error:Could not reach Elastic. For on-prem, enable CORS in Kibana: server.cors.enabled: true in kibana.yml");
      } else {
        setPushResult("error:"+e.message);
      }
    }
    setPushing(false);
  }

  async function pushToSOAR(det){
    const url = soarUrl || prompt("SOAR webhook URL (Splunk SOAR, XSOAR, Tines, n8n, etc):");
    const token = soarToken || "";
    if(!url){setPushResult("error:SOAR webhook URL required.");return;}
    LS.set("soar_url",url);LS.set("soar_token",token);
    setSoarUrl(url);
    setPushing(true);setPushResult("");
    try{
      const payload = {
        source:"DetectIQ",event_type:"detection_push",
        detection:{
          id:det.id,name:det.name,
          tactic:det.tactic,severity:det.severity,
          query_type:det.queryType,tool:det.tool,
          query:det.query,
          description:det.threat||det.description||"",
          tags:det.tags||[],created:det.created,
          mitre_id:det.ads?.mitre_id||"",
          summary:det.ads?.summary||"",
        },
        timestamp:new Date().toISOString(),
      };
      // Proxy through backend (handles CORS + auth for SOAR endpoints that restrict origin)
      const res = await fetch("/api/siem/push/soar",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({url,token,payload})
      });
      const data = await res.json();
      if(data.success){
        setPushResult("success:"+data.message+" Check your SOAR platform for the incoming event.");
      } else {
        setPushResult("error:"+(data.error||"SOAR push failed. Verify the webhook URL is reachable."));
      }
    }catch(e){
      setPushResult("error:Request failed: "+e.message);
    }
    setPushing(false);
  }

  async function pushToGitHub(det){
    const token=githubToken||prompt("GitHub personal access token:");
    const repoFull=githubRepo||prompt("GitHub repo (owner/repo format):");
    if(!token||!repoFull){setPushResult("error:GitHub token and repo required.");return;}
    const parts=repoFull.split("/");
    if(parts.length<2){setPushResult("error:Repo must be in owner/repo format.");return;}
    const [owner,repo]=parts;
    LS.set("github_token",token);LS.set("github_repo",repoFull);
    setGithubToken(token);setGithubRepo(repoFull);
    setPushing(true);setPushResult("");
    try{
      const res=await fetch("/api/github/push",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({token,repo,owner,detection:{name:det.name,query:det.query,tactic:det.tactic,severity:det.severity,queryType:det.queryType,tool:det.tool,threat:det.threat||det.description||""}})
      });
      const data=await res.json();
      if(data.success){setPushResult("success:Detection pushed to GitHub. View at: "+data.url);}
      else{setPushResult("error:"+(data.error||"GitHub push failed."));}
    }catch(e){setPushResult("error:Request failed: "+e.message);}
    setPushing(false);
  }

  async function exportSigmaAI(det){
    setSigmaModal(det);setSigmaContent("");setLoadingSigma(true);
    try{
      const res=await fetch("/api/sigma/export",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({detection:{name:det.name,query:det.query,tactic:det.tactic,technique:det.technique||"",severity:det.severity,queryType:det.queryType,tool:det.tool,threat:det.threat||det.description||""}})
      });
      const data=await res.json();
      if(data.sigma){setSigmaContent(data.sigma);}
      else{setSigmaContent("Error: "+(data.error||"Sigma export failed."));}
    }catch(e){setSigmaContent("Error: "+e.message);}
    setLoadingSigma(false);
  }

  async function pushToLogScale(det){
    if(!logscaleUrl||!logscaleToken||!logscaleRepo){setPushResult("error:LogScale URL, token, and repository are required.");return;}
    LS.set("logscale_url",logscaleUrl);LS.set("logscale_token",logscaleToken);LS.set("logscale_repo",logscaleRepo);
    setPushing(true);setPushResult("");
    try{
      const res=await fetch("/api/siem/push/logscale",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:logscaleUrl,token:logscaleToken,repo:logscaleRepo,name:det.name,query:det.query,description:det.threat||det.description||""})});
      const data=await res.json();
      if(data.success){setPushResult("success:"+data.message);}else{setPushResult("error:"+(data.error||"LogScale push failed."));}
    }catch(e){setPushResult("error:Request failed: "+e.message);}
    setPushing(false);
  }

  async function pushToSumo(det){
    if(!sumoUrl||!sumoAccessId||!sumoAccessKey){setPushResult("error:Sumo Logic URL, Access ID, and Access Key are required.");return;}
    LS.set("sumo_url",sumoUrl);LS.set("sumo_access_id",sumoAccessId);LS.set("sumo_access_key",sumoAccessKey);
    setPushing(true);setPushResult("");
    try{
      const res=await fetch("/api/siem/push/sumo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:sumoUrl,accessId:sumoAccessId,accessKey:sumoAccessKey,name:det.name,query:det.query,description:det.threat||det.description||""})});
      const data=await res.json();
      if(data.success){setPushResult("success:"+data.message);}else{setPushResult("error:"+(data.error||"Sumo Logic push failed."));}
    }catch(e){setPushResult("error:Request failed: "+e.message);}
    setPushing(false);
  }

  async function generatePlatformRule(det,platform){
    setGeneratingRule(true);setGeneratedRule("");setPushResult("");
    try{
      const res=await fetch("/api/siem/push/"+platform,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(platform==="panther"?{detection:{name:det.name,query:det.query,tactic:det.tactic,technique:det.technique||"",severity:det.severity,queryType:det.queryType,tool:det.tool,threat:det.threat||det.description||""}}:{name:det.name,query:det.query,severity:det.severity,tactic:det.tactic,description:det.threat||det.description||""})});
      const data=await res.json();
      if(data.rule){setGeneratedRule(data.rule);}else{setPushResult("error:"+(data.error||"Generation failed."));}
    }catch(e){setPushResult("error:Request failed: "+e.message);}
    setGeneratingRule(false);
  }

  async function generateTicket(det){
    setGeneratingTicket(true);setTicketModal(det);setTicketContent("");
    try{const txt=await callClaude([{role:"user",content:"Brief JIRA ticket for: "+det.name+" ("+det.severity+"/"+det.tactic+"/"+det.queryType+")\n\nSections (2-3 lines each max): Summary, Description, Acceptance Criteria, Test Steps, Rollback."}],"SOC engineer.",1000);
    setTicketContent(txt);}
    catch(e){setTicketContent("Error: "+e.message);}
    setGeneratingTicket(false);
  }

  function exportDet(det,fmt){
    const blob=new Blob([fmt==="json"?JSON.stringify(det,null,2):det.query],{type:"text/plain"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);
    a.download=det.name.replace(/\s+/g,"_")+"."+(fmt==="json"?"json":det.queryType?.toLowerCase()||"txt");
    a.click();
  }

  function exportSigma(det){
    const sigma = `title: ${det.name}
id: ${det.id}
status: experimental
description: ${det.threat||det.description||det.name}
author: DetectIQ
date: ${new Date().toISOString().split("T")[0]}
tags:
  - attack.${(det.tactic||"").toLowerCase().replace(/\s+/g,"_")}
logsource:
  product: windows
  service: security
detection:
  keywords:
    - '${det.query?.split("\n")[0]?.slice(0,60)||det.name}'
  condition: keywords
falsepositives:
  - Legitimate administrative activity
level: ${(det.severity||"medium").toLowerCase()}
`;
    const blob=new Blob([sigma],{type:"text/plain"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);
    a.download=det.name.replace(/\s+/g,"_")+".yml";a.click();
  }

  // Export full library as JSON
  function exportLibraryJSON() {
    const blob = new Blob([JSON.stringify(detections, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "detectiq-library-" + new Date().toISOString().split("T")[0] + ".json"; a.click();
  }

  // Export full library as CSV
  function exportLibraryCSV() {
    const cols = ["name","queryType","tactic","severity","score","threat","created"];
    const escape = v => '"' + String(v||"").replace(/"/g,'""') + '"';
    const rows = [cols.join(","), ...detections.map(d => cols.map(c=>escape(d[c])).join(","))];
    const blob = new Blob([rows.join("\n")], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "detectiq-library-" + new Date().toISOString().split("T")[0] + ".csv"; a.click();
  }

  // Import JSON bundle
  async function importLibraryJSON(e) {
    const file = e.target.files?.[0]; if (!file) return;
    setImporting(true); setImportMsg("");
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const items = Array.isArray(parsed) ? parsed : parsed.detections || [];
      if (!items.length) { setImportMsg("error:No detections found in file."); setImporting(false); return; }
      let imported = 0;
      for (const det of items.slice(0, 50)) {
        const newDet = { ...det, id: uid(), created: new Date().toISOString() };
        if (typeof onSaveDetection === "function") { try { await onSaveDetection(newDet); imported++; } catch {} }
      }
      setImportMsg("success:Imported " + imported + " detections.");
    } catch(e) { setImportMsg("error:Invalid JSON file: " + e.message); }
    setImporting(false);
    e.target.value = "";
  }

  // Bulk delete
  async function bulkDelete() {
    if (!bulkSelected.size) return;
    if (!window.confirm("Delete " + bulkSelected.size + " selected detection(s)?")) return;
    for (const id of bulkSelected) { try { await onDelete(id); } catch {} }
    setBulkSelected(new Set()); setBulkMode(false);
    toast?.(`Deleted ${bulkSelected.size} detection${bulkSelected.size>1?"s":""}`, "success");
  }

  function toggleBulkSelect(id) {
    setBulkSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  async function saveVersion(det) {
    setSavingVersion(true);
    try {
      await fetch("/api/detections/version", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ detectionId: det.id, userId: det.user_id || "demo", query: det.query, name: det.name, notes: saveVersionNote })
      });
      setSaveVersionNote("");
      loadVersions(det.id);
      toast?.("Version saved successfully", "success");
    } catch(e) { console.error(e); toast?.("Failed to save version", "error"); }
    setSavingVersion(false);
  }

  async function loadVersions(detectionId) {
    setLoadingVersions(detectionId);
    try {
      const res = await fetch("/api/detections/versions/" + detectionId);
      const data = await res.json();
      setVersionHistory(prev => ({ ...prev, [detectionId]: data.versions || [] }));
    } catch(e) { console.error(e); }
    setLoadingVersions(null);
  }

  function restoreVersion(det, version) {
    if (!window.confirm("Restore this version? Current query will be overwritten.")) return;
    onUpdate({ ...det, query: version.query });
    toast?.("Version restored", "success");
  }

  async function generatePlaybook(det) {
    setPlaybookModal(det); setPlaybookContent(""); setGeneratingPlaybook(true);
    try {
      const txt = await callClaudeStream(
        [{ role: "user", content: `Short IR playbook for: ${det.name} (${det.tactic}, ${det.severity})

Keep each section to 2-3 bullets, one line each:
1. TRIAGE
2. ENRICH
3. CONTAIN
4. ERADICATE
5. ESCALATE WHEN
6. FP FILTERS
7. PSEUDO-CODE (5 lines max)` }],
        "Expert SOC analyst and SOAR engineer writing incident response playbooks.", 2000,
        (partial) => setPlaybookContent(partial)
      );
      setPlaybookContent(txt);
    } catch(e) { setPlaybookContent("Error: " + e.message); }
    setGeneratingPlaybook(false);
  }

  async function scoreDetection(det) {
    setScoreModal(det); setQualityResult(null); setScoringDet(det.id);
    try {
      const res = await fetch("/api/detection/quality-score", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: det.name, query: det.query, queryType: det.queryType, tactic: det.tactic, severity: det.severity, description: det.threat })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setQualityResult(data);
      // Auto-apply score to detection (overall/10 rounded to 1dp, stored as 0-10)
      const score10 = Math.round(data.overall / 10 * 10) / 10;
      onUpdate({ ...det, score: score10, qualityBreakdown: data.breakdown });
      toast?.(`Quality score applied: ${data.overall}/100 → ${score10}/10`, "success");
    } catch(e) { setQualityResult({ error: e.message }); }
    setScoringDet(null);
  }

  async function testDetection(det) {
    setTestModal(det); setTestResult(null); setTestLoading(true);
    try {
      const res = await fetch("/api/detection/test", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: det.name, query: det.query, queryType: det.queryType, tool: det.tool, tactic: det.tactic, severity: det.severity, threat: det.threat })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setTestResult(data);
    } catch(e) { setTestResult({ error: e.message }); }
    setTestLoading(false);
  }

  const[statusType,statusMsg]=pushResult.split(/:(.+)/);

  return(
    <div>
      <SectionHeader icon="📦" title="Detection Library" color={THEME.success}>
        <div style={S.flex}>
          <span style={S.badge(THEME.success)}>{detections.length} rules</span>
          {bulkMode && bulkSelected.size > 0 && <span style={S.badge(THEME.warning)}>{bulkSelected.size} selected</span>}
          <span style={{...S.badge(THEME.purple),fontSize:9}}>BETA</span>
        </div>
      </SectionHeader>
      <HelpBox title="Detection Library Quick Reference" color={THEME.success} items={[
        {icon:"📦",title:"Your detection store",desc:"Every detection you build is saved here with full version history. Use search and filters to find rules by tactic, severity, SIEM platform, or quality score."},
        {icon:"🏅",title:"Quality Score",desc:"Each rule has a score from 0–10. Click the score badge to see the full breakdown — what's strong, what's weak, and how to improve it."},
        {icon:"⏳",title:"Staleness badges",desc:"Rules older than 90 days get a staleness badge. Old rules may reference outdated field names or miss new attacker techniques — review and re-generate periodically."},
        {icon:"📤",title:"Export & deploy",desc:"Export any rule to Sigma format for platform-agnostic sharing, or push directly to Splunk, Sentinel, Elastic, or CrowdStrike with one click."},
        {icon:"💡",title:"Bulk actions",desc:"Enable Bulk Mode to select multiple rules and export, delete, or push them all at once."},
      ]}/>


      <div style={S.card}>
        <div style={{display:"flex",gap:10,flexWrap:"wrap",marginBottom:10}}>
          <input style={{...S.input,flex:1,minWidth:180}} value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search detections..."/>
          <select style={{...S.input,width:150}} value={ft} onChange={e=>setFt(e.target.value)}><option>All</option>{TOOLS.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}</select>
          <select style={{...S.input,width:190}} value={fc} onChange={e=>setFc(e.target.value)}><option>All</option>{TACTICS.map(t=><option key={t}>{t}</option>)}</select>
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
          <button style={{...S.btn(),padding:"5px 12px",fontSize:11}} onClick={()=>{setBulkMode(b=>!b);setBulkSelected(new Set());}}>{bulkMode?"Exit Bulk Mode":"Bulk Select"}</button>
          {bulkMode && <button style={{...S.btn(),padding:"5px 12px",fontSize:11,color:THEME.danger,borderColor:THEME.danger+"44"}} onClick={bulkDelete} disabled={!bulkSelected.size}>Delete Selected ({bulkSelected.size})</button>}
          {bulkMode && bulkSelected.size < filtered.length && <button style={{...S.btn(),padding:"5px 12px",fontSize:11}} onClick={()=>setBulkSelected(new Set(filtered.map(d=>d.id)))}>Select All ({filtered.length})</button>}
          {bulkMode && bulkSelected.size > 0 && <button style={{...S.btn(),padding:"5px 12px",fontSize:11}} onClick={()=>setBulkSelected(new Set())}>Clear</button>}
          <div style={{flex:1}}/>
          <button style={{...S.btn(),padding:"5px 12px",fontSize:11}} onClick={exportLibraryJSON} title="Export all detections as JSON">Export JSON</button>
          <button style={{...S.btn(),padding:"5px 12px",fontSize:11}} onClick={exportLibraryCSV} title="Export detections as CSV spreadsheet">Export CSV</button>
          <label style={{...S.btn(),padding:"5px 12px",fontSize:11,cursor:"pointer",display:"inline-flex",alignItems:"center"}} title="Import detections from JSON">
            {importing ? <><Spinner/>Importing...</> : "Import JSON"}
            <input type="file" accept=".json" style={{display:"none"}} onChange={importLibraryJSON}/>
          </label>
        </div>
        {importMsg && <div style={{marginTop:8}}><StatusBar msg={importMsg.split(/:(.+)/)[1]||importMsg} type={importMsg.startsWith("success")?"success":"error"}/></div>}
      </div>

      {filtered.length===0&&<div style={{...S.card,textAlign:"center",color:THEME.textDim,padding:50}}><div style={{fontSize:36,marginBottom:12}}>📦</div>No detections found.</div>}

      {filtered.map(det=>{
        const t=toolObj[det.tool];
        const isSelected=selected?.id===det.id;
        const enrich=enrichData[det.id];
        const chainInfo=ATTACK_CHAIN[det.tactic];
        return(
          <div key={det.id} style={{...S.card,borderColor:bulkMode&&bulkSelected.has(det.id)?THEME.warning+"66":isSelected?THEME.accent+"66":THEME.border}}>
            {/* Header */}
            {(()=>{const daysSince=det.created?Math.floor((Date.now()-new Date(det.created).getTime())/(1000*60*60*24)):0; const isStale=daysSince>=90; return(
            <div style={{...S.row,cursor:"pointer",marginBottom:10}} onClick={()=>bulkMode?toggleBulkSelect(det.id):setSelected(isSelected?null:det)}>
              {bulkMode&&<input type="checkbox" checked={bulkSelected.has(det.id)} onChange={()=>toggleBulkSelect(det.id)} onClick={e=>e.stopPropagation()} style={{marginRight:4,cursor:"pointer"}}/>}
              <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                <span style={S.badge(sevColor[det.severity]||THEME.textDim)}>{det.severity||"Medium"}</span>
                <span style={S.badge(t?t.color:THEME.purple)}>{det.queryType}</span>
                {det.ads&&<span style={{...S.badge(THEME.accent),fontSize:9}}>ADS</span>}
                {det.score>0&&<span style={S.badge(THEME.success)}>{det.score}/10</span>}
                {isStale&&<span style={{...S.badge(THEME.warning),fontSize:9}} title={`Last updated ${daysSince} days ago — consider reviewing this detection`}>⚠ {daysSince}d old</span>}
                <span style={{fontSize:14,fontWeight:700,color:THEME.text}}>{det.name}</span>
              </div>
              <span style={{fontSize:16,color:THEME.textDim}}>{isSelected?"▲":"▼"}</span>
            </div>
            );})()}

            {det.threat&&<div style={{fontSize:12,color:THEME.textDim,marginBottom:12}}>{det.threat.slice(0,120)}</div>}

            {/* Action buttons — FREE */}
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}} onClick={e=>e.stopPropagation()}>
              <button style={{...S.btn("p"),padding:"5px 11px",fontSize:11}} onClick={()=>{
                const recs=det.qualityBreakdown?Object.entries(det.qualityBreakdown).filter(([,v])=>v.score<70).map(([k,v])=>`- ${k.replace(/_/g," ")}: ${v.notes}`).join("\n"):"";
                const prompt=det.name+" — "+(det.threat||"")+(recs?"\n\nQuality improvements needed:\n"+recs:"");
                onBuildOn&&onBuildOn(prompt,det.tactic);
              }}>Build on This</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();setShowVersions(showVersions===det.id?null:det.id);if(showVersions!==det.id)loadVersions(det.id);}}>
                📜 Versions{(versionHistory[det.id]||[]).length>0?<span style={{marginLeft:4,background:THEME.accent+"22",color:THEME.accent,borderRadius:10,padding:"0 5px",fontSize:10}}>{(versionHistory[det.id]||[]).length}</span>:""}
              </button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={()=>onSendToTriage&&onSendToTriage(det.query)}>Triage</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={()=>onExplain&&onExplain(det.query,det.tool)}>Explain</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={()=>onTranslate&&onTranslate(det.query,det.tool)}>Translate</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();scoreDetectionQuick(det);}} disabled={scoring===det.id}>{scoring===det.id?<><Spinner/>Scoring...</>:"Score"}</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();enrichDetection(det);}} disabled={enriching===det.id}>{enriching===det.id?<><Spinner/>Enriching...</>:"Enrich"}</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();exportDet(det,"query");}}>Export</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();exportSigma(det);}}>SIGMA</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:"#24292e",color:"#adbac7"}} onClick={e=>{e.stopPropagation();exportSigmaAI(det);}}>&#931; Sigma</button>
            </div>

            {/* BETA actions */}
            <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center",padding:"8px 10px",background:"rgba(124,85,255,0.04)",borderRadius:8,border:"1px solid "+THEME.purple+"22"}} onClick={e=>e.stopPropagation()}>
              <span style={{...S.badge(THEME.purple),fontSize:9,marginRight:4}}>BETA</span>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();setPushModal({det,tab:"splunk"});setPushResult("");setDataReqs(null);setIndexOverride("");setSourcetypeOverride("");}}>Push to Splunk</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();setPushModal({det,tab:"elastic"});setPushResult("");}}>Push to Elastic</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();setPushModal({det,tab:"soar"});setPushResult("");}}>Push to SOAR</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();generateTicket(det);}}>Create Ticket</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();testDetection(det);}}>🧪 Test</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();scoreDetection(det);}} disabled={scoringDet===det.id}>{scoringDet===det.id?<><Spinner/>Scoring...</>:"⭐ Score"}</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();generatePlaybook(det);}}>🎭 Playbook</button>
              <button style={{...S.btn("d"),padding:"5px 11px",fontSize:11,marginLeft:"auto"}} onClick={e=>{e.stopPropagation();if(confirm("Delete?"))onDelete(det.id);}}>Delete</button>
            </div>

            {/* Version History panel */}
            {showVersions===det.id&&(
              <div style={{marginTop:16,padding:16,background:"#050d18",borderRadius:10,border:"1px solid #1a2a3a"}}>
                <div style={{...S.row,marginBottom:12}}>
                  <div style={{display:"flex",alignItems:"center",gap:10}}>
                    <div style={{fontSize:13,fontWeight:700,color:THEME.textMid}}>📜 Version History</div>
                    {(versionHistory[det.id]||[]).length>0&&(
                      <button style={{...S.btn(),padding:"4px 12px",fontSize:11,borderColor:THEME.accent+"55",color:THEME.accent,fontWeight:700}} onClick={()=>setDiffModal({det,vA:(versionHistory[det.id]||[])[0],vB:{query:det.query,created_at:new Date().toISOString(),notes:"Current"},labelA:`Latest saved`,labelB:"Current"})}>⟷ Compare Latest vs Current</button>
                    )}
                  </div>
                  <div style={{display:"flex",gap:8}}>
                    <input style={{...S.input,fontSize:11,padding:"4px 10px",width:200}} value={saveVersionNote} onChange={e=>setSaveVersionNote(e.target.value)} placeholder="Change note (optional)"/>
                    <button style={{...S.btn("p"),padding:"4px 12px",fontSize:11}} onClick={()=>saveVersion(det)} disabled={savingVersion}>{savingVersion?<><Spinner/>Saving...</>:"💾 Save Version"}</button>
                  </div>
                </div>
                {loadingVersions===det.id&&<div style={{color:THEME.textDim,fontSize:12,textAlign:"center",padding:16}}><Spinner/> Loading versions...</div>}
                {(versionHistory[det.id]||[]).map((v,i,arr)=>(
                  <div key={v.id||i} style={{padding:"10px 0",borderBottom:"1px solid #1a2a3a"}}>
                    <div style={{display:"flex",gap:10,alignItems:"flex-start"}}>
                      <div style={{flex:1}}>
                        <div style={{display:"flex",alignItems:"center",gap:8}}>
                          <span style={{fontSize:11,color:THEME.textDim}}>{new Date(v.created_at).toLocaleString()}</span>
                          {i===0&&<span style={{...S.badge(THEME.success),fontSize:9}}>LATEST</span>}
                        </div>
                        {v.notes&&<div style={{fontSize:12,color:THEME.textMid,marginTop:3}}>{v.notes}</div>}
                        <div style={{fontSize:11,fontFamily:"monospace",color:THEME.accent,marginTop:4,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:400}}>{v.query?.slice(0,80)}...</div>
                      </div>
                      <div style={{display:"flex",gap:6,flexShrink:0}}>
                        <button style={{...S.btn(),padding:"4px 10px",fontSize:11}} title="Compare this version with current query" onClick={()=>setDiffModal({det,vA:v,vB:{query:det.query,created_at:new Date().toISOString(),notes:"Current"},labelA:`v${arr.length-i} (saved)`,labelB:"Current"})}>⟷ vs Now</button>
                        {i<arr.length-1&&<button style={{...S.btn(),padding:"4px 10px",fontSize:11}} title="Compare with previous version" onClick={()=>setDiffModal({det,vA:arr[i+1],vB:v,labelA:`v${arr.length-i-1}`,labelB:`v${arr.length-i}`})}>⟷ vs Prev</button>}
                        <button style={{...S.btn(),padding:"4px 10px",fontSize:11}} onClick={()=>restoreVersion(det,v)}>Restore</button>
                      </div>
                    </div>
                  </div>
                ))}
                {!loadingVersions&&!(versionHistory[det.id]||[]).length&&<div style={{color:THEME.textDim,fontSize:12,textAlign:"center",padding:24}}><div style={{fontSize:28,marginBottom:8}}>📜</div><div style={{fontWeight:600,color:THEME.text,marginBottom:4}}>No versions saved yet</div><div style={{fontSize:11}}>Click "Save Version" above to snapshot the current query before making changes.</div></div>}
              </div>
            )}

            {/* Enrichment panel */}
            {enrich&&!enrich.error&&(
              <div style={{marginTop:12,padding:14,background:"rgba(124,85,255,0.04)",border:"1px solid "+THEME.purple+"33",borderRadius:10}}>
                <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.15em",marginBottom:12}}>SMART ENRICHMENT</div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
                  {/* Attack Path */}
                  <div style={{padding:12,background:"rgba(255,61,85,0.05)",borderRadius:8,border:"1px solid rgba(255,61,85,0.2)"}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.danger,letterSpacing:"0.1em",marginBottom:6}}>ATTACK PATH</div>
                    <div style={{fontSize:12,color:THEME.textMid,marginBottom:8,lineHeight:1.6}}>{enrich.attack_path_summary}</div>
                    {enrich.next_tactics?.length>0&&(
                      <div>
                        <div style={{fontSize:10,color:THEME.textDim,marginBottom:4}}>Likely next tactics:</div>
                        <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                          {enrich.next_tactics.map(tac=>(
                            <button key={tac} style={{...S.btn("p"),padding:"3px 8px",fontSize:10}} onClick={()=>onBuildOn&&onBuildOn("Detection for "+tac,tac)}>{tac} →</button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                  {/* Adjacent Detections */}
                  <div style={{padding:12,background:"rgba(0,212,255,0.04)",borderRadius:8,border:"1px solid rgba(0,212,255,0.15)"}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.1em",marginBottom:6}}>BUILD THESE NEXT</div>
                    {enrich.adjacent_detections?.map((ad,i)=>(
                      <div key={i} style={{marginBottom:8}}>
                        <button style={{...S.btn("p"),padding:"3px 8px",fontSize:10,marginBottom:3,display:"block"}} onClick={()=>onBuildOn&&onBuildOn(ad.name,det.tactic)}>{ad.name}</button>
                        <div style={{fontSize:11,color:THEME.textDim,lineHeight:1.4}}>{ad.why}</div>
                      </div>
                    ))}
                  </div>
                  {/* Asset Risk */}
                  <div style={{padding:12,background:"rgba(255,170,0,0.04)",borderRadius:8,border:"1px solid rgba(255,170,0,0.2)"}}>
                    <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.1em",marginBottom:6}}>HIGH-VALUE TARGETS</div>
                    <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{enrich.high_value_targets}</div>
                  </div>
                  {/* CVSS + Quick Win */}
                  <div style={{padding:12,background:"rgba(0,232,122,0.04)",borderRadius:8,border:"1px solid rgba(0,232,122,0.2)"}}>
                    {enrich.cvss_score&&enrich.cvss_score!=="N/A"&&(
                      <div style={{marginBottom:8}}>
                        <div style={{fontSize:10,fontWeight:800,color:THEME.success,letterSpacing:"0.1em",marginBottom:4}}>CVSS SCORE</div>
                        <div style={{fontSize:22,fontWeight:900,color:parseFloat(enrich.cvss_score)>=9?THEME.danger:parseFloat(enrich.cvss_score)>=7?THEME.orange:THEME.warning}}>{enrich.cvss_score}</div>
                      </div>
                    )}
                    <div style={{fontSize:10,fontWeight:800,color:THEME.success,letterSpacing:"0.1em",marginBottom:4}}>QUICK WIN</div>
                    <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{enrich.quick_win}</div>
                    {enrich.gap_warning&&<div style={{marginTop:8,fontSize:11,color:THEME.danger,lineHeight:1.5,borderTop:"1px solid rgba(255,61,85,0.2)",paddingTop:6}}>Gap: {enrich.gap_warning}</div>}
                  </div>
                </div>
              </div>
            )}
            {enrich?.error&&<div style={{marginTop:8,fontSize:12,color:THEME.danger}}>{enrich.error}</div>}
            {scoreResult&&scoring===null&&selected?.id===det.id&&<div style={{marginTop:10,padding:12,background:"#02040a",borderRadius:8,fontSize:12,color:THEME.textMid,whiteSpace:"pre-wrap",lineHeight:1.7,border:"1px solid "+THEME.border}}>{scoreResult}</div>}
            {det.qualityBreakdown&&(
              <div style={{marginTop:10,padding:"10px 14px",background:"rgba(255,170,0,0.05)",border:"1px solid rgba(255,170,0,0.2)",borderRadius:8}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                  <span style={{fontSize:11,fontWeight:700,color:THEME.warning}}>⭐ Quality Breakdown</span>
                  <span style={{...S.badge(det.score>=8?THEME.success:det.score>=6?THEME.warning:THEME.danger),fontSize:10}}>{det.score}/10</span>
                </div>
                <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                  {Object.entries(det.qualityBreakdown).map(([k,v])=>(
                    <div key={k} style={{padding:"3px 9px",borderRadius:5,fontSize:10,background:v.score>=70?"rgba(0,232,122,0.08)":v.score>=50?"rgba(255,170,0,0.08)":"rgba(255,45,85,0.08)",border:"1px solid "+(v.score>=70?"rgba(0,232,122,0.25)":v.score>=50?"rgba(255,170,0,0.25)":"rgba(255,45,85,0.25)"),color:v.score>=70?THEME.success:v.score>=50?THEME.warning:THEME.danger,display:"flex",alignItems:"center",gap:5}}>
                      <span style={{fontWeight:700}}>{v.score}</span>
                      <span style={{opacity:0.8,textTransform:"capitalize"}}>{k.replace(/_/g," ")}</span>
                    </div>
                  ))}
                </div>
                {Object.entries(det.qualityBreakdown).some(([,v])=>v.score<70)&&(
                  <div style={{marginTop:8,fontSize:10,color:THEME.textDim}}>
                    💡 Weak areas: {Object.entries(det.qualityBreakdown).filter(([,v])=>v.score<70).map(([k,v])=>v.notes).join(" · ")}
                  </div>
                )}
              </div>
            )}

            {/* Expanded query */}
            {isSelected&&(
              <div onClick={e=>e.stopPropagation()}>
                <div style={S.divider}/>
                {det.ads?.summary&&<div style={{fontSize:13,color:THEME.textMid,marginBottom:10,padding:"8px 12px",background:THEME.accentGlow,borderRadius:7,borderLeft:"3px solid "+THEME.accentDim}}>{det.ads.summary}</div>}
                <div style={{position:"relative"}}>
                  <div style={S.code}>{det.ads?.detection_query||det.query}</div>
                  <div style={{position:"absolute",top:8,right:8}}><CopyBtn text={det.ads?.detection_query||det.query}/></div>
                </div>
              </div>
            )}
          </div>
        );
      })}

      {/* Push Modal */}
      {pushModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.82)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:1000,backdropFilter:"blur(6px)"}} onClick={()=>{setPushModal(null);setPushResult("");}}>
          <div style={{background:"linear-gradient(145deg,#0c1220,#080d18)",border:"1px solid "+THEME.borderBright,borderRadius:16,padding:32,width:"100%",maxWidth:560,maxHeight:"90vh",overflowY:"auto",boxShadow:"0 32px 80px rgba(0,0,0,0.7)"}} onClick={e=>e.stopPropagation()}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.15em",marginBottom:6}}>BETA — PUSH TO PLATFORM</div>
            <div style={{fontSize:17,fontWeight:900,color:THEME.text,marginBottom:16}}>{pushModal.det.name}</div>

            {/* Platform tabs */}
            <div style={{display:"flex",gap:6,marginBottom:8,flexWrap:"wrap"}}>
              {[{id:"splunk",label:"Splunk",color:"#ff5733"},{id:"elastic",label:"Elastic",color:"#f4bd19"},{id:"soar",label:"SOAR",color:THEME.success},{id:"github",label:"GitHub",color:"#adbac7"},{id:"crowdstrike",label:"CrowdStrike",color:"#e1292b"},{id:"logscale",label:"LogScale",color:"#ff6b35"},{id:"tanium",label:"Tanium",color:"#00a1e0"},{id:"panther",label:"Panther",color:"#7c3aed"},{id:"sumo",label:"Sumo Logic",color:"#000099"}].map(p=>(
                <button key={p.id} style={{...S.btn(pushModal.tab===p.id?"p":""),padding:"6px 12px",fontSize:11,borderColor:pushModal.tab===p.id?p.color+"88":THEME.border,color:pushModal.tab===p.id?p.color:THEME.textDim,background:pushModal.tab===p.id&&p.id==="github"?"#24292e":undefined}} onClick={()=>{setPushModal({...pushModal,tab:p.id});setDataReqs(null);setIndexOverride("");setSourcetypeOverride("");setGeneratedRule("");setPushResult("");}}>{p.label}</button>
              ))}
            </div>
            <div style={{height:12}}/>

            {/* Splunk config */}
            {pushModal.tab==="splunk"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:10,lineHeight:1.6}}>Creates a saved search with 15-min schedule and alerting via Splunk REST API.</div>

                {/* Data Requirements Section */}
                {(()=>{
                  const det=pushModal.det;
                  const parsed=parseQueryDataRefs(det?.query);
                  return(
                    <div style={{background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",borderRadius:8,padding:"12px 14px",marginBottom:14}}>
                      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                        <div style={{fontSize:11,fontWeight:700,color:THEME.accent,letterSpacing:"0.08em"}}>DATA REQUIREMENTS</div>
                        <button style={{...S.btn(),padding:"3px 10px",fontSize:10,borderColor:THEME.accent+"44",color:THEME.accent}} onClick={()=>analyzeDataRequirements(det)} disabled={loadingDataReqs}>
                          {loadingDataReqs?<><Spinner/>Analyzing...</>:"AI Analyze"}
                        </button>
                      </div>

                      {/* Auto-parsed from query */}
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
                        <div>
                          <div style={{...S.label,marginBottom:4}}>Indexes{parsed.indexes.length?"":" (auto-detect)"}</div>
                          <input style={{...S.input,fontSize:11}} value={indexOverride||parsed.indexes.join(", ")} onChange={e=>setIndexOverride(e.target.value)} placeholder="e.g. windows, main, *"/>
                        </div>
                        <div>
                          <div style={{...S.label,marginBottom:4}}>Sourcetypes{parsed.sourcetypes.length?"":" (auto-detect)"}</div>
                          <input style={{...S.input,fontSize:11}} value={sourcetypeOverride||parsed.sourcetypes.join(", ")} onChange={e=>setSourcetypeOverride(e.target.value)} placeholder="e.g. WinEventLog:Security"/>
                        </div>
                      </div>

                      {/* AI Analysis results */}
                      {dataReqs&&!dataReqs.error&&(
                        <div style={{borderTop:"1px solid rgba(0,212,255,0.1)",paddingTop:10,marginTop:4}}>
                          {dataReqs.cim_datamodels?.length>0&&(
                            <div style={{marginBottom:8}}>
                              <div style={{...S.label,marginBottom:4}}>CIM Data Models</div>
                              <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                                {dataReqs.cim_datamodels.map((m,i)=><span key={i} style={{...S.badge(THEME.accent),fontSize:9}}>{m}</span>)}
                              </div>
                            </div>
                          )}
                          {dataReqs.data_sources?.length>0&&(
                            <div style={{marginBottom:8}}>
                              <div style={{...S.label,marginBottom:4}}>Required Data Sources</div>
                              <div style={{fontSize:11,color:THEME.textMid,lineHeight:1.6}}>{dataReqs.data_sources.join(" · ")}</div>
                            </div>
                          )}
                          {dataReqs.ta_recommendations?.length>0&&(
                            <div style={{marginBottom:8}}>
                              <div style={{...S.label,marginBottom:4}}>Recommended Splunk TAs</div>
                              <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                                {dataReqs.ta_recommendations.map((t,i)=><span key={i} style={{...S.badge(THEME.purple),fontSize:9}}>{t}</span>)}
                              </div>
                            </div>
                          )}
                          {dataReqs.required_fields?.length>0&&(
                            <div style={{marginBottom:8}}>
                              <div style={{...S.label,marginBottom:4}}>Required Fields</div>
                              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:3}}>
                                {dataReqs.required_fields.slice(0,8).map((f,i)=>(
                                  <div key={i} style={{fontSize:10,color:THEME.textMid,background:"rgba(255,255,255,0.03)",borderRadius:4,padding:"3px 6px"}}>
                                    <span style={{color:THEME.text,fontFamily:"monospace"}}>{f.field}</span>
                                    {f.cim_mapping&&<span style={{color:THEME.accent}}> → {f.cim_mapping}</span>}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          {dataReqs.normalization_steps?.length>0&&(
                            <details style={{marginTop:4}}>
                              <summary style={{fontSize:11,color:THEME.textDim,cursor:"pointer",padding:"2px 0"}}>Normalization Steps</summary>
                              <ol style={{margin:"6px 0 0 16px",padding:0,fontSize:11,color:THEME.textMid,lineHeight:1.8}}>
                                {dataReqs.normalization_steps.map((s,i)=><li key={i}>{s}</li>)}
                              </ol>
                            </details>
                          )}
                          {dataReqs.notes&&<div style={{fontSize:11,color:"#f5a023",marginTop:6,lineHeight:1.5}}>{dataReqs.notes}</div>}
                        </div>
                      )}
                      {dataReqs?.error&&<div style={{fontSize:11,color:THEME.danger}}>{dataReqs.error}</div>}
                    </div>
                  );
                })()}
                <label style={S.label}>Splunk URL</label>
                <input style={{...S.input,marginBottom:10}} value={splunkUrl} onChange={e=>setSplunkUrl(e.target.value)} placeholder="https://your-splunk:8089"/>
                {/* Auth mode toggle */}
                <div style={{display:"flex",gap:6,marginBottom:10}}>
                  {["token","basic"].map(m=>(
                    <button key={m} style={{...S.btn(splunkAuthMode===m?"p":""),padding:"4px 12px",fontSize:11}} onClick={()=>{setSplunkAuthMode(m);LS.set("splunk_auth_mode",m);}}>
                      {m==="token"?"API Token":"Username / Password"}
                    </button>
                  ))}
                </div>
                {splunkAuthMode==="token"?(
                  <>
                    <label style={S.label}>API Token (Bearer)</label>
                    <input style={{...S.input,marginBottom:12,fontFamily:"monospace"}} type="password" value={splunkToken} onChange={e=>{setSplunkToken(e.target.value);LS.set("splunk_token",e.target.value);}} placeholder="Token from Settings → Tokens"/>
                  </>
                ):(
                  <>
                    <label style={S.label}>Username</label>
                    <input style={{...S.input,marginBottom:8}} value={splunkUser} onChange={e=>{setSplunkUser(e.target.value);LS.set("splunk_user",e.target.value);}} placeholder="admin"/>
                    <label style={S.label}>Password</label>
                    <input style={{...S.input,marginBottom:12,fontFamily:"monospace"}} type="password" value={splunkPass} onChange={e=>{setSplunkPass(e.target.value);LS.set("splunk_pass",e.target.value);}} placeholder="Splunk password"/>
                  </>
                )}
                {splunkUrl&&isOnPremUrl(splunkUrl)&&(
                  <div style={{fontSize:11,color:"#f5a023",background:"rgba(245,160,35,0.06)",border:"1px solid rgba(245,160,35,0.2)",borderRadius:6,padding:"7px 10px",marginBottom:12,lineHeight:1.6}}>
                    On-prem URL detected — direct push may fail due to browser network restrictions. Use cURL below if the button fails.
                  </div>
                )}
                <button style={{...S.btn("p"),width:"100%",padding:"10px",marginBottom:8}} onClick={()=>pushToSplunk(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Pushing to Splunk...</>:"Push to Splunk"}</button>
                {(()=>{
                  const det=pushModal.det;
                  const sev=det?.severity==="critical"?"1":det?.severity==="high"?"2":det?.severity==="medium"?"3":"4";
                  const q=(det?.query||"").replace(/\\/g,"\\\\").replace(/"/g,'\\"');
                  const desc=(det?.threat||det?.description||"").replace(/\\/g,"\\\\").replace(/"/g,'\\"');
                  const authFlag=splunkAuthMode==="basic"
                    ?`-u "${splunkUser||"admin"}:${splunkPass||"<PASSWORD>"}"`
                    :`-H "Authorization: Bearer ${splunkToken||"<YOUR_TOKEN>"}"`;
                  const cmd=`curl -k -X POST "${(splunkUrl||"https://splunk:8089").replace(/\/$/,"")}/services/saved/searches" \\\n  ${authFlag} \\\n  -H "Content-Type: application/x-www-form-urlencoded" \\\n  --data-urlencode "name=${det?.name||"detection"}" \\\n  --data-urlencode "search=${q}" \\\n  --data-urlencode "description=${desc}" \\\n  --data-urlencode "dispatch.earliest_time=-24h@h" \\\n  --data-urlencode "dispatch.latest_time=now" \\\n  --data-urlencode "is_scheduled=1" \\\n  --data-urlencode "cron_schedule=*/15 * * * *" \\\n  --data-urlencode "alert_type=number of events" \\\n  --data-urlencode "alert_comparator=greater than" \\\n  --data-urlencode "alert_threshold=0" \\\n  --data-urlencode "alert.severity=${sev}"`;
                  return(
                    <details style={{marginTop:4}}>
                      <summary style={{fontSize:11,color:THEME.textDim,cursor:"pointer",userSelect:"none",padding:"4px 0"}}>cURL alternative (on-prem / manual)</summary>
                      <pre style={{background:"#0a0d14",border:"1px solid "+THEME.border,borderRadius:8,padding:"10px",fontSize:10,color:THEME.textMid,overflowX:"auto",overflowY:"auto",maxHeight:160,lineHeight:1.7,whiteSpace:"pre-wrap",wordBreak:"break-all",margin:"8px 0"}}>{cmd}</pre>
                      <button style={{...S.btn(),width:"100%",padding:"8px",fontSize:11}} onClick={()=>{navigator.clipboard.writeText(cmd);setPushResult("success:cURL command copied — paste it in your terminal.");}}>Copy cURL</button>
                    </details>
                  );
                })()}
              </div>
            )}

            {/* Elastic config */}
            {pushModal.tab==="elastic"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:10,lineHeight:1.6}}>Creates a detection rule in Elastic Security via Kibana API. Rule is created as disabled for review.</div>

                {/* Elastic Data Requirements */}
                {(()=>{
                  const det=pushModal.det;
                  const dr=dataReqs;
                  return(
                    <div style={{background:"rgba(244,189,25,0.04)",border:"1px solid rgba(244,189,25,0.15)",borderRadius:8,padding:"12px 14px",marginBottom:14}}>
                      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                        <div style={{fontSize:11,fontWeight:700,color:"#f4bd19",letterSpacing:"0.08em"}}>DATA REQUIREMENTS</div>
                        <button style={{...S.btn(),padding:"3px 10px",fontSize:10,borderColor:"#f4bd1944",color:"#f4bd19"}} onClick={()=>analyzeDataRequirements(det,"elastic")} disabled={loadingDataReqs}>
                          {loadingDataReqs?<><Spinner/>Analyzing...</>:"AI Analyze"}
                        </button>
                      </div>
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:dr?8:0}}>
                        <div>
                          <div style={{...S.label,marginBottom:4}}>Index Patterns</div>
                          <input style={{...S.input,fontSize:11}} value={indexOverride} onChange={e=>setIndexOverride(e.target.value)} placeholder="logs-endpoint.events.*, winlogbeat-*"/>
                        </div>
                        <div>
                          <div style={{...S.label,marginBottom:4}}>Data Streams</div>
                          <input style={{...S.input,fontSize:11}} value={sourcetypeOverride} onChange={e=>setSourcetypeOverride(e.target.value)} placeholder="logs-endpoint.events.process-*"/>
                        </div>
                      </div>
                      {dr&&!dr.error&&(
                        <div style={{borderTop:"1px solid rgba(244,189,25,0.1)",paddingTop:10,marginTop:4}}>
                          {dr.ecs_categories?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>ECS Event Categories</div><div style={{display:"flex",flexWrap:"wrap",gap:4}}>{dr.ecs_categories.map((c,i)=><span key={i} style={{...S.badge("#f4bd19"),fontSize:9}}>{c}</span>)}</div></div>}
                          {dr.integrations?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>Elastic Agent Integrations</div><div style={{display:"flex",flexWrap:"wrap",gap:4}}>{dr.integrations.map((t,i)=><span key={i} style={{...S.badge(THEME.purple),fontSize:9}}>{t}</span>)}</div></div>}
                          {dr.beats?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>Beats Modules</div><div style={{display:"flex",flexWrap:"wrap",gap:4}}>{dr.beats.map((b,i)=><span key={i} style={{...S.badge(THEME.success),fontSize:9}}>{b}</span>)}</div></div>}
                          {dr.required_fields?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>Required Fields (ECS)</div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:3}}>{dr.required_fields.slice(0,8).map((f,i)=><div key={i} style={{fontSize:10,color:THEME.textMid,background:"rgba(255,255,255,0.03)",borderRadius:4,padding:"3px 6px"}}><span style={{color:THEME.text,fontFamily:"monospace"}}>{f.field}</span>{f.ecs_mapping&&<span style={{color:"#f4bd19"}}> → {f.ecs_mapping}</span>}</div>)}</div></div>}
                          {dr.data_sources?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>Data Sources</div><div style={{fontSize:11,color:THEME.textMid,lineHeight:1.6}}>{dr.data_sources.join(" · ")}</div></div>}
                          {dr.normalization_steps?.length>0&&<details style={{marginTop:4}}><summary style={{fontSize:11,color:THEME.textDim,cursor:"pointer",padding:"2px 0"}}>Normalization Steps</summary><ol style={{margin:"6px 0 0 16px",padding:0,fontSize:11,color:THEME.textMid,lineHeight:1.8}}>{dr.normalization_steps.map((s,i)=><li key={i}>{s}</li>)}</ol></details>}
                          {dr.notes&&<div style={{fontSize:11,color:"#f5a023",marginTop:6,lineHeight:1.5}}>{dr.notes}</div>}
                        </div>
                      )}
                      {dr?.error&&<div style={{fontSize:11,color:THEME.danger}}>{dr.error}</div>}
                    </div>
                  );
                })()}

                <label style={S.label}>Kibana URL</label>
                <input style={{...S.input,marginBottom:10}} value={elasticUrl} onChange={e=>setElasticUrl(e.target.value)} placeholder="https://your-kibana:5601"/>
                <label style={S.label}>API Key (base64 id:key)</label>
                <input style={{...S.input,marginBottom:12,fontFamily:"monospace"}} type="password" value={elasticToken} onChange={e=>setElasticToken(e.target.value)} placeholder="Elastic API key"/>
                {elasticUrl&&isOnPremUrl(elasticUrl)&&(
                  <div style={{fontSize:11,color:"#f5a023",background:"rgba(245,160,35,0.06)",border:"1px solid rgba(245,160,35,0.2)",borderRadius:6,padding:"7px 10px",marginBottom:12,lineHeight:1.6}}>
                    On-prem URL detected — direct push may fail due to browser network restrictions. Use cURL below if the button fails.
                  </div>
                )}
                <button style={{...S.btn("p"),width:"100%",padding:"10px",marginBottom:8}} onClick={()=>pushToElastic(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Pushing to Elastic...</>:"Push to Elastic"}</button>
                {(()=>{
                  const det=pushModal.det;
                  const sev=det?.severity==="critical"?"critical":det?.severity==="high"?"high":det?.severity==="medium"?"medium":"low";
                  const langMap={kql:"kuery",eql:"eql",esql:"esql"};
                  const lang=langMap[det?.queryType?.toLowerCase()]||"kuery";
                  const idxPatterns=indexOverride?indexOverride.split(",").map(s=>s.trim()).filter(Boolean):["logs-*","*"];
                  const rule=JSON.stringify({name:det?.name,description:det?.threat||det?.description||det?.name,risk_score:sev==="critical"?99:sev==="high"?73:sev==="medium"?47:21,severity:sev,type:"query",query:det?.query||"",language:lang,index:idxPatterns,enabled:false},null,2);
                  const safeRule=rule.replace(/'/g,"'\\''");
                  const cmd=`curl -k -X POST "${(elasticUrl||"https://kibana:5601").replace(/\/$/,"")}/api/detection_engine/rules" \\\n  -H "Authorization: ApiKey ${elasticToken||"<YOUR_API_KEY>"}" \\\n  -H "Content-Type: application/json" \\\n  -H "kbn-xsrf: detectiq" \\\n  -d '${safeRule}'`;
                  return(
                    <details style={{marginTop:4}}>
                      <summary style={{fontSize:11,color:THEME.textDim,cursor:"pointer",userSelect:"none",padding:"4px 0"}}>cURL alternative (on-prem / manual)</summary>
                      <pre style={{background:"#0a0d14",border:"1px solid "+THEME.border,borderRadius:8,padding:"10px",fontSize:10,color:THEME.textMid,overflowX:"auto",overflowY:"auto",maxHeight:160,lineHeight:1.7,whiteSpace:"pre-wrap",wordBreak:"break-all",margin:"8px 0"}}>{cmd}</pre>
                      <button style={{...S.btn(),width:"100%",padding:"8px",fontSize:11}} onClick={()=>{navigator.clipboard.writeText(cmd);setPushResult("success:cURL command copied — paste it in your terminal.");}}>Copy cURL</button>
                    </details>
                  );
                })()}
              </div>
            )}

            {/* SOAR config */}
            {pushModal.tab==="soar"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:10,lineHeight:1.6}}>Sends a structured JSON payload to any SOAR webhook — Splunk SOAR, Palo Alto XSOAR, Tines, n8n, Make, or any HTTP trigger.</div>

                {/* SOAR Data Requirements */}
                {(()=>{
                  const det=pushModal.det;
                  const dr=dataReqs;
                  return(
                    <div style={{background:"rgba(0,232,122,0.04)",border:"1px solid rgba(0,232,122,0.15)",borderRadius:8,padding:"12px 14px",marginBottom:14}}>
                      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                        <div style={{fontSize:11,fontWeight:700,color:THEME.success,letterSpacing:"0.08em"}}>PLAYBOOK REQUIREMENTS</div>
                        <button style={{...S.btn(),padding:"3px 10px",fontSize:10,borderColor:THEME.success+"44",color:THEME.success}} onClick={()=>analyzeDataRequirements(det,"soar")} disabled={loadingDataReqs}>
                          {loadingDataReqs?<><Spinner/>Analyzing...</>:"AI Analyze"}
                        </button>
                      </div>
                      {!dr&&<div style={{fontSize:11,color:THEME.textDim}}>Click AI Analyze to get recommended playbook actions, triage checklist, and false positive filters for this detection.</div>}
                      {dr&&!dr.error&&(
                        <div>
                          {dr.recommended_playbook_actions?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>Recommended Playbook Actions</div><ol style={{margin:"4px 0 0 16px",padding:0,fontSize:11,color:THEME.textMid,lineHeight:1.8}}>{dr.recommended_playbook_actions.map((a,i)=><li key={i}>{a}</li>)}</ol></div>}
                          {dr.triage_checklist?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>Triage Checklist</div><ol style={{margin:"4px 0 0 16px",padding:0,fontSize:11,color:THEME.textMid,lineHeight:1.8}}>{dr.triage_checklist.map((c,i)=><li key={i}>{c}</li>)}</ol></div>}
                          {dr.escalation_criteria?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>Escalation Criteria</div><div style={{display:"flex",flexWrap:"wrap",gap:4}}>{dr.escalation_criteria.map((e,i)=><span key={i} style={{...S.badge(THEME.danger),fontSize:9}}>{e}</span>)}</div></div>}
                          {dr.false_positive_filters?.length>0&&<div style={{marginBottom:8}}><div style={{...S.label,marginBottom:4}}>False Positive Filters</div><div style={{fontSize:11,color:THEME.textMid,lineHeight:1.6}}>{dr.false_positive_filters.map((f,i)=><div key={i}>• {f}</div>)}</div></div>}
                          {dr.required_fields?.length>0&&<details><summary style={{fontSize:11,color:THEME.textDim,cursor:"pointer",padding:"2px 0"}}>Required Payload Fields</summary><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:3,marginTop:6}}>{dr.required_fields.slice(0,10).map((f,i)=><div key={i} style={{fontSize:10,color:THEME.textMid,background:"rgba(255,255,255,0.03)",borderRadius:4,padding:"3px 6px"}}><span style={{color:THEME.text,fontFamily:"monospace"}}>{f.field}</span>{f.example&&<span style={{color:THEME.textDim}}> ({f.example})</span>}</div>)}</div></details>}
                          {dr.notes&&<div style={{fontSize:11,color:"#f5a023",marginTop:6,lineHeight:1.5}}>{dr.notes}</div>}
                        </div>
                      )}
                      {dr?.error&&<div style={{fontSize:11,color:THEME.danger}}>{dr.error}</div>}
                    </div>
                  );
                })()}

                <label style={S.label}>Webhook URL</label>
                <input style={{...S.input,marginBottom:10}} value={soarUrl} onChange={e=>setSoarUrl(e.target.value)} placeholder="https://your-soar/webhook/..."/>
                <label style={S.label}>Bearer Token (optional)</label>
                <input style={{...S.input,marginBottom:14,fontFamily:"monospace"}} type="password" value={soarToken} onChange={e=>setSoarToken(e.target.value)} placeholder="Optional auth token"/>
                <button style={{...S.btn("p"),width:"100%",padding:"10px"}} onClick={()=>pushToSOAR(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Sending to SOAR...</>:"Send to SOAR"}</button>
              </div>
            )}

            {/* GitHub config */}
            {pushModal.tab==="github"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Creates or updates a file at <code style={{fontFamily:"monospace",background:"rgba(255,255,255,0.05)",padding:"2px 5px",borderRadius:4}}>detections/{"{tactic}/{name}.{ext}"}</code> in your GitHub repo.</div>
                <label style={S.label}>Personal Access Token</label>
                <input style={{...S.input,marginBottom:10,fontFamily:"monospace"}} type="password" value={githubToken} onChange={e=>setGithubToken(e.target.value)} placeholder="ghp_..."/>
                <label style={S.label}>Repository (owner/repo)</label>
                <input style={{...S.input,marginBottom:14}} value={githubRepo} onChange={e=>setGithubRepo(e.target.value)} placeholder="myorg/detection-rules"/>
                <button style={{...S.btn("p"),width:"100%",padding:"10px",background:"#24292e",borderColor:"#444c56"}} onClick={()=>pushToGitHub(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Pushing to GitHub...</>:"Push to GitHub"}</button>
              </div>
            )}
            {/* CrowdStrike */}
            {pushModal.tab==="crowdstrike"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Generates a CrowdStrike FQL Custom IOA rule. Copy or download, then import via Falcon Console &gt; Endpoint Security &gt; Custom IOA Rules.</div>
                <button style={{...S.btn("p"),width:"100%",padding:"10px",marginBottom:10,borderColor:"#e1292b88",color:"#e1292b",background:"rgba(225,41,43,0.08)"}} onClick={()=>generatePlatformRule(pushModal.det,"crowdstrike")} disabled={generatingRule}>{generatingRule?<><Spinner/>Generating...</>:"Generate FQL Rule"}</button>
                {generatedRule&&(<div style={{position:"relative",marginTop:8}}><div style={{...S.code,maxHeight:220,overflowY:"auto",fontSize:11}}>{generatedRule}</div><div style={{position:"absolute",top:8,right:8,display:"flex",gap:6}}><CopyBtn text={generatedRule}/><button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>{const b=new Blob([generatedRule],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=pushModal.det.name.replace(/\s+/g,"_")+".fql";a.click();}}>↓</button></div></div>)}
              </div>
            )}
            {/* Falcon LogScale */}
            {pushModal.tab==="logscale"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Pushes a saved query to a Falcon LogScale (Humio) repository via REST API.</div>
                <label style={S.label}>LogScale URL</label>
                <input style={{...S.input,marginBottom:10}} value={logscaleUrl} onChange={e=>setLogscaleUrl(e.target.value)} placeholder="https://cloud.humio.com"/>
                <label style={S.label}>API Token</label>
                <input style={{...S.input,marginBottom:10}} type="password" value={logscaleToken} onChange={e=>setLogscaleToken(e.target.value)} placeholder="your-api-token"/>
                <label style={S.label}>Repository Name</label>
                <input style={{...S.input,marginBottom:14}} value={logscaleRepo} onChange={e=>setLogscaleRepo(e.target.value)} placeholder="my-repo"/>
                <button style={{...S.btn("p"),width:"100%",padding:"10px",borderColor:"#ff6b3588",color:"#ff6b35",background:"rgba(255,107,53,0.08)"}} onClick={()=>pushToLogScale(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Pushing...</>:"Push to LogScale"}</button>
              </div>
            )}
            {/* Tanium */}
            {pushModal.tab==="tanium"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Generates a Tanium Signal JSON. Import via Tanium Console &gt; Threat Response &gt; Signals.</div>
                <button style={{...S.btn("p"),width:"100%",padding:"10px",marginBottom:10,borderColor:"#00a1e088",color:"#00a1e0",background:"rgba(0,161,224,0.08)"}} onClick={()=>generatePlatformRule(pushModal.det,"tanium")} disabled={generatingRule}>{generatingRule?<><Spinner/>Generating...</>:"Generate Tanium Signal"}</button>
                {generatedRule&&(<div style={{position:"relative",marginTop:8}}><div style={{...S.code,maxHeight:220,overflowY:"auto",fontSize:11}}>{generatedRule}</div><div style={{position:"absolute",top:8,right:8,display:"flex",gap:6}}><CopyBtn text={generatedRule}/><button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>{const b=new Blob([generatedRule],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=pushModal.det.name.replace(/\s+/g,"_")+".json";a.click();}}>↓</button></div></div>)}
              </div>
            )}
            {/* Panther */}
            {pushModal.tab==="panther"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Generates a Panther Python detection rule using AI. Import via Panther Console &gt; Detections &gt; Create Detection.</div>
                <button style={{...S.btn("p"),width:"100%",padding:"10px",marginBottom:10,borderColor:"#7c3aed88",color:"#7c3aed",background:"rgba(124,58,237,0.08)"}} onClick={()=>generatePlatformRule(pushModal.det,"panther")} disabled={generatingRule}>{generatingRule?<><Spinner/>Generating Python rule...</>:"Generate Panther Rule"}</button>
                {generatedRule&&(<div style={{position:"relative",marginTop:8}}><div style={{...S.code,maxHeight:240,overflowY:"auto",fontSize:11}}>{generatedRule}</div><div style={{position:"absolute",top:8,right:8,display:"flex",gap:6}}><CopyBtn text={generatedRule}/><button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>{const b=new Blob([generatedRule],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=pushModal.det.name.replace(/\s+/g,"_")+".py";a.click();}}>↓</button></div></div>)}
              </div>
            )}
            {/* Sumo Logic */}
            {pushModal.tab==="sumo"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Creates a scheduled saved search in Sumo Logic (runs every 15 min) via REST API.</div>
                <label style={S.label}>API Endpoint</label>
                <input style={{...S.input,marginBottom:10}} value={sumoUrl} onChange={e=>setSumoUrl(e.target.value)} placeholder="https://api.us2.sumologic.com"/>
                <div style={S.grid2}>
                  <div><label style={S.label}>Access ID</label><input style={{...S.input}} value={sumoAccessId} onChange={e=>setSumoAccessId(e.target.value)} placeholder="su..."/></div>
                  <div><label style={S.label}>Access Key</label><input style={{...S.input}} type="password" value={sumoAccessKey} onChange={e=>setSumoAccessKey(e.target.value)} placeholder="your-access-key"/></div>
                </div>
                <div style={{height:14}}/>
                <button style={{...S.btn("p"),width:"100%",padding:"10px",borderColor:"#0000aa88",color:"#4444ff",background:"rgba(0,0,153,0.08)"}} onClick={()=>pushToSumo(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Pushing...</>:"Push to Sumo Logic"}</button>
              </div>
            )}
            {pushResult&&statusType==="error"&&statusMsg?.startsWith("SSL_CERT:")?(
              <SslCertGuide url={statusMsg.replace("SSL_CERT:","")}/>
            ):(
              pushResult&&<StatusBar msg={statusMsg||pushResult} type={statusType==="success"?"success":"error"}/>
            )}
            <button style={{...S.btn(),width:"100%",padding:"8px",marginTop:10,fontSize:12}} onClick={()=>{setPushModal(null);setPushResult("");setGeneratedRule("");}}>Close</button>
          </div>
        </div>
      )}

      {/* Sigma Modal */}
      {sigmaModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.82)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:1000,backdropFilter:"blur(6px)"}} onClick={()=>{setSigmaModal(null);setSigmaContent("");}}>
          <div style={{background:"linear-gradient(145deg,#0c1220,#080d18)",border:"1px solid "+THEME.borderBright,borderRadius:16,padding:32,width:"100%",maxWidth:620,maxHeight:"80vh",overflow:"auto",boxShadow:"0 32px 80px rgba(0,0,0,0.7)"}} onClick={e=>e.stopPropagation()}>
            <div style={{fontSize:10,fontWeight:800,color:"#adbac7",letterSpacing:"0.15em",marginBottom:6}}>SIGMA RULE EXPORT</div>
            <div style={{fontSize:17,fontWeight:900,color:THEME.text,marginBottom:16}}>{sigmaModal.name}</div>
            {loadingSigma?<div style={{textAlign:"center",padding:40,color:THEME.textDim}}><Spinner/> Converting to Sigma...</div>:(
              <div style={{position:"relative"}}>
                <div style={S.code}>{sigmaContent}</div>
                <div style={{position:"absolute",top:8,right:8}}><CopyBtn text={sigmaContent}/></div>
              </div>
            )}
            {!loadingSigma&&sigmaContent&&!sigmaContent.startsWith("Error")&&(
              <button style={{...S.btn(),padding:"8px 16px",marginTop:10,fontSize:12}} onClick={()=>{const blob=new Blob([sigmaContent],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=(sigmaModal.name||"detection").replace(/\s+/g,"_")+".yml";a.click();}}>Download .yml</button>
            )}
            <button style={{...S.btn(),width:"100%",padding:"8px",marginTop:10,fontSize:12}} onClick={()=>{setSigmaModal(null);setSigmaContent("");}}>Close</button>
          </div>
        </div>
      )}

      {/* Ticket Modal */}
      {ticketModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.82)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:1000,backdropFilter:"blur(6px)"}} onClick={()=>{setTicketModal(null);setTicketContent("");}}>
          <div style={{background:"linear-gradient(145deg,#0c1220,#080d18)",border:"1px solid "+THEME.borderBright,borderRadius:16,padding:32,width:"100%",maxWidth:600,maxHeight:"80vh",overflow:"auto",boxShadow:"0 32px 80px rgba(0,0,0,0.7)"}} onClick={e=>e.stopPropagation()}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.15em",marginBottom:6}}>BETA — DEPLOYMENT TICKET</div>
            <div style={{fontSize:17,fontWeight:900,color:THEME.text,marginBottom:16}}>{ticketModal.name}</div>
            {generatingTicket?<div style={{textAlign:"center",padding:40,color:THEME.textDim}}><Spinner/> Generating ticket...</div>:(
              <div style={{position:"relative"}}><div style={S.code}>{ticketContent}</div><div style={{position:"absolute",top:8,right:8}}><CopyBtn text={ticketContent}/></div></div>
            )}
            <button style={{...S.btn(),width:"100%",padding:"8px",marginTop:14,fontSize:12}} onClick={()=>{setTicketModal(null);setTicketContent("");}}>Close</button>
          </div>
        </div>
      )}

      {/* Test Modal */}
      {testModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.8)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:20}} onClick={()=>{setTestModal(null);setTestResult(null);}}>
          <div style={{background:"#0d1825",border:"1px solid "+THEME.accent+"33",borderRadius:14,width:"100%",maxWidth:680,maxHeight:"88vh",overflow:"hidden",display:"flex",flexDirection:"column"}} onClick={e=>e.stopPropagation()}>
            <div style={{padding:"18px 24px",borderBottom:"1px solid #1a2a3a",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{fontWeight:800,color:THEME.text,fontSize:15}}>🧪 Detection Test — {testModal.name}</div>
              <button style={{...S.btn(),padding:"5px 12px",fontSize:12}} onClick={()=>{setTestModal(null);setTestResult(null);}}>✕ Close</button>
            </div>
            <div style={{flex:1,overflowY:"auto",padding:"20px 24px"}}>
              {testLoading&&<div style={{textAlign:"center",padding:48,color:THEME.textDim}}><Spinner/><div style={{marginTop:12}}>Running detection against simulated logs...</div></div>}
              {testResult?.error&&<div style={{color:THEME.danger,padding:16,background:THEME.danger+"11",borderRadius:8}}>{testResult.error}</div>}
              {testResult&&!testResult.error&&(
                <div>
                  <div style={{display:"flex",gap:12,marginBottom:20,flexWrap:"wrap"}}>
                    <div style={{flex:1,minWidth:140,padding:"16px 18px",background:testResult.verdict==="MATCH"?THEME.success+"15":testResult.verdict==="PARTIAL_MATCH"?THEME.warning+"15":THEME.danger+"15",border:"1px solid "+(testResult.verdict==="MATCH"?THEME.success:testResult.verdict==="PARTIAL_MATCH"?THEME.warning:THEME.danger)+"44",borderRadius:10,textAlign:"center"}}>
                      <div style={{fontSize:28,marginBottom:6}}>{testResult.verdict==="MATCH"?"✅":testResult.verdict==="PARTIAL_MATCH"?"⚠️":"❌"}</div>
                      <div style={{fontSize:13,fontWeight:800,color:testResult.verdict==="MATCH"?THEME.success:testResult.verdict==="PARTIAL_MATCH"?THEME.warning:THEME.danger}}>{testResult.verdict?.replace("_"," ")}</div>
                      <div style={{fontSize:11,color:THEME.textDim,marginTop:4}}>Confidence: {testResult.confidence}%</div>
                    </div>
                    <div style={{flex:1,minWidth:140,padding:"16px 18px",background:"#050d18",border:"1px solid #1a2a3a",borderRadius:10,textAlign:"center"}}>
                      <div style={{fontSize:11,color:THEME.textDim,marginBottom:6,textTransform:"uppercase",letterSpacing:"0.08em"}}>FP Rate</div>
                      <div style={{fontSize:20,fontWeight:800,color:testResult.estimated_fp_rate==="Low"?THEME.success:testResult.estimated_fp_rate==="High"?THEME.danger:THEME.warning}}>{testResult.estimated_fp_rate||"—"}</div>
                    </div>
                    <div style={{flex:2,minWidth:200,padding:"16px 18px",background:"#050d18",border:"1px solid #1a2a3a",borderRadius:10}}>
                      <div style={{fontSize:11,color:THEME.textDim,marginBottom:6,textTransform:"uppercase",letterSpacing:"0.08em"}}>Data Sources Required</div>
                      <div style={{display:"flex",flexWrap:"wrap",gap:4}}>{(testResult.data_sources_required||[]).map((s,i)=><span key={i} style={{...S.badge(THEME.accent),fontSize:10}}>{s}</span>)}</div>
                    </div>
                  </div>
                  <div style={{marginBottom:16}}>
                    <div style={{fontSize:12,fontWeight:700,color:THEME.textMid,marginBottom:8,textTransform:"uppercase",letterSpacing:"0.06em"}}>Test Logs</div>
                    {(testResult.test_logs||[]).map((log,i)=>(
                      <div key={i} style={{marginBottom:10,padding:"12px 14px",background:log.matches?"#00e87a0a":"#ff3d550a",border:"1px solid "+(log.matches?THEME.success:THEME.danger)+"33",borderRadius:8}}>
                        <div style={{display:"flex",gap:8,marginBottom:6}}>
                          <span style={{fontSize:11,fontWeight:800,color:log.matches?THEME.success:THEME.danger}}>{log.matches?"▶ MATCH":"✗ NO MATCH"}</span>
                        </div>
                        <div style={{fontFamily:"monospace",fontSize:11,color:THEME.textMid,background:"#050d18",padding:"8px 10px",borderRadius:6,marginBottom:6,lineHeight:1.6,wordBreak:"break-all"}}>{log.log}</div>
                        <div style={{fontSize:11,color:THEME.textDim,fontStyle:"italic"}}>{log.reason}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:14}}>
                    <div style={{padding:"12px 14px",background:"#050d18",border:"1px solid "+THEME.success+"22",borderRadius:8}}>
                      <div style={{fontSize:11,fontWeight:700,color:THEME.success,marginBottom:6}}>✅ TRUE POSITIVE SCENARIO</div>
                      <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{testResult.true_positive_scenario}</div>
                    </div>
                    <div style={{padding:"12px 14px",background:"#050d18",border:"1px solid "+THEME.warning+"22",borderRadius:8}}>
                      <div style={{fontSize:11,fontWeight:700,color:THEME.warning,marginBottom:6}}>⚠️ FALSE POSITIVE SCENARIO</div>
                      <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{testResult.false_positive_scenario}</div>
                    </div>
                  </div>
                  {testResult.coverage_gaps?.length>0&&<div style={{padding:"12px 14px",background:"#050d18",border:"1px solid "+THEME.danger+"22",borderRadius:8,marginBottom:12}}>
                    <div style={{fontSize:11,fontWeight:700,color:THEME.danger,marginBottom:8}}>🕳 COVERAGE GAPS</div>
                    {testResult.coverage_gaps.map((g,i)=><div key={i} style={{fontSize:12,color:THEME.textMid,marginBottom:4}}>• {g}</div>)}
                  </div>}
                  {testResult.tuning_suggestion&&<div style={{padding:"12px 14px",background:"#050d18",border:"1px solid "+THEME.accent+"22",borderRadius:8}}>
                    <div style={{fontSize:11,fontWeight:700,color:THEME.accent,marginBottom:6}}>💡 TUNING SUGGESTION</div>
                    <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>{testResult.tuning_suggestion}</div>
                  </div>}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Quality Score Modal */}
      {scoreModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:20}} onClick={()=>{setScoreModal(null);setQualityResult(null);}}>
          <div style={{background:"#0d1825",border:"1px solid "+THEME.warning+"33",borderRadius:14,width:"100%",maxWidth:680,maxHeight:"85vh",overflow:"auto"}} onClick={e=>e.stopPropagation()}>
            <div style={{padding:"20px 24px",borderBottom:"1px solid #1a2a3a",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{fontWeight:800,color:THEME.text,fontSize:15}}>⭐ Quality Score — {scoreModal.name}</div>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                {qualityResult&&!qualityResult.error&&(
                  <button style={{...S.btn("p"),padding:"5px 14px",fontSize:11}} onClick={()=>{const score10=Math.round(qualityResult.overall/10*10)/10;onUpdate({...scoreModal,score:score10,qualityBreakdown:qualityResult.breakdown});toast?.("Score applied to library","success");}}>
                    ✓ Apply to Library
                  </button>
                )}
                <button style={S.btn()} onClick={()=>{setScoreModal(null);setQualityResult(null);}}>✕</button>
              </div>
            </div>
            <div style={{padding:"20px 24px"}}>
              {!qualityResult&&<div style={{textAlign:"center",padding:32,color:THEME.textDim}}><Spinner/><div style={{marginTop:12}}>AI is analyzing your detection rule...</div></div>}
              {qualityResult&&!qualityResult.error&&<div style={{padding:"8px 12px",background:"rgba(0,232,122,0.08)",border:"1px solid rgba(0,232,122,0.2)",borderRadius:7,marginBottom:16,fontSize:11,color:THEME.success,display:"flex",alignItems:"center",gap:8}}>✓ Score automatically applied to library card · <strong>{Math.round(qualityResult.overall/10*10)/10}/10</strong> badge is now visible on the detection.</div>}
              {qualityResult?.error&&<div style={{color:THEME.danger,padding:16}}>Error: {qualityResult.error}</div>}
              {qualityResult&&!qualityResult.error&&(
                <div>
                  <div style={{textAlign:"center",marginBottom:24}}>
                    <div style={{display:"inline-flex",flexDirection:"column",alignItems:"center",padding:"20px 32px",borderRadius:16,background:qualityResult.overall>=80?"rgba(0,232,122,0.08)":qualityResult.overall>=60?"rgba(255,170,0,0.08)":"rgba(255,45,85,0.08)",border:"1px solid "+(qualityResult.overall>=80?THEME.success:qualityResult.overall>=60?THEME.warning:THEME.danger)+"33"}}>
                      <div style={{fontSize:56,fontWeight:900,color:qualityResult.overall>=80?THEME.success:qualityResult.overall>=60?THEME.warning:THEME.danger,fontFamily:"'Syne',sans-serif",lineHeight:1}}>{qualityResult.overall}</div>
                      <div style={{fontSize:12,color:THEME.textDim,marginTop:4}}>Overall Score / 100</div>
                      <div style={{fontSize:13,fontWeight:700,color:THEME.text,marginTop:6}}>{qualityResult.overall>=80?"Production Ready":qualityResult.overall>=60?"Needs Tuning":"Needs Work"}</div>
                    </div>
                  </div>
                  <div style={{marginBottom:20}}>
                    <div style={{fontSize:12,fontWeight:700,color:THEME.textMid,marginBottom:12,letterSpacing:"0.08em"}}>SCORE BREAKDOWN</div>
                    {Object.entries(qualityResult.breakdown||{}).map(([k,v])=>(
                      <div key={k} style={{marginBottom:10}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                          <span style={{fontSize:11,color:THEME.textMid,textTransform:"capitalize"}}>{k.replace(/_/g," ")}</span>
                          <span style={{fontSize:11,fontWeight:700,color:v.score>=80?THEME.success:v.score>=60?THEME.warning:THEME.danger}}>{v.score}/100</span>
                        </div>
                        <div style={{height:6,borderRadius:3,background:"#1a2a3a",overflow:"hidden",marginBottom:3}}>
                          <div style={{height:"100%",width:v.score+"%",borderRadius:3,background:v.score>=80?THEME.success:v.score>=60?THEME.warning:THEME.danger,transition:"width 0.8s ease"}}/>
                        </div>
                        <div style={{fontSize:10,color:THEME.textDim}}>{v.notes}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:16}}>
                    {qualityResult.strengths?.length>0&&<div style={{padding:"12px 14px",background:"rgba(0,232,122,0.06)",border:"1px solid rgba(0,232,122,0.2)",borderRadius:8}}>
                      <div style={{fontSize:11,fontWeight:700,color:THEME.success,marginBottom:8}}>✅ STRENGTHS</div>
                      {qualityResult.strengths.map((s,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,marginBottom:4}}>• {s}</div>)}
                    </div>}
                    {qualityResult.weaknesses?.length>0&&<div style={{padding:"12px 14px",background:"rgba(255,45,85,0.06)",border:"1px solid rgba(255,45,85,0.2)",borderRadius:8}}>
                      <div style={{fontSize:11,fontWeight:700,color:THEME.danger,marginBottom:8}}>⚠ WEAKNESSES</div>
                      {qualityResult.weaknesses.map((w,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,marginBottom:4}}>• {w}</div>)}
                    </div>}
                  </div>
                  {qualityResult.recommendations?.length>0&&<div style={{padding:"12px 14px",background:"rgba(0,212,255,0.06)",border:"1px solid rgba(0,212,255,0.2)",borderRadius:8}}>
                    <div style={{fontSize:11,fontWeight:700,color:THEME.accent,marginBottom:8}}>💡 RECOMMENDATIONS</div>
                    {qualityResult.recommendations.map((r,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,marginBottom:4}}>{i+1}. {r}</div>)}
                  </div>}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Diff Viewer Modal */}
      {diffModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.88)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:20}} onClick={()=>setDiffModal(null)}>
          <div style={{background:"#0d1825",border:"1px solid "+THEME.accent+"33",borderRadius:14,width:"100%",maxWidth:900,maxHeight:"85vh",overflow:"hidden",display:"flex",flexDirection:"column"}} onClick={e=>e.stopPropagation()}>
            <div style={{padding:"16px 24px",borderBottom:"1px solid #1a2a3a",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{fontWeight:800,color:THEME.text,fontSize:15}}>⟷ Version Diff — {diffModal.det.name}</div>
              <button style={S.btn()} onClick={()=>setDiffModal(null)}>✕</button>
            </div>
            <div style={{padding:"16px 24px",overflow:"auto",flex:1}}>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                {[{label:diffModal.labelA,v:diffModal.vA,color:THEME.danger},{label:diffModal.labelB,v:diffModal.vB,color:THEME.success}].map(({label,v,color})=>(
                  <div key={label}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                      <span style={{...S.badge(color)}}>{label}</span>
                      <span style={{fontSize:11,color:THEME.textDim}}>{new Date(v.created_at).toLocaleString()}</span>
                    </div>
                    {v.notes&&<div style={{fontSize:11,color:THEME.textDim,marginBottom:8,padding:"4px 8px",background:"#0a1520",borderRadius:4}}>{v.notes}</div>}
                    <pre style={{background:"#050d18",border:"1px solid "+color+"22",borderRadius:8,padding:14,fontSize:11,fontFamily:"'JetBrains Mono',monospace",color:THEME.textMid,overflow:"auto",whiteSpace:"pre-wrap",wordBreak:"break-word",minHeight:200,maxHeight:400}}>{v.query}</pre>
                  </div>
                ))}
              </div>
              {/* Line-level diff highlight */}
              <div style={{marginTop:16}}>
                <div style={{fontSize:12,fontWeight:700,color:THEME.textMid,marginBottom:10,letterSpacing:"0.08em"}}>CHANGES</div>
                {(()=>{
                  const aLines=(diffModal.vA.query||"").split("\n");
                  const bLines=(diffModal.vB.query||"").split("\n");
                  const maxLen=Math.max(aLines.length,bLines.length);
                  const diffs=[];
                  for(let i=0;i<maxLen;i++){
                    const a=aLines[i]??"";const b=bLines[i]??"";
                    if(a!==b)diffs.push({line:i+1,removed:a,added:b});
                  }
                  if(diffs.length===0)return<div style={{color:THEME.success,fontSize:12,padding:12,textAlign:"center"}}>✓ Queries are identical</div>;
                  return diffs.map(({line,removed,added})=>(
                    <div key={line} style={{marginBottom:8,background:"#050d18",borderRadius:6,overflow:"hidden",border:"1px solid #1a2a3a"}}>
                      <div style={{fontSize:10,color:THEME.textDim,padding:"3px 10px",background:"#0a1520"}}>Line {line}</div>
                      {removed&&<div style={{padding:"4px 10px",background:"rgba(255,45,85,0.08)",fontFamily:"monospace",fontSize:11,color:"#ff8098"}}>− {removed}</div>}
                      {added&&<div style={{padding:"4px 10px",background:"rgba(0,232,122,0.08)",fontFamily:"monospace",fontSize:11,color:"#00e87a"}}>+ {added}</div>}
                    </div>
                  ));
                })()}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Playbook Modal */}
      {playbookModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.8)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:20}} onClick={()=>setPlaybookModal(null)}>
          <div style={{background:"#0d1825",border:"1px solid "+THEME.accent+"33",borderRadius:14,width:"100%",maxWidth:700,maxHeight:"85vh",overflow:"hidden",display:"flex",flexDirection:"column"}} onClick={e=>e.stopPropagation()}>
            <div style={{padding:"20px 24px",borderBottom:"1px solid #1a2a3a",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{fontWeight:800,color:THEME.text,fontSize:15}}>🎭 SOAR Playbook — {playbookModal.name}</div>
              <div style={{display:"flex",gap:8}}>
                <CopyBtn text={playbookContent}/>
                <button style={{...S.btn(),padding:"5px 12px",fontSize:12}} onClick={()=>setPlaybookModal(null)}>✕ Close</button>
              </div>
            </div>
            <div style={{flex:1,overflowY:"auto",padding:"20px 24px"}}>
              {generatingPlaybook&&!playbookContent&&<div style={{textAlign:"center",padding:40,color:THEME.textDim}}><Spinner/> Generating playbook...</div>}
              <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap"}}>{playbookContent}{generatingPlaybook&&<span style={{color:THEME.accent}}>▋</span>}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function AttackHeatmap({detections}){
  const[analysis,setAnalysis]=useState("");
  const[loading,setLoading]=useState(false);
  const[selectedCell,setSelectedCell]=useState(null);

  const TACTIC_COLS=[
    {id:"Reconnaissance",short:"Recon",techniques:["T1595","T1592","T1591","T1590","T1589","T1596","T1598"]},
    {id:"Resource Development",short:"Resource Dev",techniques:["T1583","T1584","T1587","T1588","T1585","T1586"]},
    {id:"Initial Access",short:"Initial Access",techniques:["T1189","T1190","T1133","T1566","T1091","T1195","T1078"]},
    {id:"Execution",short:"Execution",techniques:["T1059","T1203","T1559","T1106","T1053","T1569","T1204","T1047"]},
    {id:"Persistence",short:"Persistence",techniques:["T1098","T1547","T1037","T1176","T1136","T1543","T1546","T1574","T1505","T1078"]},
    {id:"Privilege Escalation",short:"Priv Esc",techniques:["T1548","T1134","T1547","T1543","T1484","T1574","T1055","T1053","T1068"]},
    {id:"Defense Evasion",short:"Def Evasion",techniques:["T1548","T1197","T1140","T1222","T1562","T1036","T1027","T1055","T1218","T1553"]},
    {id:"Credential Access",short:"Cred Access",techniques:["T1110","T1555","T1187","T1606","T1056","T1557","T1003","T1558","T1552"]},
    {id:"Discovery",short:"Discovery",techniques:["T1087","T1482","T1083","T1046","T1135","T1069","T1057","T1018","T1082","T1016"]},
    {id:"Lateral Movement",short:"Lateral Mvmt",techniques:["T1210","T1534","T1570","T1563","T1021","T1091","T1550"]},
    {id:"Collection",short:"Collection",techniques:["T1560","T1123","T1119","T1530","T1213","T1005","T1074","T1114","T1056","T1113"]},
    {id:"Command and Control",short:"C2",techniques:["T1071","T1132","T1001","T1568","T1573","T1095","T1571","T1572","T1090","T1219"]},
    {id:"Exfiltration",short:"Exfiltration",techniques:["T1020","T1048","T1041","T1011","T1567","T1029","T1537"]},
    {id:"Impact",short:"Impact",techniques:["T1531","T1485","T1486","T1565","T1491","T1499","T1490","T1496","T1529"]},
  ];

  const counts=TACTIC_COLS.reduce((acc,t)=>{
    acc[t.id]=detections.filter(d=>(d.tactic||"").toLowerCase()===t.id.toLowerCase()).length;
    return acc;
  },{});
  const coveredTactics=Object.values(counts).filter(v=>v>0).length;
  const maturityScore=Math.round((coveredTactics/TACTIC_COLS.length)*100);

  function cellStyle(count,isSelected){
    const base={marginTop:2,padding:"3px 2px",fontSize:8,textAlign:"center",borderRadius:3,cursor:"pointer",minHeight:24,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"monospace",transition:"all 0.15s"};
    if(isSelected) return{...base,background:"rgba(0,212,255,0.2)",border:"1px solid "+THEME.accent,color:THEME.accent};
    if(count===0) return{...base,background:"#0a0f1c",border:"1px solid "+THEME.border,color:THEME.textDim,opacity:0.5};
    if(count>=6)  return{...base,background:"#0a6644",border:"1px solid #1ab06844",color:"#00ff88"};
    if(count>=3)  return{...base,background:"#0a4a32",border:"1px solid #1a8a5044",color:"#00e87a"};
    return{...base,background:"#0a2e20",border:"1px solid #1a5c3a44",color:"#5cd18a"};
  }

  async function runGapAnalysis(){
    setLoading(true);
    const gaps=TACTIC_COLS.filter(t=>counts[t.id]===0).map(t=>t.id);
    try{const txt=await callClaude([{role:"user",content:"Analyze my MITRE ATT&CK coverage.\n\nCoverage:\n"+TACTIC_COLS.map(t=>t.id+": "+counts[t.id]+" rules").join("\n")+"\n\nUncovered: "+gaps.join(", ")+"\nMaturity: "+maturityScore+"%\nTotal: "+detections.length+" rules\n\nTop 3 priority gaps, specific detection recommendations, 3 quick wins."}],"SOC maturity expert.",1800);setAnalysis(txt);}
    catch(e){setAnalysis("Error: "+e.message);}
    setLoading(false);
  }

  return(
    <div>
      <SectionHeader icon="🗺" title="ATT&CK Coverage Heatmap" color={THEME.orange}>
        <div style={{fontSize:10,color:THEME.textDim,fontFamily:"'JetBrains Mono',monospace",marginBottom:12,padding:"6px 10px",background:"rgba(255,119,0,0.06)",borderRadius:6,border:"1px solid rgba(255,119,0,0.15)",display:"inline-flex",alignItems:"center",gap:6}}>
          <span style={{color:THEME.orange,fontWeight:700}}>&#9656;</span> Powered by MITRE ATT&CK® Framework — used under free use policy
        </div>
        <div style={S.flex}>
          <span style={S.badge(THEME.success)}>Maturity: {maturityScore}%</span>
          <span style={S.badge(THEME.accent)}>{coveredTactics}/{TACTIC_COLS.length} tactics</span>
          <span style={S.badge(THEME.purple)}>{detections.length} rules</span>
        </div>
      </SectionHeader>
      <HelpBox title="ATT&CK Heatmap Quick Reference" color={THEME.orange} items={[
        {icon:"🗺",title:"Reading the heatmap",desc:"Each column is a MITRE ATT&CK tactic (Reconnaissance → Impact). Each cell is a technique. Green = you have 3+ rules covering it. Yellow = 1–2 rules. Dark = no coverage."},
        {icon:"📊",title:"Coverage score",desc:"The maturity % in the header shows what fraction of tactics have 3+ rules (Strong posture). Aim for 70%+ coverage across all 14 tactics."},
        {icon:"🔍",title:"Gap analysis",desc:"Click 'Run AI Gap Analysis' to get a prioritized list of uncovered techniques with recommendations based on your environment type and industry."},
        {icon:"💡",title:"Tip",desc:"Click any technique cell to select it, then jump to the Builder to create a detection for that specific technique."},
      ]}/>
      <div style={S.card}>
        <div style={{overflowX:"auto",marginBottom:14}}>
          <div style={{display:"flex",gap:3,minWidth:980}}>
            {TACTIC_COLS.map(tactic=>{
              const count=counts[tactic.id]||0;
              return(
                <div key={tactic.id} style={{flex:1,minWidth:65,display:"flex",flexDirection:"column"}}>
                  <div style={{padding:"6px 3px",fontSize:9,fontWeight:800,color:count>0?THEME.success:THEME.textMid,textAlign:"center",background:count>0?"rgba(0,232,122,0.06)":THEME.bgCard,border:"1px solid "+(count>0?"rgba(0,232,122,0.2)":THEME.border),borderRadius:"4px 4px 0 0",minHeight:52,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",lineHeight:1.3}}>
                    <div style={{letterSpacing:"0.02em"}}>{tactic.short}</div>
                    <div style={{fontSize:9,opacity:0.7,marginTop:3,color:count>0?THEME.success:THEME.textDim}}>{count} rule{count!==1?"s":""}</div>
                  </div>
                  {tactic.techniques.map((tid,i)=>{
                    const hasRule=count>0&&i<count;
                    const key=tactic.id+tid;
                    return(
                      <div key={tid} style={cellStyle(hasRule?count:0,selectedCell===key)} onClick={()=>setSelectedCell(selectedCell===key?null:key)}>
                        {tid}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
        {selectedCell&&(
          <div style={{padding:"8px 12px",background:"rgba(0,212,255,0.05)",border:"1px solid "+THEME.accentDim+"33",borderRadius:7,marginBottom:12,fontSize:11,color:THEME.textMid}}>
            <span style={{color:THEME.accent,fontWeight:700,marginRight:8}}>Selected: {selectedCell.replace(/^[^T]+/,"")}</span>
            Click a technique to learn more, or use the Builder to create a detection for it.
          </div>
        )}
        <div style={{display:"flex",alignItems:"center",gap:14,flexWrap:"wrap"}}>
          <div style={{display:"flex",gap:12,fontSize:11,color:THEME.textDim,alignItems:"center"}}>
            <span>Coverage:</span>
            {[["None","#0a0f1c",THEME.border,THEME.textDim],["1-2","#0a2e20","#1a5c3a44","#5cd18a"],["3-5","#0a4a32","#1a8a5044","#00e87a"],["6+","#0a6644","#1ab06844","#00ff88"]].map(([l,bg,b,c])=>(
              <div key={l} style={{display:"flex",alignItems:"center",gap:4}}>
                <div style={{width:14,height:14,borderRadius:3,background:bg,border:"1px solid "+b}}/>
                <span style={{color:c}}>{l}</span>
              </div>
            ))}
          </div>
          <button style={{...S.btn("p"),padding:"8px 18px",marginLeft:"auto"}} onClick={runGapAnalysis} disabled={loading}>{loading&&<Spinner/>}{loading?"Analyzing...":"Run AI Gap Analysis"}</button>
        </div>
      </div>
      {analysis&&<div style={S.card}><div style={{...S.row,marginBottom:14}}><div style={S.cardTitle}><span>💡</span> AI Gap Analysis</div><CopyBtn text={analysis}/></div><div style={{fontSize:13,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap"}}>{analysis}</div></div>}
    </div>
  );
}

function AlertTriage({prefillAlert}){
  const[alert,setAlert]=useState(()=>{if(prefillAlert)return prefillAlert;if(window.location.pathname!=="/triage")return "";const p=new URLSearchParams(window.location.search);return p.get("alert")||"";});
  const[context,setContext]=useState("");const[result,setResult]=useState(null);const[loading,setLoading]=useState(false);const[err,setErr]=useState("");const[history,setHistory]=useState(LS.get("detectiq_triage",[]).slice(0,8));
  useEffect(()=>{if(alert&&window.location.pathname==="/triage"){window.history.replaceState({},"","/triage?alert="+encodeURIComponent(alert));}},[alert]);
  useEffect(()=>{if(prefillAlert){setAlert(prefillAlert);}},[prefillAlert]);
  async function triageAlert(){
    if(!alert.trim()){setErr("Paste alert data first.");return;}
    setErr("");setLoading(true);
    setResult({text:"",verdict:"ANALYZING",confidence:0,streaming:true,ts:new Date().toISOString(),preview:alert.slice(0,70)});
    try{
      const txt=await callClaudeStream([{role:"user",content:"Triage this security alert.\n\n1. VERDICT: TRUE_POSITIVE or FALSE_POSITIVE\n2. CONFIDENCE: 0-100%\n3. SEVERITY\n4. SUMMARY\n5. KEY INDICATORS\n6. RECOMMENDED ACTIONS\n\nAlert:\n"+alert+(context?"\n\nContext:\n"+context:"")}],"Senior SOC analyst.",2000,
        (partial)=>setResult(r=>({...r,text:partial}))
      );
      const isTP=txt.toLowerCase().includes("true_positive")||txt.toLowerCase().includes("true positive");
      const cm=txt.match(/confidence[:\s]+(\d+)/i);
      const r={text:txt,verdict:isTP?"TRUE_POSITIVE":"FALSE_POSITIVE",confidence:cm?parseInt(cm[1]):75,streaming:false,ts:new Date().toISOString(),preview:alert.slice(0,70)};
      setResult(r);const h=[r,...history].slice(0,8);setHistory(h);LS.set("detectiq_triage",h);
    }catch(e){setErr("Error: "+e.message);setResult(null);}
    setLoading(false);
  }
  return(
    <div>
      <SectionHeader icon="🚨" title="Alert Triage" color={THEME.danger}><span style={S.badge(THEME.danger)}>AI Verdict Engine</span></SectionHeader>
      <HelpBox title="Alert Triage Quick Reference" color={THEME.danger} items={[
        {icon:"🚨",title:"What it does",desc:"Paste any raw SIEM alert or log line and AI returns a verdict: True Positive, False Positive, or Needs Review — with a confidence score and recommended response action."},
        {icon:"🔍",title:"How to use it",desc:"Paste the alert JSON or raw log text, select your SIEM platform, and click Triage. AI will classify the alert, explain why, and suggest containment or dismissal steps."},
        {icon:"📋",title:"Confidence score",desc:"Each verdict comes with a 0–100% confidence score. Low confidence = ambiguous signal that may need manual review or additional log context."},
        {icon:"💡",title:"Tip",desc:"You can send alerts directly from the Adversary SIEM tab — it pre-fills the triage form with synthetic adversary logs so you can test your detection logic."},
      ]}/>
      {prefillAlert&&<StatusBar msg="Alert pre-filled from Attack Simulator. Click Triage Alert to analyze." type="success"/>}
      <div style={S.card}>
        <div style={S.grid2}>
          <div><label style={S.label}>Raw Alert Data</label><textarea style={{...S.textarea,minHeight:180}} value={alert} onChange={e=>setAlert(e.target.value)} placeholder="Paste raw SIEM alert, JSON event, log entry..."/></div>
          <div><label style={S.label}>Additional Context (optional)</label><textarea style={{...S.textarea,minHeight:180}} value={context} onChange={e=>setContext(e.target.value)} placeholder="Asset criticality, user role, recent changes..."/></div>
        </div>
        <div style={{marginTop:14}}><button style={{...S.btn("p"),padding:"10px 22px"}} onClick={triageAlert} disabled={loading}>{loading&&<Spinner/>}{loading?"Analyzing...":"Triage Alert"}</button></div>
        {err&&<StatusBar msg={err} type="error"/>}
      </div>
      {result&&(
        <div style={{...S.card,borderColor:result.streaming?THEME.accent+"44":result.verdict==="TRUE_POSITIVE"?THEME.danger+"44":THEME.success+"44"}}>
          <div style={S.row}><div style={S.cardTitle}><span>📊</span> {result.streaming?"Analyzing...":"Result"}</div><div style={S.flex}>
            <span style={{...S.badge(result.streaming?THEME.accent:result.verdict==="TRUE_POSITIVE"?THEME.danger:THEME.success),padding:"5px 14px",fontSize:12}}>{result.streaming?<><Spinner/>ANALYZING</>:result.verdict}</span>
            {!result.streaming&&<span style={S.badge(THEME.accent)}>Confidence: {result.confidence}%</span>}
          </div></div>
          {!result.streaming&&<div style={{width:"100%",height:6,background:THEME.border,borderRadius:3,marginBottom:16}}><div style={{width:result.confidence+"%",height:"100%",background:result.verdict==="TRUE_POSITIVE"?THEME.danger:THEME.success,borderRadius:3}}/></div>}
          <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap"}}>{result.text}{result.streaming&&<span style={{animation:"pulse 1s infinite",color:THEME.accent}}>▋</span>}</div>
        </div>
      )}
      {history.length>0&&<div style={S.card}><div style={S.cardTitle}><span>🕐</span> History</div>{history.map((h,i)=><div key={i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"9px 0",borderBottom:"1px solid "+THEME.border}}><div style={{fontSize:12,color:THEME.textMid,flex:1,marginRight:12,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{h.preview}...</div><div style={S.flex}><span style={S.badge(h.verdict==="TRUE_POSITIVE"?THEME.danger:THEME.success)}>{h.verdict}</span><span style={{fontSize:11,color:THEME.textDim}}>{new Date(h.ts).toLocaleTimeString()}</span></div></div>)}</div>}
    </div>
  );
}

function AttackChainBuilder({ onBuildDetection }){
  const[scenario,setScenario]=useState("");
  const[chain,setChain]=useState(null);
  const[loading,setLoading]=useState(false);
  const[err,setErr]=useState("");
  const[activeStep,setActiveStep]=useState(null);
  const[exportLoading,setExportLoading]=useState(false);
  const[reportText,setReportText]=useState("");
  const[mode,setMode]=useState("blue"); // blue=defender, red=attacker
  const[streamTokens,setStreamTokens]=useState(0);

  const QUICK_CAMPAIGNS=[
    {label:"Ransomware (LockBit)",scenario:"LockBit ransomware campaign targeting enterprise Windows environment via phishing email with malicious attachment"},
    {label:"APT29 / Cozy Bear",scenario:"APT29 nation-state espionage campaign targeting government contractor using spearphishing and living-off-the-land techniques"},
    {label:"Insider Threat",scenario:"Malicious insider with valid credentials exfiltrating sensitive data before leaving the company"},
    {label:"Supply Chain Attack",scenario:"Supply chain compromise via trojanized software update targeting technology companies"},
    {label:"BEC / Financial Fraud",scenario:"Business Email Compromise campaign targeting finance department for wire transfer fraud"},
    {label:"Crypto Miner",scenario:"Cryptomining malware campaign exploiting public-facing web application vulnerability"},
  ];

  const PHASE_COLORS={
    "Reconnaissance":"#ff6688","Resource Development":"#aa88ff",
    "Initial Access":THEME.danger,"Execution":"#ff7700",
    "Persistence":THEME.warning,"Privilege Escalation":"#ffcc00",
    "Defense Evasion":THEME.purple,"Credential Access":"#ff55aa",
    "Discovery":THEME.accent,"Lateral Movement":"#00aaff",
    "Collection":"#00ccaa","Command and Control":THEME.success,
    "Exfiltration":"#88ff00","Impact":THEME.danger,
  };

  async function buildChain(){
    if(!scenario.trim()){setErr("Enter a campaign scenario.");return;}
    setErr("");setLoading(true);setChain(null);setActiveStep(null);setReportText("");
    try{
      const prompt=`You are a red team expert building a realistic attack campaign simulation for detection engineering training.

Campaign: ${scenario}
Mode: ${mode==="red"?"Red Team (attacker perspective — real commands)":"Blue Team (defender perspective — what to detect)"}

Return ONLY valid JSON:
{
  "campaign_name": "short name",
  "threat_actor": "APT name or type",
  "target": "what kind of org is targeted",
  "summary": "2 sentences describing the full campaign",
  "estimated_dwell_time": "X days/weeks",
  "steps": [
    {
      "step": 1,
      "phase": "MITRE tactic name",
      "technique": "technique name",
      "technique_id": "T####",
      "objective": "what the attacker achieves in this step",
      "attacker_actions": "specific actions taken (tools, commands, methods)",
      "real_command": "${mode==="red" ? "actual command/tool syntax an attacker would run" : "N/A"}",
      "log_artifact": "exact log entry - use forward slashes only, no backslashes, no Windows paths",
      "detection_query": "one-line SPL or KQL detection for this step",
      "detection_opportunity": "when/how defenders can catch this",
      "iocs": ["specific ioc1", "specific ioc2"],
      "difficulty": "Easy/Medium/Hard to detect"
    }
  ]
}

Generate 6-8 realistic steps showing the full campaign progression. Make log_artifact look like real SIEM output.`;

      setStreamTokens(0);
      const result=await callClaudeStream([{role:"user",content:prompt}],"Expert red team operator and detection engineer. Return ONLY valid JSON.",4000,
        (partial)=>setStreamTokens(partial.length)
      );
            const m=result.match(/\{[\s\S]*\}/);
      if(!m) throw new Error("Could not parse response.");
      let cleaned=m[0]
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,"")
        .replace(/\t/g," ")
        .replace(/([^\\])\\([^"\\\/bfnrtu0-9])/g,"$1\\\\$2")
        .replace(/^\\([^"\\\/bfnrtu0-9])/g,"\\\\$1");
      let parsed;
      // Nuclear JSON fixer - replace all backslashes not part of valid escapes
      function fixJson(s){
        // Step 1: normalize all backslashes
        let out="";let inStr=false;let i=0;
        while(i<s.length){
          const ch=s[i];
          if(ch==='"'&&(i===0||s[i-1]!=="\\")){inStr=!inStr;}
          if(inStr&&ch==="\\"){
            const next=s[i+1];
            if(next&&'"\\\/bfnrtu'.includes(next)){out+=ch+next;i+=2;}
            else{out+="\\\\";i++;}
          } else {out+=ch;i++;}
        }
        return out;
      }
      try{ parsed=JSON.parse(cleaned); }
      catch(e){
        try{ parsed=JSON.parse(fixJson(cleaned)); }
        catch(e2){
          // Last resort: extract fields manually
          const getName=k=>{const m=cleaned.match(new RegExp('"'+k+'"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"')); return m?m[1].replace(/\\\\n/g,"\n"):"";};
          const getArr=k=>{const m=cleaned.match(new RegExp('"'+k+'"\\s*:\\s*\\[((?:[^\\]]|\\[[^\\]]*\\])*)\\]')); if(!m)return[];return(m[1].match(/"([^"]*)"/g)||[]).map(s=>s.slice(1,-1));};
          parsed={
            campaign_name:getName("campaign_name")||scenario.slice(0,40),
            threat_actor:getName("threat_actor")||"Unknown",
            target:getName("target")||"Enterprise",
            summary:getName("summary")||"",
            estimated_dwell_time:getName("estimated_dwell_time")||"Unknown",
            steps:[]
          };
          // Extract steps array
          const stepsMatch=cleaned.match(/"steps"\s*:\s*\[([\s\S]*)\]/);
          if(stepsMatch){
            const stepBlocks=stepsMatch[1].split(/\},\s*\{/);
            parsed.steps=stepBlocks.map((block,idx)=>{
              const g=k=>{const m=block.match(new RegExp('"'+k+'"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"')); return m?m[1]:"";}
              const gi=k=>{const m=block.match(new RegExp('"'+k+'"\\s*:\\s*(\\d+)')); return m?parseInt(m[1]):idx+1;}
              return{step:gi("step"),phase:g("phase")||"Execution",technique:g("technique")||"Unknown",technique_id:g("technique_id")||"T0000",objective:g("objective")||"",attacker_actions:g("attacker_actions")||"",real_command:g("real_command")||"N/A",log_artifact:g("log_artifact")||"",detection_query:g("detection_query")||"",detection_opportunity:g("detection_opportunity")||"",iocs:getArr("iocs"),difficulty:g("difficulty")||"Medium"};
            }).filter(s=>s.technique!=="Unknown"||s.phase!=="Execution");
          }
          if(!parsed.steps.length) throw new Error("Could not parse campaign. Try again.");
        }
      }
      setChain(parsed);
      setActiveStep(0);
    }catch(e){setErr("Error: "+e.message);}
    setLoading(false);
  }

  async function generateReport(){
    if(!chain) return;
    setExportLoading(true);
    try{
      const txt=await callClaude([{role:"user",content:"Generate a professional red team campaign report based on this attack chain.\n\nCampaign: "+chain.campaign_name+"\nThreat Actor: "+chain.threat_actor+"\nTarget: "+chain.target+"\nSteps: "+chain.steps.map(s=>s.step+". "+s.phase+" - "+s.technique+": "+s.objective).join("\n")+"\n\nInclude: Executive Summary, Campaign Timeline, Detection Coverage Assessment, Recommended Mitigations, Priority Actions. Professional format."}],"Senior red team consultant writing executive reports.",2000);
      setReportText(txt);
    }catch(e){setReportText("Error: "+e.message);}
    setExportLoading(false);
  }

  const activeStepData=chain?.steps?.[activeStep];
  const phaseColor=activeStepData?PHASE_COLORS[activeStepData.phase]||THEME.accent:THEME.accent;

  return(
    <div>
      <SectionHeader icon="🧬" title="Campaign Builder" color={THEME.danger}>
        <div style={S.flex}>
          <span style={S.badge(THEME.danger)}>Red Team</span>
          <span style={S.badge(THEME.success)}>Blue Team</span>
        </div>
      </SectionHeader>

      <div style={S.card}>
        {/* Mode toggle */}
        <div style={{display:"flex",gap:8,marginBottom:16}}>
          {[{id:"blue",label:"Blue Team — Detection Focus",color:THEME.accent},{id:"red",label:"Red Team — Attacker Commands",color:THEME.danger}].map(m=>(
            <div key={m.id} onClick={()=>setMode(m.id)}
              style={{flex:1,padding:"10px 16px",borderRadius:8,border:"1px solid "+(mode===m.id?m.color+"66":THEME.border),background:mode===m.id?m.color+"10":"transparent",cursor:"pointer",textAlign:"center",transition:"all 0.15s"}}>
              <div style={{fontSize:12,fontWeight:700,color:mode===m.id?m.color:THEME.textMid}}>{m.label}</div>
            </div>
          ))}
        </div>

        {/* Quick campaigns */}
        <label style={S.label}>Quick Campaigns</label>
        <div style={{display:"flex",flexWrap:"wrap",gap:8,marginBottom:16}}>
          {QUICK_CAMPAIGNS.map(q=>(
            <div key={q.label} onClick={()=>setScenario(q.scenario)}
              style={{padding:"5px 12px",borderRadius:7,border:"1px solid "+(scenario===q.scenario?THEME.danger+"66":THEME.border),background:scenario===q.scenario?THEME.dangerGlow:"rgba(255,255,255,0.02)",cursor:"pointer",fontSize:11,fontWeight:600,color:scenario===q.scenario?THEME.danger:THEME.textMid,transition:"all 0.15s"}}>
              {q.label}
            </div>
          ))}
        </div>

        <label style={S.label}>Campaign Scenario</label>
        <textarea style={{...S.textarea,minHeight:70,marginBottom:14}} value={scenario} onChange={e=>setScenario(e.target.value)} placeholder="Describe the attack campaign in detail — threat actor, target, initial vector..."/>
        <button style={{...S.btn("d"),padding:"11px 26px",fontSize:13}} onClick={buildChain} disabled={loading}>{loading&&<Spinner/>}{loading?`Building campaign... (${streamTokens} chars)`:"Build Attack Campaign"}</button>
        {err&&<StatusBar msg={err} type="error"/>}
      </div>

      {chain&&(
        <div>
          {/* Campaign summary */}
          <div style={{...S.card,borderColor:THEME.danger+"33",background:"linear-gradient(135deg,rgba(255,61,85,0.05),rgba(255,61,85,0.02))",marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:12}}>
              <div>
                <div style={{fontSize:10,fontWeight:800,color:THEME.danger,letterSpacing:"0.15em",marginBottom:4}}>ATTACK CAMPAIGN</div>
                <div style={{fontSize:18,fontWeight:900,color:THEME.text,marginBottom:6}}>{chain.campaign_name}</div>
                <div style={S.flex}>
                  <span style={S.badge(THEME.orange)}>{chain.threat_actor}</span>
                  <span style={S.badge(THEME.textDim)}>{chain.target}</span>
                  <span style={S.badge(THEME.warning)}>Dwell: {chain.estimated_dwell_time}</span>
                </div>
              </div>
              <div style={S.flex}>
                <button style={{...S.btn(),padding:"7px 14px",fontSize:11}} onClick={generateReport} disabled={exportLoading}>{exportLoading?<><Spinner/>Generating...</>:"Generate Report"}</button>
                <CopyBtn text={chain.steps?.map(s=>`${s.step}. [${s.phase}] ${s.technique}\n   Objective: ${s.objective}\n   Command: ${s.real_command}\n   Detection: ${s.detection_query}`).join("\n\n")||""}/>
              </div>
            </div>
            {chain.summary&&<div style={{marginTop:12,fontSize:13,color:THEME.textMid,lineHeight:1.7,borderTop:"1px solid "+THEME.border,paddingTop:10}}>{chain.summary}</div>}
          </div>

          {/* Visual step selector */}
          <div style={{display:"flex",gap:0,marginBottom:16,overflowX:"auto",padding:"4px 0"}}>
            {chain.steps?.map((step,i)=>{
              const c=PHASE_COLORS[step.phase]||THEME.accent;
              const isActive=activeStep===i;
              return(
                <div key={i} style={{display:"flex",alignItems:"center",flexShrink:0}}>
                  <div onClick={()=>setActiveStep(i)}
                    style={{display:"flex",flexDirection:"column",alignItems:"center",padding:"8px 10px",borderRadius:8,border:"1px solid "+(isActive?c+"88":THEME.border),background:isActive?c+"15":"transparent",cursor:"pointer",transition:"all 0.15s",minWidth:80,textAlign:"center"}}>
                    <div style={{width:28,height:28,borderRadius:"50%",background:isActive?"linear-gradient(135deg,"+c+","+c+"88)":THEME.bgCard,border:"1px solid "+(isActive?c:THEME.border),display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:900,color:isActive?"#000":THEME.textDim,marginBottom:4}}>{i+1}</div>
                    <div style={{fontSize:8,fontWeight:700,color:isActive?c:THEME.textDim,letterSpacing:"0.05em",lineHeight:1.3}}>{step.phase?.split(" ").slice(0,2).join(" ")}</div>
                  </div>
                  {i<chain.steps.length-1&&<div style={{width:20,height:2,background:THEME.border,flexShrink:0}}/>}
                </div>
              );
            })}
          </div>

          {/* Active step detail */}
          {activeStepData&&(
            <div style={{...S.card,borderLeft:"3px solid "+phaseColor,borderColor:phaseColor+"33"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:14,flexWrap:"wrap",gap:10}}>
                <div>
                  <div style={S.flex}>
                    <span style={S.badge(phaseColor)}>{activeStepData.phase}</span>
                    <span style={{fontSize:15,fontWeight:800,color:THEME.text}}>{activeStepData.technique}</span>
                    <span style={{fontSize:11,color:THEME.textDim,fontFamily:"monospace",background:"rgba(255,255,255,0.04)",padding:"2px 7px",borderRadius:4}}>{activeStepData.technique_id}</span>
                    <span style={{...S.badge(activeStepData.difficulty==="Hard"?THEME.success:activeStepData.difficulty==="Medium"?THEME.warning:THEME.danger),fontSize:9}}>
                      {activeStepData.difficulty==="Hard"?"Hard to detect":activeStepData.difficulty==="Medium"?"Medium":"Easy to detect"}
                    </span>
                  </div>
                </div>
                <button style={{...S.btn("p"),padding:"6px 14px",fontSize:11}}
                  onClick={()=>onBuildDetection&&onBuildDetection(activeStepData.technique+" — "+activeStepData.objective,activeStepData.phase)}>
                  Build Detection for This Step
                </button>
              </div>

              {/* Objective */}
              <div style={{fontSize:13,color:THEME.textMid,marginBottom:14,lineHeight:1.7,padding:"10px 14px",background:"rgba(255,255,255,0.02)",borderRadius:7}}>
                <span style={{fontWeight:700,color:THEME.text}}>Objective: </span>{activeStepData.objective}
              </div>

              <div style={S.grid2}>
                {/* Attacker actions */}
                <div>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.danger,letterSpacing:"0.12em",marginBottom:8}}>ATTACKER ACTIONS</div>
                  <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.8,marginBottom:10}}>{activeStepData.attacker_actions}</div>
                  {mode==="red"&&activeStepData.real_command&&activeStepData.real_command!=="N/A"&&(
                    <div>
                      <div style={{fontSize:10,fontWeight:800,color:THEME.orange,letterSpacing:"0.1em",marginBottom:6}}>COMMAND / TOOL</div>
                      <div style={{position:"relative"}}>
                        <div style={{...S.code,fontSize:11,background:"#020a04",borderColor:"rgba(255,119,0,0.2)"}}>{activeStepData.real_command}</div>
                        <div style={{position:"absolute",top:6,right:6}}><CopyBtn text={activeStepData.real_command} small={true}/></div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Log artifact */}
                <div>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.12em",marginBottom:8}}>LOG ARTIFACT (SIEM)</div>
                  <div style={{position:"relative",marginBottom:10}}>
                    <div style={{...S.code,fontSize:10,background:"#020a04",borderColor:"rgba(255,170,0,0.2)",minHeight:60}}>{activeStepData.log_artifact}</div>
                    <div style={{position:"absolute",top:6,right:6}}><CopyBtn text={activeStepData.log_artifact||""} small={true}/></div>
                  </div>
                  {/* Detection query */}
                  <div style={{fontSize:10,fontWeight:800,color:THEME.success,letterSpacing:"0.1em",marginBottom:6}}>DETECTION QUERY</div>
                  <div style={{position:"relative"}}>
                    <div style={{...S.code,fontSize:10,background:"#020a04",borderColor:"rgba(0,232,122,0.2)"}}>{activeStepData.detection_query}</div>
                    <div style={{position:"absolute",top:6,right:6}}><CopyBtn text={activeStepData.detection_query||""} small={true}/></div>
                  </div>
                </div>
              </div>

              {/* Detection opportunity */}
              {activeStepData.detection_opportunity&&(
                <div style={{marginTop:12,padding:"10px 14px",background:THEME.successGlow,border:"1px solid "+THEME.success+"33",borderRadius:8,fontSize:12,color:THEME.success,lineHeight:1.6}}>
                  <span style={{fontWeight:800}}>Detection opportunity: </span>{activeStepData.detection_opportunity}
                </div>
              )}

              {/* IOCs */}
              {activeStepData.iocs?.length>0&&(
                <div style={{marginTop:10}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:6}}>IOCs</div>
                  <div style={{display:"flex",flexWrap:"wrap"}}>{activeStepData.iocs.map((ioc,j)=><span key={j} style={S.tag}>{ioc}</span>)}</div>
                </div>
              )}

              {/* Step nav */}
              <div style={{display:"flex",justifyContent:"space-between",marginTop:16,paddingTop:12,borderTop:"1px solid "+THEME.border}}>
                <button style={{...S.btn(),padding:"7px 16px",fontSize:12}} onClick={()=>setActiveStep(Math.max(0,activeStep-1))} disabled={activeStep===0}>Previous step</button>
                <span style={{fontSize:11,color:THEME.textDim,alignSelf:"center"}}>Step {activeStep+1} of {chain.steps.length}</span>
                <button style={{...S.btn("p"),padding:"7px 16px",fontSize:12}} onClick={()=>setActiveStep(Math.min(chain.steps.length-1,activeStep+1))} disabled={activeStep===chain.steps.length-1}>Next step</button>
              </div>
            </div>
          )}

          {/* Full chain overview */}
          <div style={{...S.card,marginTop:16}}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.15em",marginBottom:12}}>FULL CAMPAIGN OVERVIEW</div>
            {chain.steps?.map((step,i)=>{
              const c=PHASE_COLORS[step.phase]||THEME.accent;
              return(
                <div key={i} onClick={()=>setActiveStep(i)}
                  style={{display:"flex",alignItems:"center",gap:12,padding:"10px 12px",borderRadius:8,marginBottom:4,border:"1px solid "+(activeStep===i?c+"44":THEME.border),background:activeStep===i?c+"08":"transparent",cursor:"pointer",transition:"all 0.15s"}}>
                  <div style={{width:24,height:24,borderRadius:"50%",background:"linear-gradient(135deg,"+c+","+c+"88)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:900,color:"#000",flexShrink:0}}>{step.step}</div>
                  <span style={S.badge(c)}>{step.phase}</span>
                  <span style={{fontSize:12,fontWeight:700,color:THEME.text,flex:1}}>{step.technique}</span>
                  <span style={{fontSize:11,color:THEME.textDim,fontFamily:"monospace"}}>{step.technique_id}</span>
                  <span style={{...S.badge(step.difficulty==="Hard"?THEME.success:step.difficulty==="Medium"?THEME.warning:THEME.danger),fontSize:9}}>{step.difficulty}</span>
                  <button style={{...S.btn("p"),padding:"3px 8px",fontSize:9}} onClick={e=>{e.stopPropagation();onBuildDetection&&onBuildDetection(step.technique+" — "+step.objective,step.phase);}}>Detect</button>
                </div>
              );
            })}
          </div>

          {/* Report */}
          {reportText&&(
            <div style={S.card}>
              <div style={{...S.row,marginBottom:14}}>
                <div style={S.cardTitle}><span>📋</span> Campaign Report</div>
                <CopyBtn text={reportText}/>
              </div>
              <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap"}}>{reportText}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Detection Health ──────────────────────────────────────────────────────────
function DetectionHealth({detections,onUpdate,onBuildOn,onNav}){
  const toast=useToast();
  const[scoring,setScoring]=useState(false);
  const[scored,setScored]=useState(0);

  const unscored=detections.filter(d=>!d.score||d.score===0);
  const lowScore=detections.filter(d=>d.score&&d.score<6);
  const missingTactic=detections.filter(d=>!d.tactic||d.tactic==="General");
  const missingSeverity=detections.filter(d=>!d.severity);
  const healthScore=detections.length===0?0:Math.round(100-(
    (unscored.length/detections.length)*40+
    (lowScore.length/detections.length)*30+
    (missingTactic.length/detections.length)*30
  ));

  async function scoreAll(){
    if(!unscored.length){toast?.("All detections already scored","info");return;}
    setScoring(true);setScored(0);
    for(const det of unscored.slice(0,10)){
      try{
        const res=await fetch("/api/detection/quality-score",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:det.name,query:det.query,queryType:det.tool||det.queryType,tactic:det.tactic,severity:det.severity})});
        const data=await res.json();
        if(data.overall){const s=Math.round(data.overall/10*10)/10;onUpdate({...det,score:s,qualityBreakdown:data.breakdown});}
      }catch(e){}
      setScored(p=>p+1);
    }
    setScoring(false);
    toast?.("Scoring complete","success");
  }

  const statBox=(label,count,color,action)=>(
    <div style={{...S.card,marginBottom:0,display:"flex",flexDirection:"column",gap:8}}>
      <div style={{fontSize:26,fontWeight:800,color:count===0?THEME.success:color,lineHeight:1}}>{count}</div>
      <div style={{fontSize:12,color:THEME.textMid,fontWeight:500}}>{label}</div>
      {count>0&&action&&<button style={{...S.btn(),padding:"4px 10px",fontSize:11,marginTop:4}} onClick={action}>{action.label||"Fix"}</button>}
    </div>
  );

  return(
    <div>
      <SectionHeader icon="❤" title="Detection Health">
        <span style={{fontSize:11,color:THEME.textMid}}>Library quality score · Gap finder · Bulk fix</span>
      </SectionHeader>
      <HelpBox title="Detection Health Quick Reference" color={THEME.success} items={[
        {icon:"❤",title:"Library health score",desc:"A composite score (0–100) across your entire detection library based on average quality, staleness, MITRE coverage, and severity distribution. Aim for 70+."},
        {icon:"⏳",title:"Stale rules",desc:"Rules not updated in 90+ days are flagged. Attackers evolve — old rules may miss new techniques or generate more false positives as environments change."},
        {icon:"📊",title:"Coverage gaps",desc:"Shows which MITRE tactics have zero or weak coverage so you know where to focus new detection engineering effort."},
        {icon:"🔧",title:"Bulk fix",desc:"Use the Bulk Fix button to re-score and get AI improvement suggestions for your lowest-scoring rules in one pass."},
      ]}/>

      {detections.length===0?(
        <div style={{...S.card,textAlign:"center",padding:48}}>
          <div style={{fontSize:32,marginBottom:12,opacity:0.4}}>❤</div>
          <div style={{fontSize:15,fontWeight:600,color:THEME.text,marginBottom:8}}>No detections yet</div>
          <div style={{fontSize:13,color:THEME.textMid,marginBottom:20}}>Build your first detection to start tracking library health.</div>
          <button style={{...S.btn("p"),padding:"8px 20px"}} onClick={()=>onNav("builder")}>Build Detection →</button>
        </div>
      ):(
        <>
          {/* Health score bar */}
          <div style={{...S.card,marginBottom:16}}>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}>
              <div style={{fontSize:13,fontWeight:600,color:THEME.text}}>Overall Library Health</div>
              <div style={{fontSize:24,fontWeight:800,color:healthScore>=70?THEME.success:healthScore>=40?THEME.warning:THEME.danger}}>{healthScore}%</div>
            </div>
            <div style={{height:6,background:THEME.bgCard,borderRadius:3,overflow:"hidden",marginBottom:8}}>
              <div style={{height:"100%",width:healthScore+"%",background:healthScore>=70?"linear-gradient(90deg,"+THEME.success+",#00c46a)":healthScore>=40?"linear-gradient(90deg,"+THEME.warning+",#ff8800)":"linear-gradient(90deg,"+THEME.danger+",#ff1a3a)",borderRadius:3,transition:"width 1s ease"}}/>
            </div>
            <div style={{fontSize:11,color:THEME.textMid}}>{detections.length} detections · {detections.filter(d=>d.score>=7).length} high quality · {unscored.length} unscored</div>
          </div>

          {/* Stats grid */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:16}}>
            <div style={{...S.card,marginBottom:0}}>
              <div style={{fontSize:26,fontWeight:800,color:unscored.length===0?THEME.success:THEME.warning,lineHeight:1,marginBottom:6}}>{unscored.length}</div>
              <div style={{fontSize:12,color:THEME.textMid,marginBottom:8}}>Unscored</div>
              {unscored.length>0&&<button style={{...S.btn("p"),padding:"4px 10px",fontSize:11}} onClick={scoreAll} disabled={scoring}>{scoring?<><Spinner/>{scored}/{Math.min(unscored.length,10)}</>:"Score All"}</button>}
            </div>
            <div style={{...S.card,marginBottom:0}}>
              <div style={{fontSize:26,fontWeight:800,color:lowScore.length===0?THEME.success:THEME.danger,lineHeight:1,marginBottom:6}}>{lowScore.length}</div>
              <div style={{fontSize:12,color:THEME.textMid,marginBottom:8}}>Low Quality (&lt;6/10)</div>
              {lowScore.length>0&&<button style={{...S.btn(),padding:"4px 10px",fontSize:11}} onClick={()=>onNav("library")}>View in Library</button>}
            </div>
            <div style={{...S.card,marginBottom:0}}>
              <div style={{fontSize:26,fontWeight:800,color:missingTactic.length===0?THEME.success:THEME.textMid,lineHeight:1,marginBottom:6}}>{missingTactic.length}</div>
              <div style={{fontSize:12,color:THEME.textMid,marginBottom:8}}>Missing Tactic</div>
            </div>
            <div style={{...S.card,marginBottom:0}}>
              <div style={{fontSize:26,fontWeight:800,color:missingSeverity.length===0?THEME.success:THEME.textMid,lineHeight:1,marginBottom:6}}>{missingSeverity.length}</div>
              <div style={{fontSize:12,color:THEME.textMid,marginBottom:8}}>Missing Severity</div>
            </div>
          </div>

          {/* Low score detections */}
          {lowScore.length>0&&(
            <div style={{...S.card,marginBottom:16}}>
              <div style={{...S.cardTitle,marginBottom:12}}>Low Quality Detections <span style={{fontSize:11,fontWeight:400,color:THEME.textMid}}>score below 6/10</span></div>
              <div style={{display:"flex",flexDirection:"column",gap:6}}>
                {lowScore.map(d=>(
                  <div key={d.id} style={{display:"flex",alignItems:"center",gap:10,padding:"9px 12px",background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:8}}>
                    <div style={{flex:1}}>
                      <div style={{fontSize:12,fontWeight:600,color:THEME.text}}>{d.name}</div>
                      <div style={{fontSize:11,color:THEME.textMid}}>{d.tactic||"No tactic"} · {d.queryType}</div>
                    </div>
                    <span style={{fontSize:13,fontWeight:700,color:d.score>=4?THEME.warning:THEME.danger}}>{d.score}/10</span>
                    <button style={{...S.btn("p"),padding:"4px 10px",fontSize:11}} onClick={()=>onBuildOn&&onBuildOn(d.name+" — "+d.threat,d.tactic)}>Improve →</button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Unscored detections */}
          {unscored.length>0&&(
            <div style={S.card}>
              <div style={{...S.cardTitle,marginBottom:12}}>Unscored Detections <span style={{fontSize:11,fontWeight:400,color:THEME.textMid}}>{unscored.length} need quality scoring</span></div>
              <div style={{display:"flex",flexDirection:"column",gap:6}}>
                {unscored.slice(0,8).map(d=>(
                  <div key={d.id} style={{display:"flex",alignItems:"center",gap:10,padding:"9px 12px",background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:8}}>
                    <div style={{flex:1}}>
                      <div style={{fontSize:12,fontWeight:600,color:THEME.text}}>{d.name}</div>
                      <div style={{fontSize:11,color:THEME.textMid}}>{d.tactic||"No tactic"} · {d.queryType}</div>
                    </div>
                    <span style={{fontSize:11,color:THEME.textDim}}>Not scored</span>
                  </div>
                ))}
                {unscored.length>8&&<div style={{fontSize:11,color:THEME.textMid,textAlign:"center",padding:8}}>+{unscored.length-8} more — click "Score All" above</div>}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Adversary SIEM ─────────────────────────────────────────────────────────────
const ADV_TECHNIQUES = [
  "T1059 - Command and Scripting Interpreter","T1078 - Valid Accounts","T1110 - Brute Force",
  "T1190 - Exploit Public-Facing Application","T1566 - Phishing","T1003 - OS Credential Dumping",
  "T1055 - Process Injection","T1547 - Boot or Logon Autostart Execution","T1053 - Scheduled Task/Job",
  "T1036 - Masquerading","T1027 - Obfuscated Files or Information","T1071 - Application Layer Protocol",
  "T1486 - Data Encrypted for Impact","T1490 - Inhibit System Recovery","T1562 - Impair Defenses",
  "T1021 - Remote Services","T1082 - System Information Discovery","T1083 - File and Directory Discovery",
  "T1105 - Ingress Tool Transfer","T1070 - Indicator Removal","T1112 - Modify Registry",
  "T1135 - Network Share Discovery","T1046 - Network Service Discovery","T1018 - Remote System Discovery",
];
const ADV_GROUPS = ["Custom","APT28 (Fancy Bear)","APT29 (Cozy Bear)","APT41","Lazarus Group","FIN7","REvil","BlackCat/ALPHV","Conti","LockBit","Scattered Spider"];
const ADV_PLATFORMS = ["Windows","Linux","macOS","Cloud/AWS","Cloud/Azure","Active Directory","Web Application"];
const ADV_LOG_TYPES = ["Windows Event Logs","Sysmon","Zeek/Network","Web Access Logs","Endpoint EDR","Linux Auditd","Cloud Trail"];

function AdversarySIEM({ detections }) {
  const [technique, setTechnique] = useState(ADV_TECHNIQUES[0]);
  const [customTech, setCustomTech] = useState("");
  const [group, setGroup] = useState("Custom");
  const [platform, setPlatform] = useState("Windows");
  const [logType, setLogType] = useState("Windows Event Logs");
  const [logCount, setLogCount] = useState(8);
  const [generating, setGenerating] = useState(false);
  const [logs, setLogs] = useState([]);
  const [testing, setTesting] = useState(false);
  const [results, setResults] = useState(null);
  const [activeLog, setActiveLog] = useState(null);
  const [streamText, setStreamText] = useState("");
  const toast = useToast();

  async function generateLogs() {
    setGenerating(true); setLogs([]); setResults(null); setStreamText(""); setActiveLog(null);
    const tech = customTech.trim() || technique;
    const groupCtx = group !== "Custom" ? ` Simulate logs as if from ${group}.` : "";
    const prompt = `You are a red team expert simulating adversary activity for detection testing.
Generate exactly ${logCount} realistic ${logType} log entries for technique: ${tech}.
Platform: ${platform}.${groupCtx}

CRITICAL: Return ONLY a raw JSON array. No markdown. No code fences. No comments. No explanation. Start your response with [ and end with ].

Each element must have these exact keys:
{"id":1,"timestamp":"2024-03-24T10:23:11Z","event_id":"4688","log_type":"${logType}","source":"HOSTNAME-01","severity":"high","summary":"brief description","raw":"full raw log line here","ioc":["ioc1","ioc2"],"technique_id":"T1059.001"}

Make logs realistic with real hostnames, IPs, usernames, paths, commands. Vary timestamps over 30 minutes.`;

    try {
      let full = "";
      await callClaudeStream([{role:"user",content:prompt}], "Expert red team adversary simulation engine.", 3000,
        chunk => { full += chunk; setStreamText(full); }
      );
      const m = full.match(/\[[\s\S]*\]/);
      if (m) {
        // Clean AI response: strip control chars, line-comments, trailing commas
        const clean = m[0]
          .replace(/[\x00-\x09\x0b\x0c\x0e-\x1f]/g, " ")   // control chars
          .replace(/^\s*\/\/[^\n]*/gm, "")                   // lines starting with //
          .replace(/\/\*[\s\S]*?\*\//g, "")                  // /* block comments */
          .replace(/,\s*([\]}])/g, "$1");                    // trailing commas
        let parsed;
        try { parsed = JSON.parse(clean); }
        catch(parseErr) {
          // Last resort: extract individual objects
          const objs = [];
          const objRx = /\{[^{}]*\}/g; let om;
          while((om = objRx.exec(clean)) !== null) { try { objs.push(JSON.parse(om[0])); } catch{} }
          if (objs.length) parsed = objs;
          else throw parseErr;
        }
        setLogs(parsed);
        setStreamText("");
        toast?.("Generated "+parsed.length+" adversary log events", "success");
      } else {
        toast?.("Could not parse logs — try again", "error");
        setStreamText("");
      }
    } catch(e) { toast?.("Generation failed: "+e.message, "error"); setStreamText(""); }
    setGenerating(false);
  }

  async function testDetections() {
    if (!logs.length) return;
    if (!detections.length) { toast?.("No detections in library to test against", "error"); return; }
    setTesting(true); setResults(null);
    const logSample = logs.map(l => `[${l.timestamp}] ${l.raw}`).join("\n");
    const detSample = detections.slice(0,12).map(d => `ID:${d.id} | ${d.name} | ${d.queryType} | Query: ${d.query.slice(0,200)}`).join("\n---\n");
    const prompt = `You are a detection validation expert. Given these adversary logs and detection rules, determine which rules would FIRE (true positive) vs MISS.

ADVERSARY LOGS:
${logSample}

DETECTION RULES:
${detSample}

Return ONLY valid JSON:
{
  "coverage_pct": 72,
  "fired": ["detection-id-1","detection-id-2"],
  "missed": ["detection-id-3"],
  "partial": ["detection-id-4"],
  "gaps": ["Gap description 1","Gap description 2"],
  "recommendations": ["Add detection for X","Tune rule Y to catch Z"]
}

Be realistic — only mark as fired if the rule logic genuinely matches the log patterns. Partial = rule concept matches but query wouldn't execute correctly.`;
    try {
      const txt = await callClaude([{role:"user",content:prompt}], "Senior detection engineer.", 2000);
      const m = txt.match(/\{[\s\S]*\}/);
      if (m) {
        const clean2 = m[0]
          .replace(/[\x00-\x09\x0b\x0c\x0e-\x1f]/g," ")
          .replace(/^\s*\/\/[^\n]*/gm,"")
          .replace(/\/\*[\s\S]*?\*\//g,"")
          .replace(/,\s*([\]}])/g,"$1");
        const r = JSON.parse(clean2);
        // resolve by ID or name (AI may return either)
        const byId = Object.fromEntries(detections.map(d=>[d.id,d]));
        const byName = Object.fromEntries(detections.map(d=>[d.name.toLowerCase().trim(),d]));
        const resolve = v => byId[v] || byName[(v||"").toLowerCase().trim()] || null;
        const firedDets = (r.fired||[]).map(resolve).filter(Boolean);
        const missedDets = (r.missed||[]).map(resolve).filter(Boolean);
        const partialDets = (r.partial||[]).map(resolve).filter(Boolean);
        // if AI returned names that matched nothing, show all detections as tested
        const anyMatched = firedDets.length||missedDets.length||partialDets.length;
        setResults({
          ...r,
          firedDets,
          missedDets: anyMatched ? missedDets : detections.slice(0,12).filter(d=>!firedDets.includes(d)),
          partialDets,
        });
      } else { toast?.("Could not parse results","error"); }
    } catch(e) { toast?.("Testing failed: "+e.message,"error"); }
    setTesting(false);
  }

  const sevColor2 = {high:THEME.danger,medium:THEME.warning,low:THEME.success};

  return (
    <div>
      <SectionHeader icon="⚔️" title="Adversary SIEM">
        <span style={{fontSize:11,padding:"3px 10px",borderRadius:5,background:"rgba(239,68,68,0.08)",border:"1px solid rgba(239,68,68,0.2)",color:"#f87171",fontWeight:500}}>Red Team Lab</span>
        <span style={{fontSize:12,color:THEME.textDim}}>Generate adversary logs · Test detections · Find gaps</span>
      </SectionHeader>
      <HelpBox title="Adversary SIEM Quick Reference" color={THEME.danger} items={[
        {icon:"⚔️",title:"What it does",desc:"Simulates adversary behavior by generating realistic SIEM log events for any ATT&CK technique or threat scenario. Use it to test whether your detections would fire on real attacker activity."},
        {icon:"📋",title:"How to use it",desc:"Describe an attack scenario (e.g. 'Mimikatz credential dumping on Windows'), select a SIEM platform, and click Generate. AI produces log lines that a real attacker would generate."},
        {icon:"🔗",title:"Send to Triage",desc:"Click 'Send to Triage' on any generated log set to automatically test it against AI verdict — see if your current detections would catch it."},
        {icon:"💡",title:"Tip",desc:"Use this before building a detection to understand what the adversary logs actually look like — then reference those fields in your detection query for maximum accuracy."},
      ]}/>


      {/* Config Panel */}
      <div style={{...S.card,marginBottom:16}}>
        <div style={{...S.cardTitle,marginBottom:14}}>Adversary Profile</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:14}}>
          <div>
            <label style={S.label}>ATT&CK Technique</label>
            <select style={S.input} value={technique} onChange={e=>setTechnique(e.target.value)}>
              {ADV_TECHNIQUES.map(t=><option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label style={S.label}>Adversary Group</label>
            <select style={S.input} value={group} onChange={e=>setGroup(e.target.value)}>
              {ADV_GROUPS.map(g=><option key={g} value={g}>{g}</option>)}
            </select>
          </div>
          <div>
            <label style={S.label}>Platform</label>
            <select style={S.input} value={platform} onChange={e=>setPlatform(e.target.value)}>
              {ADV_PLATFORMS.map(p=><option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          <div>
            <label style={S.label}>Log Type</label>
            <select style={S.input} value={logType} onChange={e=>setLogType(e.target.value)}>
              {ADV_LOG_TYPES.map(l=><option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div>
            <label style={S.label}>Custom Technique (optional)</label>
            <input style={S.input} value={customTech} onChange={e=>setCustomTech(e.target.value)} placeholder="e.g. LSASS dump via ProcDump"/>
          </div>
          <div>
            <label style={S.label}>Log Count</label>
            <select style={S.input} value={logCount} onChange={e=>setLogCount(Number(e.target.value))}>
              {[5,8,12,15,20].map(n=><option key={n} value={n}>{n} events</option>)}
            </select>
          </div>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <button style={{...S.btn("p"),padding:"9px 20px",fontSize:13,fontWeight:600}} onClick={generateLogs} disabled={generating}>
            {generating?<><Spinner/>Generating...</>:"Generate Adversary Logs"}
          </button>
          {logs.length>0&&<button style={{...S.btn(),padding:"9px 20px",fontSize:13}} onClick={testDetections} disabled={testing}>
            {testing?<><Spinner/>Testing...</>:"Test My Detections"}
          </button>}
          {logs.length>0&&!results&&!testing&&<span style={{fontSize:12,color:THEME.textMid}}>← Run against your {detections.length} detections to find gaps</span>}
          {logs.length>0&&results&&<span style={{fontSize:12,color:THEME.textMid}}>{logs.length} events tested</span>}
        </div>
      </div>

      {/* Streaming output */}
      {streamText&&(
        <div style={{...S.card,marginBottom:16}}>
          <div style={{fontSize:11,color:THEME.textMid,marginBottom:8,fontWeight:500}}>Generating adversary activity...</div>
          <div style={{...S.code,maxHeight:200,overflowY:"auto",fontSize:11}}>{streamText}</div>
        </div>
      )}

      {/* Log Stream + Coverage side by side */}
      {(logs.length>0||results)&&(
        <div style={{display:"grid",gridTemplateColumns:results?"1fr 1fr":"1fr",gap:16}}>

          {/* Log Stream */}
          {logs.length>0&&(
            <div style={S.card}>
              <div style={{...S.cardTitle,marginBottom:14}}>Log Stream <span style={{fontSize:11,fontWeight:400,color:THEME.textMid,marginLeft:4}}>{logs.length} events</span></div>
              <div style={{display:"flex",flexDirection:"column",gap:6,maxHeight:520,overflowY:"auto"}}>
                {logs.map((log,i)=>(
                  <div key={i} onClick={()=>setActiveLog(activeLog===i?null:i)}
                    style={{background:activeLog===i?THEME.bgCardHover:"transparent",border:"1px solid "+(activeLog===i?THEME.borderBright:THEME.border),borderRadius:8,padding:"10px 12px",cursor:"pointer",transition:"all 0.15s"}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:activeLog===i?8:0}}>
                      <span style={{...S.badge(sevColor2[log.severity]||THEME.textDim),fontSize:9}}>{(log.severity||"med").toUpperCase()}</span>
                      <span style={{fontSize:10,color:THEME.textDim,fontFamily:"monospace"}}>{log.timestamp?.slice(11,19)||"--:--:--"}</span>
                      <span style={{fontSize:10,color:THEME.accent,fontFamily:"monospace"}}>{log.event_id}</span>
                      <span style={{fontSize:11,color:THEME.text,fontWeight:600,flex:1}}>{log.summary}</span>
                    </div>
                    {activeLog===i&&(
                      <div>
                        <div style={{...S.code,fontSize:10,marginBottom:8,padding:"8px 10px"}}>{log.raw}</div>
                        {log.ioc?.length>0&&(
                          <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
                            <span style={{fontSize:10,color:THEME.textDim,fontWeight:700}}>IOCs:</span>
                            {log.ioc.map((ioc,j)=><span key={j} style={{fontSize:9,fontFamily:"monospace",padding:"2px 7px",borderRadius:4,background:THEME.bgCard,border:"1px solid "+THEME.border,color:THEME.textMid}}>{ioc}</span>)}
                          </div>
                        )}
                        {log.technique_id&&<div style={{marginTop:6}}><span style={S.badge(THEME.purple)}>{log.technique_id}</span></div>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detection Coverage */}
          {results&&(
            <div style={{...S.card,borderColor:"#1a2a3a"}}>
              <div style={S.cardTitle}>Detection Coverage</div>

              {/* Coverage meter */}
              <div style={{marginBottom:16}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                  <span style={{fontSize:12,color:THEME.textMid}}>Detection Rate</span>
                  <span style={{fontSize:18,fontWeight:800,color:results.coverage_pct>=70?THEME.success:results.coverage_pct>=40?THEME.warning:THEME.danger}}>{results.coverage_pct}%</span>
                </div>
                <div style={{height:8,background:"#0a0e1a",borderRadius:4,overflow:"hidden"}}>
                  <div style={{height:"100%",width:results.coverage_pct+"%",background:results.coverage_pct>=70?"linear-gradient(90deg,"+THEME.success+",#00c46a)":results.coverage_pct>=40?"linear-gradient(90deg,"+THEME.warning+",#ff8800)":"linear-gradient(90deg,"+THEME.danger+",#ff1a3a)",borderRadius:4,transition:"width 0.8s ease"}}/>
                </div>
                <div style={{display:"flex",gap:16,marginTop:8}}>
                  <span style={{fontSize:11,color:THEME.success}}>✓ {results.firedDets?.length||0} fired</span>
                  <span style={{fontSize:11,color:THEME.warning}}>~ {results.partialDets?.length||0} partial</span>
                  <span style={{fontSize:11,color:THEME.danger}}>✗ {results.missedDets?.length||0} missed</span>
                </div>
              </div>

              {/* Fired */}
              {results.firedDets?.length>0&&(
                <div style={{marginBottom:12}}>
                  <div style={{fontSize:11,fontWeight:600,color:THEME.success,marginBottom:6}}>Fired</div>
                  {results.firedDets.map((d,i)=>(
                    <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"5px 8px",background:"rgba(0,232,122,0.05)",border:"1px solid rgba(0,232,122,0.15)",borderRadius:6,marginBottom:4}}>
                      <span style={{fontSize:10,color:THEME.success}}>●</span>
                      <span style={{fontSize:11,color:THEME.text,fontWeight:600}}>{d.name}</span>
                      <span style={{...S.badge(THEME.success),fontSize:9,marginLeft:"auto"}}>{d.queryType}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Partial */}
              {results.partialDets?.length>0&&(
                <div style={{marginBottom:12}}>
                  <div style={{fontSize:11,fontWeight:600,color:THEME.warning,marginBottom:6}}>Partial match</div>
                  {results.partialDets.map((d,i)=>(
                    <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"5px 8px",background:"rgba(255,170,0,0.05)",border:"1px solid rgba(255,170,0,0.15)",borderRadius:6,marginBottom:4}}>
                      <span style={{fontSize:10,color:THEME.warning}}>◐</span>
                      <span style={{fontSize:11,color:THEME.text,fontWeight:600}}>{d.name}</span>
                      <span style={{...S.badge(THEME.warning),fontSize:9,marginLeft:"auto"}}>{d.queryType}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Missed */}
              {results.missedDets?.length>0&&(
                <div style={{marginBottom:12}}>
                  <div style={{fontSize:11,fontWeight:600,color:THEME.danger,marginBottom:6}}>Not detected</div>
                  {results.missedDets.map((d,i)=>(
                    <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"5px 8px",background:"rgba(255,61,85,0.05)",border:"1px solid rgba(255,61,85,0.15)",borderRadius:6,marginBottom:4}}>
                      <span style={{fontSize:10,color:THEME.danger}}>✗</span>
                      <span style={{fontSize:11,color:THEME.text,fontWeight:600}}>{d.name}</span>
                      <span style={{...S.badge(THEME.danger),fontSize:9,marginLeft:"auto"}}>{d.queryType}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Gaps */}
              {results.gaps?.length>0&&(
                <div style={{marginBottom:12,padding:12,background:"rgba(255,61,85,0.04)",border:"1px solid rgba(255,61,85,0.15)",borderRadius:8}}>
                  <div style={{fontSize:11,fontWeight:700,color:THEME.danger,marginBottom:8}}>⚠ Detection Gaps</div>
                  {results.gaps.map((g,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,padding:"3px 0",borderBottom:"1px solid #1a2030"}}>• {g}</div>)}
                </div>
              )}

              {/* Recommendations */}
              {results.recommendations?.length>0&&(
                <div style={{padding:12,background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",borderRadius:8}}>
                  <div style={{fontSize:11,fontWeight:700,color:THEME.accent,marginBottom:8}}>💡 Recommendations</div>
                  {results.recommendations.map((r,i)=><div key={i} style={{fontSize:11,color:THEME.textMid,padding:"3px 0",borderBottom:"1px solid #1a2030"}}>→ {r}</div>)}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!logs.length&&!generating&&!streamText&&(
        <div style={{...S.card,textAlign:"center",padding:"48px 32px"}}>
          <div style={{fontSize:32,marginBottom:12,opacity:0.4}}>⚔️</div>
          <div style={{fontSize:16,fontWeight:600,color:THEME.text,marginBottom:6}}>No logs generated yet</div>
          <div style={{fontSize:13,color:THEME.textMid,maxWidth:420,margin:"0 auto",lineHeight:1.7,marginBottom:24}}>
            Configure an adversary profile above and generate logs to test your detection coverage.
          </div>
          <div style={{display:"flex",gap:8,justifyContent:"center",flexWrap:"wrap"}}>
            {["T1003 · LSASS Dump","T1059 · PowerShell","T1486 · Ransomware","T1566 · Phishing"].map(t=>(
              <button key={t} style={{fontSize:11,padding:"5px 12px",borderRadius:6,background:"transparent",border:"1px solid "+THEME.border,color:THEME.textMid,cursor:"pointer",fontFamily:"inherit"}}
                onClick={()=>{setTechnique(ADV_TECHNIQUES.find(x=>x.includes(t.split("·")[0].trim().split(" ")[0]))||ADV_TECHNIQUES[0]);}}>
                {t}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ThreatIntel({ onBuildDetection, onSimulate, onHunt }){
  const[kevData,setKevData]=useState([]);const[kevLoading,setKevLoading]=useState(false);const[aptFeed,setAptFeed]=useState([]);const[aptLoading,setAptLoading]=useState(false);const[kevErr,setKevErr]=useState("");const[search,setSearch]=useState("");const[huntResult,setHuntResult]=useState("");const[huntLoading,setHuntLoading]=useState(false);
  async function loadKEV(){setKevLoading(true);setKevErr("");try{const res=await fetch("/api/kev");if(!res.ok)throw new Error("HTTP "+res.status);const data=await res.json();setKevData((data.vulnerabilities||[]).slice(0,60));}catch(e){setKevErr("Failed: "+e.message);}setKevLoading(false);}
  async function loadAPTFeed(){setAptLoading(true);try{const txt=await callClaude([{role:"user",content:'Generate 8 APT profiles. Return ONLY valid JSON: [{"apt":"name","origin":"country","aliases":["alt"],"sector":"target","ttps":["T1234"],"recent_activity":"description","severity":"Critical/High/Medium","motivation":"espionage/financial/disruption"}]'}],"Threat intelligence expert.",1800);const m=txt.match(/\[[\s\S]*\]/);if(m)setAptFeed(JSON.parse(m[0]));}catch(e){console.error(e);}setAptLoading(false);}
  async function generateHuntPlan(){
    setHuntLoading(true);setHuntResult("");
    const kevSample=kevData.slice(0,5).map(v=>v.cveID+" - "+v.vulnerabilityName).join("\n");
    const aptSample=aptFeed.slice(0,3).map(a=>a.apt+" ("+a.origin+"): "+(a.ttps||[]).join(", ")).join("\n");
    try{const txt=await callClaude([{role:"user",content:"Generate a prioritized threat hunt plan based on:\n\nRecent KEVs:\n"+kevSample+"\n\nActive APTs:\n"+aptSample+"\n\nProvide: 1. Top 3 hunt priorities 2. Hunting queries for each 3. Data sources 4. IOCs to search for"}],"Senior threat hunter.",2000);setHuntResult(txt);}
    catch(e){setHuntResult("Error: "+e.message);}
    setHuntLoading(false);
  }
  const fk=kevData.filter(v=>!search||v.cveID?.toLowerCase().includes(search.toLowerCase())||v.vulnerabilityName?.toLowerCase().includes(search.toLowerCase()));
  return(
    <div>
      <SectionHeader icon="🌐" title="Threat Intelligence" color={THEME.success}>
        <div style={S.flex}>
          <span style={S.badge(THEME.success)}>Live Feed</span>
          {(kevData.length>0||aptFeed.length>0)&&<button style={{...S.btn("p"),padding:"6px 14px",fontSize:11}} onClick={generateHuntPlan} disabled={huntLoading}>{huntLoading?<><Spinner/>Generating...</>:"Generate Hunt Plan"}</button>}
        </div>
      </SectionHeader>
      <HelpBox title="Threat Intelligence Quick Reference" color={THEME.success} items={[
        {icon:"🌐",title:"What it does",desc:"Pulls live threat intelligence from CISA KEV (Known Exploited Vulnerabilities), APT feeds, and CVE advisories. Use it to stay current on active threats and build detections before attackers hit you."},
        {icon:"🔴",title:"CISA KEV",desc:"The Known Exploited Vulnerabilities catalog — CVEs that CISA has confirmed are being actively exploited in the wild. High-priority targets for detection coverage."},
        {icon:"🎯",title:"Generate Hunt Plan",desc:"Select an APT group or threat context and click 'Generate Hunt Plan' to get a prioritized list of hunt hypotheses, log sources to check, and detection recommendations."},
        {icon:"💡",title:"Tip",desc:"Click any KEV entry to auto-populate the Detection Builder with the CVE context — AI will generate a detection tailored to that specific vulnerability."},
      ]}/>
      {huntResult&&<div style={{...S.card,borderColor:THEME.success+"44",marginBottom:16}}><div style={{...S.row,marginBottom:10}}><div style={S.cardTitle}><span>🎯</span> Threat Hunt Plan</div><CopyBtn text={huntResult}/></div><div style={{fontSize:13,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap"}}>{huntResult}</div></div>}
      <div style={S.grid2}>
        <div style={S.card}>
          <div style={{...S.row,marginBottom:14}}><div style={S.cardTitle}><span>🔴</span> CISA KEV</div><button style={S.btn("p")} onClick={loadKEV} disabled={kevLoading}>{kevLoading?<><Spinner/>Loading...</>:"Load KEV Feed"}</button></div>
          {kevErr&&<StatusBar msg={kevErr} type="error"/>}
          {kevData.length>0&&<><input style={{...S.input,marginBottom:12}} value={search} onChange={e=>setSearch(e.target.value)} placeholder="Filter CVEs..."/><div style={{maxHeight:460,overflowY:"auto"}}>{fk.map((v,i)=><div key={i} style={{padding:"12px 0",borderBottom:"1px solid "+THEME.border}}>
              <div style={S.flex}><span style={S.badge(THEME.danger)}>{v.cveID}</span><span style={{fontSize:12,fontWeight:700,color:THEME.text}}>{v.vendorProject}</span></div>
              <div style={{fontSize:12,color:THEME.textMid,marginTop:4,marginBottom:6,lineHeight:1.5}}>{v.vulnerabilityName}</div>
              <div style={{fontSize:11,color:THEME.textDim,marginBottom:8}}>Due: {v.dueDate}</div>
              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                <button style={{...S.btn("p"),padding:"4px 10px",fontSize:10}} onClick={()=>onBuildDetection&&onBuildDetection(v.cveID+" - "+v.vulnerabilityName,"Initial Access")}>Build Detection</button>
                <button style={{...S.btn("d"),padding:"4px 10px",fontSize:10}} onClick={()=>onSimulate&&onSimulate(v.cveID+" - "+v.vulnerabilityName+" exploitation","Initial Access")}>Simulate</button>
                <button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>onHunt&&onHunt(v.cveID,v.vulnerabilityName)}>Hunt</button>
              </div>
            </div>)}</div></>}
          {!kevData.length&&!kevLoading&&<div style={{color:THEME.textDim,fontSize:13,textAlign:"center",padding:"40px 20px"}}><div style={{fontSize:32,marginBottom:12}}>🛡</div>Click Load KEV Feed to fetch latest.</div>}
        </div>
        <div style={S.card}>
          <div style={{...S.row,marginBottom:14}}><div style={S.cardTitle}><span>👁</span> APT Intelligence</div><button style={S.btn("p")} onClick={loadAPTFeed} disabled={aptLoading}>{aptLoading?<><Spinner/>Generating...</>:"Generate Feed"}</button></div>
          <div style={{maxHeight:510,overflowY:"auto"}}>
            {aptFeed.map((apt,i)=><div key={i} style={{padding:"14px 0",borderBottom:"1px solid "+THEME.border}}>
              <div style={S.flex}><span style={S.badge(apt.severity==="Critical"?THEME.danger:apt.severity==="High"?THEME.orange:THEME.warning)}>{apt.severity}</span><span style={{fontSize:14,fontWeight:800}}>{apt.apt}</span><span style={{fontSize:11,color:THEME.textDim}}>{apt.origin}</span></div>
              <div style={{fontSize:11,color:THEME.textDim,marginTop:6,marginBottom:6}}>Targets: {apt.sector} · {apt.motivation}</div>
              <div style={{fontSize:12,color:THEME.textMid,marginBottom:8}}>{apt.recent_activity}</div>
              {apt.ttps?.length>0&&<div style={{display:"flex",flexWrap:"wrap",marginBottom:8}}>{apt.ttps.map((t,j)=><span key={j} style={S.tag}>{t}</span>)}</div>}
              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                <button style={{...S.btn("p"),padding:"4px 10px",fontSize:10}} onClick={()=>onBuildDetection&&onBuildDetection(apt.apt+" TTPs: "+(apt.ttps||[]).join(", "),"Defense Evasion")}>Build Detection</button>
                <button style={{...S.btn("d"),padding:"4px 10px",fontSize:10}} onClick={()=>onSimulate&&onSimulate(apt.apt+" attack campaign targeting "+apt.sector,"Lateral Movement")}>Simulate APT</button>
                <button style={{...S.btn(),padding:"4px 10px",fontSize:10}} onClick={()=>onHunt&&onHunt(apt.apt,(apt.ttps||[]).join(", "))}>Hunt TTPs</button>
              </div>
            </div>)}
            {!aptFeed.length&&!aptLoading&&<div style={{color:THEME.textDim,fontSize:13,textAlign:"center",padding:"40px 20px"}}><div style={{fontSize:32,marginBottom:12}}>👁</div>Click Generate Feed for APT intel.</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Detection Chain Builder ────────────────────────────────────────────────────
const KILL_CHAIN_NEXT={
  "Reconnaissance":["Resource Development","Initial Access"],
  "Resource Development":["Initial Access","Execution"],
  "Initial Access":["Execution","Persistence","Defense Evasion"],
  "Execution":["Persistence","Privilege Escalation","Defense Evasion"],
  "Persistence":["Privilege Escalation","Defense Evasion","Credential Access"],
  "Privilege Escalation":["Defense Evasion","Credential Access","Discovery"],
  "Defense Evasion":["Credential Access","Discovery","Lateral Movement"],
  "Credential Access":["Discovery","Lateral Movement","Collection"],
  "Discovery":["Lateral Movement","Collection","Command and Control"],
  "Lateral Movement":["Collection","Command and Control","Exfiltration"],
  "Collection":["Command and Control","Exfiltration","Impact"],
  "Command and Control":["Exfiltration","Impact"],
  "Exfiltration":["Impact"],
  "Impact":[],
};

function DetectionChain({detections}){
  const[nameA,setNameA]=useState(""); const[queryA,setQueryA]=useState("");
  const[nameB,setNameB]=useState(""); const[queryB,setQueryB]=useState("");
  const[correlField,setCorrelField]=useState("host");
  const[timeWindow,setTimeWindow]=useState("15");
  const[platform,setPlatform]=useState("Splunk");
  const[loading,setLoading]=useState(false);
  const[result,setResult]=useState(null);
  const[err,setErr]=useState("");
  const[activeOut,setActiveOut]=useState("splunk");
  const[copyDet,setCopyDet]=useState(null);
  const[detA,setDetA]=useState(null);
  const[suggestionsB,setSuggestionsB]=useState([]);

  function loadDet(which,det){
    if(which==="a"){
      setNameA(det.name);setQueryA(det.query||"");setDetA(det);
      // compute suggestions for B based on kill chain progression
      const nextTactics=KILL_CHAIN_NEXT[det.tactic]||[];
      const suggestions=detections.filter(d=>
        d.id!==det.id&&(
          nextTactics.some(t=>d.tactic&&d.tactic.toLowerCase()===t.toLowerCase())||
          (nextTactics.length===0&&d.id!==det.id)// impact: suggest any
        )
      ).slice(0,6);
      // if no tactic match, fall back to all others
      setSuggestionsB(suggestions.length>0?suggestions:detections.filter(d=>d.id!==det.id).slice(0,4));
    }
    else{setNameB(det.name);setQueryB(det.query||"");}
  }
  async function generate(){
    if(!nameA||!nameB){setErr("Enter both detection names.");return;}
    setLoading(true);setErr("");setResult(null);
    try{
      const res=await fetch("/api/detection/chain",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({nameA,queryA,nameB,queryB,queryType:"SPL",correlField,timeWindowMin:parseInt(timeWindow)||15,platform})});
      const data=await res.json(); if(data.error)throw new Error(data.error); setResult(data);
    }catch(e){setErr(e.message);}
    setLoading(false);
  }
  const outTabs=[{id:"splunk",label:"Splunk ES",key:"splunk_correlation"},{id:"elastic",label:"Elastic EQL",key:"elastic_query"},{id:"sentinel",label:"Sentinel KQL",key:"sentinel_kql"},{id:"chronicle",label:"Chronicle",key:"chronicle_udm"}];
  return(
    <div>
      <SectionHeader icon="🔗" title="Detection Chain Builder" color={THEME.accent}>
        <span style={S.badge(THEME.accent)}>Multi-stage correlation</span>
        <span style={{fontSize:11,color:THEME.textDim}}>Chain two detections into a Critical correlation rule</span>
      </SectionHeader>
      <HelpBox title="How Detection Chaining Works" color={THEME.accent} items={[
        {icon:"🎯",title:"What it does",desc:"Combines two separate detections (e.g. Reconnaissance + Lateral Movement) into a single high-fidelity correlation rule. Only fires if both events occur on the same host/user within your time window."},
        {icon:"⏱",title:"Time window",desc:"The correlation fires only if Detection B occurs within N minutes of Detection A on the same entity. Shorter windows = higher confidence but may miss slow-and-low attacks."},
        {icon:"🔗",title:"Correlation field",desc:"The field used to link the two events (host, src_ip, user, etc.). Choose the field that uniquely identifies the entity moving through the kill chain."},
        {icon:"📋",title:"Output",desc:"Get Splunk ES correlation, Elastic EQL, Microsoft Sentinel KQL, and Google Chronicle YARA-L versions of the combined rule — ready to paste into your SIEM."},
      ]}/>
      <div style={S.card}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
          {/* Detection A */}
          <div style={{padding:"14px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.accentDim+"55",borderRadius:8}}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.12em",marginBottom:10}}>DETECTION A — EARLY STAGE</div>
            <input style={{...S.input,marginBottom:8}} placeholder="Detection name..." value={nameA} onChange={e=>setNameA(e.target.value)}/>
            <textarea style={{...S.textarea,minHeight:80,fontSize:11,fontFamily:"monospace"}} placeholder="Paste detection query (optional)..." value={queryA} onChange={e=>setQueryA(e.target.value)}/>
            {detections.length>0&&(
              <div style={{marginTop:8}}>
                <select style={{...S.input,fontSize:11}} onChange={e=>{const d=detections.find(x=>x.id===e.target.value);if(d)loadDet("a",d);}}>
                  <option value="">Load from library...</option>
                  {detections.map(d=><option key={d.id} value={d.id}>{d.name}</option>)}
                </select>
              </div>
            )}
          </div>

          {/* Detection B — with smart suggestions */}
          <div style={{padding:"14px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.purple+"55",borderRadius:8}}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.12em",marginBottom:10}}>DETECTION B — LATER STAGE</div>

            {/* Smart suggestions */}
            {suggestionsB.length>0&&!nameB&&(
              <div style={{marginBottom:10}}>
                <div style={{fontSize:10,color:THEME.textDim,fontWeight:600,marginBottom:6,letterSpacing:"0.05em"}}>
                  💡 SUGGESTED NEXT-STAGE DETECTIONS
                  {detA?.tactic&&<span style={{color:THEME.purple,marginLeft:6}}>following {detA.tactic}</span>}
                </div>
                <div style={{display:"flex",flexDirection:"column",gap:5}}>
                  {suggestionsB.map(d=>{
                    const nextTactics=KILL_CHAIN_NEXT[detA?.tactic]||[];
                    const isMatch=nextTactics.some(t=>d.tactic&&d.tactic.toLowerCase()===t.toLowerCase());
                    return(
                      <div key={d.id}
                        onClick={()=>loadDet("b",d)}
                        style={{display:"flex",alignItems:"center",gap:8,padding:"8px 10px",borderRadius:7,border:"1px solid "+(isMatch?THEME.purple+"44":THEME.border),background:isMatch?"rgba(168,85,247,0.06)":"rgba(255,255,255,0.02)",cursor:"pointer",transition:"all 0.15s"}}
                        onMouseEnter={e=>{e.currentTarget.style.borderColor=THEME.purple+"88";e.currentTarget.style.background="rgba(168,85,247,0.1)";}}
                        onMouseLeave={e=>{e.currentTarget.style.borderColor=isMatch?THEME.purple+"44":THEME.border;e.currentTarget.style.background=isMatch?"rgba(168,85,247,0.06)":"rgba(255,255,255,0.02)";}}>
                        <div style={{flex:1,minWidth:0}}>
                          <div style={{fontSize:11,fontWeight:600,color:THEME.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.name}</div>
                          {d.tactic&&<div style={{fontSize:9,color:isMatch?THEME.purple:THEME.textDim,marginTop:1}}>{d.tactic}</div>}
                        </div>
                        {isMatch&&<span style={{fontSize:9,color:THEME.purple,fontWeight:700,flexShrink:0}}>CHAIN →</span>}
                        <span style={{fontSize:11,color:THEME.textDim,flexShrink:0}}>+</span>
                      </div>
                    );
                  })}
                </div>
                <div style={{height:1,background:THEME.border,margin:"10px 0"}}/>
              </div>
            )}

            <input style={{...S.input,marginBottom:8}} placeholder="Detection name..." value={nameB} onChange={e=>setNameB(e.target.value)}/>
            <textarea style={{...S.textarea,minHeight:80,fontSize:11,fontFamily:"monospace"}} placeholder="Paste detection query (optional)..." value={queryB} onChange={e=>setQueryB(e.target.value)}/>
            {detections.length>0&&(
              <div style={{marginTop:8}}>
                <select style={{...S.input,fontSize:11}} onChange={e=>{const d=detections.find(x=>x.id===e.target.value);if(d)loadDet("b",d);}}>
                  <option value="">Load from library...</option>
                  {detections.map(d=><option key={d.id} value={d.id}>{d.name}</option>)}
                </select>
              </div>
            )}
          </div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:16}}>
          <div>
            <label style={S.label}>Correlation Field</label>
            <select style={S.input} value={correlField} onChange={e=>setCorrelField(e.target.value)}>
              {["host","src_ip","user","dest_ip","process_id","session_id"].map(f=><option key={f} value={f}>{f}</option>)}
            </select>
          </div>
          <div>
            <label style={S.label}>Time Window (minutes)</label>
            <input style={S.input} type="number" min="1" max="1440" value={timeWindow} onChange={e=>setTimeWindow(e.target.value)} placeholder="15"/>
          </div>
          <div>
            <label style={S.label}>Primary Platform</label>
            <select style={S.input} value={platform} onChange={e=>setPlatform(e.target.value)}>
              {["Splunk","Elastic","Microsoft Sentinel","Google Chronicle"].map(p=><option key={p} value={p}>{p}</option>)}
            </select>
          </div>
        </div>
        <button style={{...S.btn("p"),padding:"10px 28px",fontSize:13,width:"100%"}} onClick={generate} disabled={loading}>{loading?<><Spinner/> Generating correlation rule...</>:"🔗 Generate Correlation Rule"}</button>
        {err&&<div style={{color:THEME.danger,fontSize:12,marginTop:10}}>{err}</div>}
      </div>
      {result&&(
        <div style={S.card}>
          <div style={{marginBottom:14,padding:"14px 16px",background:"rgba(255,61,85,0.05)",border:"1px solid rgba(255,61,85,0.3)",borderRadius:8}}>
            <div style={{fontSize:14,fontWeight:700,color:THEME.text,marginBottom:4}}>{result.correlation_name}</div>
            <div style={{fontSize:12,color:THEME.textMid,marginBottom:8}}>{result.attack_narrative}</div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <span style={S.badge(THEME.danger)}>Risk: {result.risk_score}</span>
              <span style={S.badge(THEME.danger)}>{result.severity}</span>
              {(result.mitre_techniques||[]).map((t,i)=><span key={i} style={S.badge(THEME.warning)}>{t}</span>)}
            </div>
          </div>
          <div style={{padding:"10px 14px",background:"rgba(0,212,255,0.04)",border:"1px solid "+THEME.borderBright,borderRadius:8,marginBottom:14}}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.1em",marginBottom:4}}>RECOMMENDED RESPONSE</div>
            <div style={{fontSize:12,color:THEME.textMid}}>{result.recommended_response}</div>
          </div>
          <div style={{display:"flex",gap:6,marginBottom:12}}>
            {outTabs.map(t=><button key={t.id} onClick={()=>setActiveOut(t.id)} style={{padding:"6px 14px",borderRadius:6,border:"1px solid "+(activeOut===t.id?THEME.accentDim+"88":"transparent"),background:activeOut===t.id?"rgba(0,212,255,0.08)":"transparent",color:activeOut===t.id?THEME.accent:THEME.textDim,cursor:"pointer",fontFamily:"inherit",fontSize:11,fontWeight:activeOut===t.id?700:400}}>{t.label}</button>)}
          </div>
          {outTabs.map(t=>activeOut===t.id&&(
            <div key={t.id}>
              <div style={{display:"flex",justifyContent:"flex-end",marginBottom:6}}><CopyBtn text={result[t.key]||""}/></div>
              <div style={{...S.code,whiteSpace:"pre-wrap"}}>{result[t.key]||"Not generated for this platform."}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Log Replay ────────────────────────────────────────────────────────────────
function LogReplay({detections=[]}){
  const[query,setQuery]=useState("");
  const[queryType,setQueryType]=useState("SPL");
  const[logs,setLogs]=useState("");
  const[loading,setLoading]=useState(false);
  const[result,setResult]=useState(null);
  const[err,setErr]=useState("");
  const[loadedFrom,setLoadedFrom]=useState("");
  const PLATFORMS=[{id:"SPL",label:"Splunk SPL"},{id:"KQL",label:"Elastic KQL"},{id:"KQL_SENTINEL",label:"Sentinel KQL"},{id:"EQL",label:"Elastic EQL"},{id:"YARA-L",label:"Chronicle YARA-L"}];
  function loadFromLibrary(id){
    const det=detections.find(d=>d.id===id); if(!det)return;
    setQuery(det.query||""); setQueryType(det.queryType||"SPL"); setLoadedFrom(det.name); setResult(null);
  }
  async function runReplay(){
    if(!query.trim()||!logs.trim()){setErr("Paste both a query and log lines first.");return;}
    setLoading(true);setErr("");setResult(null);
    try{
      const res=await fetch("/api/detection/replay",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query,queryType,logs})});
      const data=await res.json(); if(data.error)throw new Error(data.error); setResult(data);
    }catch(e){setErr(e.message);}
    setLoading(false);
  }
  function handleFile(e){
    const file=e.target.files[0]; if(!file)return;
    const reader=new FileReader();
    reader.onload=ev=>setLogs(ev.target.result);
    reader.readAsText(file);
  }
  return(
    <div>
      <SectionHeader icon="🎮" title="Log Replay" color={THEME.purple}>
        <span style={S.badge(THEME.purple)}>Dry Run</span>
        <span style={{fontSize:11,color:THEME.textDim}}>Test your detection against real log lines before deploying</span>
      </SectionHeader>
      <HelpBox title="How Log Replay Works" color={THEME.purple} items={[
        {icon:"🎮",title:"What it does",desc:"AI reads your detection query and evaluates each log line to decide if it would match — simulating what your SIEM would do in production, without needing to actually run the query."},
        {icon:"📁",title:"How to use it",desc:"Paste your detection query on the left, then paste or upload real log lines on the right (up to 200 lines). Click Run Replay to get matched/unmatched results with explanations."},
        {icon:"🔧",title:"Tuning suggestions",desc:"The AI also flags which parts of your query are over-broad or too restrictive and suggests specific tuning steps to reduce false positives before you deploy."},
        {icon:"💡",title:"Pro tip",desc:"Use the 'Load from library' dropdown above to auto-fill any saved detection, so you don't need to copy-paste the query manually."},
      ]}/>
      {detections.length===0&&!query&&(
        <div style={{padding:"32px 24px",textAlign:"center",border:"1px dashed "+THEME.border,borderRadius:10,marginBottom:16}}>
          <div style={{fontSize:36,marginBottom:10}}>🎮</div>
          <div style={{fontSize:14,fontWeight:600,color:THEME.text,marginBottom:6}}>No detections in your library yet</div>
          <div style={{fontSize:12,color:THEME.textDim,marginBottom:14,lineHeight:1.7}}>Build a detection first, then come back here to dry-run it against real log lines before deploying to your SIEM.</div>
        </div>
      )}
      {detections.length>0&&(
        <div style={{...S.card,padding:"12px 16px",marginBottom:10,display:"flex",alignItems:"center",gap:10,background:"rgba(139,92,246,0.04)"}}>
          <span style={{fontSize:11,color:THEME.textDim,flexShrink:0}}>Load from library:</span>
          <select style={{...S.input,flex:1,fontSize:11,padding:"6px 10px"}} onChange={e=>loadFromLibrary(e.target.value)} value="">
            <option value="">Select a detection to auto-fill query...</option>
            {detections.map(d=><option key={d.id} value={d.id}>{d.name} ({d.queryType})</option>)}
          </select>
          {loadedFrom&&<span style={{...S.badge(THEME.purple),flexShrink:0,fontSize:10}}>Loaded: {loadedFrom}</span>}
        </div>
      )}
      <div style={S.card}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
          <div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
              <label style={S.label}>Detection Query</label>
              <select style={{...S.input,width:"auto",padding:"4px 8px",fontSize:11}} value={queryType} onChange={e=>setQueryType(e.target.value)}>
                {PLATFORMS.map(p=><option key={p.id} value={p.id}>{p.label}</option>)}
              </select>
            </div>
            <textarea style={{...S.textarea,minHeight:180,fontFamily:"monospace",fontSize:12}} placeholder="Paste your SPL/KQL/EQL detection query here..." value={query} onChange={e=>setQuery(e.target.value)}/>
          </div>
          <div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
              <label style={S.label}>Log Lines (paste or upload)</label>
              <label style={{...S.btn(),padding:"4px 10px",fontSize:11,cursor:"pointer"}}>
                📁 Upload
                <input type="file" accept=".log,.txt,.json,.csv" style={{display:"none"}} onChange={handleFile}/>
              </label>
            </div>
            <textarea style={{...S.textarea,minHeight:180,fontFamily:"monospace",fontSize:11}} placeholder={"Paste log lines here (up to 200 lines)\n\nExample:\n2024-01-15 10:23:44 host=web01 user=jdoe process=cmd.exe CommandLine=powershell.exe -enc abc123\n2024-01-15 10:23:45 host=web01 user=admin process=explorer.exe CommandLine=explorer.exe"} value={logs} onChange={e=>setLogs(e.target.value)}/>
          </div>
        </div>
        <button style={{...S.btn("p"),padding:"10px 28px",fontSize:13,width:"100%"}} onClick={runReplay} disabled={loading}>{loading?<><Spinner/> AI is evaluating log lines against query...</>:"🎮 Run Replay"}</button>
        {err&&<div style={{color:THEME.danger,fontSize:12,marginTop:10}}>{err}</div>}
      </div>
      {result&&(
        <div style={S.card}>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10,marginBottom:16}}>
            {[{label:"TOTAL LINES",val:result.total_lines,color:THEME.textMid},{label:"MATCHED",val:result.match_count,color:THEME.success},{label:"NOT MATCHED",val:result.unmatched_lines?.length||0,color:THEME.textDim}].map(({label,val,color})=>(
              <div key={label} style={{padding:"14px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:8,textAlign:"center"}}>
                <div style={{fontSize:28,fontWeight:800,color}}>{val}</div>
                <div style={{fontSize:10,color:THEME.textDim,letterSpacing:"0.1em",marginTop:2}}>{label}</div>
              </div>
            ))}
          </div>
          <div style={{marginBottom:12,padding:"10px 14px",background:"rgba(0,212,255,0.04)",border:"1px solid "+THEME.borderBright,borderRadius:8}}>
            <div style={{fontSize:11,color:THEME.textMid,marginBottom:4}}>{result.query_analysis}</div>
            <div style={{fontSize:11,color:THEME.warning}}>{result.tuning_suggestion}</div>
          </div>
          {result.matched_lines?.length>0&&(
            <div style={{marginBottom:14}}>
              <div style={{fontSize:10,fontWeight:800,color:THEME.success,letterSpacing:"0.12em",marginBottom:8}}>✅ MATCHED LINES ({result.matched_lines.length})</div>
              {result.matched_lines.map((line,i)=>(
                <div key={i} style={{padding:"8px 12px",background:"rgba(0,232,122,0.05)",border:"1px solid rgba(0,232,122,0.2)",borderRadius:6,marginBottom:6,fontFamily:"monospace",fontSize:11,color:THEME.text}}>
                  {result.match_explanations?.[String(result.match_indices?.[i])]&&<div style={{fontSize:10,color:THEME.success,marginBottom:4}}>{result.match_explanations[String(result.match_indices[i])]}</div>}
                  {line}
                </div>
              ))}
            </div>
          )}
          {result.unmatched_lines?.length>0&&(
            <div>
              <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.12em",marginBottom:8}}>✗ NOT MATCHED ({result.unmatched_lines.length})</div>
              <div style={{maxHeight:200,overflowY:"auto"}}>
                {result.unmatched_lines.map((line,i)=>(
                  <div key={i} style={{padding:"6px 12px",background:"rgba(255,255,255,0.01)",border:"1px solid "+THEME.border,borderRadius:6,marginBottom:4,fontFamily:"monospace",fontSize:11,color:THEME.textDim}}>{line}</div>
                ))}
              </div>
              {result.non_match_reasons&&<div style={{marginTop:8,fontSize:11,color:THEME.textDim}}>{result.non_match_reasons}</div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Defend Page (Honeytoken + DNS Sinkhole) ───────────────────────────────────
function DefendPage({detections=[]}){
  const[subTab,setSubTab]=useState("honey");
  const[threat,setThreat]=useState(""); const[tactic,setTactic]=useState(""); const[detName,setDetName]=useState(""); const[queryType,setQueryType]=useState("SPL");
  const[loadedDetection,setLoadedDetection]=useState(null);

  function loadDetection(id){
    const det=detections.find(d=>d.id===id); if(!det)return;
    setDetName(det.name||"");
    setTactic(det.tactic||"");
    setThreat(det.threat||det.ads?.attack_overview?.slice(0,200)||"");
    setQueryType(det.queryType||"SPL");
    setLoadedDetection(det);
  }
  const[honeytokenData,setHoneytokenData]=useState(null); const[honeytokenLoading,setHoneytokenLoading]=useState(false); const[honeytokenErr,setHoneytokenErr]=useState("");
  const[sinkholeData,setSinkholeData]=useState(null); const[sinkholeLoading,setSinkholeLoading]=useState(false); const[sinkholeErr,setSinkholeErr]=useState("");

  async function runHoneytoken(){
    if(!detName&&!tactic){setHoneytokenErr("Enter at least a detection name or tactic.");return;}
    setHoneytokenLoading(true);setHoneytokenErr("");setHoneytokenData(null);
    try{
      const res=await fetch("/api/detection/honeytoken",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:detName||tactic,queryType,tactic,threat})});
      const data=await res.json(); if(data.error)throw new Error(data.error); setHoneytokenData(data);
    }catch(e){setHoneytokenErr(e.message);}
    setHoneytokenLoading(false);
  }
  async function runSinkhole(){
    if(!detName&&!threat){setSinkholeErr("Enter detection name or threat context.");return;}
    setSinkholeLoading(true);setSinkholeErr("");setSinkholeData(null);
    try{
      const res=await fetch("/api/detection/dns-sinkhole",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:detName||threat,tactic,threat})});
      const data=await res.json(); if(data.error)throw new Error(data.error); setSinkholeData(data);
    }catch(e){setSinkholeErr(e.message);}
    setSinkholeLoading(false);
  }

  const HONEY_COLOR="#f59e0b"; const SINK_COLOR="#06b6d4";
  const str=v=>Array.isArray(v)?v.join("\n"):v&&typeof v==="object"?JSON.stringify(v):String(v||"");

  return(
    <div>
      <SectionHeader icon="🛡" title="Defend" color={THEME.purple}>
        <span style={S.badge(THEME.purple)}>Zero-FP Traps</span>
      </SectionHeader>
      <HelpBox title="How the Defend tools work" color={THEME.purple} items={[
        {icon:"🍯",title:"Honeytokens & Canaries",desc:"Fake credentials, files, AWS keys, and AD accounts that look real. Any access to them = 100% confidence alert with zero false positives. No tuning, no investigation — just instant attacker confirmation."},
        {icon:"🕳",title:"DNS Sinkhole",desc:"Block C2 domains before malware calls home. DetectIQ generates Pi-hole blocklists, BIND9 RPZ zones, Windows DNS policies, and Unbound configs based on your threat context."},
        {icon:"🔗",title:"Auto-fill from library",desc:"Use the 'Auto-fill' dropdown to load threat context from any saved detection. The tool will tailor the honeytoken or sinkhole config to match that specific threat scenario."},
        {icon:"📋",title:"Deployment",desc:"Each generated config includes copy-paste deployment commands for your specific platform, plus a companion SIEM detection query to alert when the trap is triggered."},
      ]}/>

      {/* Hero cards */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:20}}>
        {[
          {id:"honey",icon:"🍯",title:"Honeytokens & Canaries",color:HONEY_COLOR,bg:"rgba(245,158,11,0.06)",border:"rgba(245,158,11,0.25)",desc:"Plant fake credentials, canary files, and DNS tokens across your environment. Any access = 100% confidence alert with zero false positives.",pills:["Fake AD accounts","Canary files","AWS key tokens","DNS canaries","Honey shares"]},
          {id:"sinkhole",icon:"🕳",title:"DNS Sinkhole",color:SINK_COLOR,bg:"rgba(6,182,212,0.06)",border:"rgba(6,182,212,0.25)",desc:"Block and detect C2 domains before the malware calls home. Generate Pi-hole, BIND9 RPZ, Windows DNS, and Unbound configs in one click.",pills:["Pi-hole blocklist","BIND9 RPZ zone","Windows DNS","Unbound config","SIEM detection"]},
        ].map(card=>(
          <div key={card.id} onClick={()=>setSubTab(card.id)} style={{padding:"20px 22px",background:subTab===card.id?card.bg:"rgba(255,255,255,0.02)",border:"1px solid "+(subTab===card.id?card.border:THEME.border),borderRadius:10,cursor:"pointer",transition:"all 0.15s"}}
            onMouseEnter={e=>{e.currentTarget.style.background=card.bg;e.currentTarget.style.borderColor=card.border;}}
            onMouseLeave={e=>{if(subTab!==card.id){e.currentTarget.style.background="rgba(255,255,255,0.02)";e.currentTarget.style.borderColor=THEME.border;}}}>
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:10}}>
              <div style={{width:36,height:36,borderRadius:8,background:card.bg,border:"1px solid "+card.border,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18}}>{card.icon}</div>
              <div style={{fontSize:13,fontWeight:700,color:subTab===card.id?card.color:THEME.text}}>{card.title}</div>
              {subTab===card.id&&<span style={{...S.badge(card.color),marginLeft:"auto",fontSize:9}}>SELECTED</span>}
            </div>
            <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6,marginBottom:12}}>{card.desc}</div>
            <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>{card.pills.map((p,i)=><span key={i} style={{fontSize:9,padding:"2px 8px",borderRadius:4,background:subTab===card.id?card.bg:"rgba(255,255,255,0.04)",border:"1px solid "+(subTab===card.id?card.border:THEME.border),color:subTab===card.id?card.color:THEME.textDim}}>{p}</span>)}</div>
          </div>
        ))}
      </div>

      {/* Context inputs */}
      <div style={{...S.card,marginBottom:16,background:"rgba(255,255,255,0.015)"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
          <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em"}}>THREAT CONTEXT</div>
          {detections.length>0&&(
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <span style={{fontSize:10,color:THEME.textDim}}>Auto-fill from library:</span>
              <select style={{...S.input,width:"auto",padding:"5px 10px",fontSize:11,minWidth:220}} onChange={e=>loadDetection(e.target.value)} defaultValue="">
                <option value="">Select a detection...</option>
                {detections.map(d=><option key={d.id} value={d.id}>{d.name} ({d.queryType})</option>)}
              </select>
            </div>
          )}
        </div>
        {loadedDetection&&(
          <div style={{display:"flex",alignItems:"center",gap:8,padding:"8px 12px",background:"rgba(79,142,247,0.07)",border:"1px solid "+THEME.accentDim+"44",borderRadius:7,marginBottom:12}}>
            <span style={{fontSize:13}}>🔗</span>
            <span style={{fontSize:11,color:THEME.accent,fontWeight:600}}>Context loaded from:</span>
            <span style={{fontSize:11,color:THEME.text}}>{loadedDetection.name}</span>
            <span style={{...S.badge(THEME.accent),fontSize:9}}>{loadedDetection.queryType}</span>
            {loadedDetection.tactic&&<span style={{...S.badge(THEME.purple),fontSize:9}}>{loadedDetection.tactic}</span>}
            <button style={{marginLeft:"auto",fontSize:10,color:THEME.textDim,background:"none",border:"none",cursor:"pointer"}} onClick={()=>{setLoadedDetection(null);setDetName("");setTactic("");setThreat("");setQueryType("SPL");}}>✕ Clear</button>
          </div>
        )}
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginBottom:10}}>
          <div><label style={S.label}>Detection / Threat Name</label><input style={S.input} value={detName} onChange={e=>setDetName(e.target.value)} placeholder="e.g. Lateral Movement via WMI"/></div>
          <div><label style={S.label}>MITRE Tactic</label><input style={S.input} value={tactic} onChange={e=>setTactic(e.target.value)} placeholder="e.g. Lateral Movement"/></div>
          <div><label style={S.label}>Query Type</label>
            <select style={S.input} value={queryType} onChange={e=>setQueryType(e.target.value)}>
              {["SPL","KQL","EQL","YARA-L","KQL_SENTINEL"].map(q=><option key={q} value={q}>{q}</option>)}
            </select>
          </div>
        </div>
        <div><label style={S.label}>Threat Description (optional — helps generate more specific configs)</label><input style={S.input} value={threat} onChange={e=>setThreat(e.target.value)} placeholder="e.g. Attacker using DNS C2 to exfiltrate data from compromised hosts..."/></div>
      </div>

      {/* Generate button */}
      {subTab==="honey"&&(
        <div>
          <button style={{...S.btn("p"),padding:"11px 28px",fontSize:13,marginBottom:16,background:"rgba(245,158,11,0.12)",borderColor:"rgba(245,158,11,0.4)",color:HONEY_COLOR}} onClick={runHoneytoken} disabled={honeytokenLoading}>
            {honeytokenLoading?<><Spinner/> Designing honeytoken traps...</>:"🍯 Generate Honeytokens & Canaries"}
          </button>
          {honeytokenErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8,marginBottom:14}}>{honeytokenErr}</div>}
          {!honeytokenData&&!honeytokenLoading&&!honeytokenErr&&(
            <div style={{padding:"48px 24px",textAlign:"center",border:"1px dashed "+THEME.border,borderRadius:10}}>
              <div style={{fontSize:40,marginBottom:12}}>🍯</div>
              <div style={{fontSize:14,fontWeight:600,color:THEME.text,marginBottom:8}}>Plant traps. Catch attackers in the act.</div>
              <div style={{fontSize:12,color:THEME.textDim,maxWidth:500,margin:"0 auto",lineHeight:1.7}}>Honeytokens are fake assets that look real to attackers. Any interaction triggers a 100%-confidence alert — no tuning, no FP investigation needed.</div>
              <div style={{display:"flex",justifyContent:"center",gap:20,marginTop:20}}>
                {["Fake AD Account","Canary S3 Bucket","DNS Token","Honey File","Fake API Key"].map((t,i)=>(
                  <div key={i} style={{padding:"8px 14px",background:"rgba(245,158,11,0.06)",border:"1px solid rgba(245,158,11,0.2)",borderRadius:8,fontSize:11,color:HONEY_COLOR}}>{t}</div>
                ))}
              </div>
            </div>
          )}
          {honeytokenData&&(
            <div>
              <div style={{marginBottom:16,padding:"14px 18px",background:"rgba(245,158,11,0.06)",border:"1px solid rgba(245,158,11,0.25)",borderRadius:10,display:"flex",gap:12,alignItems:"flex-start"}}>
                <div style={{fontSize:28}}>🍯</div>
                <div>
                  <div style={{fontSize:13,fontWeight:700,color:HONEY_COLOR,marginBottom:4}}>{str(honeytokenData.coverage_benefit)}</div>
                  <div style={{fontSize:11,color:THEME.textDim}}>Use managed canary tokens at <a href="https://canarytokens.org/generate" target="_blank" rel="noopener noreferrer" style={{color:THEME.accent}}>canarytokens.org ↗</a> for DNS/HTTP/AWS tokens without infrastructure</div>
                </div>
              </div>
              <div style={{display:"grid",gap:12}}>
                {(Array.isArray(honeytokenData.tokens)?honeytokenData.tokens:[]).map((t,i)=>(
                  <div key={i} style={{border:"1px solid "+THEME.border,borderRadius:10,overflow:"hidden"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"12px 16px",background:"rgba(245,158,11,0.04)",borderBottom:"1px solid "+THEME.border}}>
                      <div style={{display:"flex",alignItems:"center",gap:10}}>
                        <div style={{width:32,height:32,borderRadius:6,background:"rgba(245,158,11,0.12)",border:"1px solid rgba(245,158,11,0.3)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14}}>🍯</div>
                        <div>
                          <div style={{fontSize:13,fontWeight:700,color:THEME.text}}>{str(t.type||t.name)}</div>
                          <div style={{fontSize:10,color:THEME.textDim}}>{str(t.platform)}</div>
                        </div>
                      </div>
                      <div style={{display:"flex",gap:6,alignItems:"center"}}>
                        <span style={{padding:"3px 10px",borderRadius:4,background:"rgba(0,232,122,0.1)",border:"1px solid rgba(0,232,122,0.3)",fontSize:10,color:THEME.success,fontWeight:700}}>✓ {str(t.alert_confidence||"100%")}</span>
                        <span style={S.badge(THEME.success)}>Zero FP</span>
                      </div>
                    </div>
                    <div style={{padding:"14px 16px"}}>
                      <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>{str(t.description)}</div>
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                        <div>
                          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                            <span style={{fontSize:10,fontWeight:800,color:THEME.warning,letterSpacing:"0.1em"}}>DEPLOY COMMAND</span>
                            <CopyBtn text={str(t.deployment_cmd||t.deploy_command||"")}/>
                          </div>
                          <div style={{...S.code,fontSize:10,padding:"8px 10px",whiteSpace:"pre-wrap"}}>{str(t.deployment_cmd||t.deploy_command)}</div>
                        </div>
                        <div>
                          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                            <span style={{fontSize:10,fontWeight:800,color:THEME.accent,letterSpacing:"0.1em"}}>DETECTION QUERY</span>
                            <CopyBtn text={str(t.detection_query||t.siem_query||"")}/>
                          </div>
                          <div style={{...S.code,fontSize:10,padding:"8px 10px",whiteSpace:"pre-wrap"}}>{str(t.detection_query||t.siem_query)}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              {honeytokenData.deployment_guide&&(
                <div style={{marginTop:12,padding:"14px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:10}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:8}}>DEPLOYMENT GUIDE</div>
                  <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.8}}>{str(honeytokenData.deployment_guide)}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {subTab==="sinkhole"&&(
        <div>
          <button style={{...S.btn("p"),padding:"11px 28px",fontSize:13,marginBottom:16,background:"rgba(6,182,212,0.1)",borderColor:"rgba(6,182,212,0.4)",color:SINK_COLOR}} onClick={runSinkhole} disabled={sinkholeLoading}>
            {sinkholeLoading?<><Spinner/> Generating sinkhole configs...</>:"🕳 Generate DNS Sinkhole Configs"}
          </button>
          {sinkholeErr&&<div style={{color:THEME.danger,fontSize:13,padding:12,background:"rgba(255,61,85,0.06)",borderRadius:8,marginBottom:14}}>{sinkholeErr}</div>}
          {!sinkholeData&&!sinkholeLoading&&!sinkholeErr&&(
            <div style={{padding:"48px 24px",textAlign:"center",border:"1px dashed "+THEME.border,borderRadius:10}}>
              <div style={{fontSize:40,marginBottom:12}}>🕳</div>
              <div style={{fontSize:14,fontWeight:600,color:THEME.text,marginBottom:8}}>Block C2 domains. Detect the attempt.</div>
              <div style={{fontSize:12,color:THEME.textDim,maxWidth:500,margin:"0 auto",lineHeight:1.7}}>DNS sinkholes redirect malicious domain lookups to a controlled IP. The malware can't phone home — and the DNS query becomes your alert.</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8,marginTop:20,maxWidth:600,margin:"20px auto 0"}}>
                {[{icon:"🐛",label:"Malware calls home"},{icon:"→",label:""},{icon:"🕳",label:"DNS Sinkhole intercepts"},{icon:"→",label:""},{icon:"🚨",label:"Alert fires in SIEM"}].map((s,i)=>(
                  <div key={i} style={{textAlign:"center"}}>
                    <div style={{fontSize:20,marginBottom:4}}>{s.icon}</div>
                    <div style={{fontSize:9,color:THEME.textDim}}>{s.label}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {sinkholeData&&(
            <div>
              <div style={{marginBottom:16,padding:"14px 18px",background:"rgba(6,182,212,0.06)",border:"1px solid rgba(6,182,212,0.25)",borderRadius:10}}>
                <div style={{fontSize:10,fontWeight:800,color:SINK_COLOR,letterSpacing:"0.12em",marginBottom:8}}>DOMAINS TO SINKHOLE — {(Array.isArray(sinkholeData.inferred_domains)?sinkholeData.inferred_domains:[]).length} identified</div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>{(Array.isArray(sinkholeData.inferred_domains)?sinkholeData.inferred_domains:[]).map((d,i)=><span key={i} style={{fontFamily:"monospace",fontSize:11,padding:"3px 10px",borderRadius:4,background:"rgba(255,61,85,0.1)",border:"1px solid rgba(255,61,85,0.3)",color:THEME.danger}}>{str(d)}</span>)}</div>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
                {[{label:"Pi-hole Blocklist",key:"pihole_blocklist",color:"#82c341",icon:"🍓"},{label:"BIND9 RPZ Zone",key:"bind9_rpz",color:THEME.warning,icon:"📋"},{label:"Windows DNS (PowerShell)",key:"windows_dns_rpz",color:THEME.accent,icon:"🖥"},{label:"Unbound Config",key:"unbound_conf",color:THEME.purple,icon:"🔒"}].map(({label,key,color,icon})=>(
                  <div key={key} style={{border:"1px solid "+THEME.border,borderRadius:8,overflow:"hidden"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 12px",background:"rgba(255,255,255,0.02)",borderBottom:"1px solid "+THEME.border}}>
                      <span style={{fontSize:11,fontWeight:700,color}}>{icon} {label}</span>
                      <CopyBtn text={str(sinkholeData[key])}/>
                    </div>
                    <div style={{...S.code,fontSize:10,padding:"8px 12px",whiteSpace:"pre-wrap",maxHeight:120,overflow:"auto"}}>{str(sinkholeData[key])||"Not generated."}</div>
                  </div>
                ))}
              </div>
              <div style={{border:"1px solid rgba(255,61,85,0.3)",borderRadius:8,overflow:"hidden",marginBottom:12}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 12px",background:"rgba(255,61,85,0.05)",borderBottom:"1px solid rgba(255,61,85,0.2)"}}>
                  <span style={{fontSize:11,fontWeight:700,color:THEME.danger}}>🚨 Sinkhole Hit Detection Query</span>
                  <CopyBtn text={str(sinkholeData.sinkhole_detection_query||sinkholeData.detection_query)}/>
                </div>
                <div style={{...S.code,fontSize:11,padding:"10px 14px",whiteSpace:"pre-wrap"}}>{str(sinkholeData.sinkhole_detection_query||sinkholeData.detection_query)||"Not generated."}</div>
              </div>
              {sinkholeData.deployment_steps&&(
                <div style={{padding:"14px 16px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:10}}>
                  <div style={{fontSize:10,fontWeight:800,color:THEME.textDim,letterSpacing:"0.1em",marginBottom:10}}>DEPLOYMENT STEPS</div>
                  <div style={{display:"grid",gap:8}}>
                    {(Array.isArray(sinkholeData.deployment_steps)?sinkholeData.deployment_steps:[]).map((s,i)=>(
                      <div key={i} style={{display:"flex",gap:10,alignItems:"flex-start"}}>
                        <div style={{width:20,height:20,borderRadius:"50%",background:"rgba(6,182,212,0.1)",border:"1px solid rgba(6,182,212,0.3)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:SINK_COLOR,flexShrink:0}}>{i+1}</div>
                        <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.5,paddingTop:2}}>{str(s)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function GitHubExport({detections}){
  const[token,setToken]=useState(LS.get("gh_token",""));const[repo,setRepo]=useState(LS.get("gh_repo",""));const[branch,setBranch]=useState(LS.get("gh_branch","main"));const[path,setPath]=useState(LS.get("gh_path","detections/"));const[status,setStatus]=useState("");const[loading,setLoading]=useState(false);const[selected,setSelected]=useState([]);
  function toggleSelect(id){setSelected(p=>p.includes(id)?p.filter(x=>x!==id):[...p,id]);}
  async function pushToGitHub(){if(!token||!repo){setStatus("error:Enter token and repo.");return;}const toExport=detections.filter(d=>selected.includes(d.id));if(!toExport.length){setStatus("error:Select at least one detection.");return;}setLoading(true);setStatus("");LS.set("gh_token",token);LS.set("gh_repo",repo);let success=0,failed=0;for(const det of toExport){try{const filename=path+det.name.replace(/\s+/g,"_").toLowerCase()+"."+det.queryType.toLowerCase();const content=btoa(unescape(encodeURIComponent("# "+det.name+"\n# Tactic: "+det.tactic+"\n# Severity: "+det.severity+"\n\n"+det.query)));const checkRes=await fetch("https://api.github.com/repos/"+repo+"/contents/"+filename,{headers:{"Authorization":"token "+token,"Accept":"application/vnd.github.v3+json"}});let sha;if(checkRes.ok){const ex=await checkRes.json();sha=ex.sha;}const body={message:"Add: "+det.name,content,branch};if(sha)body.sha=sha;const res=await fetch("https://api.github.com/repos/"+repo+"/contents/"+filename,{method:"PUT",headers:{"Authorization":"token "+token,"Content-Type":"application/json","Accept":"application/vnd.github.v3+json"},body:JSON.stringify(body)});if(res.ok)success++;else failed++;}catch{failed++;}}setStatus((failed===0?"success":"error")+":Exported "+success+(failed>0?", "+failed+" failed":"")+" to "+repo);setLoading(false);}
  const[statusType,statusMsg]=status.split(":");
  return(
    <div>
      <SectionHeader icon="🐙" title="GitHub Export" color={THEME.textMid}/>
      <div style={S.card}>
        <div style={S.grid2}>
          <div><label style={S.label}>Personal Access Token</label><input style={{...S.input,marginBottom:12,fontFamily:"monospace"}} type="password" value={token} onChange={e=>setToken(e.target.value)} placeholder="ghp_xxxx"/><label style={S.label}>Repository</label><input style={{...S.input,marginBottom:12}} value={repo} onChange={e=>setRepo(e.target.value)} placeholder="yourname/detection-rules"/><div style={S.grid2}><div><label style={S.label}>Branch</label><input style={S.input} value={branch} onChange={e=>setBranch(e.target.value)} placeholder="main"/></div><div><label style={S.label}>Path</label><input style={S.input} value={path} onChange={e=>setPath(e.target.value)} placeholder="detections/"/></div></div></div>
          <div><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}><label style={S.label}>Select ({selected.length}/{detections.length})</label><button style={{...S.btn(),padding:"4px 10px",fontSize:11}} onClick={()=>setSelected(detections.map(d=>d.id))}>All</button></div><div style={{maxHeight:200,overflowY:"auto",border:"1px solid "+THEME.border,borderRadius:8,padding:8}}>{!detections.length&&<div style={{color:THEME.textDim,fontSize:12,textAlign:"center",padding:16}}>No detections yet.</div>}{detections.map(d=>(<div key={d.id} style={{display:"flex",alignItems:"center",gap:8,padding:"7px 4px",borderBottom:"1px solid "+THEME.border,cursor:"pointer"}} onClick={()=>toggleSelect(d.id)}><div style={{width:15,height:15,borderRadius:4,border:"1px solid "+(selected.includes(d.id)?THEME.accent:THEME.border),background:selected.includes(d.id)?THEME.accentGlow:"transparent",flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,color:THEME.accent}}>{selected.includes(d.id)?"v":""}</div><div style={{flex:1}}><div style={{fontSize:12,fontWeight:600}}>{d.name}</div><div style={{fontSize:10,color:THEME.textDim}}>{d.queryType} · {d.tactic}</div></div></div>))}</div></div>
        </div>
        <div style={{marginTop:16}}><button style={{...S.btn("p"),padding:"10px 22px"}} onClick={pushToGitHub} disabled={loading||!selected.length}>{loading&&<Spinner/>}{loading?"Pushing...":"Push to GitHub"}</button></div>
        {status&&<StatusBar msg={statusMsg} type={statusType}/>}
      </div>
    </div>
  );
}

function TeamWorkspace({detections, user}){
  // ── Team members — Supabase-first, localStorage fallback ─────────────────
  const storageKey = "detectiq_team_" + (user?.id || "demo");
  const [members, setMembers] = useState(() => LS.get(storageKey, []));
  const [membersLoading, setMembersLoading] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("Analyst");
  const [teamName, setTeamName] = useState(() => LS.get("detectiq_team_name", "Detection Team"));
  const [inviting, setInviting] = useState(false);
  const [inviteMsg, setInviteMsg] = useState("");
  const [editingMember, setEditingMember] = useState(null);
  // ── Comments ──────────────────────────────────────────────────────────────
  const [comments, setComments] = useState(LS.get("detectiq_comments", []));
  const [activity, setActivity] = useState(LS.get("detectiq_activity", []));
  const [newComment, setNewComment] = useState("");
  const [selectedDet, setSelectedDet] = useState("");
  const [author, setAuthor] = useState(LS.get("detectiq_author", user?.email?.split("@")[0] || "Analyst"));

  // Load team from Supabase on mount
  useEffect(() => {
    if (!user) return;
    setMembersLoading(true);
    supabase.from("team_members").select("*").eq("owner_user_id", user.id).neq("status","removed").order("invited_at", { ascending: true })
      .then(({ data, error }) => {
        if (!error && data) {
          if (data.length > 0) {
            const mapped = data.map(m => ({ id: m.id, name: m.member_name || m.member_email.split("@")[0], email: m.member_email, role: m.role, status: m.status, invitedAt: m.invited_at, joinedAt: m.joined_at }));
            const hasOwner = mapped.find(m => m.role === "Owner");
            const final = hasOwner ? mapped : [{ id: user.id, name: user.email?.split("@")[0] || "You", email: user.email || "", role: "Owner", status: "active", joinedAt: new Date().toISOString() }, ...mapped];
            setMembers(final); LS.set(storageKey, final);
          } else {
            const ownerRow = { owner_user_id: user.id, member_email: user.email || "", member_name: user.email?.split("@")[0] || "You", member_user_id: user.id, role: "Owner", status: "active", team_name: teamName };
            supabase.from("team_members").insert([ownerRow]).then(() => {});
            const ownerLocal = [{ id: user.id, name: ownerRow.member_name, email: ownerRow.member_email, role: "Owner", status: "active", joinedAt: new Date().toISOString() }];
            setMembers(ownerLocal); LS.set(storageKey, ownerLocal);
          }
        }
      }).catch(() => {}).finally(() => setMembersLoading(false));
  }, [user]);

  function syncMembers(updated) { setMembers(updated); LS.set(storageKey, updated); }

  async function sendInvite() {
    if (!inviteEmail.includes("@")) { setInviteMsg("error:Enter a valid email address."); return; }
    if (members.find(m => m.email === inviteEmail)) { setInviteMsg("error:This person is already on your team."); return; }
    setInviting(true); setInviteMsg("");
    try {
      const res = await fetch("/api/teams/invite", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inviterUserId: user?.id, inviterEmail: user?.email, inviteeEmail: inviteEmail, teamName })
      });
      const data = await res.json();
      if (data.success) {
        if (user) {
          await supabase.from("team_members").upsert([{ owner_user_id: user.id, member_email: inviteEmail, member_name: inviteEmail.split("@")[0], role: inviteRole, status: "pending", team_name: teamName, invite_token: data.token }], { onConflict: "owner_user_id,member_email" });
        }
        const newMember = { id: uid(), name: inviteEmail.split("@")[0], email: inviteEmail, role: inviteRole, status: "pending", invitedAt: new Date().toISOString(), token: data.token };
        syncMembers([...members, newMember]);
        const a = [{ id: uid(), text: "Invited " + inviteEmail + " as " + inviteRole, ts: new Date().toISOString() }, ...activity].slice(0, 20);
        setActivity(a); LS.set("detectiq_activity", a);
        setInviteMsg("success:Invite sent to " + inviteEmail);
        setInviteEmail("");
      } else { setInviteMsg("error:" + (data.error || "Invite failed.")); }
    } catch(e) { setInviteMsg("error:Request failed: " + e.message); }
    setInviting(false);
  }

  async function removeMember(id) {
    const m = members.find(x => x.id === id);
    if (!m || m.role === "Owner") return;
    if (user) { await supabase.from("team_members").update({ status: "removed" }).eq("owner_user_id", user.id).eq("member_email", m.email).catch(() => {}); }
    syncMembers(members.filter(x => x.id !== id));
    const a = [{ id: uid(), text: "Removed " + m.email + " from team", ts: new Date().toISOString() }, ...activity].slice(0, 20);
    setActivity(a); LS.set("detectiq_activity", a);
  }

  async function changeRole(id, role) {
    const m = members.find(x => x.id === id);
    if (m && user) { await supabase.from("team_members").update({ role }).eq("owner_user_id", user.id).eq("member_email", m.email).catch(() => {}); }
    syncMembers(members.map(x => x.id === id ? { ...x, role } : x));
    setEditingMember(null);
  }

  function postComment() {
    if (!newComment.trim()) return;
    const c = { id: uid(), author, text: newComment, detection: selectedDet, ts: new Date().toISOString() };
    const u = [c, ...comments].slice(0, 50); setComments(u); LS.set("detectiq_comments", u);
    const a = [{ id: uid(), text: author + " commented on " + (selectedDet || "General"), ts: new Date().toISOString() }, ...activity].slice(0, 20);
    setActivity(a); LS.set("detectiq_activity", a); setNewComment("");
  }

  const ROLES = ["Owner", "Admin", "Analyst", "Read-only"];
  const roleColor = r => r === "Owner" ? THEME.accent : r === "Admin" ? THEME.purple : r === "Analyst" ? THEME.success : THEME.textDim;
  const statusColor = s => s === "active" ? THEME.success : s === "pending" ? THEME.warning : THEME.textDim;
  const [invMsgType, invMsgText] = inviteMsg.split(/:(.+)/);

  return (
    <div>
      <SectionHeader icon="👥" title="Team Workspace" color={THEME.purple}>
        <div style={S.flex}>
          <span style={S.badge(THEME.purple)}>{members.filter(m=>m.status==="active").length} active · {members.filter(m=>m.status==="pending").length} pending</span>
        </div>
      </SectionHeader>
      <HelpBox title="Team Workspace Quick Reference" color={THEME.purple} items={[
        {icon:"👥",title:"Team roles",desc:"Admins can invite members and manage all detections. Editors can build and edit. Viewers can read and export but not save changes."},
        {icon:"📨",title:"Inviting members",desc:"Enter an email address and select a role, then click Invite. They'll receive an email with a link to join your team workspace."},
        {icon:"🔒",title:"Shared library",desc:"All team members share the same Detection Library. Changes are visible to everyone in real time — use the version history to track who changed what."},
        {icon:"💡",title:"Tip",desc:"Assign the Viewer role to stakeholders or auditors who need read-only access to your detection posture without making changes."},
      ]}/>

      <div style={S.grid2}>
        {/* ── Left column: roster + invite ── */}
        <div>
          {/* Team Members */}
          <div style={S.card}>
            <div style={{...S.row, marginBottom: 14}}>
              <div style={S.cardTitle}><span>👥</span> Team Members {membersLoading&&<Spinner/>}</div>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <input style={{...S.input,width:140,fontSize:12,padding:"4px 10px"}} value={teamName} onChange={e=>{setTeamName(e.target.value);LS.set("detectiq_team_name",e.target.value);}} placeholder="Team name..."/>
              </div>
            </div>
            {members.length === 0 && (
              <div style={{color:THEME.textDim,fontSize:13,textAlign:"center",padding:"30px 20px"}}>
                <div style={{fontSize:32,marginBottom:10}}>👤</div>
                Invite teammates to get started
              </div>
            )}
            {members.map(m => (
              <div key={m.id} style={{display:"flex",alignItems:"center",gap:10,padding:"12px 0",borderBottom:"1px solid "+THEME.border}}>
                {/* Avatar */}
                <div style={{width:36,height:36,borderRadius:"50%",background:"linear-gradient(135deg,"+roleColor(m.role)+"33,"+roleColor(m.role)+"11)",border:"1px solid "+roleColor(m.role)+"44",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:800,color:roleColor(m.role),flexShrink:0}}>
                  {(m.name||m.email||"?")[0].toUpperCase()}
                </div>
                {/* Info */}
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:13,fontWeight:700,color:THEME.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{m.name || m.email.split("@")[0]}</div>
                  <div style={{fontSize:11,color:THEME.textDim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{m.email}</div>
                </div>
                {/* Role + status */}
                <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:4,flexShrink:0}}>
                  {editingMember === m.id ? (
                    <select style={{...S.input,padding:"2px 8px",fontSize:11,width:100}} value={m.role} onChange={e=>changeRole(m.id,e.target.value)} onBlur={()=>setEditingMember(null)} autoFocus>
                      {ROLES.filter(r=>r!=="Owner").map(r=><option key={r}>{r}</option>)}
                    </select>
                  ) : (
                    <span onClick={()=>m.role!=="Owner"&&setEditingMember(m.id)} style={{...S.badge(roleColor(m.role)),cursor:m.role!=="Owner"?"pointer":"default",fontSize:10}}>{m.role}</span>
                  )}
                  <span style={{fontSize:10,color:statusColor(m.status),fontWeight:700,letterSpacing:"0.06em"}}>{m.status === "pending" ? "⏳ PENDING" : "● ACTIVE"}</span>
                </div>
                {/* Remove */}
                {m.role !== "Owner" && (
                  <button style={{...S.btn(),padding:"4px 8px",fontSize:11,color:THEME.danger,borderColor:THEME.danger+"44",flexShrink:0}} onClick={()=>removeMember(m.id)} title="Remove">✕</button>
                )}
              </div>
            ))}
          </div>

          {/* Invite */}
          <div style={S.card}>
            <div style={{...S.cardTitle,marginBottom:14}}><span>✉️</span> Invite Member</div>
            <label style={S.label}>Email Address</label>
            <input style={{...S.input,marginBottom:10}} type="email" value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)} onKeyDown={e=>e.key==="Enter"&&sendInvite()} placeholder="colleague@company.com"/>
            <label style={S.label}>Role</label>
            <select style={{...S.input,marginBottom:14}} value={inviteRole} onChange={e=>setInviteRole(e.target.value)}>
              {["Admin","Analyst","Read-only"].map(r=><option key={r}>{r}</option>)}
            </select>
            <button style={{...S.btn("p"),width:"100%",padding:"10px"}} onClick={sendInvite} disabled={inviting}>{inviting?<><Spinner/>Sending invite...</>:"Send Invite"}</button>
            {inviteMsg && <StatusBar msg={invMsgText||inviteMsg} type={invMsgType==="success"?"success":"error"}/>}
            <div style={{marginTop:12,padding:"10px 12px",background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.12)",borderRadius:8,fontSize:11,color:THEME.textDim,lineHeight:1.6}}>
              Invites are sent via email with a join link. The member will appear as <span style={{color:THEME.warning,fontWeight:700}}>PENDING</span> until they accept.
            </div>
          </div>
        </div>

        {/* ── Right column: activity, stats, comments ── */}
        <div>
          <div style={S.card}>
            <div style={{...S.cardTitle,marginBottom:12}}><span>📡</span> Activity Feed</div>
            <div style={{maxHeight:180,overflowY:"auto"}}>
              {activity.map(a=><div key={a.id} style={{padding:"8px 0",borderBottom:"1px solid "+THEME.border,fontSize:12,color:THEME.textMid,display:"flex",justifyContent:"space-between",gap:8}}>
                <span>{a.text}</span><span style={{color:THEME.textDim,flexShrink:0,fontSize:11}}>{new Date(a.ts).toLocaleTimeString()}</span>
              </div>)}
              {!activity.length && <div style={{color:THEME.textDim,fontSize:13,textAlign:"center",padding:16}}>No activity yet.</div>}
            </div>
          </div>

          <div style={S.card}>
            <div style={{...S.cardTitle,marginBottom:12}}><span>📊</span> Team Stats</div>
            <div style={S.grid2}>
              {[["Members",members.filter(m=>m.status==="active").length,THEME.accent],["Pending",members.filter(m=>m.status==="pending").length,THEME.warning],["Detections",detections.length,THEME.success],["Comments",comments.length,THEME.purple]].map(([label,val,color])=>(
                <div key={label} style={{textAlign:"center",padding:14,background:color+"08",borderRadius:10,border:"1px solid "+color+"20"}}>
                  <div style={{fontSize:26,fontWeight:900,color}}>{val}</div>
                  <div style={{fontSize:11,color:THEME.textMid,marginTop:4,fontWeight:700}}>{label}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={S.card}>
            <div style={{...S.cardTitle,marginBottom:12}}><span>💬</span> Team Comments</div>
            <label style={S.label}>Your Name</label>
            <input style={{...S.input,marginBottom:10}} value={author} onChange={e=>{setAuthor(e.target.value);LS.set("detectiq_author",e.target.value);}} placeholder="Your name..."/>
            <label style={S.label}>Related Detection</label>
            <select style={{...S.input,marginBottom:10}} value={selectedDet} onChange={e=>setSelectedDet(e.target.value)}>
              <option value="">General</option>
              {detections.map(d=><option key={d.id} value={d.name}>{d.name}</option>)}
            </select>
            <textarea style={{...S.textarea,minHeight:70}} value={newComment} onChange={e=>setNewComment(e.target.value)} placeholder="Share findings, notes, or updates..."/>
            <button style={{...S.btn("p"),marginTop:10,width:"100%"}} onClick={postComment}>Post Comment</button>
            <div style={{maxHeight:240,overflowY:"auto",marginTop:14}}>
              {comments.map(c=>(
                <div key={c.id} style={{padding:"12px 0",borderBottom:"1px solid "+THEME.border}}>
                  <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                    <span style={{fontSize:12,fontWeight:700,color:THEME.accent}}>{c.author}</span>
                    <span style={{fontSize:11,color:THEME.textDim}}>{new Date(c.ts).toLocaleString()}</span>
                  </div>
                  {c.detection && <div style={{fontSize:11,color:THEME.purple,marginBottom:4}}>re: {c.detection}</div>}
                  <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.6}}>{c.text}</div>
                </div>
              ))}
              {!comments.length && <div style={{color:THEME.textDim,fontSize:13,textAlign:"center",padding:16}}>No comments yet.</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function CommunityTab({ user, detections, onCloneDetection }) {
  const [feed, setFeed] = useState([]);
  const [feedLoading, setFeedLoading] = useState(false);
  const [feedErr, setFeedErr] = useState("");
  const [search, setSearch] = useState("");
  const [filterTactic, setFilterTactic] = useState("All");
  const [filterTool, setFilterTool] = useState("All");
  const [sort, setSort] = useState("stars");
  const [sharing, setSharing] = useState(null);
  const [shareMsg, setShareMsg] = useState({});
  const [cloning, setCloning] = useState(null);

  useEffect(() => { loadFeed(); }, [filterTactic, filterTool, sort]);

  async function loadFeed() {
    setFeedLoading(true); setFeedErr("");
    try {
      const params = new URLSearchParams({ sort, limit: 40 });
      if (filterTactic !== "All") params.set("tactic", filterTactic);
      if (filterTool !== "All") params.set("tool", filterTool);
      if (search) params.set("search", search);
      const res = await fetch("/api/community/list?" + params);
      const data = await res.json();
      setFeed(data.detections || []);
    } catch(e) { setFeedErr("Failed to load community feed."); }
    setFeedLoading(false);
  }

  async function shareDetection(det) {
    if (!user) { setShareMsg({[det.id]:"error:Sign in to share detections."}); return; }
    setSharing(det.id);
    try {
      const res = await fetch("/api/community/share", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ detection: det, userId: user.id, authorName: user.email?.split("@")[0] })
      });
      const data = await res.json();
      setShareMsg({[det.id]: data.success ? "success:Shared to community!" : "error:" + (data.error || "Share failed.")});
    } catch(e) { setShareMsg({[det.id]:"error:" + e.message}); }
    setSharing(null);
  }

  async function starDetection(id) {
    try {
      await fetch("/api/community/star", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
      setFeed(f => f.map(d => d.id === id ? { ...d, stars: (d.stars || 0) + 1 } : d));
    } catch {}
  }

  async function cloneDetection(communityDet) {
    if (!user) { alert("Sign in to clone detections."); return; }
    setCloning(communityDet.id);
    try {
      const res = await fetch("/api/community/clone", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: communityDet.id, userId: user.id })
      });
      const data = await res.json();
      if (data.success) { onCloneDetection && onCloneDetection(data.detection); alert("Cloned to your library!"); }
      else alert("Clone failed: " + data.error);
    } catch(e) { alert("Clone failed: " + e.message); }
    setCloning(null);
  }

  const toolObj = TOOLS.reduce((a, t) => { a[t.id] = t; return a; }, {});

  return (
    <div>
      <SectionHeader icon="🌍" title="Community Detections" color={THEME.accent}>
        <div style={S.flex}>
          <span style={S.badge(THEME.accent)}>{feed.length} rules</span>
          <span style={S.badge(THEME.success)}>Open Source</span>
        </div>
      </SectionHeader>

      {/* Your detections — share panel */}
      {user && detections.length > 0 && (
        <div style={S.card}>
          <div style={{...S.cardTitle,marginBottom:12}}><span>📤</span> Share Your Detections</div>
          <div style={{maxHeight:200,overflowY:"auto"}}>
            {detections.slice(0,10).map(det => {
              const msg = shareMsg[det.id] || "";
              const [mt, mm] = msg.split(/:(.+)/);
              return (
                <div key={det.id} style={{display:"flex",alignItems:"center",gap:10,padding:"9px 0",borderBottom:"1px solid "+THEME.border}}>
                  <span style={{...S.badge(THEME.accent),fontSize:10,flexShrink:0}}>{det.queryType||det.tool}</span>
                  <span style={{fontSize:12,fontWeight:700,color:THEME.text,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{det.name}</span>
                  {mm && <span style={{fontSize:11,color:mt==="success"?THEME.success:THEME.danger}}>{mm}</span>}
                  <button style={{...S.btn("p"),padding:"4px 12px",fontSize:11,flexShrink:0}} onClick={()=>shareDetection(det)} disabled={sharing===det.id}>
                    {sharing===det.id?<><Spinner/>Sharing...</>:"Share"}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Community feed filters */}
      <div style={S.card}>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          <input style={{...S.input,flex:1,minWidth:160}} value={search} onChange={e=>setSearch(e.target.value)} onKeyDown={e=>e.key==="Enter"&&loadFeed()} placeholder="Search community rules..."/>
          <select style={{...S.input,width:160}} value={filterTactic} onChange={e=>setFilterTactic(e.target.value)}><option>All</option>{TACTICS.map(t=><option key={t}>{t}</option>)}</select>
          <select style={{...S.input,width:140}} value={filterTool} onChange={e=>setFilterTool(e.target.value)}><option value="All">All Platforms</option>{TOOLS.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}</select>
          <select style={{...S.input,width:120}} value={sort} onChange={e=>setSort(e.target.value)}>
            <option value="stars">Most Starred</option>
            <option value="new">Newest</option>
          </select>
          <button style={S.btn("p")} onClick={loadFeed}>Search</button>
        </div>
      </div>

      {feedErr && <StatusBar msg={feedErr} type="error"/>}
      {feedLoading && <div style={{textAlign:"center",padding:40,color:THEME.textDim}}><Spinner/> Loading community feed...</div>}

      {!feedLoading && feed.length === 0 && (
        <div style={{...S.card,textAlign:"center",padding:"56px 32px"}}>
          <div style={{fontSize:56,marginBottom:16}}>🌍</div>
          <div style={{fontSize:17,fontWeight:800,color:THEME.text,marginBottom:10,fontFamily:"'Syne',sans-serif"}}>Community Feed is Empty</div>
          <div style={{fontSize:13,color:THEME.textDim,maxWidth:400,margin:"0 auto 24px",lineHeight:1.7}}>
            No detection rules have been shared yet. Be the first to contribute — open your Detection Library and click <strong style={{color:THEME.accent}}>Share</strong> on any rule.
          </div>
          <div style={{display:"flex",gap:16,justifyContent:"center",flexWrap:"wrap"}}>
            {[{icon:"🛡",label:"Share a Detection",desc:"Publish rules to help the community"},
              {icon:"⭐",label:"Star Rules",desc:"Upvote your favourites"},
              {icon:"📋",label:"Clone & Adapt",desc:"Fork rules into your library"}].map(f=>(
              <div key={f.label} style={{padding:"16px 20px",background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:10,width:140}}>
                <div style={{fontSize:24,marginBottom:6}}>{f.icon}</div>
                <div style={{fontSize:12,fontWeight:700,color:THEME.text,marginBottom:4}}>{f.label}</div>
                <div style={{fontSize:10,color:THEME.textDim}}>{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {feed.map(det => {
        const t = toolObj[det.tool];
        return (
          <div key={det.id} style={S.card}>
            <div style={{...S.row,marginBottom:10}}>
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap",marginBottom:6}}>
                  <span style={S.badge(det.severity==="Critical"?THEME.danger:det.severity==="High"?"#ff7700":det.severity==="Medium"?THEME.warning:THEME.success)}>{det.severity||"Medium"}</span>
                  <span style={{...S.badge(THEME.accent),fontSize:10}}>{det.query_type||det.tool||"Unknown"}</span>
                  <span style={{...S.badge(THEME.purple),fontSize:10}}>{det.tactic||"Unknown"}</span>
                </div>
                <div style={{fontSize:14,fontWeight:800,color:THEME.text,marginBottom:4}}>{det.name}</div>
                <div style={{fontSize:12,color:THEME.textDim}}>by {det.author_name||"Anonymous"} · {new Date(det.created_at).toLocaleDateString()}</div>
              </div>
              <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:8,flexShrink:0}}>
                <div style={{display:"flex",gap:8,alignItems:"center"}}>
                  <button style={{...S.btn(),padding:"4px 10px",fontSize:11,display:"flex",alignItems:"center",gap:4}} onClick={()=>starDetection(det.id)}>⭐ {det.stars||0}</button>
                  <button style={{...S.btn(),padding:"4px 10px",fontSize:11,display:"flex",alignItems:"center",gap:4}} onClick={()=>cloneDetection(det)} disabled={cloning===det.id}>
                    {cloning===det.id?<><Spinner/>Cloning...</>:<>📋 Clone ({det.clone_count||0})</>}
                  </button>
                </div>
                {det.score>0&&<span style={{fontSize:11,color:det.score>7?THEME.success:det.score>4?THEME.warning:THEME.textDim,fontWeight:700}}>Score: {det.score}/10</span>}
              </div>
            </div>
            {det.threat&&<div style={{fontSize:12,color:THEME.textMid,marginBottom:10,lineHeight:1.6}}>{det.threat.slice(0,120)}{det.threat.length>120?"...":""}</div>}
            <div style={{fontFamily:"monospace",fontSize:11,color:THEME.accent,background:"#050d18",padding:"10px 12px",borderRadius:8,lineHeight:1.6,maxHeight:80,overflow:"hidden",position:"relative"}}>
              {det.query?.slice(0,200)}{det.query?.length>200?"...":""}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function MetricsDashboard({ detections }) {
  const byTactic = TACTICS.reduce((acc, t) => { acc[t] = detections.filter(d => d.tactic === t).length; return acc; }, {});
  const byTool = TOOLS.reduce((acc, t) => { acc[t.name] = detections.filter(d => d.tool === t.id || d.queryType === t.id).length; return acc; }, {});
  const bySeverity = ["Critical","High","Medium","Low","Informational"].reduce((acc, s) => { acc[s] = detections.filter(d => d.severity === s).length; return acc; }, {});
  const avgScore = detections.filter(d => d.score > 0).length ? (detections.filter(d => d.score > 0).reduce((a, d) => a + d.score, 0) / detections.filter(d => d.score > 0).length).toFixed(1) : "—";
  const tacticsWithCoverage = Object.values(byTactic).filter(v => v > 0).length;
  const coveragePct = Math.round((tacticsWithCoverage / TACTICS.length) * 100);
  const platformsCovered = Object.values(byTool).filter(v => v > 0).length;
  const highCritical = (bySeverity["Critical"] || 0) + (bySeverity["High"] || 0);

  if (detections.length === 0) return (
    <div>
      <SectionHeader icon="📊" title="Metrics & ROI" color={THEME.accent}>
        <span style={S.badge(THEME.accent)}>Detection Engineering KPIs</span>
      </SectionHeader>
      <div style={{...S.card,textAlign:"center",padding:"56px 32px"}}>
        <div style={{fontSize:56,marginBottom:16}}>📊</div>
        <div style={{fontSize:17,fontWeight:800,color:THEME.text,marginBottom:10,fontFamily:"'Syne',sans-serif"}}>No Data Yet</div>
        <div style={{fontSize:13,color:THEME.textDim,maxWidth:380,margin:"0 auto 24px",lineHeight:1.7}}>
          Build your first detection to start tracking KPIs — tactic coverage, severity breakdown, platform distribution, and ROI estimates will appear here automatically.
        </div>
        <div style={{display:"flex",gap:12,justifyContent:"center",flexWrap:"wrap"}}>
          {[["📈","MITRE Coverage","Track tactic % covered"],["🛡","Severity Split","Critical vs Low breakdown"],["💰","ROI Estimate","Time saved vs manual work"],["🌐","Platform Coverage","SIEMs with detections"]].map(([icon,label,desc])=>(
            <div key={label} style={{padding:"14px 18px",background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:10,textAlign:"left",minWidth:140}}>
              <div style={{fontSize:20,marginBottom:6}}>{icon}</div>
              <div style={{fontSize:12,fontWeight:700,color:THEME.text,marginBottom:3}}>{label}</div>
              <div style={{fontSize:10,color:THEME.textDim}}>{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div>
      <SectionHeader icon="📊" title="Metrics & ROI" color={THEME.accent}>
        <span style={S.badge(THEME.accent)}>Detection Engineering KPIs</span>
      </SectionHeader>

      {/* Top stats */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:14,marginBottom:20}}>
        {[
          ["Total Detections", detections.length, THEME.accent, "rules built"],
          ["MITRE Coverage", coveragePct + "%", THEME.success, tacticsWithCoverage + " of " + TACTICS.length + " tactics"],
          ["Platforms", platformsCovered, THEME.purple, "SIEMs covered"],
          ["Avg Quality", avgScore, THEME.warning, "out of 10"],
          ["High/Critical", highCritical, THEME.danger, "priority rules"],
        ].map(([label, val, color, sub]) => (
          <div key={label} style={{background:"#0d1825",border:"1px solid "+color+"22",borderRadius:12,padding:"18px 16px",textAlign:"center"}}>
            <div style={{fontSize:32,fontWeight:900,color,lineHeight:1}}>{val}</div>
            <div style={{fontSize:12,fontWeight:700,color:THEME.textMid,marginTop:6}}>{label}</div>
            <div style={{fontSize:10,color:THEME.textDim,marginTop:3}}>{sub}</div>
          </div>
        ))}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
        {/* Coverage by tactic */}
        <div style={{background:"#0d1825",border:"1px solid #1a2a3a",borderRadius:12,padding:"18px 20px"}}>
          <div style={{fontWeight:800,color:THEME.text,fontSize:13,marginBottom:14}}>Coverage by MITRE Tactic</div>
          {TACTICS.map(t => {
            const count = byTactic[t] || 0;
            const pct = detections.length ? Math.min(100, Math.round((count / Math.max(...Object.values(byTactic), 1)) * 100)) : 0;
            return (
              <div key={t} style={{marginBottom:8}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:11,marginBottom:3}}>
                  <span style={{color:count>0?THEME.textMid:THEME.textDim}}>{t}</span>
                  <span style={{color:count>0?THEME.accent:THEME.textDim,fontWeight:700}}>{count}</span>
                </div>
                <div style={{height:4,background:"#1a2a3a",borderRadius:2}}>
                  <div style={{height:"100%",width:pct+"%",background:count>2?THEME.success:count>0?THEME.warning:"transparent",borderRadius:2,transition:"width 0.3s"}}/>
                </div>
              </div>
            );
          })}
        </div>

        {/* Severity breakdown + platform coverage */}
        <div>
          <div style={{background:"#0d1825",border:"1px solid #1a2a3a",borderRadius:12,padding:"18px 20px",marginBottom:14}}>
            <div style={{fontWeight:800,color:THEME.text,fontSize:13,marginBottom:14}}>Severity Breakdown</div>
            {Object.entries(bySeverity).map(([sev, count]) => {
              const color = sev==="Critical"?THEME.danger:sev==="High"?"#ff7700":sev==="Medium"?THEME.warning:sev==="Low"?THEME.success:THEME.textDim;
              return (
                <div key={sev} style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
                  <span style={{fontSize:11,fontWeight:700,color,minWidth:80}}>{sev}</span>
                  <div style={{flex:1,height:6,background:"#1a2a3a",borderRadius:3}}>
                    <div style={{height:"100%",width:detections.length?(count/detections.length*100)+"%":"0%",background:color,borderRadius:3}}/>
                  </div>
                  <span style={{fontSize:12,fontWeight:800,color,minWidth:20,textAlign:"right"}}>{count}</span>
                </div>
              );
            })}
          </div>
          <div style={{background:"#0d1825",border:"1px solid #1a2a3a",borderRadius:12,padding:"18px 20px"}}>
            <div style={{fontWeight:800,color:THEME.text,fontSize:13,marginBottom:12}}>Platform Coverage</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
              {TOOLS.map(t => {
                const count = byTool[t.name] || 0;
                return <span key={t.id} style={{...S.badge(count>0?THEME.accent:THEME.textDim+"33"),fontSize:10}}>{t.name} {count>0?"("+count+")":"—"}</span>;
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ROI estimate */}
      <div style={{background:"#0d1825",border:"1px solid "+THEME.success+"22",borderRadius:12,padding:"20px 24px"}}>
        <div style={{fontWeight:800,color:THEME.text,fontSize:13,marginBottom:12}}>💰 Estimated ROI</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12}}>
          {[
            ["Manual Build Time Saved", (detections.length * 4) + "h", "~4h per detection manually"],
            ["Translations Equivalent", (detections.length * TOOLS.length) + " queries", "1 rule × 10 platforms"],
            ["Rules Ready to Deploy", highCritical, "High + Critical severity"],
            ["Coverage Gaps", TACTICS.length - tacticsWithCoverage, "tactics still uncovered"],
          ].map(([label, val, sub]) => (
            <div key={label} style={{background:"#050d18",borderRadius:8,padding:"14px 16px"}}>
              <div style={{fontSize:20,fontWeight:900,color:THEME.success}}>{val}</div>
              <div style={{fontSize:11,fontWeight:700,color:THEME.textMid,marginTop:4}}>{label}</div>
              <div style={{fontSize:10,color:THEME.textDim,marginTop:2}}>{sub}</div>
            </div>
          ))}
        </div>
      </div>

      {detections.length===0&&(
        <div style={{textAlign:"center",color:THEME.textDim,padding:"60px 20px"}}>
          <div style={{fontSize:48,marginBottom:16}}>📊</div>
          <div style={{fontSize:15,fontWeight:700,color:THEME.textMid,marginBottom:8}}>No data yet</div>
          <div style={{fontSize:13}}>Build your first detection to see metrics here.</div>
        </div>
      )}
    </div>
  );
}

function GettingStarted({ onNav, detections }) {
  const [items, setItems] = useState(LS.get("getting_started", {
    built_detection: false, ran_simulation: false,
    checked_intel: false, enabled_autopilot: false,
    tried_replay: false, used_defend: false, chained_detections: false,
  }));
  const checks = [
    {key:"built_detection", icon:"🔨", title:"Build your first detection", desc:"Use the ADS framework to create a production-ready rule", tab:"builder", color:THEME.accent},
    {key:"ran_simulation", icon:"🎯", title:"Run an attack simulation", desc:"Generate realistic attack logs to test your coverage", tab:"adversary", color:THEME.danger},
    {key:"tried_replay", icon:"🎮", title:"Dry-run with Log Replay", desc:"Test your detection against real log samples before deploying", tab:"replay", color:THEME.purple},
    {key:"chained_detections", icon:"🔗", title:"Chain two detections", desc:"Build a multi-stage correlation rule that spans the kill chain", tab:"chain", color:THEME.warning},
    {key:"used_defend", icon:"🛡", title:"Set up a honeytoken trap", desc:"Plant canary assets that trigger 100%-confidence alerts", tab:"defend", color:THEME.orange},
    {key:"checked_intel", icon:"🌐", title:"Check the live threat feed", desc:"See active CVEs and build detections from KEV entries", tab:"intel", color:THEME.success},
    {key:"enabled_autopilot", icon:"🤖", title:"Enable Detection Autopilot", desc:"Let DetectIQ auto-draft detections for new vulnerabilities", tab:"autopilot", color:"#8b5cf6"},
  ];
  // Auto-check built_detection if detections exist
  useEffect(() => {
    if (detections.length > 0 && !items.built_detection) {
      const updated = { ...items, built_detection: true };
      setItems(updated);
      LS.set("getting_started", updated);
    }
  }, [detections.length]);
  const done = Object.values(items).filter(Boolean).length;
  const total = checks.length;
  if (done === total) return null;
  return (
    <div style={{...S.card,marginBottom:20,borderColor:THEME.accent+"22",background:"linear-gradient(135deg,rgba(0,212,255,0.03),rgba(0,0,0,0))"}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
        <div>
          <div style={{fontSize:14,fontWeight:800,color:THEME.text,marginBottom:3}}>Getting Started</div>
          <div style={{fontSize:11,color:THEME.textDim,fontFamily:"'JetBrains Mono',monospace"}}>{done} of {total} complete</div>
        </div>
        <div style={{position:"relative",width:44,height:44}}>
          <svg width="44" height="44" style={{transform:"rotate(-90deg)"}}>
            <circle cx="22" cy="22" r="18" fill="none" stroke={THEME.border} strokeWidth="3"/>
            <circle cx="22" cy="22" r="18" fill="none" stroke={THEME.accent} strokeWidth="3"
              strokeDasharray={2*Math.PI*18} strokeDashoffset={2*Math.PI*18*(1-done/total)}
              style={{transition:"stroke-dashoffset 0.5s ease"}}/>
          </svg>
          <div style={{position:"absolute",inset:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:THEME.accent}}>{Math.round(done/total*100)}%</div>
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))",gap:8}}>
        {checks.map(item=>{
          const checked = items[item.key];
          return(
            <div key={item.key}
              onClick={()=>{ if(!checked){onNav(item.tab);const u={...items,[item.key]:true};setItems(u);LS.set("getting_started",u);} }}
              style={{padding:"12px 14px",borderRadius:10,border:"1px solid "+(checked?THEME.success+"33":item.color+"22"),background:checked?"rgba(0,232,122,0.04)":item.color+"06",cursor:checked?"default":"pointer",transition:"all 0.2s",opacity:checked?0.7:1}}
              onMouseEnter={e=>{if(!checked){e.currentTarget.style.borderColor=item.color+"55";e.currentTarget.style.background=item.color+"10";}}}
              onMouseLeave={e=>{if(!checked){e.currentTarget.style.borderColor=item.color+"22";e.currentTarget.style.background=item.color+"06";}}}
            >
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                <div style={{width:26,height:26,borderRadius:7,background:checked?THEME.success+"18":item.color+"15",border:"1px solid "+(checked?THEME.success+"33":item.color+"25"),display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,flexShrink:0}}>
                  {checked?"✓":item.icon}
                </div>
                <div style={{fontSize:12,fontWeight:700,color:checked?THEME.success:THEME.text,textDecoration:checked?"line-through":"none"}}>{item.title}</div>
              </div>
              <div style={{fontSize:10,color:THEME.textDim,lineHeight:1.5,paddingLeft:34}}>{item.desc}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DashboardHome({ detections, onNav, user }) {
  const TACTICS_LIST=["Reconnaissance","Resource Development","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];
  const[mitreCount,setMitreCount]=useState(216);
  useEffect(()=>{ fetch("/api/mitre/techniques").then(r=>r.json()).then(d=>{if(d.count)setMitreCount(d.count);}).catch(()=>{}); },[]);

  // ── computed stats ──────────────────────────────────────────────────────────
  const total = detections.length;
  const tacticCounts = TACTICS_LIST.reduce((a,t)=>{ a[t]=detections.filter(d=>(d.tactic||"").toLowerCase()===t.toLowerCase()).length; return a; },{});
  const coveredCount = TACTICS_LIST.filter(t=>tacticCounts[t]>0).length;
  const strongCount  = TACTICS_LIST.filter(t=>tacticCounts[t]>=3).length;
  const coveragePct  = Math.round(coveredCount/14*100);
  const maturityPct  = Math.round(strongCount/14*100);
  const criticalCount= detections.filter(d=>d.severity==="Critical").length;
  const highCount    = detections.filter(d=>d.severity==="High").length;
  const medCount     = detections.filter(d=>d.severity==="Medium").length;
  const scoredDets   = detections.filter(d=>d.score>0);
  const avgScore     = scoredDets.length ? (scoredDets.reduce((s,d)=>s+d.score,0)/scoredDets.length).toFixed(1) : null;
  const adsCount     = detections.filter(d=>d.ads).length;
  const nowMs        = Date.now();
  const staleCount   = detections.filter(d=>d.created&&(nowMs-new Date(d.created).getTime())>90*24*60*60*1000).length;
  const gaps         = TACTICS_LIST.filter(t=>tacticCounts[t]===0);
  const partial      = TACTICS_LIST.filter(t=>tacticCounts[t]>0&&tacticCounts[t]<3);
  const recentDets   = [...detections].sort((a,b)=>new Date(b.created||0)-new Date(a.created||0)).slice(0,6);

  // SIEM breakdown
  const siemMap = detections.reduce((a,d)=>{ const k=d.queryType||d.tool||"Other"; a[k]=(a[k]||0)+1; return a; },{});
  const siemBreakdown = Object.entries(siemMap).sort((a,b)=>b[1]-a[1]).slice(0,5);

  const GAP_TIPS={
    "Reconnaissance":"Monitor external scanning — detect port/service enumeration with network flow alerts.",
    "Resource Development":"Track infra abuse — flag new domains, cert issuance, and bulk account creation.",
    "Initial Access":"Cover phishing, exploit attempts, and VPN anomalies. High ROI for first-alert coverage.",
    "Execution":"PowerShell, cmd.exe, and script interpreters are your highest-signal telemetry sources.",
    "Persistence":"Registry run keys, scheduled tasks, and new service creation are easy wins.",
    "Privilege Escalation":"Focus on token impersonation, UAC bypass, and sudo/su anomalies.",
    "Defense Evasion":"Log clearing, AV tampering, and process injection are critical blind spots.",
    "Credential Access":"LSASS access, credential dumping, and Kerberoasting are top priorities.",
    "Discovery":"Net commands, ADRecon, and BloodHound usage leave clear artifacts.",
    "Lateral Movement":"PsExec, WMI remote exec, and RDP lateral movement are well-logged.",
    "Collection":"Keyloggers, clipboard access, and staged archive creation are detectable.",
    "Command and Control":"DNS tunneling, beacon jitter, and non-standard ports are detectable patterns.",
    "Exfiltration":"Data staging + large outbound transfers to new IPs are your key signals.",
    "Impact":"Ransomware shadow copy deletion and bulk file encryption are high-fidelity signals.",
  };

  return (
    <div>
      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <div style={{background:"linear-gradient(135deg,rgba(79,142,247,0.07) 0%,rgba(139,92,246,0.05) 100%)",border:"1px solid "+THEME.border,borderRadius:14,padding:"30px 32px",marginBottom:20,position:"relative",overflow:"hidden"}}>
        {/* background grid decoration */}
        <div style={{position:"absolute",inset:0,backgroundImage:"radial-gradient(circle at 80% 50%, rgba(79,142,247,0.06) 0%, transparent 60%)",pointerEvents:"none"}}/>
        <div style={{display:"flex",gap:32,alignItems:"center",flexWrap:"wrap",position:"relative"}}>
          <div style={{flex:"1 1 300px"}}>
            <div style={{display:"inline-flex",alignItems:"center",gap:6,padding:"4px 10px",borderRadius:20,background:"rgba(79,142,247,0.1)",border:"1px solid "+THEME.accentDim+"33",marginBottom:14}}>
              <span style={{width:6,height:6,borderRadius:"50%",background:THEME.success,display:"inline-block",animation:"subtlepulse 2s infinite"}}/>
              <span style={{fontSize:10,fontWeight:700,color:THEME.accent,letterSpacing:"0.08em"}}>DETECTION ENGINEERING PLATFORM</span>
            </div>
            <div style={{fontSize:28,fontWeight:800,letterSpacing:"-0.025em",marginBottom:10,lineHeight:1.2,color:THEME.text,fontFamily:"'Syne',sans-serif"}}>
              {user
                ? <>Welcome back, <span style={{color:THEME.accent}}>{user.email.split("@")[0]}</span>.</>
                : <>Build detections that <span style={{color:THEME.accent}}>actually work.</span></>}
            </div>
            <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,marginBottom:22}}>
              {total>0
                ? <>{total} detection{total>1?"s":""} in your library · <span style={{color:coveragePct>=70?THEME.success:coveragePct>=40?THEME.warning:THEME.danger}}>{coveragePct}% MITRE coverage</span> · {mitreCount} ATT&amp;CK techniques indexed</>
                : <>AI-powered · ADS Framework · 10 SIEM platforms · {mitreCount} MITRE ATT&amp;CK techniques indexed</>}
            </div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <button style={{...S.btn("p"),padding:"10px 22px",fontSize:13,fontWeight:700}} onClick={()=>onNav("builder")}>+ Build Detection</button>
              <button style={{...S.btn(),padding:"10px 20px",fontSize:13}} onClick={()=>onNav("library")}>My Library {total>0&&<span style={{marginLeft:5,background:THEME.accentGlow,color:THEME.accent,borderRadius:10,padding:"0 6px",fontSize:11}}>{total}</span>}</button>
              <button style={{...S.btn(),padding:"10px 20px",fontSize:13}} onClick={()=>onNav("intel")}>Threat Intel</button>
            </div>
          </div>
          {/* ── Stat grid ─── */}
          <div style={{flex:"0 1 420px",display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10}}>
            {[
              {value:total||"0",label:"Detections",sub:"in library",accent:THEME.accent,icon:"🛡"},
              {value:coveredCount+"/14",label:"Tactics",sub:"MITRE covered",accent:THEME.success,icon:"🗺"},
              {value:coveragePct+"%",label:"Coverage",sub:coveragePct>=70?"Strong posture":coveragePct>=40?"Building up":"Needs work",accent:coveragePct>=70?THEME.success:coveragePct>=40?THEME.warning:THEME.danger,icon:"📊"},
              {value:avgScore||"—",label:"Avg Score",sub:scoredDets.length+" scored",accent:avgScore>=7?THEME.success:avgScore>=5?THEME.warning:THEME.textDim,icon:"🏅"},
              {value:criticalCount+highCount||"—",label:"High+ Alerts",sub:criticalCount+" critical",accent:criticalCount>0?THEME.danger:THEME.warning,icon:"🔴"},
              {value:staleCount||"—",label:"Stale Rules",sub:"90+ days old",accent:staleCount>0?THEME.warning:THEME.success,icon:"⏳"},
            ].map(s=>(
              <div key={s.label} style={{background:"rgba(255,255,255,0.025)",border:"1px solid "+THEME.border,borderRadius:10,padding:"14px 14px 12px",position:"relative",overflow:"hidden",cursor:s.label==="Stale Rules"&&staleCount>0?"pointer":s.label==="Detections"&&total>0?"pointer":"default"}} onClick={()=>{if(s.label==="Detections"&&total>0)onNav("library");if(s.label==="Stale Rules"&&staleCount>0)onNav("library");}}>
                <div style={{position:"absolute",top:10,right:10,fontSize:16,opacity:0.15}}>{s.icon}</div>
                <div style={{fontSize:22,fontWeight:800,color:s.accent,lineHeight:1,marginBottom:3,fontFamily:"'JetBrains Mono',monospace"}}>{s.value}</div>
                <div style={{fontSize:11,fontWeight:700,color:THEME.text,marginBottom:2}}>{s.label}</div>
                <div style={{fontSize:10,color:THEME.textDim}}>{s.sub}</div>
                <div style={{position:"absolute",bottom:0,left:0,right:0,height:2,background:s.accent,opacity:0.35,borderRadius:"0 0 10px 10px"}}/>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Onboarding checklist ──────────────────────────────────────────── */}
      <GettingStarted onNav={onNav} detections={detections}/>

      {/* ── Honeycomb visual ─────────────────────────────────────────────── */}
      {total>0&&<HoneycombGrid detections={detections}/>}

      {/* ── Bottom section ───────────────────────────────────────────────── */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16}}>

        {/* Quick Launch */}
        <div style={{...S.card,marginBottom:0}}>
          <div style={{...S.cardTitle,marginBottom:14}}><span>⚡</span> Quick Launch</div>
          <div style={{display:"flex",flexDirection:"column",gap:5}}>
            {[
              {icon:"🔨",label:"Detection Builder",desc:"AI + ADS framework",tab:"builder",color:THEME.accent},
              {icon:"🔗",label:"Detection Chain",desc:"Multi-stage correlation",tab:"chain",color:THEME.accent},
              {icon:"🎮",label:"Log Replay",desc:"Dry-run before deploy",tab:"replay",color:THEME.purple},
              {icon:"🛡",label:"Defend",desc:"Honeytokens + sinkhole",tab:"defend",color:THEME.orange},
              {icon:"🔄",label:"Query Translator",desc:"10 SIEM formats",tab:"translator",color:THEME.purple},
              {icon:"🔍",label:"Alert Triage",desc:"AI verdict engine",tab:"triage",color:THEME.warning},
              {icon:"🌐",label:"Threat Intel",desc:"CISA KEV + live feeds",tab:"intel",color:THEME.success},
              {icon:"📖",label:"Documentation",desc:"Every feature explained",tab:"docs",color:THEME.textMid},
            ].map(a=>(
              <div key={a.tab} onClick={()=>onNav(a.tab)}
                style={{display:"flex",alignItems:"center",gap:10,padding:"8px 10px",borderRadius:7,border:"1px solid transparent",cursor:"pointer",transition:"all 0.13s"}}
                onMouseEnter={e=>{e.currentTarget.style.borderColor=a.color+"44";e.currentTarget.style.background=a.color+"08";}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor="transparent";e.currentTarget.style.background="transparent";}}>
                <div style={{width:28,height:28,borderRadius:6,background:a.color+"12",border:"1px solid "+a.color+"20",display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,flexShrink:0}}>{a.icon}</div>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:12,fontWeight:600,color:THEME.text}}>{a.label}</div>
                  <div style={{fontSize:10,color:THEME.textDim}}>{a.desc}</div>
                </div>
                <span style={{fontSize:12,color:THEME.textDim}}>›</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Detections + SIEM breakdown */}
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          <div style={{...S.card,marginBottom:0,flex:1}}>
            <div style={{display:"flex",alignItems:"center",marginBottom:12}}>
              <div style={S.cardTitle}><span>📋</span> Recent Detections</div>
              <button style={{...S.btn(),padding:"3px 10px",fontSize:11,marginLeft:"auto"}} onClick={()=>onNav("library")}>View all {total>0&&`(${total})`}</button>
            </div>
            {recentDets.length===0?(
              <div style={{textAlign:"center",padding:"24px 16px",color:THEME.textDim}}>
                <div style={{fontSize:28,marginBottom:8}}>🛡</div>
                <div style={{fontSize:12,marginBottom:4,fontWeight:600,color:THEME.text}}>No detections yet</div>
                <div style={{fontSize:11,marginBottom:12}}>Start with the AI-powered builder</div>
                <button style={{...S.btn("p"),padding:"7px 16px",fontSize:12}} onClick={()=>onNav("builder")}>Build Your First</button>
              </div>
            ):recentDets.map((det,i)=>(
              <div key={det.id} style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",borderBottom:i<recentDets.length-1?"1px solid "+THEME.border:"none"}}>
                <div style={{width:7,height:7,borderRadius:"50%",background:sevColor[det.severity]||THEME.textDim,flexShrink:0}}/>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:12,fontWeight:600,color:THEME.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{det.name}</div>
                  <div style={{fontSize:10,color:THEME.textDim,marginTop:1}}>{det.tactic||"—"} · {det.queryType||det.tool||"?"}</div>
                </div>
                <div style={{display:"flex",gap:3,flexShrink:0,alignItems:"center"}}>
                  {det.ads&&<span style={{...S.badge(THEME.accent),fontSize:8}}>ADS</span>}
                  {det.score>0&&<span style={{...S.badge(det.score>=7?THEME.success:det.score>=5?THEME.warning:THEME.textDim),fontSize:8}}>{det.score}/10</span>}
                  {det.severity&&<span style={{...S.badge(sevColor[det.severity]||THEME.textDim),fontSize:8}}>{det.severity}</span>}
                </div>
              </div>
            ))}
          </div>

          {/* SIEM Breakdown */}
          {siemBreakdown.length>0&&(
            <div style={{...S.card,marginBottom:0}}>
              <div style={{...S.cardTitle,marginBottom:12}}><span>📡</span> Platform Breakdown</div>
              {siemBreakdown.map(([name,count])=>(
                <div key={name} style={{marginBottom:8}}>
                  <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                    <span style={{fontSize:11,color:THEME.textMid}}>{name}</span>
                    <span style={{fontSize:11,color:THEME.text,fontWeight:600}}>{count} <span style={{color:THEME.textDim,fontWeight:400}}>({Math.round(count/total*100)}%)</span></span>
                  </div>
                  <div style={{height:4,background:THEME.border,borderRadius:4,overflow:"hidden"}}>
                    <div style={{height:"100%",background:THEME.accent,borderRadius:4,width:Math.round(count/total*100)+"%",transition:"width 0.6s ease"}}/>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right column: severity dist + top gaps + links */}
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          {/* Severity distribution */}
          {total>0&&(
            <div style={{...S.card,marginBottom:0}}>
              <div style={{...S.cardTitle,marginBottom:12}}><span>🎯</span> Severity Distribution</div>
              {[
                {label:"Critical",count:criticalCount,color:"#ff3d55"},
                {label:"High",count:highCount,color:"#ff7700"},
                {label:"Medium",count:medCount,color:"#ffaa00"},
                {label:"Low",count:detections.filter(d=>d.severity==="Low").length,color:THEME.success},
                {label:"Info",count:detections.filter(d=>d.severity==="Informational").length,color:THEME.textDim},
              ].filter(s=>s.count>0).map(s=>(
                <div key={s.label} style={{display:"flex",alignItems:"center",gap:8,marginBottom:7}}>
                  <div style={{width:8,height:8,borderRadius:"50%",background:s.color,flexShrink:0}}/>
                  <div style={{flex:1,fontSize:11,color:THEME.textMid}}>{s.label}</div>
                  <div style={{width:80,height:4,background:THEME.border,borderRadius:4,overflow:"hidden"}}>
                    <div style={{height:"100%",background:s.color,borderRadius:4,width:Math.round(s.count/total*100)+"%"}}/>
                  </div>
                  <div style={{fontSize:11,fontWeight:700,color:THEME.text,minWidth:20,textAlign:"right"}}>{s.count}</div>
                </div>
              ))}
              {adsCount>0&&(
                <div style={{marginTop:10,paddingTop:10,borderTop:"1px solid "+THEME.border,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{fontSize:11,color:THEME.textDim}}>ADS Framework rules</span>
                  <span style={{...S.badge(THEME.accent),fontSize:9}}>{adsCount} / {total}</span>
                </div>
              )}
            </div>
          )}

          {/* Top coverage gaps or empty state CTA */}
          {total===0?(
            <div style={{...S.card,marginBottom:0,textAlign:"center",padding:"28px 20px"}}>
              <div style={{fontSize:36,marginBottom:12}}>🚀</div>
              <div style={{fontSize:14,fontWeight:700,color:THEME.text,marginBottom:6}}>Ready to get started?</div>
              <div style={{fontSize:12,color:THEME.textDim,lineHeight:1.7,marginBottom:18}}>Build your first detection in under 2 minutes. Just describe the threat and pick your SIEM.</div>
              <div style={{display:"flex",flexDirection:"column",gap:8}}>
                <button style={{...S.btn("p"),padding:"10px 0",fontSize:13,fontWeight:600,width:"100%"}} onClick={()=>onNav("builder")}>🔨 Build a Detection</button>
                <button style={{...S.btn(),padding:"9px 0",fontSize:12,width:"100%"}} onClick={()=>onNav("intel")}>🌐 Browse Threat Intel</button>
                <button style={{...S.btn(),padding:"9px 0",fontSize:12,width:"100%"}} onClick={()=>onNav("docs")}>📖 Read the Docs</button>
              </div>
            </div>
          ):(
            <div style={{...S.card,marginBottom:0}}>
              <div style={{display:"flex",alignItems:"center",marginBottom:12}}>
                <div style={S.cardTitle}><span>🔗</span> Explore</div>
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:5}}>
                {[
                  {label:"ATT&CK Heatmap",tab:"heatmap",icon:"🗺",desc:coveredCount+"/14 tactics covered"},
                  {label:"Detection Health",tab:"health",icon:"❤️",desc:staleCount>0?staleCount+" stale rules to review":"All rules healthy"},
                  {label:"Adversary SIEM",tab:"adversary",icon:"🤖",desc:"Simulate attack coverage"},
                  {label:"Metrics Dashboard",tab:"metrics",icon:"📊",desc:"Coverage trends over time"},
                  {label:"Community Rules",tab:"community",icon:"🌍",desc:"Clone from community library"},
                  {label:"Autopilot",tab:"autopilot",icon:"🤖",desc:"AI auto-drafts from threat intel"},
                ].map(l=>(
                  <div key={l.tab} onClick={()=>onNav(l.tab)}
                    style={{display:"flex",alignItems:"center",gap:9,padding:"7px 8px",borderRadius:7,cursor:"pointer",transition:"all 0.13s",border:"1px solid transparent"}}
                    onMouseEnter={e=>{e.currentTarget.style.background="rgba(255,255,255,0.03)";e.currentTarget.style.borderColor=THEME.border;}}
                    onMouseLeave={e=>{e.currentTarget.style.background="transparent";e.currentTarget.style.borderColor="transparent";}}>
                    <span style={{fontSize:14}}>{l.icon}</span>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{fontSize:12,fontWeight:600,color:THEME.text}}>{l.label}</div>
                      <div style={{fontSize:10,color:THEME.textDim}}>{l.desc}</div>
                    </div>
                    <span style={{fontSize:12,color:THEME.textDim}}>›</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AutopilotTab({ user, detections, onSaveDetection, onNav }) {
  const toast = useToast();
  const SIEM_OPTIONS = ["splunk","sentinel","crowdstrike","elastic","logscale","qradar","chronicle","tanium","panther","sumo"];
  const [enabled, setEnabled] = useState(false);
  const [saving, setSaving] = useState(false);
  const [siemTool, setSiemTool] = useState("splunk");
  const [running, setRunning] = useState(false);
  const [drafts, setDrafts] = useState([]);
  const [savedDrafts, setSavedDrafts] = useState({});
  const [dismissedDrafts, setDismissedDrafts] = useState({});
  const [lastRun, setLastRun] = useState(null);
  const [newCount, setNewCount] = useState(null);
  const [lastKevIds, setLastKevIds] = useState([]);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [schedFreq, setSchedFreq] = useState(LS.get("autopilot_freq","3d"));
  const [schedEmail, setSchedEmail] = useState(LS.get("autopilot_email_notify",true));
  const [schedTactics, setSchedTactics] = useState(LS.get("autopilot_tactics",[]));
  const ALL_TACTICS=["Reconnaissance","Resource Development","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];

  useEffect(() => {
    const saved = LS.get("autopilot_settings", null);
    if (saved) {
      setSiemTool(saved.siemTool || "splunk");
      setLastKevIds(saved.lastKevIds || []);
      setLastRun(saved.lastRun || null);
      setEnabled(saved.enabled || false);
    }
    const savedDraftsData = LS.get("autopilot_drafts", []);
    setDrafts(savedDraftsData);
    if (user) {
      // Load settings from Supabase
      supabase.from("autopilot_settings").select("enabled,siem_tool").eq("user_id", user.id).single()
        .then(({ data }) => {
          if (data) {
            setEnabled(data.enabled || false);
            setSiemTool(data.siem_tool || "splunk");
            const cur = LS.get("autopilot_settings", {});
            LS.set("autopilot_settings", Object.assign({}, cur, { enabled: data.enabled, siemTool: data.siem_tool }));
          }
        });
      // Load background cron drafts from Supabase (these won't be in localStorage)
      supabase.from("autopilot_drafts")
        .select("*").eq("user_id", user.id).eq("status", "pending")
        .order("created_at", { ascending: false }).limit(30)
        .then(({ data }) => {
          if (data && data.length > 0) {
            const local = LS.get("autopilot_drafts", []);
            const merged = [...data, ...local];
            const deduped = [...new Map(merged.map(d => [d.cve_id, d])).values()].slice(0, 30);
            setDrafts(deduped);
            LS.set("autopilot_drafts", deduped);
            // Notify if there are new cron-generated drafts not seen before
            const seenIds = new Set(local.map(d => d.cve_id));
            const newFromCron = data.filter(d => !seenIds.has(d.cve_id));
            if (newFromCron.length > 0) {
              setMsg(newFromCron.length + " new detection draft" + (newFromCron.length > 1 ? "s" : "") + " generated by Autopilot — review below.");
            }
          }
        });
    }
  }, [user?.id]);
  async function toggleEnabled(val) {
    setEnabled(val);
    const cur = LS.get("autopilot_settings", {});
    LS.set("autopilot_settings", Object.assign({}, cur, {enabled: val, siemTool}));
    if (!user) return;
    setSaving(true);
    try {
      await supabase.from("autopilot_settings").upsert(
        {user_id: user.id, enabled: val, siem_tool: siemTool, updated_at: new Date().toISOString()},
        {onConflict: "user_id"}
      );
      setMsg(val ? "Autopilot enabled. Background scanner runs every 3 days." : "Autopilot disabled.");
    } catch(e) { setErr("Failed to save settings."); }
    setSaving(false);
  }

  async function runAutopilot() {
    if (!user) { setErr("Sign in to use Detection Autopilot."); return; }
    setRunning(true); setErr(""); setMsg("");
    try {
      const res = await fetch("/api/autopilot/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lastKevIds, siemTool, userId: user.id })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Run failed");
      const now = new Date().toISOString();
      setLastRun(now);
      setNewCount(data.newCount);
      if (data.allIds && data.allIds.length) {
        setLastKevIds(data.allIds);
        LS.set("autopilot_settings", { siemTool, lastKevIds: data.allIds, lastRun: now });
      }
      if (data.drafts && data.drafts.length > 0) {
        const merged = [...data.drafts, ...drafts].slice(0, 20);
        setDrafts(merged);
        LS.set("autopilot_drafts", merged);
        setMsg(data.drafts.length + " detection draft" + (data.drafts.length > 1 ? "s" : "") + " generated from " + data.newCount + " new KEV " + (data.newCount === 1 ? "entry" : "entries") + ".");
      } else {
        setMsg("No new KEV entries since last run. Coverage is up to date.");
      }
    } catch(e) { setErr(e.message); }
    setRunning(false);
  }

  function approveDraft(draft) {
    const det = {
      id: uid(), name: draft.detection_name,
      query: draft.detection_query, queryType: draft.siem_tool,
      tool: draft.siem_tool, tactic: draft.detection_tactic,
      severity: draft.detection_severity,
      threat: draft.detection_summary || draft.vulnerability_name,
      description: draft.detection_summary || draft.vulnerability_name,
      tags: [draft.cve_id, draft.detection_tactic, "autopilot"],
      score: 0, created: new Date().toISOString()
    };
    onSaveDetection(det);
    setSavedDrafts(p => ({ ...p, [draft.cve_id]: true }));
    setMsg("Saved to library: " + draft.detection_name);
    toast?.("Saved to library: " + draft.detection_name, "success");
  }

  const visibleDrafts = drafts.filter(d => !dismissedDrafts[d.cve_id]);
  const sevColor2 = { Critical: THEME.danger, High: THEME.orange, Medium: THEME.warning, Low: THEME.success };

  return (
    <div>
      <SectionHeader icon="🤖" title="Detection Autopilot" color={THEME.accent}>
        <div style={{fontSize:12,color:THEME.textMid,marginBottom:20,lineHeight:1.7}}>
          Autopilot watches the CISA KEV feed and automatically drafts detections for new vulnerabilities. Review and approve drafts before they go to your library.
        </div>
      </SectionHeader>
      <HelpBox title="Detection Autopilot Quick Reference" color={THEME.accent} items={[
        {icon:"🤖",title:"What it does",desc:"Monitors the CISA Known Exploited Vulnerabilities feed and automatically generates draft detection rules whenever a new CVE is added. You review and approve before anything goes live."},
        {icon:"✅",title:"Review & approve",desc:"Drafts appear in the queue below. Each one shows the CVE, affected platforms, and the generated rule. Approve to add to your library, or edit before approving."},
        {icon:"⚙️",title:"Platform targeting",desc:"Set your primary SIEM platform in Settings so Autopilot generates rules in the right query language for your environment."},
        {icon:"💡",title:"Tip",desc:"Autopilot drafts are a starting point — always review the generated logic before approving, especially for complex CVEs with unusual exploitation patterns."},
      ]}/>

      <div style={{...S.card,borderColor:enabled?THEME.accent+"33":THEME.border}}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:16}}>
          <div style={{display:"flex",alignItems:"center",gap:16}}>
            <div style={{width:52,height:28,borderRadius:14,background:enabled?"rgba(0,212,255,0.2)":THEME.border,border:"1px solid "+(enabled?THEME.accent:THEME.border),cursor:saving?"not-allowed":"pointer",position:"relative",transition:"all 0.25s",flexShrink:0}} onClick={()=>!saving&&toggleEnabled(!enabled)}><div style={{position:"absolute",top:4,left:enabled?26:4,width:18,height:18,borderRadius:"50%",background:enabled?THEME.accent:THEME.textDim,transition:"all 0.25s",boxShadow:enabled?"0 0 8px rgba(0,212,255,0.6)":"none"}}/></div>
            <div>
              <div style={{fontSize:14,fontWeight:700,color:enabled?THEME.accent:THEME.text}}>Autopilot {enabled?"Enabled":"Disabled"} {saving&&<span style={{fontSize:11,color:THEME.textDim}}>(saving...)</span>}</div>
              <div style={{fontSize:11,color:THEME.textDim,marginTop:2,fontFamily:"'JetBrains Mono',monospace"}}>{enabled?"Scans KEV every 3 days and auto-drafts detections":"Toggle to enable background KEV scanning"}</div>
              <div style={{fontSize:10,color:THEME.textDim,marginTop:2,fontFamily:"'JetBrains Mono',monospace"}}>{lastRun ? "Last run: " + new Date(lastRun).toLocaleString() : "Never run"}</div>
            </div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:12,flexWrap:"wrap"}}>
            <div>
              <label style={S.label}>Target SIEM</label>
              <select style={{...S.input,width:140,padding:"7px 10px"}} value={siemTool}
                onChange={e => setSiemTool(e.target.value)}>
                {SIEM_OPTIONS.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
              </select>
            </div>
            <div style={{paddingTop:18}}>
              <button style={{...S.btn("p"),padding:"9px 22px",fontSize:13,opacity:running?0.6:1}}
                onClick={runAutopilot} disabled={running}>
                {running ? <><Spinner/>Scanning KEV...</> : "▶ Run Now"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {err && <StatusBar msg={err} type="error"/>}
      {msg && <StatusBar msg={msg} type="success"/>}

      {/* Schedule Configuration */}
      <div style={S.card}>
        <div style={{...S.cardTitle,marginBottom:14}}><span>🗓</span> Schedule & Filters</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
          <div>
            <label style={S.label}>Scan Frequency</label>
            <select style={{...S.input,cursor:"pointer"}} value={schedFreq} onChange={e=>{setSchedFreq(e.target.value);LS.set("autopilot_freq",e.target.value);}}>
              <option value="1d">Daily</option>
              <option value="3d">Every 3 Days</option>
              <option value="7d">Weekly</option>
              <option value="manual">Manual Only</option>
            </select>
            <div style={{fontSize:10,color:THEME.textDim,marginTop:4}}>How often Autopilot checks the CISA KEV feed in the background.</div>
          </div>
          <div>
            <label style={S.label}>Email Notifications</label>
            <div style={{display:"flex",alignItems:"center",gap:10,marginTop:6}}>
              <div style={{width:44,height:24,borderRadius:12,background:schedEmail?"rgba(0,212,255,0.2)":THEME.border,border:"1px solid "+(schedEmail?THEME.accent:THEME.border),cursor:"pointer",position:"relative",transition:"all 0.2s"}}
                onClick={()=>{setSchedEmail(!schedEmail);LS.set("autopilot_email_notify",!schedEmail);}}>
                <div style={{position:"absolute",top:3,left:schedEmail?22:3,width:16,height:16,borderRadius:"50%",background:schedEmail?THEME.accent:THEME.textDim,transition:"all 0.2s"}}/>
              </div>
              <span style={{fontSize:12,color:schedEmail?THEME.text:THEME.textDim}}>{schedEmail?"Email me when new drafts are ready":"Notifications off"}</span>
            </div>
          </div>
        </div>
        <div>
          <label style={S.label}>Tactic Filter <span style={{color:THEME.textDim,fontSize:10,fontWeight:400}}>(leave empty = all tactics)</span></label>
          <div style={{display:"flex",flexWrap:"wrap",gap:6,marginTop:6}}>
            {ALL_TACTICS.map(t=>{
              const on=schedTactics.includes(t);
              return(
                <span key={t} onClick={()=>{const n=on?schedTactics.filter(x=>x!==t):[...schedTactics,t];setSchedTactics(n);LS.set("autopilot_tactics",n);}}
                  style={{padding:"3px 10px",borderRadius:5,fontSize:10,cursor:"pointer",fontWeight:600,transition:"all 0.15s",
                    background:on?"rgba(0,212,255,0.12)":"transparent",
                    border:"1px solid "+(on?THEME.accent:THEME.border),
                    color:on?THEME.accent:THEME.textDim}}>
                  {t}
                </span>
              );
            })}
          </div>
          {schedTactics.length>0&&<div style={{fontSize:10,color:THEME.accent,marginTop:6}}>Filtering to {schedTactics.length} tactic{schedTactics.length>1?"s":""}: {schedTactics.join(", ")}</div>}
        </div>
      </div>

      {lastRun && (
        <div style={{...S.grid4,marginBottom:16}}>
          {[
            {label:"Drafts Pending", value: visibleDrafts.filter(d=>!savedDrafts[d.cve_id]).length, color:THEME.warning, icon:"📋"},
            {label:"Approved", value: Object.keys(savedDrafts).length, color:THEME.success, icon:"✅"},
            {label:"Dismissed", value: Object.keys(dismissedDrafts).length, color:THEME.textDim, icon:"🗑"},
            {label:"New CVEs Found", value: newCount||0, color:THEME.danger, icon:"🔴"},
          ].map(s => (
            <div key={s.label} style={{...S.card,marginBottom:0,padding:"14px 18px",borderColor:s.color+"22"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                <div style={{fontSize:10,color:THEME.textDim,fontFamily:"'JetBrains Mono',monospace"}}>{s.label}</div>
                <span>{s.icon}</span>
              </div>
              <div style={{fontSize:28,fontWeight:900,color:s.color}}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {visibleDrafts.length === 0 ? (
        <div style={{...S.card,textAlign:"center",padding:"48px 20px"}}>
          <div style={{fontSize:48,marginBottom:16}}>🤖</div>
          <div style={{fontSize:16,fontWeight:700,color:THEME.text,marginBottom:8}}>No drafts yet</div>
          <div style={{fontSize:13,color:THEME.textDim,marginBottom:24}}>
            Click Run Now to scan the CISA KEV feed and auto-generate detection drafts for new vulnerabilities.
          </div>
          <button style={{...S.btn("p"),padding:"10px 24px",fontSize:13}} onClick={runAutopilot} disabled={running}>
            {running ? <><Spinner/>Scanning...</> : "▶ Run First Scan"}
          </button>
        </div>
      ) : (
        <div>
          <div style={{fontSize:12,fontWeight:700,color:THEME.textMid,marginBottom:12,fontFamily:"'JetBrains Mono',monospace"}}>
            {visibleDrafts.filter(d=>!savedDrafts[d.cve_id]).length} draft{visibleDrafts.filter(d=>!savedDrafts[d.cve_id]).length!==1?"s":""} awaiting review
          </div>
          {visibleDrafts.map((draft,i) => {
            const isApproved = savedDrafts[draft.cve_id];
            return (
              <div key={draft.cve_id+i} style={{...S.card,borderColor:isApproved?THEME.success+"33":THEME.border}}>
                <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:12,flexWrap:"wrap"}}>
                  <div style={{flex:1,minWidth:200}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap",marginBottom:8}}>
                      <span style={{...S.badge(THEME.danger),fontSize:9}}>{draft.cve_id}</span>
                      <span style={{...S.badge(sevColor2[draft.detection_severity]||THEME.textDim),fontSize:9}}>{draft.detection_severity}</span>
                      <span style={{...S.badge(THEME.purple),fontSize:9}}>{draft.detection_tactic}</span>
                      <span style={{...S.badge(THEME.accent),fontSize:9}}>{(draft.siem_tool||"").toUpperCase()}</span>
                      {isApproved && <span style={{...S.badge(THEME.success),fontSize:9}}>Saved</span>}
                    </div>
                    <div style={{fontSize:14,fontWeight:700,color:THEME.text,marginBottom:4}}>{draft.detection_name}</div>
                    <div style={{fontSize:11,color:THEME.textDim,marginBottom:6}}>{draft.vendor_project}</div>
                    <div style={{fontSize:12,color:THEME.textMid,marginBottom:10,lineHeight:1.6}}>{draft.vulnerability_name}</div>
                    <div style={{...S.code,fontSize:11,maxHeight:120,overflow:"auto"}}>{draft.detection_query}</div>
                    {draft.date_added && <div style={{fontSize:10,color:THEME.textDim,marginTop:8,fontFamily:"'JetBrains Mono',monospace"}}>KEV added: {draft.date_added}</div>}
                  </div>
                  <div style={{display:"flex",flexDirection:"column",gap:8,flexShrink:0}}>
                    {!isApproved ? (
                      <>
                        <button style={{...S.btn("s"),padding:"7px 16px",fontSize:12}} onClick={()=>approveDraft(draft)}>Approve</button>
                        <button style={{...S.btn("d"),padding:"7px 16px",fontSize:12}} onClick={()=>setDismissedDrafts(p=>({...p,[draft.cve_id]:true}))}>Dismiss</button>
                      </>
                    ) : (
                      <button style={{...S.btn(),padding:"7px 16px",fontSize:12}} onClick={()=>onNav("library")}>View in Library</button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div style={{...S.card,marginTop:8,background:"rgba(0,212,255,0.03)",borderColor:THEME.accent+"18"}}>
        <div style={{...S.cardTitle,marginBottom:12}}><span>i</span> How Autopilot Works</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
          {[
            {n:"1",t:"Scans CISA KEV",d:"Fetches the live Known Exploited Vulnerabilities feed and finds new entries since your last run.",c:THEME.accent},
            {n:"2",t:"Drafts Detections",d:"For each new CVE, generates a detection query tuned to your chosen SIEM platform.",c:THEME.purple},
            {n:"3",t:"Queues for Review",d:"Drafts appear here for review. Approve, or dismiss each one before it hits your library.",c:THEME.warning},
            {n:"4",t:"Saves to Library",d:"Approved detections go to your Detection Library tagged with the CVE ID and autopilot badge.",c:THEME.success},
          ].map(s => (
            <div key={s.n} style={{display:"flex",gap:12,alignItems:"flex-start"}}>
              <div style={{width:24,height:24,borderRadius:"50%",background:s.c+"18",border:"1px solid "+s.c+"44",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:s.c,flexShrink:0}}>{s.n}</div>
              <div>
                <div style={{fontSize:12,fontWeight:700,color:THEME.text,marginBottom:3}}>{s.t}</div>
                <div style={{fontSize:11,color:THEME.textDim,lineHeight:1.6}}>{s.d}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function UserSettingsTab({ user, onSignOut }) {
  const toast = useToast();
  const [displayName, setDisplayName] = useState("");
  const [defaultSiem, setDefaultSiem] = useState("splunk");
  const [siemKeys, setSiemKeys] = useState({});
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedSiem, setExpandedSiem] = useState(null);
  const [pwStatus, setPwStatus] = useState(null);
  const [auditLog, setAuditLog] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);

  useEffect(() => {
    if (!user?.id) return;
    setAuditLoading(true);
    fetch("/api/siem/audit?userId=" + user.id)
      .then(r => r.json())
      .then(d => setAuditLog(d.audit || []))
      .catch(() => {})
      .finally(() => setAuditLoading(false));
  }, [user?.id]);

  useEffect(() => {
    if (!user) return;
    supabase.from("user_settings").select("*").eq("user_id", user.id).single()
      .then(({ data }) => {
        if (data) {
          setDisplayName(data.display_name || "");
          setDefaultSiem(data.default_siem || "splunk");
          setSiemKeys(data.siem_api_keys || {});
        }
        setLoading(false);
      });
  }, [user?.id]);

  const saveSettings = async () => {
    if (!user) return;
    setSaving(true); setStatus(null);
    const { error } = await supabase.from("user_settings").upsert({
      user_id: user.id,
      display_name: displayName,
      default_siem: defaultSiem,
      siem_api_keys: siemKeys,
      updated_at: new Date().toISOString()
    }, { onConflict: "user_id" });
    setSaving(false);
    if (error) { setStatus({ type: "error", msg: "Save failed: " + error.message }); toast?.("Save failed: " + error.message, "error"); }
    else { setStatus({ type: "success", msg: "Settings saved." }); toast?.("Settings saved", "success"); }
  };

  const sendPasswordReset = async () => {
    const { error } = await supabase.auth.resetPasswordForEmail(user.email);
    if (error) setPwStatus({ type: "error", msg: error.message });
    else setPwStatus({ type: "success", msg: "Reset email sent to " + user.email });
  };

  const initials = (user?.email || "U").slice(0, 2).toUpperCase();
  const memberSince = user?.created_at
    ? new Date(user.created_at).toLocaleDateString("en-US", { year: "numeric", month: "long" })
    : "Unknown";

  if (!user) return (
    <div style={{...S.card, textAlign:"center", color:THEME.textDim, padding:40}}>
      Sign in to access settings.
    </div>
  );

  return (
    <div style={{maxWidth:720, margin:"0 auto"}}>

      {/* Profile Header */}
      <div style={{...S.card, display:"flex", alignItems:"center", gap:20, marginBottom:4}}>
        <div style={{width:64,height:64,borderRadius:"50%",background:"linear-gradient(135deg,"+THEME.accent+"30,"+THEME.purple+"30)",border:"2px solid "+THEME.accentDim,display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,fontWeight:800,color:THEME.accent,flexShrink:0}}>
          {initials}
        </div>
        <div style={{flex:1}}>
          <div style={{fontSize:18,fontWeight:700,color:THEME.text,fontFamily:"'Syne',sans-serif"}}>
            {displayName || user.email.split("@")[0]}
          </div>
          <div style={{fontSize:12,color:THEME.textDim,marginTop:3}}>{user.email}</div>
          <div style={{fontSize:11,color:THEME.textDim,marginTop:2}}>Member since {memberSince}</div>
        </div>
        <span style={S.badge(THEME.success)}>ACTIVE</span>
      </div>

      {status && <StatusBar msg={status.msg} type={status.type}/>}

      <div style={S.grid2}>
        {/* Profile */}
        <div style={S.card}>
          <div style={S.cardTitle}>👤 Profile</div>
          <label style={S.label}>Display Name</label>
          <input style={S.input} placeholder={user.email.split("@")[0]} value={displayName} onChange={e=>setDisplayName(e.target.value)}/>
          <div style={{marginTop:12}}>
            <label style={S.label}>Email</label>
            <input style={{...S.input,opacity:0.5,cursor:"not-allowed"}} value={user.email} readOnly/>
          </div>
        </div>

        {/* Preferences */}
        <div style={S.card}>
          <div style={S.cardTitle}>⚙️ Preferences</div>
          <label style={S.label}>Default SIEM</label>
          <select style={{...S.input,cursor:"pointer"}} value={defaultSiem} onChange={e=>setDefaultSiem(e.target.value)}>
            {TOOLS.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <div style={{marginTop:12,fontSize:11,color:THEME.textDim,lineHeight:1.6}}>
            Pre-selected across Builder, Simulator, and Translator tabs.
          </div>
        </div>
      </div>

      {/* SIEM API Keys */}
      <div style={S.card}>
        <div style={S.cardTitle}>🔑 SIEM API Keys</div>
        <div style={{fontSize:11,color:THEME.textDim,marginBottom:14,lineHeight:1.6}}>
          Store your API keys to enable one-click detection push from the Library. Keys are saved securely to your account.
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:6}}>
          {TOOLS.map(tool=>(
            <div key={tool.id} style={{border:"1px solid "+(expandedSiem===tool.id?tool.color+"55":THEME.border),borderRadius:8,overflow:"hidden",transition:"border-color 0.15s"}}>
              <div onClick={()=>setExpandedSiem(expandedSiem===tool.id?null:tool.id)}
                style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"10px 14px",cursor:"pointer",background:siemKeys[tool.id]?tool.color+"08":"transparent",transition:"background 0.15s"}}>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <span style={{width:7,height:7,borderRadius:"50%",background:siemKeys[tool.id]?THEME.success:THEME.border,display:"inline-block",flexShrink:0,transition:"background 0.2s"}}/>
                  <span style={{fontSize:12,fontWeight:600,color:siemKeys[tool.id]?THEME.text:THEME.textMid}}>{tool.name}</span>
                  <span style={{fontSize:10,color:tool.color,background:tool.color+"18",border:"1px solid "+tool.color+"33",borderRadius:4,padding:"1px 6px"}}>{tool.lang}</span>
                </div>
                <span style={{fontSize:11,color:THEME.textDim}}>{siemKeys[tool.id]?"✓ Configured":expandedSiem===tool.id?"▲":"▼"}</span>
              </div>
              {expandedSiem===tool.id&&(
                <div style={{padding:"12px 14px",borderTop:"1px solid "+THEME.border,background:"rgba(0,0,0,0.2)",display:"flex",flexDirection:"column",gap:10}}>
                  {["splunk","elastic","qradar","chronicle","sumo"].includes(tool.id)&&(
                    <div>
                      <label style={S.label}>Instance URL</label>
                      <input style={{...S.input,fontFamily:"'JetBrains Mono',monospace",fontSize:11}}
                        placeholder={tool.id==="splunk"?"https://splunk.company.com:8089":tool.id==="elastic"?"https://my-cluster.es.io":tool.id==="sumo"?"https://api.us2.sumologic.com":"https://..."}
                        value={(siemKeys[tool.id+"_url"])||""}
                        onChange={e=>setSiemKeys({...siemKeys,[tool.id+"_url"]:e.target.value})}/>
                    </div>
                  )}
                  <div>
                    <label style={S.label}>API Key / Token</label>
                    <div style={{display:"flex",gap:8}}>
                      <input style={{...S.input,fontFamily:"'JetBrains Mono',monospace",fontSize:11}}
                        type="password"
                        placeholder={"Enter "+tool.name+" API key or token..."}
                        value={siemKeys[tool.id]||""}
                        onChange={e=>setSiemKeys({...siemKeys,[tool.id]:e.target.value})}/>
                      {siemKeys[tool.id]&&(
                        <button style={{...S.btn("d"),padding:"9px 12px"}} onClick={()=>setSiemKeys({...siemKeys,[tool.id]:""})} title="Clear">✕</button>
                      )}
                    </div>
                  </div>
                  {tool.id==="sentinel"&&(
                    <div>
                      <label style={S.label}>Workspace ID</label>
                      <input style={{...S.input,fontFamily:"'JetBrains Mono',monospace",fontSize:11}}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        value={siemKeys["sentinel_workspace"]||""}
                        onChange={e=>setSiemKeys({...siemKeys,sentinel_workspace:e.target.value})}/>
                    </div>
                  )}
                  {tool.id==="crowdstrike"&&(
                    <div>
                      <label style={S.label}>Client ID</label>
                      <input style={{...S.input,fontFamily:"'JetBrains Mono',monospace",fontSize:11}}
                        placeholder="CrowdStrike Client ID"
                        value={siemKeys["crowdstrike_client_id"]||""}
                        onChange={e=>setSiemKeys({...siemKeys,crowdstrike_client_id:e.target.value})}/>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Save Button */}
      <div style={{display:"flex",justifyContent:"flex-end",marginBottom:16}}>
        <button style={{...S.btn("p"),padding:"10px 28px",fontSize:13}} onClick={saveSettings} disabled={saving}>
          {saving?<><Spinner/>Saving...</>:"💾  Save Settings"}
        </button>
      </div>

      {/* Account Security */}
      <div style={S.card}>
        <div style={S.cardTitle}>🔒 Account Security</div>
        {pwStatus&&<StatusBar msg={pwStatus.msg} type={pwStatus.type}/>}
        <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
          <button style={S.btn("s")} onClick={sendPasswordReset}>📧  Send Password Reset</button>
          <button style={S.btn("d")} onClick={onSignOut}>⏏  Sign Out</button>
        </div>
        <div style={{marginTop:10,fontSize:11,color:THEME.textDim}}>
          Password reset email will be sent to <span style={{color:THEME.accent}}>{user.email}</span>
        </div>
      </div>

      {/* SIEM Push Audit Log */}
      <div style={S.card}>
        <div style={{...S.cardTitle,marginBottom:14}}><span>📋</span> SIEM Push Audit Log {auditLoading&&<Spinner/>}</div>
        {auditLog.length===0&&!auditLoading&&<div style={{color:THEME.textDim,fontSize:13,textAlign:"center",padding:20}}>No SIEM pushes recorded yet.</div>}
        <div style={{maxHeight:280,overflowY:"auto"}}>
          {auditLog.map((entry,i)=>(
            <div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"9px 0",borderBottom:"1px solid "+THEME.border}}>
              <span style={{fontSize:10,fontWeight:800,padding:"2px 8px",borderRadius:4,background:entry.status==="success"?THEME.success+"15":THEME.danger+"15",color:entry.status==="success"?THEME.success:THEME.danger,flexShrink:0}}>{entry.status.toUpperCase()}</span>
              <span style={{fontSize:11,fontWeight:700,color:THEME.accent,minWidth:70,flexShrink:0}}>{entry.platform}</span>
              <span style={{fontSize:12,color:THEME.textMid,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{entry.detection_name||"—"}</span>
              <span style={{fontSize:11,color:THEME.textDim,flexShrink:0}}>{new Date(entry.created_at).toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}

// ── Docs Page ─────────────────────────────────────────────────────────────────
const DOCS = [
  {
    id:"getting-started", section:"Getting Started", icon:"🚀", title:"Getting Started with DetectIQ",
    summary:"Build your first production-ready detection in under 5 minutes.",
    content:[
      {h:"What is DetectIQ?", p:"DetectIQ is an AI-powered detection engineering platform. It helps security teams write, test, improve, and deploy SIEM detection rules across Splunk, Microsoft Sentinel, Elastic, CrowdStrike, Chronicle, QRadar, and more — using plain-English threat descriptions instead of raw query syntax."},
      {h:"Quick Start (3 steps)", p:"1. Go to Build → Detection Builder. 2. Select your SIEM, describe the threat (e.g. 'Mimikatz LSASS dump'), and click Generate. 3. Click Save to store it in your Library."},
      {h:"The ADS Framework", p:"DetectIQ uses the Alerting and Detection Strategy (ADS) framework developed by Palantir. Every generated detection includes: Goal, Categorization (MITRE tactic/technique), Strategy Abstract, Technical Context, Blind Spots, False Positives, Validation, and Priority. This ensures production-quality output, not just a raw query."},
      {h:"SIEM Support", p:"10 platforms supported: Splunk (SPL), Microsoft Sentinel (KQL), Elastic/EQL, CrowdStrike Falcon (CQL), Falcon LogScale (LogScale), IBM QRadar (AQL), Google Chronicle (YARA-L), Tanium (Signal), Panther (Python), Sumo Logic."},
      {h:"Authentication", p:"Sign up with email/password. All detections are saved to your account via Supabase. Demo mode is available without an account (detections saved to browser localStorage only)."},
    ]
  },
  {
    id:"builder", section:"Build", icon:"🔨", title:"Detection Builder",
    summary:"AI generates complete detection rules from a plain-English threat description.",
    content:[
      {h:"Overview", p:"The Detection Builder is the core of DetectIQ. Describe an attack scenario and it generates a complete detection rule with full ADS documentation, ready to deploy to your SIEM."},
      {h:"Threat Scenario field", p:"Describe the attack behavior in plain English. Examples: 'PowerShell downloading payload from internet', 'WMI lateral movement to remote host', 'Kerberoasting via impacket'. The more specific, the better the query. Include process names, file paths, or known malware names if relevant."},
      {h:"Log Sample field", p:"Paste a real log line from your SIEM. DetectIQ will ground the query in your actual field names and index/sourcetype, avoiding generic templates that need heavy post-generation tuning. Highly recommended for Splunk and QRadar users."},
      {h:"Beginner Mode", p:"Toggle Beginner Mode (top right of builder) to see simplified explanations of every field, with examples and a step-by-step wizard. Recommended for analysts new to detection engineering."},
      {h:"Score button 🏅", p:"Rates the active detection on 5 dimensions: Specificity, Coverage Breadth, False Positive Risk, Data Source Quality, and MITRE Alignment. Score is 1-10. Aim for 7+ before deploying. Scores below 5 include specific improvement recommendations."},
      {h:"Enrich button 🔍", p:"Pulls threat intelligence context for the detection: related MITRE techniques, known threat actors, affected platforms, recommended data sources, and tuning tips. Runs against the current query."},
      {h:"ML/UBA tab 🧠", p:"Generates behavioral/statistical detection logic instead of static IOC matching. Includes: ML model approach, feature engineering, baseline period, anomaly threshold, Risk Score rules, Risk Based Alerting (RBA) rules, and a User Behavior Analytics (UBA) query. Use the 'Use This Query ↑' button to apply any generated query to the active detection."},
      {h:"Blast Radius tab 💥", p:"Estimates how many alerts per day this detection would fire across 4 org sizes (500, 1k, 5k, 10k endpoints). Helps you decide if a rule needs pre-deployment tuning to avoid alert fatigue."},
      {h:"False Positives tab ⚠️", p:"AI predicts the top 5 legitimate activities that would trigger this rule (e.g. 'IT admin running PowerShell for patch management'). Generates ready-to-paste exclusion logic for Splunk NOT, Elastic must_not, and Sentinel where clauses."},
      {h:"LOTL tab 🔧", p:"Living-off-the-Land coverage. For a given tactic, generates detections for every common built-in OS tool attackers abuse: PowerShell, WMI, certutil, mshta, regsvr32, etc. Each comes with a detection query and evasion notes."},
      {h:"Workflow tab ⚡", p:"Generates a complete incident response workflow for the detection: enrichment steps, containment actions, investigation queries, notification templates, and escalation paths. Useful for building SOAR playbooks."},
      {h:"Deploy tab 🚀", p:"Test the detection, generate Sigma format, create JIRA/ServiceNow tickets, push directly to Splunk or Elastic via API, or export to GitHub. Configure SIEM API credentials in Settings → Account."},
    ]
  },
  {
    id:"library", section:"Analyze", icon:"📚", title:"Detection Library",
    summary:"All your saved detections — search, manage, export, and push to SIEM.",
    content:[
      {h:"Overview", p:"The Library stores every detection you've built or imported. Detections are saved to your Supabase account (or localStorage in demo mode). You can search, filter, edit, export, and push them to your SIEM from here."},
      {h:"Search and Filter", p:"Use the search box to filter by name or threat description. Filter by SIEM platform (Splunk, Elastic, etc.) or by MITRE tactic using the dropdowns. All filters apply simultaneously."},
      {h:"Staleness Badge ⚠", p:"Any detection not updated in 90+ days shows an amber '⚠ Xd old' badge. This is a reminder to review — threat landscapes change, and an old rule may have degraded field names or outdated IOCs."},
      {h:"Version History 📜", p:"Every detection has a full version history. Click '📜 Versions' on any detection card to view past versions, see what changed, restore an older version, or save the current state as a named checkpoint with notes."},
      {h:"Export options", p:"Per-detection: Export (raw query file), SIGMA (AI-generated Sigma format), or SIGMA with AI enrichment. Whole library: Export JSON (full detection objects) or Export CSV (spreadsheet with name, tactic, severity, score, etc.)."},
      {h:"Import JSON", p:"Import a JSON bundle of detections (same format as Export JSON). Useful for migrating detections between accounts or importing community rule packs. Limit: 50 detections per import."},
      {h:"Bulk Select", p:"Click 'Bulk Select' to select multiple detections for batch deletion."},
      {h:"Score / Enrich / Explain / Translate", p:"Each detection card has one-click access to Score (quality rating), Enrich (threat intel context), Explain (plain-English breakdown), and Translate (convert to another SIEM platform)."},
      {h:"Push to SIEM (Beta)", p:"Push directly to Splunk Enterprise or Elastic Security via their REST APIs. Requires API credentials configured in Settings → Account. Also supports SOAR webhook push and JIRA/ServiceNow ticket creation."},
      {h:"Playbook generation 🎭", p:"Generates a full incident response playbook for any detection: detection summary, initial triage steps, investigation queries, containment actions, and escalation criteria."},
    ]
  },
  {
    id:"translator", section:"Build", icon:"🔄", title:"Query Translator",
    summary:"Convert any detection query between 10 SIEM platforms instantly.",
    content:[
      {h:"Overview", p:"Paste a query in any supported language (SPL, KQL, EQL, AQL, YARA-L, CQL, LogScale, Sigma, Python, Sumo Logic) and translate it to any other platform. DetectIQ preserves the detection logic while adapting field names, operators, and syntax to the target platform."},
      {h:"Supported platforms", p:"Splunk SPL ↔ Microsoft Sentinel KQL ↔ Elastic EQL/KQL ↔ IBM QRadar AQL ↔ Google Chronicle YARA-L ↔ CrowdStrike CQL ↔ Falcon LogScale ↔ Tanium Signal ↔ Panther Python ↔ Sumo Logic."},
      {h:"Field mapping", p:"The AI maps common field names across platforms (e.g. Splunk's CommandLine → Elastic's process.command_line → Sentinel's ProcessCommandLine). You can override the mapping by including a log sample."},
      {h:"Limitations", p:"Translation is AI-based, not rule-based. Always validate translated queries against your actual data before deploying. Complex aggregations and joins may need manual adjustment."},
    ]
  },
  {
    id:"explainer", section:"Build", icon:"💡", title:"Detection Explainer",
    summary:"Paste any detection query and get a plain-English breakdown.",
    content:[
      {h:"Overview", p:"The Explainer accepts any query in any supported language and produces: a plain-English summary, line-by-line breakdown, what data sources are required, what attacks it detects, what it misses, and improvement suggestions."},
      {h:"Use cases", p:"Onboarding new analysts to existing rules, auditing inherited detection libraries, understanding community-sourced rules before deploying, and generating documentation for detection reviews."},
      {h:"Output sections", p:"Summary, Detection Logic breakdown, Data Sources required, MITRE mapping, Blind Spots, False Positive scenarios, and Recommended Improvements."},
    ]
  },
  {
    id:"heatmap", section:"Analyze", icon:"🗺", title:"ATT&CK Heatmap",
    summary:"Visual coverage map across all 14 MITRE ATT&CK tactics.",
    content:[
      {h:"Overview", p:"The heatmap shows which MITRE ATT&CK tactics and techniques you have detection coverage for, color-coded by number of rules. Green = 3+ rules, Yellow = 1-2 rules, Red = no coverage."},
      {h:"Gap analysis", p:"The Dashboard home page also shows a Coverage Gap Analysis panel summarizing which tactics are fully covered, partially covered, or completely missing — with specific recommendations for each gap."},
      {h:"MITRE Coverage Score", p:"Shown on the Dashboard: percentage of the 14 MITRE tactics that have at least one detection. 70%+ is considered a solid baseline posture. 100% with 3+ rules per tactic is the target for mature SOC teams."},
    ]
  },
  {
    id:"chain", section:"Build", icon:"🔗", title:"Detection Chain Builder",
    summary:"Chain two detections into one high-fidelity multi-stage correlation rule.",
    content:[
      {h:"Overview", p:"Detection chaining creates a correlation rule that only fires when Detection A AND Detection B both occur on the same entity within a time window. This dramatically reduces false positives while catching multi-stage attacks that single rules miss."},
      {h:"Example", p:"Chain 'PowerShell download' (Execution) + 'New scheduled task created' (Persistence). The chain fires only if both happen on the same host within 15 minutes — high confidence of a staged attack."},
      {h:"Detection A vs B", p:"Detection A should be the earlier-stage event (e.g. Reconnaissance, Initial Access, Execution). Detection B should be the later-stage event (e.g. Persistence, Lateral Movement, Exfiltration). The chain assumes B follows A within the time window."},
      {h:"Correlation Field", p:"The field used to link the two events. Options: host, src_ip, user, dest_ip, process_id, session_id. Choose the field that uniquely identifies the entity moving through the kill chain. For lateral movement, dest_ip is often best. For user-centric attacks, user is best."},
      {h:"Time Window", p:"How many minutes after Detection A fires to look for Detection B. 15 minutes is a sensible default. For slow-and-low attacks, use 60-240 minutes. For fast attacks (ransomware, wiper), use 5 minutes."},
      {h:"Load from library", p:"Use the 'Load from library...' dropdown in each detection panel to auto-fill name and query from any saved detection. You can also type detection names and queries manually."},
      {h:"Output formats", p:"Generates ready-to-deploy versions in: Splunk ES (correlation search), Elastic EQL (sequence query), Microsoft Sentinel (KQL with join), and Google Chronicle (YARA-L with multiple events). Use the tab selector to switch between formats."},
    ]
  },
  {
    id:"replay", section:"Build", icon:"🎮", title:"Log Replay",
    summary:"Dry-run your detection against real log lines before deploying.",
    content:[
      {h:"Overview", p:"Log Replay simulates what your SIEM would do when it processes each log line through your detection query — without needing live SIEM access. The AI evaluates each line and explains why it matches or doesn't match."},
      {h:"How to use", p:"1. Paste your detection query on the left (or load from library using the dropdown). 2. Paste log lines on the right, or click '📁 Upload' to upload a .log/.txt/.json/.csv file. 3. Click 'Run Replay'."},
      {h:"Loading from library", p:"Use the purple 'Load from library' bar at the top to auto-fill any saved detection's query and platform. The badge shows which detection is currently loaded."},
      {h:"Results", p:"You get: total lines evaluated, match count, unmatched count, matched lines (highlighted with reason), unmatched lines, and query analysis (what the query is actually doing vs what you think it's doing)."},
      {h:"Tuning suggestions", p:"The AI flags over-broad or over-restrictive clauses and suggests specific changes. For example: 'CommandLine contains \\'powershell\\' would be improved by adding -enc or -encodedcommand to reduce FPs from legitimate PS usage.'"},
      {h:"Limitations", p:"Log Replay is AI-based simulation, not actual SIEM query execution. It works well for simple field-match queries but may miss edge cases in complex aggregations (stats, timechart) or correlated searches. Always validate in your SIEM before production deployment."},
      {h:"File upload", p:"Supports .log, .txt, .json, and .csv files. Up to 200 lines are evaluated per run. For larger files, sample representative lines."},
    ]
  },
  {
    id:"defend", section:"Build", icon:"🛡", title:"Defend — Honeytokens & DNS Sinkhole",
    summary:"Plant traps that catch attackers with 100% confidence and zero false positives.",
    content:[
      {h:"Overview", p:"The Defend page generates two types of deception-based detection assets: Honeytokens/Canaries and DNS Sinkholes. Unlike behavioral detections that can have false positives, any interaction with a honeytoken or sinkhole is almost certainly malicious."},
      {h:"Honeytokens & Canaries", p:"Fake assets planted in your environment that look real to attackers. Types include: fake Active Directory accounts, canary files (documents with embedded alerts), AWS access keys (that alert on use), DNS canary tokens, and honey SMB shares. Any access to these is immediate, high-confidence evidence of compromise."},
      {h:"Token types generated", p:"Each generated set includes 5+ token types with: deployment instructions (PowerShell/AWS CLI/AD commands), file content or credential values, the SIEM detection query to monitor for usage, and expected alert description."},
      {h:"DNS Sinkhole", p:"Routes known-malicious C2 domains to a controlled IP (0.0.0.0 or a monitoring server) before malware can connect. Generate blocklists and zone configs for: Pi-hole, BIND9 RPZ (Response Policy Zone), Windows DNS Server, and Unbound."},
      {h:"Sinkhole config contents", p:"Each generated config includes: the sinkhole domain list, copy-paste config block for your DNS server, reload/restart commands, and a companion SIEM detection query to alert when any internal host queries a sinkhole domain."},
      {h:"Auto-fill from library", p:"Use the 'Auto-fill from library' dropdown to load threat context from any saved detection. The tool will tailor the honeytokens or sinkhole config to match that specific threat — e.g. a lateral movement detection will generate honeytokens that mimic admin shares and service accounts."},
      {h:"Loaded detection banner", p:"When you auto-fill from library, a blue banner appears showing the detection name, query type, and tactic. Click ✕ to clear and start fresh."},
      {h:"Zero false positives", p:"Honeytokens are never used by legitimate processes. Any alert from a honeytoken is nearly 100% a true positive — no tuning needed, no investigation of FPs. This makes them ideal for 24/7 unattended monitoring."},
    ]
  },
  {
    id:"triage", section:"Analyze", icon:"🎯", title:"Alert Triage",
    summary:"Review, prioritize, and investigate alerts with AI-assisted triage.",
    content:[
      {h:"Overview", p:"Alert Triage helps analysts work through incoming alerts faster by providing AI-assisted context, severity scoring, and investigation steps for each alert."},
      {h:"How to use", p:"Paste alert data (log line, alert text, or JSON) into the triage input and click Triage. The AI evaluates severity, identifies the likely attack type, maps to MITRE, and suggests immediate investigation steps."},
      {h:"From library", p:"Click 'Triage' on any detection in the Library to pre-populate the triage input with the detection's query for quick context-aware triage."},
    ]
  },
  {
    id:"adversary", section:"Analyze", icon:"🤖", title:"Adversary SIEM",
    summary:"Generate adversary campaigns and map each step against your existing detections.",
    content:[
      {h:"Overview", p:"The Adversary SIEM generates realistic multi-stage attack campaigns — including actual attacker commands, TTPs, and lateral movement paths — and cross-references each step against your saved detections to show where you have coverage and where you have blind spots."},
      {h:"How to use", p:"Select a pre-built attack scenario (e.g. ransomware, APT lateral movement, credential theft) or describe a custom threat actor campaign. The AI generates a full kill-chain sequence with real attacker commands, then maps each step to your saved detections."},
      {h:"Coverage report", p:"Each attack step shows: Covered (you have a detection), Partial (detection exists but may miss this variant), or Blind Spot (no detection). Use the 'Build Detection' button on any blind spot to jump to the builder with the gap pre-filled as context."},
      {h:"Campaign Builder", p:"Choose Red Team mode to generate a full attack campaign with real commands and payloads, or Blue Team mode to generate detection-focused documentation. Export a professional campaign debrief report from either mode."},
    ]
  },
  {
    id:"health", section:"Analyze", icon:"❤️", title:"Detection Health",
    summary:"Monitor detection quality, staleness, and coverage gaps across your library.",
    content:[
      {h:"Overview", p:"Detection Health gives you a portfolio-level view of your detection library's quality and completeness. It flags stale rules, scores coverage, and identifies which detections need attention."},
      {h:"Health metrics", p:"Each detection is scored on: Age (days since last update), Score (quality rating from 1-10), Coverage (MITRE tactic/technique), Data Source availability, and last deployment status."},
      {h:"Staleness", p:"Detections older than 90 days are flagged as stale (also shown with ⚠ badge in the Library). Click any stale detection to review and update it."},
    ]
  },
  {
    id:"intel", section:"Intel", icon:"🌐", title:"Threat Intel",
    summary:"Browse live CVEs, CISA KEV, and threat feeds — then build detections directly from them.",
    content:[
      {h:"Overview", p:"The Threat Intel page aggregates real-time threat data: CISA Known Exploited Vulnerabilities (KEV), recent CVEs, and threat actor TTPs. Every item has a 'Build Detection' button to jump straight to the builder with context pre-filled."},
      {h:"CISA KEV feed", p:"The CISA Known Exploited Vulnerabilities catalog lists vulnerabilities actively exploited in the wild. Use these to prioritize which detections to build — if CISA says it's being exploited, you need coverage."},
      {h:"Building from intel", p:"Click 'Build Detection' on any CVE or KEV entry. The builder opens pre-populated with the vulnerability name, affected platform, and known exploitation technique. You just need to select your SIEM and click Generate."},
    ]
  },
  {
    id:"autopilot", section:"Intel", icon:"🤖", title:"Detection Autopilot",
    summary:"Auto-generate detections from threat intel feeds without manual intervention.",
    content:[
      {h:"Overview", p:"Autopilot monitors threat intel feeds and automatically drafts detections for new vulnerabilities and TTPs. Drafts appear in your queue for review before being saved to your library."},
      {h:"How it works", p:"When a new critical CVE or KEV entry appears, Autopilot generates a detection rule for your default SIEM (configured in Settings → Account). It's saved as a draft — you review, edit if needed, and approve to save to library."},
      {h:"Configuration", p:"Set your default SIEM in Settings → Account → Preferences. Autopilot will use this platform for all auto-generated detections."},
    ]
  },
  {
    id:"atomic", section:"Build", icon:"⚛", title:"Atomic Tests",
    summary:"Browse Atomic Red Team tests and build detections directly from attack simulations.",
    content:[
      {h:"Overview", p:"The Atomic Tests library contains hundreds of real-world attack simulations from the Atomic Red Team project. Each test has the actual commands an attacker would run, making it ideal for building high-fidelity detections."},
      {h:"How to use", p:"Browse by MITRE tactic or search for a specific technique. Click any test to see the full command, platform, and description. Click 'Build Detection' to jump to the builder with the test pre-loaded as context."},
      {h:"Import as detection", p:"Click 'Import as Detection' to save the atomic test directly to your library as a detection skeleton, then enrich and refine it using the builder tools."},
    ]
  },
  {
    id:"team", section:"Settings", icon:"👥", title:"Team Workspace",
    summary:"Manage team members, roles, and collaborate on detections.",
    content:[
      {h:"Overview", p:"The Team tab lets you invite colleagues, assign roles (Admin, Engineer, Analyst, Reviewer), and collaborate on detections. Activity logs track who built what and when."},
      {h:"Roles", p:"Admin: full access including delete. Engineer: build and edit detections. Analyst: view and triage only. Reviewer: can comment and approve but not edit."},
      {h:"Comments", p:"Leave comments on specific detections for collaborative review. Tag teammates using @mention in the comment box."},
    ]
  },
  {
    id:"settings", section:"Settings", icon:"⚙️", title:"Account & Settings",
    summary:"Configure your SIEM API keys, profile, and preferences.",
    content:[
      {h:"Profile", p:"Set your display name. Your email (used for login) cannot be changed here — use the password reset flow to update authentication credentials."},
      {h:"Default SIEM", p:"Set your preferred SIEM platform. This is pre-selected across the Builder, Translator, and Explainer tabs so you don't have to choose every time."},
      {h:"SIEM API Keys", p:"Store API keys for Splunk, Elastic, Sentinel, CrowdStrike, and others to enable one-click detection push from the Library. Keys are stored securely in your account. For Splunk, provide instance URL + token (or username/password). For Elastic, provide instance URL + API key."},
      {h:"Account Security", p:"Send a password reset email or sign out from this page."},
      {h:"SIEM Push Audit Log", p:"Every detection push to a SIEM is logged here with timestamp, platform, detection name, and success/failure status. Useful for audit trails and compliance reporting."},
    ]
  },
  {
    id:"metrics", section:"Analyze", icon:"📊", title:"Metrics Dashboard",
    summary:"Track detection engineering activity, coverage trends, and team output over time.",
    content:[
      {h:"Overview", p:"The Metrics Dashboard shows activity over time: detections built per week, coverage growth across MITRE tactics, severity distribution, and SIEM platform breakdown."},
      {h:"Coverage trend", p:"Track how your MITRE coverage score has grown month-over-month. Use this to demonstrate detection engineering ROI to leadership."},
    ]
  },
  {
    id:"community", section:"Intel", icon:"🌍", title:"Community",
    summary:"Share detections with the DetectIQ community and clone rules built by others.",
    content:[
      {h:"Overview", p:"The Community tab is a shared detection library where users can publish their detections for others to clone and use. All community detections are reviewed for quality before appearing publicly."},
      {h:"Sharing", p:"Click 'Share' on any detection in your Library to publish it. You can choose to share anonymously or with your display name."},
      {h:"Cloning", p:"Click 'Clone' on any community detection to copy it to your Library. You can then edit and customize it for your environment."},
      {h:"Star ratings", p:"Star community detections you find useful. Stars help surface high-quality rules for other users."},
    ]
  },
];

function DocsPage({ onNav }) {
  const [search, setSearch] = useState("");
  const [activeDoc, setActiveDoc] = useState(null);
  const [activeSection, setActiveSection] = useState("All");

  const sections = ["All", ...Array.from(new Set(DOCS.map(d => d.section)))];

  const filtered = DOCS.filter(doc => {
    const matchSection = activeSection === "All" || doc.section === activeSection;
    if (!search.trim()) return matchSection;
    const q = search.toLowerCase();
    const inTitle = doc.title.toLowerCase().includes(q);
    const inSummary = doc.summary.toLowerCase().includes(q);
    const inContent = doc.content.some(c => c.h.toLowerCase().includes(q) || c.p.toLowerCase().includes(q));
    return matchSection && (inTitle || inSummary || inContent);
  });

  // highlight matching text
  function hl(text) {
    if (!search.trim()) return text;
    const idx = text.toLowerCase().indexOf(search.toLowerCase());
    if (idx === -1) return text;
    return <>{text.slice(0, idx)}<mark style={{background:THEME.accent+"33",color:THEME.accent,borderRadius:2,padding:"0 2px"}}>{text.slice(idx, idx+search.length)}</mark>{text.slice(idx+search.length)}</>;
  }

  // Find sections matching search even if content matches
  function sectionMatchCount(section) {
    return DOCS.filter(d => {
      const q = search.toLowerCase();
      if (!q) return d.section === section || section === "All";
      const match = d.title.toLowerCase().includes(q) || d.summary.toLowerCase().includes(q) || d.content.some(c => c.h.toLowerCase().includes(q) || c.p.toLowerCase().includes(q));
      return match && (section === "All" || d.section === section);
    }).length;
  }

  return (
    <div>
      <SectionHeader icon="📖" title="Documentation" color={THEME.accent}>
        <span style={S.badge(THEME.accent)}>{DOCS.length} articles</span>
      </SectionHeader>
      <HelpBox title="Documentation Quick Reference" color={THEME.accent} items={[
        {icon:"🔍",title:"Search",desc:"Use the search bar to find articles by keyword. Results match article titles, summaries, and body content."},
        {icon:"🏷",title:"Filter by category",desc:"Click a category tag (Getting Started, Detection, Analysis, etc.) to browse articles by topic."},
        {icon:"↗️",title:"Open in context",desc:"Each article has an 'Open →' button that navigates directly to the relevant tab in the platform — so you can read and do at the same time."},
        {icon:"💡",title:"Tip",desc:"If you're new, start with the 'Getting Started' category — it covers the full workflow from building your first detection to pushing it to your SIEM."},
      ]}/>

      {/* Search */}
      <div style={{...S.card, padding:"14px 16px", marginBottom:16, display:"flex", gap:12, alignItems:"center"}}>
        <span style={{fontSize:16, opacity:0.6}}>🔍</span>
        <input
          autoFocus
          style={{...S.input, flex:1, fontSize:14, border:"none", background:"transparent", padding:"4px 0"}}
          placeholder="Search all docs — e.g. 'false positive', 'export CSV', 'honeytoken', 'correlation field'..."
          value={search}
          onChange={e => { setSearch(e.target.value); setActiveDoc(null); }}
        />
        {search && <button style={{...S.btn(), padding:"4px 10px", fontSize:11}} onClick={() => setSearch("")}>Clear</button>}
      </div>

      <div style={{display:"grid", gridTemplateColumns:"200px 1fr", gap:16, alignItems:"start"}}>
        {/* Sidebar */}
        <div style={{position:"sticky", top:20}}>
          <div style={{fontSize:10, fontWeight:800, color:THEME.textDim, letterSpacing:"0.1em", marginBottom:10, paddingLeft:4}}>SECTIONS</div>
          {sections.map(s => {
            const count = sectionMatchCount(s);
            return (
              <div key={s} onClick={() => { setActiveSection(s); setActiveDoc(null); }}
                style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"8px 12px",borderRadius:7,cursor:"pointer",marginBottom:3,background:activeSection===s?"rgba(79,142,247,0.1)":"transparent",border:"1px solid "+(activeSection===s?THEME.accentDim+"44":"transparent"),transition:"all 0.15s"}}
                onMouseEnter={e=>{ if(activeSection!==s) e.currentTarget.style.background="rgba(255,255,255,0.03)"; }}
                onMouseLeave={e=>{ if(activeSection!==s) e.currentTarget.style.background="transparent"; }}
              >
                <span style={{fontSize:12, fontWeight:activeSection===s?700:400, color:activeSection===s?THEME.accent:THEME.textMid}}>{s}</span>
                {search && <span style={{fontSize:10, color:count>0?THEME.accent:THEME.textDim, background:count>0?THEME.accentGlow:"transparent", borderRadius:10, padding:"1px 6px"}}>{count}</span>}
              </div>
            );
          })}

          <div style={{height:1, background:THEME.border, margin:"12px 4px"}}/>
          <div style={{fontSize:10, fontWeight:800, color:THEME.textDim, letterSpacing:"0.1em", marginBottom:10, paddingLeft:4}}>QUICK LINKS</div>
          {[
            {label:"Build your first detection", tab:"builder"},
            {label:"View your library", tab:"library"},
            {label:"Check threat intel", tab:"intel"},
            {label:"ATT&CK heatmap", tab:"heatmap"},
          ].map(l => (
            <div key={l.tab} onClick={() => onNav(l.tab)}
              style={{padding:"7px 12px",borderRadius:7,cursor:"pointer",marginBottom:3,fontSize:12,color:THEME.accent,display:"flex",alignItems:"center",gap:6}}
              onMouseEnter={e=>e.currentTarget.style.background="rgba(79,142,247,0.06)"}
              onMouseLeave={e=>e.currentTarget.style.background="transparent"}
            >
              <span style={{fontSize:10}}>→</span>{l.label}
            </div>
          ))}
        </div>

        {/* Main content */}
        <div>
          {search && filtered.length === 0 && (
            <div style={{...S.card, textAlign:"center", padding:48}}>
              <div style={{fontSize:32, marginBottom:10}}>🔍</div>
              <div style={{fontSize:14, fontWeight:600, color:THEME.text, marginBottom:6}}>No results for "{search}"</div>
              <div style={{fontSize:12, color:THEME.textDim}}>Try a different search term or browse by section.</div>
            </div>
          )}

          {/* Article detail view */}
          {activeDoc && !search && (() => {
            const doc = DOCS.find(d => d.id === activeDoc);
            if (!doc) return null;
            return (
              <div>
                <button style={{...S.btn(), padding:"6px 14px", fontSize:12, marginBottom:14}} onClick={() => setActiveDoc(null)}>← Back</button>
                <div style={S.card}>
                  <div style={{display:"flex", alignItems:"center", gap:10, marginBottom:6}}>
                    <span style={{fontSize:24}}>{doc.icon}</span>
                    <div>
                      <div style={{fontSize:11, color:THEME.accent, fontWeight:600, marginBottom:2}}>{doc.section}</div>
                      <div style={{fontSize:20, fontWeight:800, color:THEME.text, fontFamily:"'Syne',sans-serif"}}>{doc.title}</div>
                    </div>
                  </div>
                  <div style={{fontSize:13, color:THEME.textMid, marginBottom:20, paddingBottom:16, borderBottom:"1px solid "+THEME.border, lineHeight:1.7}}>{doc.summary}</div>
                  {doc.content.map((block, i) => (
                    <div key={i} style={{marginBottom:20}}>
                      <div style={{fontSize:13, fontWeight:700, color:THEME.text, marginBottom:6, display:"flex", alignItems:"center", gap:8}}>
                        <span style={{width:3, height:16, background:THEME.accent, borderRadius:2, display:"inline-block", flexShrink:0}}/>
                        {block.h}
                      </div>
                      <div style={{fontSize:12, color:THEME.textMid, lineHeight:1.8, paddingLeft:11}}>{block.p}</div>
                    </div>
                  ))}
                  <div style={{marginTop:20, paddingTop:16, borderTop:"1px solid "+THEME.border, display:"flex", gap:8, flexWrap:"wrap"}}>
                    {doc.id !== "getting-started" && (
                      <button style={{...S.btn("p"), padding:"8px 18px", fontSize:12}} onClick={() => { const TAB_MAP={"getting-started":"home","atomic":"usecases","heatmap":"heatmap","metrics":"metrics","community":"community"}; onNav(TAB_MAP[doc.id]||doc.id); }}>Open {doc.title} →</button>
                    )}
                    <button style={{...S.btn(), padding:"8px 18px", fontSize:12}} onClick={() => setActiveDoc(null)}>← Back to Docs</button>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Article list */}
          {(!activeDoc || search) && (
            <div style={{display:"flex", flexDirection:"column", gap:10}}>
              {filtered.map(doc => {
                // Find matching content blocks for search
                const matchingBlocks = search ? doc.content.filter(c =>
                  c.h.toLowerCase().includes(search.toLowerCase()) ||
                  c.p.toLowerCase().includes(search.toLowerCase())
                ) : [];
                return (
                  <div key={doc.id}
                    onClick={() => { if (!search) { setActiveDoc(doc.id); } }}
                    style={{...S.card, cursor:search?"default":"pointer", transition:"border-color 0.15s", marginBottom:0}}
                    onMouseEnter={e=>{ if(!search) e.currentTarget.style.borderColor=THEME.accent+"44"; }}
                    onMouseLeave={e=>{ if(!search) e.currentTarget.style.borderColor=THEME.border; }}
                  >
                    <div style={{display:"flex", alignItems:"flex-start", gap:12}}>
                      <div style={{width:40,height:40,borderRadius:10,background:THEME.accentGlow,border:"1px solid "+THEME.accentDim+"33",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,flexShrink:0}}>{doc.icon}</div>
                      <div style={{flex:1, minWidth:0}}>
                        <div style={{display:"flex", alignItems:"center", gap:8, marginBottom:4}}>
                          <span style={{fontSize:10, color:THEME.accent, fontWeight:700, background:THEME.accentGlow, padding:"2px 7px", borderRadius:4}}>{doc.section}</span>
                        </div>
                        <div style={{fontSize:14, fontWeight:700, color:THEME.text, marginBottom:4}}>{hl(doc.title)}</div>
                        <div style={{fontSize:12, color:THEME.textMid, lineHeight:1.6}}>{hl(doc.summary)}</div>
                        {/* Show matching content snippets when searching */}
                        {matchingBlocks.length > 0 && (
                          <div style={{marginTop:10, display:"flex", flexDirection:"column", gap:8}}>
                            {matchingBlocks.slice(0, 2).map((block, i) => (
                              <div key={i} style={{padding:"8px 12px", background:"rgba(79,142,247,0.05)", border:"1px solid "+THEME.accentDim+"22", borderRadius:6}}>
                                <div style={{fontSize:11, fontWeight:700, color:THEME.accent, marginBottom:4}}>{hl(block.h)}</div>
                                <div style={{fontSize:11, color:THEME.textMid, lineHeight:1.6}}>{hl(block.p.length > 180 ? block.p.slice(0, 180) + "…" : block.p)}</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                      {!search && <span style={{fontSize:18, color:THEME.textDim, flexShrink:0}}>→</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function GettingStartedPage({onNav,detections}){
  const steps=[
    {
      num:1,
      icon:"🔨",
      title:"Build Your First Detection",
      color:"#00d4ff",
      tab:"builder",
      summary:"Describe a threat in plain English — DetectIQ writes the detection rule for you.",
      bullets:[
        "Type a scenario like \"detect lateral movement via PsExec\" or pick a MITRE tactic",
        "AI generates a complete Splunk SPL, KQL, or EQL rule with field mappings",
        "Get an automatic Quality Score (0–10) based on specificity, field coverage, and false-positive risk",
        "Add enrichments — Threat Intel lookups, GeoIP, WHOIS — with one click",
        "Save to your Detection Library and push to your SIEM",
      ],
      cta:"Open Detection Builder",
    },
    {
      num:2,
      icon:"📋",
      title:"Review & Score Your Detections",
      color:"#00e87a",
      tab:"library",
      summary:"Your Detection Library tracks every rule you build with version history and quality scoring.",
      bullets:[
        "Each detection gets a score from 0–10 — click it to see why (what's missing, what's strong)",
        "Staleness badges flag rules older than 90 days that may need updating",
        "Filter by tactic, severity, SIEM platform, or ADS framework compliance",
        "Export to Sigma format for platform-agnostic portability",
        "One-click push to Splunk, Sentinel, Elastic, or CrowdStrike",
      ],
      cta:"Open Detection Library",
    },
    {
      num:3,
      icon:"🔄",
      title:"Translate Across Platforms",
      color:"#a855f7",
      tab:"translator",
      summary:"Already have rules in Splunk? Convert them to Sentinel KQL or Elastic EQL instantly.",
      bullets:[
        "Paste any query — SPL, KQL, EQL, YARA-L, QRadar AQL, and more",
        "AI translates field names, functions, and syntax to your target platform",
        "Supports 10 SIEM/EDR platforms including CrowdStrike, Chronicle, and Sumo Logic",
        "Flags fields that don't exist on the target platform so you can fix them",
      ],
      cta:"Open Translator",
    },
    {
      num:4,
      icon:"🎮",
      title:"Test Before You Deploy",
      color:"#f59e0b",
      tab:"replay",
      summary:"Dry-run your detection against real log samples before pushing to production.",
      bullets:[
        "Pick any saved detection and paste log lines to test against",
        "AI evaluates which log lines would trigger the rule and which wouldn't",
        "Catch false positives and tune your rule before it goes live",
        "Compare two detections side-by-side on the same log set",
      ],
      cta:"Open Log Replay",
    },
    {
      num:5,
      icon:"🗺",
      title:"Check Your MITRE Coverage",
      color:"#ff7700",
      tab:"heatmap",
      summary:"See which ATT&CK tactics you're covered for and where your gaps are.",
      bullets:[
        "The Honeycomb on your Dashboard shows tactic coverage at a glance",
        "Open the full ATT&CK Heatmap for technique-level detail",
        "Gap badges show tactics with zero detections — click to build one",
        "Run AI Gap Analysis to get prioritized recommendations based on your environment",
        "Target 3+ rules per tactic for a Strong posture (shown in green)",
      ],
      cta:"Open ATT&CK Heatmap",
    },
    {
      num:6,
      icon:"🔗",
      title:"Chain Multi-Stage Detections",
      color:"#00d4ff",
      tab:"chain",
      summary:"Correlate two detections into a kill-chain rule that fires only when both conditions are met.",
      bullets:[
        "Pick two saved detections and define the time window between them",
        "AI generates a correlation rule in your chosen SIEM format",
        "Ideal for detecting lateral movement + persistence, or recon + exfiltration",
        "Reduces alert fatigue by requiring multiple signals before firing",
      ],
      cta:"Open Detection Chain",
    },
    {
      num:7,
      icon:"🛡",
      title:"Defend with Traps & Sinkholing",
      color:"#ef4444",
      tab:"defend",
      summary:"Deploy honeytokens and DNS sinkholes — any trigger is a 100%-confidence alert.",
      bullets:[
        "Generate fake AD accounts, canary files, and AWS honeytokens",
        "Create DNS sinkhole configs for Pi-hole, BIND9, or Windows DNS Server",
        "Import any saved detection to auto-generate a matching defence trap",
        "Honeytoken alerts have near-zero false positives — if it fires, something is wrong",
      ],
      cta:"Open Defend",
    },
  ];

  const done=detections.length>0;

  return(
    <div>
      {/* Hero */}
      <div style={{...S.card,background:"linear-gradient(135deg,rgba(0,212,255,0.06) 0%,rgba(0,232,122,0.04) 100%)",border:"1px solid rgba(0,212,255,0.18)",marginBottom:24,padding:"28px 32px"}}>
        <div style={{display:"flex",alignItems:"flex-start",gap:20}}>
          <div style={{fontSize:40,lineHeight:1}}>🚀</div>
          <div style={{flex:1}}>
            <div style={{fontSize:22,fontWeight:800,color:THEME.text,marginBottom:6,letterSpacing:"-0.02em"}}>
              Welcome to DetectIQ
            </div>
            <div style={{fontSize:14,color:THEME.textMid,lineHeight:1.7,maxWidth:680,marginBottom:16}}>
              DetectIQ is your AI-powered detection engineering platform. Follow the steps below to go from zero to a fully-covered MITRE ATT&CK posture — each step builds on the last.
            </div>
            <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
              <button style={{...S.btn("p"),padding:"9px 20px",fontSize:13,fontWeight:700}} onClick={()=>onNav("builder")}>
                Start Building Detections →
              </button>
              <button style={{...S.btn(),padding:"9px 20px",fontSize:13}} onClick={()=>onNav("home")}>
                View Dashboard
              </button>
            </div>
          </div>
          {done&&(
            <div style={{textAlign:"center",padding:"14px 20px",background:"rgba(0,232,122,0.08)",border:"1px solid rgba(0,232,122,0.2)",borderRadius:10,flexShrink:0}}>
              <div style={{fontSize:28,fontWeight:900,color:THEME.success,lineHeight:1}}>{detections.length}</div>
              <div style={{fontSize:10,color:THEME.textDim,marginTop:2}}>detections built</div>
            </div>
          )}
        </div>
      </div>

      {/* Steps */}
      <div style={{display:"flex",flexDirection:"column",gap:16}}>
        {steps.map((step,idx)=>(
          <div key={step.num} style={{...S.card,marginBottom:0,border:"1px solid "+step.color+"22",transition:"border-color 0.2s"}}
            onMouseEnter={e=>e.currentTarget.style.borderColor=step.color+"55"}
            onMouseLeave={e=>e.currentTarget.style.borderColor=step.color+"22"}>
            <div style={{display:"flex",gap:16,alignItems:"flex-start"}}>
              {/* Step number */}
              <div style={{width:44,height:44,borderRadius:12,background:step.color+"14",border:"1px solid "+step.color+"33",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                <div style={{fontSize:18,lineHeight:1}}>{step.icon}</div>
                <div style={{fontSize:8,color:step.color,fontWeight:800,fontFamily:"'JetBrains Mono',monospace",marginTop:1}}>0{step.num}</div>
              </div>
              {/* Content */}
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:6,flexWrap:"wrap"}}>
                  <div style={{fontSize:15,fontWeight:700,color:THEME.text}}>{step.title}</div>
                  <span style={{...S.badge(step.color),fontSize:9}}>Step {step.num}</span>
                </div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:12,lineHeight:1.6}}>{step.summary}</div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:14}}>
                  {step.bullets.map((b,i)=>(
                    <div key={i} style={{display:"flex",alignItems:"flex-start",gap:7,padding:"7px 12px",background:step.color+"08",border:"1px solid "+step.color+"18",borderRadius:8,fontSize:11,color:THEME.textMid,lineHeight:1.5,flex:"1 1 260px",minWidth:0}}>
                      <span style={{color:step.color,fontWeight:700,flexShrink:0,marginTop:1}}>›</span>
                      <span>{b}</span>
                    </div>
                  ))}
                </div>
                <button style={{...S.btn("p"),padding:"7px 18px",fontSize:12,background:step.color+"18",border:"1px solid "+step.color+"44",color:step.color}}
                  onClick={()=>onNav(step.tab)}
                  onMouseEnter={e=>{e.currentTarget.style.background=step.color+"30";}}
                  onMouseLeave={e=>{e.currentTarget.style.background=step.color+"18";}}>
                  {step.cta} →
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Footer tip */}
      <div style={{marginTop:20,padding:"14px 20px",background:"rgba(255,255,255,0.02)",border:"1px solid "+THEME.border,borderRadius:10,display:"flex",alignItems:"center",gap:12}}>
        <span style={{fontSize:20}}>💡</span>
        <div style={{fontSize:12,color:THEME.textMid,lineHeight:1.6}}>
          <span style={{color:THEME.text,fontWeight:600}}>Pro tip: </span>
          You don't need to follow the steps in order. If you already have Splunk rules, start at <span style={{color:"#a855f7",cursor:"pointer",fontWeight:600}} onClick={()=>onNav("translator")}>Step 3 — Translator</span>. If you want to see your MITRE gaps first, jump to <span style={{color:THEME.orange,cursor:"pointer",fontWeight:600}} onClick={()=>onNav("heatmap")}>Step 5 — ATT&CK Map</span>.
        </div>
      </div>
    </div>
  );
}

const NAV_STRUCTURE=[
  {id:"start",label:"Get Started",icon:"🚀",desc:"Step-by-step guide to building your first detection and exploring the platform"},
  {id:"home",label:"Dashboard",icon:"🏠",desc:"Overview of your detections, coverage, and activity"},
  {groupId:"build",label:"Build",icon:"🔨",desc:"Create and manage detections",children:[
    {id:"builder",label:"Detection Builder",desc:"AI-powered builder — generate SPL/KQL/EQL detections from a scenario or tactic"},
    {id:"translator",label:"Translator",desc:"Convert queries between SIEM platforms (Splunk ↔ Sentinel ↔ Elastic, etc.)"},
    {id:"usecases",label:"Atomic Tests",desc:"Browse and simulate Atomic Red Team tests to validate your detections"},
    {id:"chain",label:"Detection Chain",desc:"Chain two detections into a multi-stage correlation rule — flags kill chain sequences"},
    {id:"replay",label:"Log Replay",desc:"Dry-run your detection against real log lines before deploying — AI evaluates which lines match"},
    {id:"defend",label:"Defend",desc:"Honeytokens, canary traps, and DNS sinkhole configs — catch attackers with zero false positives"},
  ]},
  {groupId:"analyze",label:"Analyze",icon:"📊",desc:"Analyze and improve detection coverage",children:[
    {id:"library",label:"Library",desc:"All your saved detections — search, edit, export, or push to SIEM"},
    {id:"heatmap",label:"ATT&CK Map",desc:"MITRE ATT&CK heatmap showing which tactics and techniques you have coverage for"},
    {id:"triage",label:"Triage",desc:"Review and prioritize detections by severity, quality score, and gaps"},
    {id:"adversary",label:"Adversary SIEM",desc:"Simulate adversary behavior and map it against your SIEM detections"},
    {id:"health",label:"Detection Health",desc:"Monitor detection quality, false positive rates, and coverage gaps"},
  ]},
  {groupId:"intel",label:"Intel",icon:"🌐",desc:"Threat intelligence and automated detection",children:[
    {id:"intel",label:"Threat Intel",desc:"Browse CVEs, KEV catalog, and threat feeds to inform your detections"},
    {id:"autopilot",label:"Autopilot",desc:"Auto-generate detections from threat intel feeds and CVE advisories"},
  ]},
  {groupId:"config",label:"Settings",icon:"⚙️",desc:"Configure integrations and account",children:[
    {id:"team",label:"Team",desc:"Manage team members, roles, and collaboration settings"},
    {id:"settings",label:"Account",desc:"API keys, SIEM integrations, profile, and billing"},
    {id:"docs",label:"Documentation",desc:"Full searchable docs — every feature explained with examples"},
  ]},
];

// flat map for lookups
const NAV_ITEMS=NAV_STRUCTURE.flatMap(n=>n.children?n.children:[n]);
const NAV_GROUPS=[];// kept for compat, unused

function DetectIQLogo({size="sm",onClick,theme="dark"}){
  const sz=size==="xl"?52:size==="lg"?32:size==="md"?22:18;
  const wordSz=size==="xl"?Math.round(sz*0.72):Math.round(sz*0.82);
  const dim=theme==="light"?"#1a2a3a":"#4a5e72";
  return(
    <span style={{display:"inline-flex",alignItems:"center",gap:Math.round(sz*0.32),cursor:onClick?"pointer":"default",userSelect:"none"}} onClick={onClick}>
      <svg width={sz} height={sz} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M16 3L5 7.5V14.5C5 21 9.5 27 16 29C22.5 27 27 21 27 14.5V7.5L16 3Z" fill="rgba(0,212,255,0.07)" stroke="#00d4ff" strokeWidth="1.5" strokeLinejoin="round"/>
        <path d="M11 16l3.5 3.5L21 12" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
      {size!=="icon"&&(
        <span style={{lineHeight:1}}>
          <span style={{display:"block",fontSize:wordSz,fontWeight:800,letterSpacing:"-0.025em",lineHeight:1}}><span style={{color:"#e8f4ff"}}>Detect</span><span style={{color:"#00d4ff"}}>IQ</span></span>
          {size==="sm"&&<span style={{display:"block",fontSize:Math.round(sz*0.5),color:dim,fontWeight:400,letterSpacing:"0.02em",marginTop:1}}>v5.5</span>}
        </span>
      )}
    </span>
  );
}

function NavTooltip({text,visible,y}){
  if(!visible||!text)return null;
  return(
    <div style={{position:"fixed",left:228,top:y-12,zIndex:9999,pointerEvents:"none",background:"#0a0f1e",border:"1px solid "+THEME.borderBright,borderRadius:7,padding:"7px 12px",maxWidth:240,boxShadow:"0 4px 20px rgba(0,0,0,0.6)"}}>
      <div style={{fontSize:11,color:THEME.text,lineHeight:1.5}}>{text}</div>
      <div style={{position:"absolute",left:-5,top:14,width:8,height:8,background:"#0a0f1e",border:"1px solid "+THEME.borderBright,borderRight:"none",borderTop:"none",transform:"rotate(45deg)"}}/>
    </div>
  );
}

function Sidebar({tab,setTab,collapsed,setCollapsed,detections,user,onSignIn,onSignOut,autopilotDrafts=0,kevCount=0}){
  // auto-expand group containing active tab
  const activeGroup=NAV_STRUCTURE.find(n=>n.children&&n.children.some(c=>c.id===tab))?.groupId||null;
  const[expanded,setExpanded]=useState(()=>new Set(activeGroup?[activeGroup]:[]));
  const[tooltip,setTooltip]=useState({visible:false,text:"",y:0});
  const tooltipTimer=useRef(null);

  // keep group open when tab changes
  useEffect(()=>{
    if(activeGroup)setExpanded(p=>new Set([...p,activeGroup]));
  },[activeGroup]);

  const toggleGroup=gid=>setExpanded(p=>{const n=new Set(p);n.has(gid)?n.delete(gid):n.add(gid);return n;});

  const showTip=(e,text)=>{
    if(!text)return;
    clearTimeout(tooltipTimer.current);
    const rect=e.currentTarget.getBoundingClientRect();
    tooltipTimer.current=setTimeout(()=>setTooltip({visible:true,text,y:rect.top+rect.height/2}),400);
  };
  const hideTip=()=>{clearTimeout(tooltipTimer.current);setTooltip({visible:false,text:"",y:0});};

  const badge=(id)=>{
    if(id==="library"&&detections.length>0)return<span style={{marginLeft:"auto",fontSize:10,background:THEME.accent+"18",color:THEME.accent,borderRadius:10,padding:"0 6px",fontWeight:600}}>{detections.length}</span>;
    if(id==="autopilot"&&autopilotDrafts>0)return<span style={{marginLeft:"auto",fontSize:10,background:THEME.warning+"18",color:THEME.warning,borderRadius:10,padding:"0 6px",fontWeight:600}}>{autopilotDrafts}</span>;
    if(id==="intel"&&kevCount>0)return<span style={{marginLeft:"auto",fontSize:9,background:THEME.danger+"18",color:THEME.danger,borderRadius:3,padding:"0 5px",fontWeight:600}}>NEW</span>;
    return null;
  };

  return(
    <div style={{width:collapsed?56:220,background:THEME.sidebar,borderRight:"1px solid "+THEME.sidebarBorder,display:"flex",flexDirection:"column",height:"100vh",position:"sticky",top:0,flexShrink:0,transition:"width 0.2s ease",overflow:"hidden"}}>
      <NavTooltip text={tooltip.text} visible={tooltip.visible} y={tooltip.y}/>
      {/* Logo */}
      <div style={{height:56,display:"flex",alignItems:"center",justifyContent:collapsed?"center":"space-between",padding:collapsed?"0":"0 16px",borderBottom:"1px solid "+THEME.sidebarBorder,flexShrink:0}}>
        {!collapsed&&<DetectIQLogo size="sm" onClick={()=>setTab("home")}/>}
        <button onClick={()=>setCollapsed(!collapsed)} style={{background:"transparent",border:"none",color:THEME.textDim,cursor:"pointer",padding:"4px 6px",fontSize:14,lineHeight:1}}>{collapsed?"›":"‹"}</button>
      </div>

      {/* Nav items */}
      <div style={{flex:1,overflowY:"auto",overflowX:"hidden",padding:"8px 0"}}>
        {NAV_STRUCTURE.map(item=>{
          if(!item.children){
            // single item (Dashboard)
            const active=tab===item.id;
            return(
              <div key={item.id} onClick={()=>setTab(item.id)}
                style={{display:"flex",alignItems:"center",gap:10,padding:collapsed?"10px 0":"8px 16px",cursor:"pointer",background:active?THEME.accent+"12":"transparent",borderLeft:active?"2px solid "+THEME.accent:"2px solid transparent",transition:"all 0.12s",justifyContent:collapsed?"center":"flex-start",marginBottom:2}}
                onMouseEnter={e=>{if(!active)e.currentTarget.style.background=THEME.accent+"07";showTip(e,item.desc);}}
                onMouseLeave={e=>{if(!active)e.currentTarget.style.background="transparent";hideTip();}}>
                <span style={{fontSize:14,flexShrink:0,color:active?THEME.accent:THEME.textDim}}>{item.icon}</span>
                {!collapsed&&<span style={{fontSize:12,fontWeight:active?600:500,color:active?THEME.text:THEME.textMid}}>{item.label}</span>}
              </div>
            );
          }
          // group with children
          const isOpen=expanded.has(item.groupId);
          const hasActive=item.children.some(c=>c.id===tab);
          return(
            <div key={item.groupId} style={{marginBottom:2}}>
              {/* Group header */}
              <div onClick={()=>collapsed?setTab(item.children[0].id):toggleGroup(item.groupId)}
                style={{display:"flex",alignItems:"center",gap:10,padding:collapsed?"10px 0":"7px 16px",cursor:"pointer",transition:"all 0.12s",justifyContent:collapsed?"center":"flex-start",borderLeft:hasActive?"2px solid "+THEME.accent+"55":"2px solid transparent"}}
                onMouseEnter={e=>{e.currentTarget.style.background=THEME.accent+"06";showTip(e,item.desc);}}
                onMouseLeave={e=>{e.currentTarget.style.background="transparent";hideTip();}}>
                <span style={{fontSize:14,flexShrink:0,color:hasActive?THEME.accent:THEME.textDim}}>{item.icon}</span>
                {!collapsed&&<>
                  <span style={{fontSize:12,fontWeight:600,color:hasActive?THEME.text:THEME.textMid,flex:1}}>{item.label}</span>
                  <span style={{fontSize:10,color:THEME.textDim,transition:"transform 0.15s",display:"inline-block",transform:isOpen?"rotate(90deg)":"rotate(0deg)"}}>›</span>
                </>}
              </div>
              {/* Sub-items — hidden in collapsed mode */}
              {isOpen&&!collapsed&&item.children.map(child=>{
                const active=tab===child.id;
                return(
                  <div key={child.id} onClick={()=>setTab(child.id)}
                    style={{display:"flex",alignItems:"center",gap:8,padding:"6px 16px 6px 34px",cursor:"pointer",background:active?THEME.accent+"10":"transparent",borderLeft:active?"2px solid "+THEME.accent:"2px solid transparent",transition:"all 0.12s"}}
                    onMouseEnter={e=>{if(!active)e.currentTarget.style.background=THEME.accent+"07";showTip(e,child.desc);}}
                    onMouseLeave={e=>{if(!active)e.currentTarget.style.background="transparent";hideTip();}}>
                    <span style={{fontSize:11,color:active?THEME.text:THEME.textMid,fontWeight:active?600:400,flex:1}}>{child.label}</span>
                    {badge(child.id)}
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>

      {/* User footer */}
      <div style={{borderTop:"1px solid "+THEME.sidebarBorder,padding:collapsed?"10px 0":"10px 12px",flexShrink:0}}>
        {user?(
          <div style={{display:"flex",alignItems:"center",gap:8,justifyContent:collapsed?"center":"flex-start"}}>
            <div style={{width:28,height:28,borderRadius:"50%",background:"linear-gradient(135deg,"+THEME.accent+"30,"+THEME.purple+"30)",border:"1px solid "+THEME.accentDim,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:THEME.accent,flexShrink:0,cursor:"pointer"}} title="Settings" onClick={()=>setTab("settings")}>{user.email.slice(0,2).toUpperCase()}</div>
            {!collapsed&&<div style={{flex:1,minWidth:0}}><div style={{fontSize:11,color:THEME.text,fontWeight:600,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{user.email.split("@")[0]}</div><div style={{fontSize:10,color:THEME.textDim,cursor:"pointer"}} onClick={onSignOut}>Sign out</div></div>}
          </div>
        ):(
          <div style={{display:"flex",justifyContent:collapsed?"center":"flex-start"}}>
            {collapsed
              ?<div onClick={onSignIn} style={{width:28,height:28,borderRadius:"50%",background:THEME.accentGlow,border:"1px solid "+THEME.accentDim,display:"flex",alignItems:"center",justifyContent:"center",cursor:"pointer",fontSize:12}} title="Sign In">→</div>
              :<button style={{...S.btn("p"),width:"100%",padding:"7px",fontSize:11,justifyContent:"center",display:"flex"}} onClick={onSignIn}>Sign In / Sign Up</button>
            }
          </div>
        )}
      </div>
    </div>
  );
}

function DemoBanner({onSignIn}){
  return(
    <div style={{background:"linear-gradient(90deg,rgba(255,170,0,0.08),rgba(255,170,0,0.04))",borderBottom:"1px solid rgba(255,170,0,0.2)",padding:"8px 24px",display:"flex",alignItems:"center",justifyContent:"space-between",fontSize:12,flexShrink:0}}>
      <span style={{color:THEME.textMid}}><span style={{color:THEME.warning,fontWeight:800,marginRight:8}}>DEMO MODE</span>Detections saved locally only.</span>
      <button style={{...S.btn("p"),padding:"5px 14px",fontSize:11}} onClick={onSignIn}>Sign In Free</button>
    </div>
  );
}

// ── Lazy Tab Mount ─────────────────────────────────────────────────────────────
// Only mounts a tab's content the first time it's visited.
// After that, it stays mounted but hidden (preserving state).
function LazyTab({ id, tab, children, skeleton }) {
  const [mounted, setMounted] = useState(false);
  const [ready, setReady] = useState(false);
  const isActive = tab === id;

  useEffect(() => {
    if (isActive && !mounted) {
      setMounted(true);
      // Small delay so the skeleton shows first, making the UI feel responsive
      const t = setTimeout(() => setReady(true), 80);
      return () => clearTimeout(t);
    }
    if (isActive && mounted) setReady(true);
  }, [isActive, mounted]);

  if (!mounted) return isActive ? <div>{skeleton}</div> : null;

  return (
    <div style={{display: isActive ? "block" : "none"}}>
      {!ready ? skeleton : children}
    </div>
  );
}


function AppInner(){
  const{user,loading,signOut}=useAuth();
  const VALID_TABS=["start","home","builder","usecases","translator","explainer","library","heatmap","triage","adversary","health","intel","team","autopilot","metrics","community","settings","chain","replay","defend","docs"];
  const[tab,setTab]=useState(()=>{const p=window.location.pathname.replace(/^\//,"");return VALID_TABS.includes(p)?p:"home";});
  useEffect(()=>{
    const url=tab==="home"?"/":"/"+tab;
    if(window.location.pathname!==url)window.history.pushState({tab},"",url);
  },[tab]);
  useEffect(()=>{
    const onPop=()=>{
      const p=window.location.pathname.replace(/^\//,"");
      setTab(VALID_TABS.includes(p)?p:"home");
    };
    window.addEventListener("popstate",onPop);
    return()=>window.removeEventListener("popstate",onPop);
  },[]);
  const[showLogin,setShowLogin]=useState(false);
  const[showOnboarding,setShowOnboarding]=useState(false);
  useEffect(()=>{
    if(!LS.get("onboarding_done",false)&&user){
      setShowOnboarding(true);
    }
  },[user]);
  const[demoMode,setDemoMode]=useState(false);
  const[collapsed,setCollapsed]=useState(false);
  const[sidebarOpen,setSidebarOpen]=useState(false);
  const[cmdkOpen,setCmdkOpen]=useState(false);
  const[cmdkQuery,setCmdkQuery]=useState("");
  useEffect(()=>{
    function onKey(e){
      if((e.metaKey||e.ctrlKey)&&e.key==="k"){e.preventDefault();setCmdkOpen(o=>!o);setCmdkQuery("");}
      if(e.key==="Escape")setCmdkOpen(false);
    }
    window.addEventListener("keydown",onKey);
    return()=>window.removeEventListener("keydown",onKey);
  },[]);
  const[detections,setDetections]=useState([]);
  const[dbLoading,setDbLoading]=useState(false);
  const[triagePrefill,setTriagePrefill]=useState("");
  const[explainerPrefill,setExplainerPrefill]=useState({query:"",tool:""});
  const[translatorPrefill,setTranslatorPrefill]=useState({query:"",tool:""});
  const[builderPrefill,setBuilderPrefill]=useState(()=>{if(window.location.pathname!=="/builder")return {scenario:"",tactic:""};const p=new URLSearchParams(window.location.search);return p.get("tactic")?{tactic:p.get("tactic")||"",scenario:p.get("scenario")||""}:{scenario:"",tactic:""};});
  useEffect(()=>{if(tab==="builder"&&builderPrefill.tactic){window.history.replaceState({},"","/builder?tactic="+encodeURIComponent(builderPrefill.tactic)+(builderPrefill.scenario?"&scenario="+encodeURIComponent(builderPrefill.scenario):""));}},[builderPrefill,tab]);

  useEffect(()=>{
    if(user){setDbLoading(true);fetchDetectionsFromDB(user.id).then(d=>setDetections(d)).catch(console.error).finally(()=>setDbLoading(false));}
    else{setDetections(LS.get("detectiq_detections",[]));}
  },[user]);

  async function saveDetection(det){
    if(user){try{const saved=await saveDetectionToDB(user.id,det);setDetections(p=>[saved,...p]);}catch(err){alert("Save failed: "+err.message);}}
    else{const u=[det,...detections];setDetections(u);LS.set("detectiq_detections",u);}
  }
  async function deleteDetection(id){
    if(user){try{await deleteDetectionFromDB(id);}catch(e){console.error(e);}}
    else{LS.set("detectiq_detections",detections.filter(d=>d.id!==id));}
    setDetections(p=>p.filter(d=>d.id!==id));
  }
  async function updateDetection(det){
    if(user){try{await updateDetectionInDB(det);}catch(e){console.error(e);}}
    else{const u=detections.map(d=>d.id===det.id?det:d);LS.set("detectiq_detections",u);}
    setDetections(p=>p.map(d=>d.id===det.id?det:d));
  }

  function handleSendToTriage(logEvent){
    setTriagePrefill(logEvent);
    setTab("triage");
  }

  function handleSendToBuilder(scenario,tactic){
    setBuilderPrefill({scenario,tactic});
    setTab("builder");
  }

  function handleHunt(name,ttps){
    setBuilderPrefill({scenario:"Threat hunt for "+name+": "+ttps,tactic:"Discovery"});
    setTab("builder");
  }

  if(loading){return(<div style={{minHeight:"100vh",background:THEME.bg,display:"flex",alignItems:"center",justifyContent:"center"}}><div style={{textAlign:"center"}}><div style={{marginBottom:14}}><DetectIQLogo size="lg"/></div><Spinner/><span style={{color:THEME.textDim,fontSize:13}}>Loading...</span></div></div>);}

  if(!user&&!demoMode){
  const FEATURES=[
    {title:"AI Detection Builder",desc:"Generate production-ready rules in SPL, KQL, EQL, and more from a plain-English threat description. Full ADS framework output — query, false positives, blind spots, and tuning guide."},
    {title:"Detection Chain Builder",desc:"Chain two detections into a single multi-stage correlation rule. Fires only when both events occur on the same host within your time window — dramatically reducing false positives."},
    {title:"Log Replay",desc:"Dry-run your detection against real log lines before deploying. AI evaluates each line, explains matches, and suggests query tuning — no SIEM access needed."},
    {title:"Blast Radius & FP Estimator",desc:"Know your alert volume before you deploy. Estimates daily alerts across 4 org sizes, then predicts the top false-positive scenarios with ready-to-paste exclusion logic."},
    {title:"Threat Intel + Autopilot",desc:"Live CISA KEV feed, CVE tracking, and AI APT profiles. Autopilot auto-drafts detections for new vulnerabilities — one-click review and save to library."},
    {title:"Detection Library",desc:"Every saved detection with version history, staleness badges, quality scoring, Sigma export, and one-click push to Splunk, Elastic, Sentinel, or SOAR."},
    {title:"Query Translator",desc:"Translate detection queries between 10 platforms — Splunk SPL, Sentinel KQL, CrowdStrike CQL, Elastic EQL, Chronicle YARA-L, QRadar AQL, and more."},
    {title:"Defend — Honeytokens & Sinkhole",desc:"Generate honeytoken configs (fake AD accounts, canary files, AWS keys) and DNS sinkhole rules (Pi-hole, BIND9, Windows DNS). Any trap trigger is a 100%-confidence alert."},
    {title:"ATT&CK Coverage Dashboard",desc:"Real-time MITRE coverage score, tactic-by-tactic progress bars, gap analysis with actionable recommendations, and full interactive heatmap."},
  ];
  const ROLES=[
    {role:"SOC Analysts",desc:"Triage alerts faster with AI verdicts on any raw log or SIEM alert. Get confidence scores, attack classification, and recommended containment actions instantly.",color:"#00d4ff"},
    {role:"Detection Engineers",desc:"Build, score, translate, and deploy rules across your SIEM stack. Dry-run with Log Replay, estimate blast radius, predict false positives — before a single alert fires.",color:"#00d4ff"},
    {role:"Threat Hunters",desc:"Build hunt hypotheses from live CISA KEV and APT intel. Chain detections across the kill chain, then replay logs to validate coverage before committing to production.",color:"#00d4ff"},
    {role:"Security Architects",desc:"Track MITRE ATT&CK coverage across all 14 tactics. Identify gaps, measure detection maturity, and plan coverage roadmaps with data-driven gap analysis.",color:"#00d4ff"},
  ];
  return(
    <>
      <style>{`
        *{box-sizing:border-box;margin:0;padding:0;}
        body{background:#040810;overflow-x:hidden;font-family:'Inter',system-ui,-apple-system,sans-serif;}
        @keyframes spin{to{transform:rotate(360deg);}}
        @keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
        @keyframes subtlepulse{0%,100%{opacity:0.35}50%{opacity:0.65}}
        ::-webkit-scrollbar{width:5px;}
        ::-webkit-scrollbar-track{background:#040810;}
        ::-webkit-scrollbar-thumb{background:#162436;border-radius:3px;}
        .lp-btn-primary{padding:11px 28px;border-radius:7px;font-size:13px;font-weight:700;cursor:pointer;border:none;background:#00d4ff;color:#040810;transition:all 0.15s;font-family:inherit;letter-spacing:-0.01em;}
        .lp-btn-primary:hover{background:#22d4f8;transform:translateY(-1px);}
        .lp-btn-secondary{padding:11px 28px;border-radius:7px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid #162436;background:transparent;color:#d0dce8;transition:all 0.15s;font-family:inherit;}
        .lp-btn-secondary:hover{border-color:#243850;color:#e8f4ff;}
        .lp-nav-btn{padding:7px 16px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid #0f1c2e;background:transparent;color:#4a5e72;transition:all 0.15s;font-family:inherit;}
        .lp-nav-btn:hover{color:#d0dce8;border-color:#162436;}
        .lp-nav-btn.p{border-color:#00d4ff;background:rgba(0,212,255,0.08);color:#00d4ff;}
        .lp-nav-btn.p:hover{background:rgba(0,212,255,0.14);}
        .lp-feat{padding:20px;border-radius:0;border:none;background:#060b12;transition:all 0.18s;cursor:default;border-left:3px solid transparent;}
        .lp-feat:hover{background:#0a1120;border-left-color:#00d4ff;}
        .lp-role{padding:22px 20px;border-radius:8px;border:1px solid #0f1c2e;background:#070c14;border-top:2px solid #0f1c2e;transition:background 0.18s;}
        .lp-role:hover{background:#0a1120;}
        .lp-stat-divider{width:1px;background:#0f1c2e;height:36px;flex-shrink:0;}
      `}</style>

      {/* Sticky nav */}
      <div style={{position:"sticky",top:0,zIndex:100,background:"rgba(4,8,16,0.97)",backdropFilter:"blur(12px)",borderBottom:"1px solid #0f1c2e",padding:"0 48px",height:52,display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <DetectIQLogo size="md"/>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <button className="lp-nav-btn" onClick={()=>setDemoMode(true)}>Live Demo</button>
          <button className="lp-nav-btn p" onClick={()=>setShowLogin(true)}>Sign In</button>
        </div>
      </div>

      {/* Hero — left/right split */}
      <div style={{maxWidth:1200,margin:"0 auto",padding:"72px 48px 64px",display:"flex",alignItems:"center",gap:56,animation:"fadeup 0.45s ease forwards",position:"relative"}}>
        <div style={{position:"absolute",width:500,height:300,borderRadius:"50%",filter:"blur(80px)",background:"rgba(0,212,255,0.04)",top:"10%",right:"5%",animation:"subtlepulse 5s ease-in-out infinite",pointerEvents:"none"}}/>

        {/* Left column — 55% */}
        <div style={{flex:"0 0 55%",minWidth:0}}>
          <div style={{fontSize:10,fontWeight:700,color:"#00d4ff",letterSpacing:"0.18em",marginBottom:20,textTransform:"uppercase"}}>Detection Engineering Platform</div>
          <h1 style={{fontSize:"clamp(32px,3.8vw,48px)",fontWeight:800,lineHeight:1.12,letterSpacing:"-0.03em",marginBottom:18,color:"#e8f4ff",fontFamily:"'Inter',system-ui,sans-serif"}}>
            Build detection coverage<br/><span style={{color:"#00d4ff"}}>that holds.</span>
          </h1>
          <p style={{fontSize:15,color:"#4a5e72",lineHeight:1.75,marginBottom:36,maxWidth:480,fontFamily:"'Inter',system-ui,sans-serif"}}>
            The complete detection engineering workbench. Build AI-powered detections with the ADS framework, translate across 10 SIEMs, dry-run with Log Replay, triage alerts instantly, and track your full MITRE ATT&CK coverage — all in one place.
          </p>
          <div style={{display:"flex",gap:10,flexWrap:"wrap",marginBottom:48}}>
            <button className="lp-btn-primary" onClick={()=>setShowLogin(true)}>Get Started Free</button>
            <button className="lp-btn-secondary" onClick={()=>setDemoMode(true)}>Explore Demo</button>
          </div>
          {/* Stats row */}
          <div style={{display:"flex",alignItems:"center",gap:0}}>
            {[["10","SIEM Platforms"],["14","MITRE Tactics"],["7+","AI Tools"],["ADS","Framework"]].map(([n,l],i,arr)=>(
              <div key={l} style={{display:"flex",alignItems:"center"}}>
                <div style={{paddingRight:28,paddingLeft:i===0?0:28,borderLeft:i===0?"none":"1px solid #1a2536"}}>
                  <div style={{fontSize:28,fontWeight:800,color:"#00d4ff",lineHeight:1,letterSpacing:"-0.03em",fontFamily:"'Inter',system-ui,sans-serif"}}>{n}</div>
                  <div style={{fontSize:10,color:"#3a4e62",marginTop:5,letterSpacing:"0.1em",textTransform:"uppercase",fontWeight:500}}>{l}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right column — 45% compact browser mockup */}
        <div style={{flex:"0 0 45%",minWidth:0}}>
          <div style={{background:"#060b12",border:"1px solid #0f1c2e",borderRadius:12,overflow:"hidden",boxShadow:"0 24px 64px rgba(0,0,0,0.5)"}}>
            <div style={{padding:"9px 14px",background:"#040810",borderBottom:"1px solid #0f1c2e",display:"flex",alignItems:"center",gap:8}}>
              <div style={{display:"flex",gap:5}}>
                <div style={{width:9,height:9,borderRadius:"50%",background:"#1a2030"}}/>
                <div style={{width:9,height:9,borderRadius:"50%",background:"#1a2030"}}/>
                <div style={{width:9,height:9,borderRadius:"50%",background:"#1a2030"}}/>
              </div>
              <div style={{flex:1,background:"#070c14",border:"1px solid #0f1c2e",borderRadius:4,padding:"3px 10px",fontSize:9,color:"#2a3a4a",textAlign:"center"}}>detect-iq.com</div>
            </div>
            <div style={{padding:14,display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              {/* ADS card */}
              <div style={{background:"#040810",border:"1px solid rgba(0,212,255,0.12)",borderRadius:8,padding:12,display:"flex",flexDirection:"column",gap:7}}>
                <div style={{display:"flex",alignItems:"center",gap:5}}>
                  <div style={{width:5,height:5,borderRadius:"50%",background:"#00d4ff",opacity:0.9}}/>
                  <div style={{fontSize:7,fontWeight:700,color:"#2a5060",letterSpacing:"0.12em"}}>ADS BUILDER</div>
                </div>
                <div style={{fontSize:10,fontWeight:700,color:"#e8f4ff",lineHeight:1.3}}>Ransomware via BITS Transfer</div>
                <div style={{display:"flex",gap:3}}>
                  <span style={{padding:"1px 5px",borderRadius:3,fontSize:7,fontWeight:600,background:"rgba(0,212,255,0.08)",color:"#00d4ff",border:"1px solid rgba(0,212,255,0.18)"}}>T1197</span>
                  <span style={{padding:"1px 5px",borderRadius:3,fontSize:7,fontWeight:600,background:"rgba(0,212,255,0.04)",color:"#4a6070",border:"1px solid #0f1c2e"}}>SPL</span>
                </div>
                <div style={{background:"#02050a",border:"1px solid #0f1c2e",borderRadius:4,padding:"6px 8px",fontSize:7,color:"#4a7a90",fontFamily:"monospace",lineHeight:1.7}}>
                  index=wineventlog EventCode=4688<br/>
                  | where process_name='bitsadmin.exe'<br/>
                  | rex field=cmd 'Transfer ...'<br/>
                  | table _time, host, user
                </div>
                <div style={{display:"flex",gap:4}}>
                  <div style={{flex:1,padding:"4px 0",borderRadius:4,background:"rgba(0,212,255,0.06)",border:"1px solid rgba(0,212,255,0.15)",fontSize:7,fontWeight:600,color:"#00d4ff",textAlign:"center"}}>Save</div>
                  <div style={{flex:1,padding:"4px 0",borderRadius:4,background:"#040810",border:"1px solid #0f1c2e",fontSize:7,fontWeight:600,color:"#4a5e72",textAlign:"center"}}>Push</div>
                </div>
              </div>
              {/* MITRE coverage — single cyan palette */}
              <div style={{background:"#040810",border:"1px solid #0f1c2e",borderRadius:8,padding:12,display:"flex",flexDirection:"column",gap:7}}>
                <div style={{fontSize:7,fontWeight:700,color:"#2a5060",letterSpacing:"0.12em"}}>ATT&CK COVERAGE</div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:3,flex:1}}>
                  {[["Init. Access",3,0.9],["Execution",5,1.0],["Persistence",4,0.8],["Priv. Esc.",2,0.5],["Def. Evasion",6,1.0],["Cred. Access",3,0.7],["Discovery",4,0.8],["Lat. Move",2,0.5],["Impact",1,0.3]].map(([n,cnt,op])=>(
                    <div key={n} style={{background:`rgba(0,212,255,${op*0.07})`,border:`1px solid rgba(0,212,255,${op*0.18})`,borderRadius:4,padding:"4px 3px",textAlign:"center"}}>
                      <div style={{fontSize:6,color:`rgba(0,212,255,${0.4+op*0.5})`,fontWeight:600,lineHeight:1.2}}>{n}</div>
                      <div style={{fontSize:9,fontWeight:700,color:`rgba(0,212,255,${0.5+op*0.4})`,marginTop:1}}>{cnt}</div>
                    </div>
                  ))}
                </div>
                <div style={{padding:"4px 7px",background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.1)",borderRadius:4,fontSize:7,color:"#2a5060",fontWeight:600}}>9/14 tactics covered</div>
              </div>
              {/* Triage verdict — full width */}
              <div style={{gridColumn:"1/-1",background:"#040810",border:"1px solid #0f1c2e",borderRadius:8,padding:12}}>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:6}}>
                  <div style={{fontSize:7,fontWeight:700,color:"#2a5060",letterSpacing:"0.12em"}}>AI TRIAGE VERDICT</div>
                  <div style={{padding:"2px 8px",borderRadius:3,background:"rgba(0,212,255,0.06)",border:"1px solid rgba(0,212,255,0.15)",fontSize:7,fontWeight:700,color:"#00d4ff"}}>97% confidence</div>
                </div>
                <div style={{fontSize:7,color:"#2a4050",fontFamily:"monospace",background:"#02050a",borderRadius:4,padding:"5px 7px",marginBottom:6,lineHeight:1.6}}>
                  svchost.exe spawns net.exe /add — LSASS memory access from cmd.exe
                </div>
                <div style={{padding:"5px 8px",background:"rgba(180,40,40,0.04)",border:"1px solid rgba(180,40,40,0.15)",borderRadius:4}}>
                  <div style={{fontSize:8,fontWeight:700,color:"#c84040"}}>TRUE POSITIVE — Defense Evasion + Credential Access</div>
                  <div style={{fontSize:7,color:"#3a4a5a",marginTop:2}}>Recommended: Isolate host, escalate to IR</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Features */}
      <div style={{padding:"64px 48px",borderTop:"1px solid #0f1c2e"}}>
        <div style={{maxWidth:1100,margin:"0 auto"}}>
          <div style={{fontSize:9,fontWeight:700,color:"#00d4ff",letterSpacing:"0.2em",marginBottom:12,textTransform:"uppercase"}}>Platform</div>
          <div style={{fontSize:26,fontWeight:700,color:"#d0dce8",marginBottom:36,letterSpacing:"-0.02em"}}>Everything in one workbench.</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:1,background:"#0f1c2e",borderRadius:10,overflow:"hidden"}}>
            {FEATURES.map(f=>(
              <div key={f.title} className="lp-feat" style={{borderRadius:0,background:"#060b12"}}>
                <div style={{fontSize:12,fontWeight:700,color:"#d0dce8",marginBottom:7}}>{f.title}</div>
                <div style={{fontSize:12,color:"#4a5e72",lineHeight:1.65}}>{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Who it's for */}
      <div style={{padding:"64px 48px",background:"#060b12",borderTop:"1px solid #0f1c2e",borderBottom:"1px solid #0f1c2e"}}>
        <div style={{maxWidth:1100,margin:"0 auto"}}>
          <div style={{fontSize:9,fontWeight:700,color:"#00d4ff",letterSpacing:"0.2em",marginBottom:12,textTransform:"uppercase"}}>Built for</div>
          <div style={{fontSize:26,fontWeight:700,color:"#d0dce8",marginBottom:36,letterSpacing:"-0.02em"}}>Every role on the security team.</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))",gap:12}}>
            {ROLES.map(r=>(
              <div key={r.role} className="lp-role">
                <div style={{fontSize:13,fontWeight:700,color:r.color,marginBottom:8}}>{r.role}</div>
                <div style={{fontSize:12,color:"#4a5e72",lineHeight:1.65}}>{r.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom CTA */}
      <div style={{padding:"64px 48px",borderBottom:"1px solid #0f1c2e"}}>
        <div style={{maxWidth:560}}>
          <div style={{fontSize:26,fontWeight:700,marginBottom:10,letterSpacing:"-0.02em"}}><span style={{color:"#e8f4ff"}}>Start building </span><span style={{color:"#00d4ff"}}>better detections.</span></div>
          <div style={{fontSize:13,color:"#4a5e72",marginBottom:28,lineHeight:1.7}}>Free to use. No credit card required. Full platform access from day one.</div>
          <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
            <button className="lp-btn-primary" onClick={()=>setShowLogin(true)}>Create Free Account</button>
            <button className="lp-btn-secondary" onClick={()=>setDemoMode(true)}>Explore Demo</button>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div style={{padding:"20px 48px",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:12}}>
        <DetectIQLogo size="sm"/>
        <div style={{fontSize:10,color:"#1e2e3e",textAlign:"right"}}>ATT&amp;CK® and MITRE ATT&amp;CK® are registered trademarks of The MITRE Corporation. Used under MITRE's free use policy.</div>
      </div>

      {showLogin&&<LoginModal onClose={()=>setShowLogin(false)} onDemo={()=>{setDemoMode(true);setShowLogin(false);}}/>}
      {showOnboarding&&user&&<OnboardingModal user={user} onComplete={(siem,goal)=>{
        setShowOnboarding(false);
        if(goal==="build")setTab("builder");
        else if(goal==="hunt")setTab("triage");
        else if(goal==="simulate")setTab("adversary");
      }}/>}
    </>
  );}

  return(
    <>
      <style>{`
        *{box-sizing:border-box;margin:0;padding:0;}
        body{background:#05080f;font-family:'Courier New',monospace;}
        @keyframes spin{to{transform:rotate(360deg);}}
        @keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
        ::-webkit-scrollbar{width:5px;}
        ::-webkit-scrollbar-track{background:#05080f;}
        ::-webkit-scrollbar-thumb{background:#1e2d45;border-radius:3px;}
        ::-webkit-scrollbar-thumb:hover{background:#243040;}
        select option{background:#0a0e1a;color:#dce8f0;}
        input:focus,textarea:focus,select:focus{border-color:#0088aa!important;box-shadow:0 0 0 3px rgba(0,136,170,0.06)!important;}
        button:hover:not(:disabled){opacity:0.82;transform:translateY(-1px);}
        button:active:not(:disabled){transform:translateY(0);}
        button:disabled{opacity:0.4;cursor:not-allowed;}
        @media (max-width: 768px) {
          .detect-sidebar { display: none !important; }
          .detect-sidebar.mobile-open { display: flex !important; position: fixed; z-index: 500; left: 0; top: 0; bottom: 0; width: 260px; }
          .detect-main { margin-left: 0 !important; padding: 12px !important; }
          .detect-grid2 { grid-template-columns: 1fr !important; }
          .detect-grid3 { grid-template-columns: 1fr !important; }
          .mobile-menu-btn { display: block !important; }
        }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      `}</style>
      <button style={{display:"none",position:"fixed",top:14,left:14,zIndex:600,background:THEME.surface,border:"1px solid "+THEME.border,borderRadius:8,padding:"6px 10px",cursor:"pointer",fontSize:18}} className="mobile-menu-btn" onClick={()=>setSidebarOpen(o=>!o)}>☰</button>
      <div style={{display:"flex",height:"100vh",overflow:"hidden",background:THEME.bg,fontFamily:"'Courier New',monospace",color:THEME.text}}>
        <div className={sidebarOpen?"detect-sidebar mobile-open":"detect-sidebar"} style={{display:"flex",flexDirection:"column",height:"100vh",position:"sticky",top:0,flexShrink:0}}>
          <Sidebar tab={tab} setTab={(t)=>{setTab(t);setSidebarOpen(false);}} collapsed={collapsed} setCollapsed={setCollapsed} detections={detections} user={user} onSignIn={()=>setShowLogin(true)} onSignOut={signOut} autopilotDrafts={LS.get("autopilot_drafts",[]).filter(d=>!LS.get("autopilot_dismissed",{})[d.cve_id]).length} kevCount={0}/>
        </div>
        <div className="detect-main" style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
          <div style={{height:56,borderBottom:"1px solid "+THEME.sidebarBorder,display:"flex",alignItems:"center",justifyContent:"space-between",padding:"0 28px",flexShrink:0,background:THEME.bg}}>
            <div style={{fontSize:13,fontWeight:700,color:THEME.textMid}}>{NAV_ITEMS.find(n=>n.id===tab)?.icon} {NAV_ITEMS.find(n=>n.id===tab)?.label}</div>
            <div style={S.flex}>
              {dbLoading&&<><Spinner/><span style={{fontSize:11,color:THEME.textDim}}>Syncing...</span></>}
              <span style={{fontSize:11,color:THEME.textDim}}><span style={{color:THEME.success,marginRight:4}}>●</span>{detections.length} rules</span>
              {!user&&<span style={{...S.badge(THEME.warning),fontSize:10}}>DEMO</span>}
            </div>
          </div>
          {!user&&demoMode&&<DemoBanner onSignIn={()=>setShowLogin(true)}/>}
          <div style={{flex:1,overflowY:"auto",padding:"28px 32px"}}>
            <LazyTab id="start" tab={tab} skeleton={<SkeletonCard/>}>
              <GettingStartedPage detections={detections} onNav={setTab}/>
            </LazyTab>
            <LazyTab id="home" tab={tab} skeleton={<SkeletonDashboard/>}>
              <DashboardHome detections={detections} onNav={setTab} user={user}/>
            </LazyTab>
            <LazyTab id="builder" tab={tab} skeleton={<div style={S.card}><Skeleton width="40%" height={22} style={{marginBottom:16}}/><SkeletonGrid count={2}/></div>}>
              <DetectionBuilder onSave={saveDetection} onSendToTriage={handleSendToTriage} prefill={builderPrefill}/>
            </LazyTab>
            <LazyTab id="usecases" tab={tab} skeleton={<SkeletonGrid count={6}/>}>
              <AtomicTests onImport={saveDetection} onBuildOn={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("builder");}}/>
            </LazyTab>
            <LazyTab id="translator" tab={tab} skeleton={<SkeletonCard/>}>
              <QueryTranslator prefill={translatorPrefill}/>
            </LazyTab>
            <LazyTab id="explainer" tab={tab} skeleton={<SkeletonCard/>}>
              <DetectionExplainer prefill={explainerPrefill}/>
            </LazyTab>
            <LazyTab id="library" tab={tab} skeleton={<SkeletonGrid count={4}/>}>
              <DetectionLibrary
                detections={detections}
                onDelete={deleteDetection}
                onUpdate={updateDetection}
                onBuildOn={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("builder");}}
                onSendToTriage={(query)=>{setTriagePrefill(query);setTab("triage");}}
                onExplain={(query,tool)=>{setExplainerPrefill({query,tool});setTab("explainer");}}
                onTranslate={(query,tool)=>{setTranslatorPrefill({query,tool});setTab("translator");}}
              />
            </LazyTab>
            <LazyTab id="heatmap" tab={tab} skeleton={<SkeletonCard/>}>
              <AttackHeatmap detections={detections}/>
            </LazyTab>
            <LazyTab id="triage" tab={tab} skeleton={<SkeletonCard/>}>
              <AlertTriage prefillAlert={triagePrefill}/>
            </LazyTab>
            <LazyTab id="adversary" tab={tab} skeleton={<SkeletonGrid count={4}/>}>
              <AdversarySIEM detections={detections}/>
            </LazyTab>
            <LazyTab id="health" tab={tab} skeleton={<SkeletonGrid count={4}/>}>
              <DetectionHealth detections={detections} onUpdate={updateDetection} onBuildOn={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("builder");}} onNav={setTab}/>
            </LazyTab>
            <LazyTab id="intel" tab={tab} skeleton={<div style={S.grid2}><SkeletonCard/><SkeletonCard/></div>}>
              <ThreatIntel onBuildDetection={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("builder");}} onSimulate={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("adversary");}} onHunt={handleHunt}/>
            </LazyTab>
            <LazyTab id="autopilot" tab={tab} skeleton={<SkeletonCard/>}>
              <AutopilotTab user={user} detections={detections} onSaveDetection={det=>{setDetections(p=>[det,...p]);saveDetection(det);}} onNav={setTab}/>
            </LazyTab>
            <LazyTab id="team" tab={tab} skeleton={<div style={S.grid2}><SkeletonCard/><SkeletonCard/></div>}>
              <TeamWorkspace detections={detections} user={user}/>
            </LazyTab>
            <LazyTab id="metrics" tab={tab} skeleton={<SkeletonCard/>}>
              <MetricsDashboard detections={detections}/>
            </LazyTab>
            <LazyTab id="community" tab={tab} skeleton={<div style={S.grid2}><SkeletonCard/><SkeletonCard/></div>}>
              <CommunityTab user={user} detections={detections} onCloneDetection={det=>{const newDet={...det,id:uid(),created:new Date().toISOString()};setDetections(p=>[newDet,...p]);if(user){saveDetection(newDet);}else{const u=[newDet,...detections];setDetections(u);LS.set("detectiq_detections",u);}}}/>
            </LazyTab>
            <LazyTab id="settings" tab={tab} skeleton={<SkeletonCard/>}>
              <UserSettingsTab user={user} onSignOut={()=>supabase.auth.signOut()}/>
            </LazyTab>
            <LazyTab id="chain" tab={tab} skeleton={<SkeletonCard/>}>
              <DetectionChain detections={detections}/>
            </LazyTab>
            <LazyTab id="replay" tab={tab} skeleton={<SkeletonCard/>}>
              <LogReplay detections={detections}/>
            </LazyTab>
            <LazyTab id="defend" tab={tab} skeleton={<SkeletonCard/>}>
              <DefendPage detections={detections}/>
            </LazyTab>
            <LazyTab id="docs" tab={tab} skeleton={<SkeletonCard/>}>
              <DocsPage onNav={setTab}/>
            </LazyTab>
          </div>
        </div>
      </div>
      {showLogin&&<LoginModal onClose={()=>setShowLogin(false)} onDemo={()=>{setDemoMode(true);setShowLogin(false);}}/>}
      {cmdkOpen&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.7)",zIndex:9999,display:"flex",alignItems:"flex-start",justifyContent:"center",paddingTop:"15vh"}} onClick={()=>setCmdkOpen(false)}>
          <div style={{background:"#0d1825",border:"1px solid "+THEME.accent+"44",borderRadius:14,width:"100%",maxWidth:580,boxShadow:"0 24px 64px rgba(0,212,255,0.15)"}} onClick={e=>e.stopPropagation()}>
            <div style={{padding:"16px 20px",borderBottom:"1px solid #1a2a3a",display:"flex",alignItems:"center",gap:10}}>
              <span style={{color:THEME.textDim,fontSize:14}}>🔍</span>
              <input autoFocus style={{...S.input,border:"none",background:"transparent",fontSize:15,flex:1,padding:0}} value={cmdkQuery} onChange={e=>setCmdkQuery(e.target.value)} placeholder="Search detections..."/>
              <span style={{fontSize:11,color:THEME.textDim,background:"#1a2a3a",padding:"2px 6px",borderRadius:4}}>ESC</span>
            </div>
            <div style={{maxHeight:360,overflowY:"auto",padding:"8px 0"}}>
              {detections.filter(d=>!cmdkQuery||d.name.toLowerCase().includes(cmdkQuery.toLowerCase())||d.tactic?.toLowerCase().includes(cmdkQuery.toLowerCase())||d.threat?.toLowerCase().includes(cmdkQuery.toLowerCase())).slice(0,12).map(d=>(
                <div key={d.id} style={{padding:"10px 20px",cursor:"pointer",display:"flex",alignItems:"center",gap:12,borderRadius:8,margin:"2px 8px"}} onClick={()=>{setTab("library");setCmdkOpen(false);}} onMouseEnter={e=>e.currentTarget.style.background="#1a2a3a"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                  <span style={{fontSize:11,fontWeight:700,color:THEME.accent,minWidth:30,fontFamily:"monospace"}}>{d.queryType||d.tool||"?"}</span>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:13,fontWeight:700,color:THEME.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.name}</div>
                    <div style={{fontSize:11,color:THEME.textDim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.tactic} · {d.severity}</div>
                  </div>
                  <span style={{fontSize:10,color:d.score>7?THEME.success:d.score>4?THEME.warning:THEME.textDim,fontWeight:700}}>{d.score?d.score+"/10":""}</span>
                </div>
              ))}
              {detections.filter(d=>!cmdkQuery||d.name.toLowerCase().includes(cmdkQuery.toLowerCase())||d.tactic?.toLowerCase().includes(cmdkQuery.toLowerCase())||d.threat?.toLowerCase().includes(cmdkQuery.toLowerCase())).length===0&&(
                <div style={{padding:"24px 20px",textAlign:"center",color:THEME.textDim,fontSize:13}}>No detections match "{cmdkQuery}"</div>
              )}
              {!cmdkQuery&&detections.length===0&&<div style={{padding:"24px 20px",textAlign:"center",color:THEME.textDim,fontSize:13}}>No detections yet. Build your first one!</div>}
            </div>
            <div style={{padding:"10px 20px",borderTop:"1px solid #1a2a3a",fontSize:11,color:THEME.textDim,display:"flex",gap:16}}>
              <span>↵ Go to Library</span><span>ESC Close</span><span style={{marginLeft:"auto"}}>⌘K Toggle</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ── Global Toast System ───────────────────────────────────────────────────────
const ToastContext = createContext(null);
export function useToast(){ return useContext(ToastContext); }
function ToastProvider({ children }){
  const [toasts, setToasts] = useState([]);
  const toast = useCallback((msg, type="success", duration=3500) => {
    const id = Date.now() + Math.random();
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), duration);
  }, []);
  const COLOR = { success: THEME.success, error: THEME.danger, info: THEME.accent, warning: THEME.warning };
  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div style={{position:"fixed",bottom:24,right:24,zIndex:9999,display:"flex",flexDirection:"column",gap:8,pointerEvents:"none"}}>
        {toasts.map(t => (
          <div key={t.id} style={{
            padding:"12px 18px", borderRadius:10, fontSize:13, fontWeight:600,
            background:"#0d1825", border:"1px solid "+COLOR[t.type]+"55",
            color:COLOR[t.type], boxShadow:"0 8px 32px rgba(0,0,0,0.6)",
            display:"flex", alignItems:"center", gap:10, minWidth:260, maxWidth:400,
            animation:"slideInRight 0.25s ease", pointerEvents:"auto",
            fontFamily:"'JetBrains Mono',monospace",
          }}>
            <span>{t.type==="success"?"✓":t.type==="error"?"✕":t.type==="warning"?"⚠":"ℹ"}</span>
            <span style={{flex:1}}>{t.msg}</span>
          </div>
        ))}
      </div>
      <style>{`@keyframes slideInRight{from{opacity:0;transform:translateX(30px)}to{opacity:1;transform:translateX(0)}}`}</style>
    </ToastContext.Provider>
  );
}

export default function App(){
  return <AuthProvider><ToastProvider><AppInner/></ToastProvider></AuthProvider>;
}
