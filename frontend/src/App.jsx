import { useState, useEffect, useContext, createContext } from "react";
import { supabase } from "./supabase";

const THEME = {
  bg: "#05080f", bgCard: "#0a0e1a", bgCardHover: "#0d1220",
  border: "#151d2e", borderBright: "#1e2d45",
  accent: "#00d4ff", accentDim: "#0088aa", accentGlow: "rgba(0,212,255,0.1)",
  success: "#00e87a", successGlow: "rgba(0,232,122,0.1)",
  warning: "#ffaa00", warningGlow: "rgba(255,170,0,0.1)",
  danger: "#ff3d55", dangerGlow: "rgba(255,61,85,0.1)",
  purple: "#7c55ff", purpleGlow: "rgba(124,85,255,0.1)",
  orange: "#ff7700", orangeGlow: "rgba(255,119,0,0.1)",
  text: "#dce8f0", textDim: "#4a5a6a", textMid: "#7a8a9a",
  sidebar: "#07090f", sidebarBorder: "#111827",
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
  input: {width:"100%",background:"#03060d",border:"1px solid "+THEME.border,borderRadius:7,padding:"10px 13px",color:THEME.text,fontFamily:"inherit",fontSize:13,outline:"none",boxSizing:"border-box",transition:"border-color 0.15s"},
  textarea: {width:"100%",background:"#03060d",border:"1px solid "+THEME.border,borderRadius:7,padding:"10px 13px",color:THEME.text,fontFamily:"inherit",fontSize:13,outline:"none",resize:"vertical",boxSizing:"border-box",minHeight:100,transition:"border-color 0.15s"},
  btn: (v="p")=>({padding:"9px 18px",borderRadius:7,border:v==="p"?"1px solid "+THEME.accentDim:v==="d"?"1px solid "+THEME.danger+"66":v==="s"?"1px solid "+THEME.success+"66":"1px solid "+THEME.border,background:v==="p"?"linear-gradient(135deg,rgba(0,212,255,0.12),rgba(0,136,170,0.08))":v==="d"?THEME.dangerGlow:v==="s"?THEME.successGlow:"rgba(255,255,255,0.03)",color:v==="p"?THEME.accent:v==="d"?THEME.danger:v==="s"?THEME.success:THEME.textMid,cursor:"pointer",fontFamily:"inherit",fontSize:12,fontWeight:700,transition:"all 0.15s",whiteSpace:"nowrap",letterSpacing:"0.03em"}),
  badge: (c)=>({display:"inline-flex",alignItems:"center",padding:"3px 9px",borderRadius:5,fontSize:10,fontWeight:700,background:c+"18",color:c,border:"1px solid "+c+"33",letterSpacing:"0.05em"}),
  card: {background:THEME.bgCard,border:"1px solid "+THEME.border,borderRadius:12,padding:20,marginBottom:16,transition:"border-color 0.2s"},
  cardTitle: {fontSize:12,fontWeight:800,color:THEME.accent,letterSpacing:"0.04em",textTransform:"none",marginBottom:16,display:"flex",alignItems:"center",gap:8,fontFamily:"'Syne',sans-serif"},
  label: {fontSize:10,color:THEME.textDim,marginBottom:6,display:"block",letterSpacing:"0.06em",textTransform:"uppercase",fontWeight:600,fontFamily:"'JetBrains Mono',monospace"},
  code: {background:"#02040a",border:"1px solid "+THEME.border,borderRadius:8,padding:16,fontSize:12,color:"#7dd3fc",overflowX:"auto",whiteSpace:"pre-wrap",wordBreak:"break-all",fontFamily:"'Courier New',monospace",lineHeight:1.8},
  spinner: {display:"inline-block",width:12,height:12,border:"2px solid rgba(0,212,255,0.15)",borderTop:"2px solid #00d4ff",borderRadius:"50%",animation:"spin 0.7s linear infinite",marginRight:7,verticalAlign:"middle"},
  tag: {display:"inline-flex",alignItems:"center",padding:"3px 9px",borderRadius:5,fontSize:11,background:"rgba(0,212,255,0.08)",color:"#00d4ff",border:"1px solid rgba(0,136,170,0.25)",marginRight:4,marginBottom:4},
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
    {id:"simulate",icon:"⚡",title:"Simulate Attacks",desc:"Generate realistic attack logs to test your detection coverage",tab:"simulator",color:THEME.purple},
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
          <div style={{fontSize:26,fontWeight:900,marginBottom:8}}><span style={{color:THEME.accent}}>DETECT</span><span style={{color:THEME.text}}>IQ</span></div>
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

function SectionHeader({ icon, title, color = THEME.accent, children }) {
  return (
    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:20}}>
      <div style={{display:"flex",alignItems:"center",gap:10}}>
        <div style={{width:32,height:32,borderRadius:8,background:color+"15",border:"1px solid "+color+"30",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14}}>{icon}</div>
        <div style={{fontSize:16,fontWeight:800,color:THEME.text,letterSpacing:"-0.01em"}}>{title}</div>
      </div>
      {children}
    </div>
  );
}

function StatCard({ value, label, icon, color = THEME.accent, sub }) {
  return (
    <div style={{background:"linear-gradient(135deg,"+color+"08,"+color+"03)",border:"1px solid "+color+"20",borderRadius:12,padding:"18px 20px",position:"relative",overflow:"hidden"}}>
      <div style={{position:"absolute",top:14,right:16,fontSize:22,opacity:0.4}}>{icon}</div>
      <div style={{fontSize:28,fontWeight:900,color:color,letterSpacing:"-0.02em",lineHeight:1}}>{value}</div>
      <div style={{fontSize:12,fontWeight:700,color:THEME.textMid,marginTop:6,letterSpacing:"0.03em"}}>{label}</div>
      {sub && <div style={{fontSize:11,color:THEME.textDim,marginTop:3}}>{sub}</div>}
    </div>
  );
}

// ── Tabbed ADS View ───────────────────────────────────────────────────────────
function ADSResult({ ads, threat, tactic, tool, onSave, detName, setDetName, severity, beginner, onSendToTriage }) {
  const [activeTab, setActiveTab] = useState("overview");
  if (!ads) return null;

  const tabs = [
    { id:"overview",  label:"Overview",       icon:"📋" },
    { id:"behaviors", label:"Behaviors",      icon:"👁"  },
    { id:"query",     label:"Query",          icon:"⚡"  },
    { id:"fp",        label:"False Positives",icon:"🔇"  },
    { id:"tuning",    label:"Tuning",         icon:"🎛"  },
    { id:"refs",      label:"References",     icon:"📎"  },
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
          <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
            <input style={{...S.input,width:200}} value={detName} onChange={e=>setDetName(e.target.value)} placeholder="Detection name..."/>
            <button style={{...S.btn("s"),padding:"9px 16px"}} onClick={onSave}>Save</button>
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
              <span style={{fontSize:11,color:tool.color,fontWeight:700}}>{tool.name} — {tool.lang}</span>
              <CopyBtn text={ads.detection_query||""}/>
            </div>
            <div style={S.code}>{ads.detection_query||"No query generated."}</div>
            {beginner&&<div style={{marginTop:10,padding:"10px 14px",background:THEME.accentGlow,border:"1px solid "+THEME.accentDim+"33",borderRadius:8,fontSize:12,color:THEME.accent}}><b>Beginner tip:</b> Copy this query and paste it directly into {tool.name}. The comments (lines starting with //) explain what each part does.</div>}
          </div>
        )}

        {activeTab==="fp"&&<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap"}}>{ads.false_positive_guidance||"No false positive guidance available."}</div>}
        {activeTab==="tuning"&&<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap"}}>{ads.tuning_tips||"No tuning tips available."}</div>}
        {activeTab==="refs"&&<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.8,whiteSpace:"pre-wrap"}}>{ads.references||"No references available."}</div>}
      </div>
    </div>
  );
}

// ── Detection Builder ─────────────────────────────────────────────────────────
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

  useEffect(()=>{
    if(prefill?.scenario){
      setThreat(prefill.scenario);
      if(prefill.tactic) setTactic(prefill.tactic);
    }
  },[prefill]);

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

      const adsPrompt = `Generate a concise Attack Detection Strategy (ADS) for this threat.

Threat: ${threat}
MITRE Tactic: ${tactic}
Target SIEM: ${selectedTool.name} (${selectedTool.lang})
${hint}

Return ONLY valid JSON:
{
  "technique_name": "short detection name",
  "mitre_id": "T####",
  "summary": "one sentence: what this detects and why it matters",
  "attack_overview": "2 short paragraphs: what the attacker does and why",
  "observable_behaviors": "5-7 bullet points of specific log artifacts to look for",
  "simulated_events": ["3 realistic log entries as strings, formatted exactly as they appear in ${selectedTool.name}"],
  "detection_query": "production-ready ${selectedTool.lang} query with inline comments",
  "false_positive_guidance": "3-4 specific legitimate scenarios that could trigger this, and how to tell them apart",
  "tuning_tips": "3-4 specific tuning suggestions",
  "references": "MITRE URL + 2 related technique IDs"
}`;

      const result = await callClaude([{role:"user",content:adsPrompt}], "Expert detection engineer. Return ONLY valid JSON, no markdown.", 5000);
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if(!jsonMatch) throw new Error("Could not parse response. Try again.");
      const cleaned = jsonMatch[0].replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "").replace(/(?<!\\)\\(?!["\\/bfnrtu])/g, "\\\\");
      const adsData = JSON.parse(cleaned);
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

      <div style={S.card}>
        <ToolSelector selected={selectedTool} onSelect={setSelectedTool}/>
        <div style={S.grid2}>
          <div><label style={S.label}>Threat Scenario</label><textarea style={{...S.textarea,minHeight:80}} value={threat} onChange={e=>setThreat(e.target.value)} placeholder="e.g. Mimikatz LSASS credential dumping, PowerShell encoded execution..."/></div>
          <div><label style={S.label}>Log Sample (optional)</label><textarea style={{...S.textarea,minHeight:80}} value={logSample} onChange={e=>setLogSample(e.target.value)} placeholder={"Paste a real "+selectedTool.name+" log to ground the query"}/></div>
        </div>
        <div style={{...S.grid2,marginTop:12}}>
          <div><label style={S.label}>MITRE Tactic</label><select style={S.input} value={tactic} onChange={e=>setTactic(e.target.value)}>{TACTICS.map(t=><option key={t}>{t}</option>)}</select></div>
          <div><label style={S.label}>Severity</label><select style={S.input} value={severity} onChange={e=>setSeverity(e.target.value)}>{SEVERITIES.map(s=><option key={s}>{s}</option>)}</select></div>
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
          <button style={{...S.btn("p"),padding:"11px 26px",fontSize:13}} onClick={runPipeline} disabled={loading}>{loading&&<Spinner/>}{loading?"Generating ADS...":"Generate ADS"}</button>
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
  const[copyMode,setCopyMode]=useState("raw"); // raw | parsed

  useEffect(()=>{
    if(prefill?.scenario){setScenario(prefill.scenario);if(prefill.tactic)setTactic(prefill.tactic);}
  },[prefill]);

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

      const result=await callClaude([{role:"user",content:prompt}],"Expert SIEM engineer and red teamer. Return ONLY valid JSON.",4000);
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
            <label style={S.label}>MITRE Tactic</label>
            <select style={S.input} value={tactic} onChange={e=>setTactic(e.target.value)}>{TACTICS.map(t=><option key={t}>{t}</option>)}</select>
          </div>
        </div>

        <div style={{marginTop:14,display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
          <button style={{...S.btn("d"),padding:"11px 26px",fontSize:13}} onClick={simulate} disabled={loading}>{loading&&<Spinner/>}{loading?"Simulating...":"Simulate Attack"}</button>
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
  const[inputQuery,setInputQuery]=useState("");const[fromTool,setFromTool]=useState(TOOLS[0]);
  useEffect(()=>{if(prefill?.query){setInputQuery(prefill.query);const t=TOOLS.find(t=>t.id===prefill.tool);if(t)setFromTool(t);}},[prefill]);const[toTool,setToTool]=useState(TOOLS[1]);const[result,setResult]=useState("");const[loading,setLoading]=useState(false);const[err,setErr]=useState("");
  async function translate(){if(!inputQuery.trim()){setErr("Paste a query first.");return;}setErr("");setLoading(true);setResult("");try{const txt=await callClaude([{role:"user",content:"Translate this "+fromTool.lang+" query to "+toTool.lang+" for "+toTool.name+". Preserve all logic. Return ONLY the translated query.\n\n"+inputQuery}],"Expert in all SIEM query languages.",2000);setResult(txt);}catch(e){setErr("Translation failed: "+e.message);}setLoading(false);}
  return(
    <div>
      <SectionHeader icon="🔄" title="Query Translator" color={THEME.purple}><span style={S.badge(THEME.purple)}>10 Platforms</span></SectionHeader>
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
        <div style={{marginTop:14}}><button style={{...S.btn("p"),padding:"10px 22px"}} onClick={translate} disabled={loading}>{loading&&<Spinner/>}{loading?"Translating...":"Translate Query"}</button></div>
        {err&&<StatusBar msg={err} type="error"/>}
      </div>
    </div>
  );
}

function DetectionExplainer({prefill}){
  const[query,setQuery]=useState(()=>{if(window.location.pathname!=="/explainer")return "";const p=new URLSearchParams(window.location.search);return p.get("query")?decodeURIComponent(p.get("query")):"";});
  const[tool,setTool]=useState(()=>{const p=new URLSearchParams(window.location.search);return TOOLS.find(t=>t.id===p.get("tool"))||TOOLS[0];});
  const[result,setResult]=useState("");const[loading,setLoading]=useState(false);const[err,setErr]=useState("");
  useEffect(()=>{if(query&&window.location.pathname==="/explainer"){window.history.replaceState({},"","/explainer?query="+encodeURIComponent(query)+"&tool="+tool.id);}},[query,tool.id]);
  useEffect(()=>{if(prefill?.query){setQuery(prefill.query);const t=TOOLS.find(t=>t.id===prefill.tool);if(t)setTool(t);}},[prefill]);
  async function explain(){if(!query.trim()){setErr("Paste a query first.");return;}setErr("");setLoading(true);setResult("");try{const txt=await callClaude([{role:"user",content:"Analyze and explain this "+tool.lang+" detection query.\n\n1. PLAIN ENGLISH SUMMARY\n2. LOGIC BREAKDOWN\n3. WHAT IT DETECTS\n4. MITRE ATT&CK techniques\n5. FALSE POSITIVE RISKS\n6. IMPROVEMENT SUGGESTIONS\n\nQuery:\n"+query}],"Expert SOC analyst.",2000);setResult(txt);}catch(e){setErr("Error: "+e.message);}setLoading(false);}
  return(
    <div>
      <SectionHeader icon="🔍" title="Detection Explainer" color={THEME.warning}><span style={S.badge(THEME.warning)}>AI Analysis</span></SectionHeader>
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
  const[elasticUrl,setElasticUrl]=useState(LS.get("elastic_url",""));
  const[elasticToken,setElasticToken]=useState(LS.get("elastic_token",""));
  const[soarUrl,setSoarUrl]=useState(LS.get("soar_url",""));
  const[soarToken,setSoarToken]=useState(LS.get("soar_token",""));
  const[githubToken,setGithubToken]=useState(LS.get("github_token",""));
  const[githubRepo,setGithubRepo]=useState(LS.get("github_repo",""));
  const[sigmaModal,setSigmaModal]=useState(null);
  const[sigmaContent,setSigmaContent]=useState("");
  const[loadingSigma,setLoadingSigma]=useState(false);

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

  async function scoreDetection(det){
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

  // ── Real push functions ───────────────────────────────────────────────────
  async function pushToSplunk(det){
    const url = splunkUrl || prompt("Splunk URL (e.g. https://your-splunk:8089):");
    const token = splunkToken || prompt("Splunk management API token (not HEC):");
    if(!url||!token){setPushResult("error:Splunk URL and token required.");return;}
    LS.set("splunk_url",url);LS.set("splunk_token",token);
    setSplunkUrl(url);setSplunkToken(token);
    setPushing(true);setPushResult("");
    try{
      // Proxy through backend to avoid CORS restrictions
      const res = await fetch("/api/siem/push/splunk",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          url,token,
          name:det.name,
          query:det.query,
          severity:det.severity,
          description:det.threat||det.description||"",
          tactic:det.tactic,queryType:det.queryType
        })
      });
      const data = await res.json();
      if(data.success){
        setPushResult("success:"+data.message);
      } else {
        setPushResult("error:"+(data.error||"Push failed. Check your Splunk URL (must be the management API port, usually 8089) and token."));
      }
    }catch(e){
      setPushResult("error:Request failed: "+e.message);
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
      // Proxy through backend to avoid CORS restrictions
      const res = await fetch("/api/siem/push/elastic",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          url,token,
          name:det.name,
          query:det.query,
          severity:det.severity,
          description:det.threat||det.description||det.name,
          tactic:det.tactic,queryType:det.queryType
        })
      });
      const data = await res.json();
      if(data.success){
        setPushResult("success:"+data.message);
      } else {
        setPushResult("error:"+(data.error||"Push failed. Check your Kibana URL and API key (Base64 of id:api_key from Management → API Keys)."));
      }
    }catch(e){
      setPushResult("error:Request failed: "+e.message);
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

  async function generateTicket(det){
    setGeneratingTicket(true);setTicketModal(det);setTicketContent("");
    try{const txt=await callClaude([{role:"user",content:"Write a JIRA/ServiceNow ticket for deploying this detection rule.\n\nDetection: "+det.name+"\nSeverity: "+det.severity+"\nTactic: "+det.tactic+"\nPlatform: "+det.queryType+"\nQuery:\n"+det.query+"\n\nInclude: Summary, Description, Acceptance Criteria, Testing Steps, Rollback Plan. Keep it concise."}],"SOC engineer.",1000);
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

  const[statusType,statusMsg]=pushResult.split(/:(.+)/);

  return(
    <div>
      <SectionHeader icon="📦" title="Detection Library" color={THEME.success}>
        <div style={S.flex}>
          <span style={S.badge(THEME.success)}>{detections.length} rules</span>
          <span style={{...S.badge(THEME.purple),fontSize:9}}>BETA</span>
        </div>
      </SectionHeader>

      <div style={S.card}>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          <input style={{...S.input,flex:1,minWidth:180}} value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search detections..."/>
          <select style={{...S.input,width:150}} value={ft} onChange={e=>setFt(e.target.value)}><option>All</option>{TOOLS.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}</select>
          <select style={{...S.input,width:190}} value={fc} onChange={e=>setFc(e.target.value)}><option>All</option>{TACTICS.map(t=><option key={t}>{t}</option>)}</select>
        </div>
      </div>

      {filtered.length===0&&<div style={{...S.card,textAlign:"center",color:THEME.textDim,padding:50}}><div style={{fontSize:36,marginBottom:12}}>📦</div>No detections found.</div>}

      {filtered.map(det=>{
        const t=toolObj[det.tool];
        const isSelected=selected?.id===det.id;
        const enrich=enrichData[det.id];
        const chainInfo=ATTACK_CHAIN[det.tactic];
        return(
          <div key={det.id} style={{...S.card,borderColor:isSelected?THEME.accent+"66":THEME.border}}>
            {/* Header */}
            <div style={{...S.row,cursor:"pointer",marginBottom:10}} onClick={()=>setSelected(isSelected?null:det)}>
              <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                <span style={S.badge(sevColor[det.severity]||THEME.textDim)}>{det.severity||"Medium"}</span>
                <span style={S.badge(t?t.color:THEME.purple)}>{det.queryType}</span>
                {det.ads&&<span style={{...S.badge(THEME.accent),fontSize:9}}>ADS</span>}
                {det.score>0&&<span style={S.badge(THEME.success)}>{det.score}/10</span>}
                <span style={{fontSize:14,fontWeight:700,color:THEME.text}}>{det.name}</span>
              </div>
              <span style={{fontSize:16,color:THEME.textDim}}>{isSelected?"▲":"▼"}</span>
            </div>

            {det.threat&&<div style={{fontSize:12,color:THEME.textDim,marginBottom:12}}>{det.threat.slice(0,120)}</div>}

            {/* Action buttons — FREE */}
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}} onClick={e=>e.stopPropagation()}>
              <button style={{...S.btn("p"),padding:"5px 11px",fontSize:11}} onClick={()=>onBuildOn&&onBuildOn(det.name+" — "+(det.threat||""),det.tactic)}>Build on This</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={()=>onSendToTriage&&onSendToTriage(det.query)}>Triage</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={()=>onExplain&&onExplain(det.query,det.tool)}>Explain</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={()=>onTranslate&&onTranslate(det.query,det.tool)}>Translate</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();scoreDetection(det);}} disabled={scoring===det.id}>{scoring===det.id?<><Spinner/>Scoring...</>:"Score"}</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();enrichDetection(det);}} disabled={enriching===det.id}>{enriching===det.id?<><Spinner/>Enriching...</>:"Enrich"}</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();exportDet(det,"query");}}>Export</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11}} onClick={e=>{e.stopPropagation();exportSigma(det);}}>SIGMA</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:"#24292e",color:"#adbac7"}} onClick={e=>{e.stopPropagation();exportSigmaAI(det);}}>&#931; Sigma</button>
            </div>

            {/* BETA actions */}
            <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center",padding:"8px 10px",background:"rgba(124,85,255,0.04)",borderRadius:8,border:"1px solid "+THEME.purple+"22"}} onClick={e=>e.stopPropagation()}>
              <span style={{...S.badge(THEME.purple),fontSize:9,marginRight:4}}>BETA</span>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();setPushModal({det,tab:"splunk"});setPushResult("");}}>Push to Splunk</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();setPushModal({det,tab:"elastic"});setPushResult("");}}>Push to Elastic</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();setPushModal({det,tab:"soar"});setPushResult("");}}>Push to SOAR</button>
              <button style={{...S.btn(),padding:"5px 11px",fontSize:11,borderColor:THEME.purple+"44",color:THEME.purple}} onClick={e=>{e.stopPropagation();generateTicket(det);}}>Create Ticket</button>
              <button style={{...S.btn("d"),padding:"5px 11px",fontSize:11,marginLeft:"auto"}} onClick={e=>{e.stopPropagation();if(confirm("Delete?"))onDelete(det.id);}}>Delete</button>
            </div>

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
          <div style={{background:"linear-gradient(145deg,#0c1220,#080d18)",border:"1px solid "+THEME.borderBright,borderRadius:16,padding:32,width:"100%",maxWidth:560,boxShadow:"0 32px 80px rgba(0,0,0,0.7)"}} onClick={e=>e.stopPropagation()}>
            <div style={{fontSize:10,fontWeight:800,color:THEME.purple,letterSpacing:"0.15em",marginBottom:6}}>BETA — PUSH TO PLATFORM</div>
            <div style={{fontSize:17,fontWeight:900,color:THEME.text,marginBottom:16}}>{pushModal.det.name}</div>

            {/* Platform tabs */}
            <div style={{display:"flex",gap:6,marginBottom:20}}>
              {[{id:"splunk",label:"Splunk",color:"#ff5733"},{id:"elastic",label:"Elastic",color:"#f4bd19"},{id:"soar",label:"SOAR / Webhook",color:THEME.success},{id:"github",label:"GitHub",color:"#adbac7"}].map(p=>(
                <button key={p.id} style={{...S.btn(pushModal.tab===p.id?"p":""),padding:"7px 14px",fontSize:12,borderColor:pushModal.tab===p.id?p.color+"88":THEME.border,color:pushModal.tab===p.id?p.color:THEME.textDim,background:pushModal.tab===p.id&&p.id==="github"?"#24292e":undefined}} onClick={()=>setPushModal({...pushModal,tab:p.id})}>{p.label}</button>
              ))}
            </div>

            {/* Splunk config */}
            {pushModal.tab==="splunk"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Creates a saved search with 15-min schedule and alerting via Splunk REST API.</div>
                <label style={S.label}>Splunk URL</label>
                <input style={{...S.input,marginBottom:10}} value={splunkUrl} onChange={e=>setSplunkUrl(e.target.value)} placeholder="https://your-splunk:8089"/>
                <label style={S.label}>API Token (Bearer)</label>
                <input style={{...S.input,marginBottom:14,fontFamily:"monospace"}} type="password" value={splunkToken} onChange={e=>setSplunkToken(e.target.value)} placeholder="Splunk HEC or management token"/>
                <button style={{...S.btn("p"),width:"100%",padding:"10px"}} onClick={()=>pushToSplunk(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Pushing to Splunk...</>:"Push to Splunk"}</button>
              </div>
            )}

            {/* Elastic config */}
            {pushModal.tab==="elastic"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Creates a detection rule in Elastic Security via Kibana API. Rule is created as disabled for review.</div>
                <label style={S.label}>Kibana URL</label>
                <input style={{...S.input,marginBottom:10}} value={elasticUrl} onChange={e=>setElasticUrl(e.target.value)} placeholder="https://your-kibana:5601"/>
                <label style={S.label}>API Key (base64 id:key)</label>
                <input style={{...S.input,marginBottom:14,fontFamily:"monospace"}} type="password" value={elasticToken} onChange={e=>setElasticToken(e.target.value)} placeholder="Elastic API key"/>
                <button style={{...S.btn("p"),width:"100%",padding:"10px"}} onClick={()=>pushToElastic(pushModal.det)} disabled={pushing}>{pushing?<><Spinner/>Pushing to Elastic...</>:"Push to Elastic"}</button>
              </div>
            )}

            {/* SOAR config */}
            {pushModal.tab==="soar"&&(
              <div>
                <div style={{fontSize:12,color:THEME.textMid,marginBottom:14,lineHeight:1.6}}>Sends a structured JSON payload to any SOAR webhook — Splunk SOAR, Palo Alto XSOAR, Tines, n8n, Make, or any HTTP trigger.</div>
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
            {pushResult&&<StatusBar msg={statusMsg||pushResult} type={statusType==="success"?"success":"error"}/>}
            <button style={{...S.btn(),width:"100%",padding:"8px",marginTop:10,fontSize:12}} onClick={()=>{setPushModal(null);setPushResult("");}}>Close</button>
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
  const[alert,setAlert]=useState(()=>{if(prefillAlert)return prefillAlert;if(window.location.pathname!=="/triage")return "";const p=new URLSearchParams(window.location.search);return p.get("alert")?decodeURIComponent(p.get("alert")):"";});
  const[context,setContext]=useState("");const[result,setResult]=useState(null);const[loading,setLoading]=useState(false);const[err,setErr]=useState("");const[history,setHistory]=useState(LS.get("detectiq_triage",[]).slice(0,8));
  useEffect(()=>{if(alert&&window.location.pathname==="/triage"){window.history.replaceState({},"","/triage?alert="+encodeURIComponent(alert));}},[alert]);
  useEffect(()=>{if(prefillAlert){setAlert(prefillAlert);}},[prefillAlert]);
  async function triageAlert(){
    if(!alert.trim()){setErr("Paste alert data first.");return;}
    setErr("");setLoading(true);setResult(null);
    try{
      const txt=await callClaude([{role:"user",content:"Triage this security alert.\n\n1. VERDICT: TRUE_POSITIVE or FALSE_POSITIVE\n2. CONFIDENCE: 0-100%\n3. SEVERITY\n4. SUMMARY\n5. KEY INDICATORS\n6. RECOMMENDED ACTIONS\n\nAlert:\n"+alert+(context?"\n\nContext:\n"+context:"")}],"Senior SOC analyst.",2000);
      const isTP=txt.toLowerCase().includes("true_positive")||txt.toLowerCase().includes("true positive");
      const cm=txt.match(/confidence[:\s]+(\d+)/i);
      const r={text:txt,verdict:isTP?"TRUE_POSITIVE":"FALSE_POSITIVE",confidence:cm?parseInt(cm[1]):75,ts:new Date().toISOString(),preview:alert.slice(0,70)};
      setResult(r);const h=[r,...history].slice(0,8);setHistory(h);LS.set("detectiq_triage",h);
    }catch(e){setErr("Error: "+e.message);}
    setLoading(false);
  }
  return(
    <div>
      <SectionHeader icon="🚨" title="Alert Triage" color={THEME.danger}><span style={S.badge(THEME.danger)}>AI Verdict Engine</span></SectionHeader>
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
        <div style={{...S.card,borderColor:result.verdict==="TRUE_POSITIVE"?THEME.danger+"44":THEME.success+"44"}}>
          <div style={S.row}><div style={S.cardTitle}><span>📊</span> Result</div><div style={S.flex}><span style={{...S.badge(result.verdict==="TRUE_POSITIVE"?THEME.danger:THEME.success),padding:"5px 14px",fontSize:12}}>{result.verdict}</span><span style={S.badge(THEME.accent)}>Confidence: {result.confidence}%</span></div></div>
          <div style={{width:"100%",height:6,background:THEME.border,borderRadius:3,marginBottom:16}}><div style={{width:result.confidence+"%",height:"100%",background:result.verdict==="TRUE_POSITIVE"?THEME.danger:THEME.success,borderRadius:3}}/></div>
          <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.9,whiteSpace:"pre-wrap"}}>{result.text}</div>
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

      const result=await callClaude([{role:"user",content:prompt}],"Expert red team operator and detection engineer. Return ONLY valid JSON.",4000);
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
        <button style={{...S.btn("d"),padding:"11px 26px",fontSize:13}} onClick={buildChain} disabled={loading}>{loading&&<Spinner/>}{loading?"Building campaign...":"Build Attack Campaign"}</button>
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

function TeamWorkspace({detections}){
  const[comments,setComments]=useState(LS.get("detectiq_comments",[]));const[activity,setActivity]=useState(LS.get("detectiq_activity",[]));const[newComment,setNewComment]=useState("");const[selectedDet,setSelectedDet]=useState("");const[author,setAuthor]=useState(LS.get("detectiq_author","Analyst"));
  function postComment(){if(!newComment.trim())return;const c={id:uid(),author,text:newComment,detection:selectedDet,ts:new Date().toISOString()};const u=[c,...comments].slice(0,50);setComments(u);LS.set("detectiq_comments",u);const a=[{id:uid(),text:author+" commented on "+(selectedDet||"General"),ts:new Date().toISOString()},...activity].slice(0,20);setActivity(a);LS.set("detectiq_activity",a);setNewComment("");}
  return(
    <div>
      <SectionHeader icon="👥" title="Team Workspace" color={THEME.purple}><span style={S.badge(THEME.purple)}>{comments.length} comments</span></SectionHeader>
      <div style={S.grid2}>
        <div style={S.card}><div style={S.cardTitle}><span>💬</span> Comments</div><label style={S.label}>Your Name</label><input style={{...S.input,marginBottom:12}} value={author} onChange={e=>{setAuthor(e.target.value);LS.set("detectiq_author",e.target.value);}} placeholder="Your name..."/><label style={S.label}>Related Detection</label><select style={{...S.input,marginBottom:12}} value={selectedDet} onChange={e=>setSelectedDet(e.target.value)}><option value="">General</option>{detections.map(d=><option key={d.id} value={d.name}>{d.name}</option>)}</select><textarea style={{...S.textarea,minHeight:80}} value={newComment} onChange={e=>setNewComment(e.target.value)} placeholder="Share findings or notes..."/><button style={{...S.btn("p"),marginTop:12,width:"100%"}} onClick={postComment}>Post Comment</button><div style={{maxHeight:300,overflowY:"auto",marginTop:16}}>{comments.map(c=><div key={c.id} style={{padding:"12px 0",borderBottom:"1px solid "+THEME.border}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><span style={{fontSize:12,fontWeight:700,color:THEME.accent}}>{c.author}</span><span style={{fontSize:11,color:THEME.textDim}}>{new Date(c.ts).toLocaleString()}</span></div>{c.detection&&<div style={{fontSize:11,color:THEME.purple,marginBottom:4}}>re: {c.detection}</div>}<div style={{fontSize:13,color:THEME.textMid,lineHeight:1.6}}>{c.text}</div></div>)}{!comments.length&&<div style={{color:THEME.textDim,fontSize:13,textAlign:"center",padding:20}}>No comments yet.</div>}</div></div>
        <div><div style={S.card}><div style={S.cardTitle}><span>📡</span> Activity</div><div style={{maxHeight:220,overflowY:"auto"}}>{activity.map(a=><div key={a.id} style={{padding:"8px 0",borderBottom:"1px solid "+THEME.border,fontSize:12,color:THEME.textMid}}>{a.text}<span style={{color:THEME.textDim,marginLeft:8,fontSize:11}}>{new Date(a.ts).toLocaleTimeString()}</span></div>)}{!activity.length&&<div style={{color:THEME.textDim,fontSize:13}}>No activity yet.</div>}</div></div><div style={S.card}><div style={S.cardTitle}><span>📊</span> Statistics</div><div style={S.grid2}>{[["Detections",detections.length,THEME.accent],["Platforms",[...new Set(detections.map(d=>d.tool||d.queryType))].length,THEME.purple],["Tactics",[...new Set(detections.map(d=>d.tactic))].length,THEME.success],["Comments",comments.length,THEME.warning]].map(([label,val,color])=><div key={label} style={{textAlign:"center",padding:16,background:color+"08",borderRadius:10,border:"1px solid "+color+"20"}}><div style={{fontSize:28,fontWeight:900,color}}>{val}</div><div style={{fontSize:11,color:THEME.textMid,marginTop:4,fontWeight:700}}>{label}</div></div>)}</div></div></div>
      </div>
    </div>
  );
}

function GettingStarted({ onNav, detections }) {
  const [items, setItems] = useState(LS.get("getting_started", {
    built_detection: false, ran_simulation: false,
    checked_intel: false, enabled_autopilot: false,
  }));
  const checks = [
    {key:"built_detection", icon:"🔨", title:"Build your first detection", desc:"Use the ADS framework to create a production-ready rule", tab:"builder", color:THEME.accent},
    {key:"ran_simulation", icon:"🎯", title:"Run an attack simulation", desc:"Generate realistic attack logs to test your coverage", tab:"simulator", color:THEME.danger},
    {key:"checked_intel", icon:"🌐", title:"Check the live threat feed", desc:"See active CVEs and build detections from KEV entries", tab:"intel", color:THEME.success},
    {key:"enabled_autopilot", icon:"🤖", title:"Enable Detection Autopilot", desc:"Let DetectIQ auto-draft detections for new vulnerabilities", tab:"autopilot", color:THEME.purple},
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
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
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
  const TACTIC_GRID=[
    {name:"Initial Access",icon:"🚪",key:"Initial Access",color:THEME.danger},
    {name:"Execution",icon:"⚡",key:"Execution",color:THEME.orange},
    {name:"Persistence",icon:"🔒",key:"Persistence",color:THEME.warning},
    {name:"Priv. Escalation",icon:"⬆️",key:"Privilege Escalation",color:THEME.accent},
    {name:"Defense Evasion",icon:"🥷",key:"Defense Evasion",color:THEME.purple},
    {name:"Credential Access",icon:"🔑",key:"Credential Access",color:THEME.danger},
    {name:"Discovery",icon:"🔍",key:"Discovery",color:THEME.success},
    {name:"Lateral Movement",icon:"➡️",key:"Lateral Movement",color:THEME.orange},
    {name:"Collection",icon:"📦",key:"Collection",color:THEME.accent},
    {name:"Command & Control",icon:"📡",key:"Command and Control",color:THEME.purple},
    {name:"Exfiltration",icon:"📤",key:"Exfiltration",color:THEME.warning},
    {name:"Impact",icon:"💥",key:"Impact",color:THEME.danger},
    {name:"Reconnaissance",icon:"👁",key:"Reconnaissance",color:THEME.success},
    {name:"Resource Dev",icon:"🛠",key:"Resource Development",color:THEME.accent},
  ];
  const TIPS=[
    {cat:"Classic",color:"#00d4ff",setup:"Why do hackers prefer dark mode?",punchline:"Because light attracts bugs!"},
    {cat:"Networking",color:"#7c55ff",setup:"Why did the router break up with the modem?",punchline:"There was no connection."},
    {cat:"SOC Life",color:"#ffaa00",setup:"How many SOC analysts does it take to change a lightbulb?",punchline:"Unknown. Still investigating. Severity: Medium."},
    {cat:"Passwords",color:"#00e87a",setup:"What did the firewall say to the hacker?",punchline:"You shall not pass! (But seriously, rotate your keys.)"},
    {cat:"Malware",color:"#ff3d55",setup:"Why did the ransomware go to therapy?",punchline:"It had too many trust issues and kept encrypting its feelings."},
    {cat:"Logs",color:"#00d4ff",setup:"Why do security engineers make terrible comedians?",punchline:"Their timing is always off by 3 seconds in the logs."},
    {cat:"Phishing",color:"#ff7700",setup:"I got a phishing email saying I won a free cruise.",punchline:"I clicked. Turns out the boat was a C2 server."},
    {cat:"Zero Days",color:"#7c55ff",setup:"What do you call a vulnerability with no patch?",punchline:"A feature in production."},
    {cat:"Incident Response",color:"#00e87a",setup:"What did the CISO say after the breach?",punchline:"This is fine. (The office was on fire.)"},
    {cat:"Compliance",color:"#ffaa00",setup:"Why did the pentester fail the audit?",punchline:"They were too transparent."},
    {cat:"Cloud",color:"#00d4ff",setup:"Why is cloud security like marriage?",punchline:"Everyone assumes someone else is handling it."},
    {cat:"Threat Intel",color:"#ff3d55",setup:"What do you call an APT group that only attacks on Fridays?",punchline:"A weekend threat actor."},
    {cat:"SOC Life",color:"#ff7700",setup:"Why did the alert go to therapy?",punchline:"Too many false positives — it had trust issues."},
    {cat:"Cryptography",color:"#7c55ff",setup:"Why don't cryptographers ever tell jokes in public?",punchline:"They always encrypt the punchline."},
    {cat:"Detection",color:"#00e87a",setup:"What did the SIEM say to the noisy log source?",punchline:"You've got some serious alerting issues we need to talk about."},
    {cat:"Passwords",color:"#00d4ff",setup:"My password is 'incorrect'.",punchline:"So when I forget it, my computer tells me: your password is incorrect."},
  ];
  const[mitreCount,setMitreCount]=useState(216);
  useEffect(()=>{
    fetch("/api/mitre/techniques").then(r=>r.json()).then(d=>{if(d.count)setMitreCount(d.count);}).catch(()=>{});
  },[]);
  const tipIndex=Math.floor(Date.now()/(1000*60*60*24))%TIPS.length;
  const tip=TIPS[tipIndex];
  const recentDets=detections.slice(0,5);
  const tacticMap={};
  TACTIC_GRID.forEach(t=>{tacticMap[t.key]=detections.filter(d=>d.tactic===t.key).length;});
  const coveredCount=TACTIC_GRID.filter(t=>tacticMap[t.key]>0).length;
  const highCount=detections.filter(d=>d.severity==="Critical"||d.severity==="High").length;
  const gapTactics=TACTIC_GRID.filter(t=>!tacticMap[t.key]);
  return(
    <div>
      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <div style={{background:"linear-gradient(135deg,#0a1628 0%,#080e1c 100%)",border:"1px solid "+THEME.borderBright,borderRadius:16,padding:"28px 32px",marginBottom:20,position:"relative",overflow:"hidden"}}>
        <div style={{position:"absolute",top:0,right:0,width:400,height:"100%",background:"radial-gradient(ellipse at 80% 50%,rgba(0,212,255,0.05) 0%,transparent 70%)",pointerEvents:"none"}}/>
        <div style={{position:"absolute",bottom:-40,left:-40,width:200,height:200,background:"radial-gradient(circle,rgba(124,85,255,0.04),transparent 70%)",pointerEvents:"none"}}/>
        <div style={{display:"flex",gap:28,alignItems:"center",flexWrap:"wrap",position:"relative"}}>
          <div style={{flex:"1 1 320px"}}>
            <div style={{fontSize:10,color:THEME.accentDim,fontWeight:700,letterSpacing:"0.18em",marginBottom:10,fontFamily:"'JetBrains Mono',monospace"}}>DETECTION ENGINEERING PLATFORM</div>
            <div style={{fontSize:28,fontWeight:900,letterSpacing:"-0.02em",marginBottom:8,lineHeight:1.2}}>
              {user?<>Welcome back, <span style={{color:THEME.accent}}>{user.email.split("@")[0]}</span>.</>:<>Welcome to <span style={{color:THEME.accent}}>DetectIQ</span>.</>}
            </div>
            <div style={{fontSize:13,color:THEME.textMid,lineHeight:1.7,marginBottom:20}}>
              {detections.length} detection{detections.length!==1?"s":""} built · {coveredCount}/14 MITRE tactics covered · {mitreCount} ATT&amp;CK techniques indexed
            </div>
            <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
              <button style={{...S.btn("p"),padding:"10px 22px",fontSize:13,fontWeight:700}} onClick={()=>onNav("builder")}>Build Detection</button>
              <button style={{...S.btn(),padding:"10px 22px",fontSize:13}} onClick={()=>onNav("library")}>My Library</button>
              <button style={{...S.btn(),padding:"10px 22px",fontSize:13}} onClick={()=>onNav("intel")}>Threat Intel</button>
            </div>
          </div>
          <div style={{flex:"0 1 380px",display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
            {[
              {value:detections.length,label:"Detections Built",color:THEME.accent,icon:"🛡"},
              {value:coveredCount+"/14",label:"Tactics Covered",color:THEME.success,icon:"🗺"},
              {value:mitreCount,label:"MITRE Techniques",color:THEME.purple,icon:"📡"},
              {value:highCount||"—",label:"High+ Severity",color:THEME.danger,icon:"🔴"},
            ].map(s=>(
              <div key={s.label} style={{background:"rgba(255,255,255,0.02)",border:"1px solid "+s.color+"22",borderRadius:10,padding:"14px 16px"}}>
                <div style={{fontSize:10,marginBottom:4}}>{s.icon}</div>
                <div style={{fontSize:26,fontWeight:900,color:s.color,lineHeight:1,marginBottom:3}}>{s.value}</div>
                <div style={{fontSize:10,color:THEME.textDim,fontWeight:600}}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
      <GettingStarted onNav={onNav} detections={detections}/>
      {/* ── Honeycomb visual ─────────────────────────────────────────────── */}
      {detections.length>0&&<HoneycombGrid detections={detections}/>}
      {/* ── Bottom 3 columns ──────────────────────────────────────────────── */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16}}>
        {/* Quick Launch */}
        <div style={{...S.card,marginBottom:0}}>
          <div style={{...S.cardTitle,marginBottom:14}}><span>⚡</span> Quick Launch</div>
          <div style={{display:"flex",flexDirection:"column",gap:6}}>
            {[
              {icon:"🔨",label:"Detection Builder",desc:"ADS + AI-powered",tab:"builder",color:THEME.accent},
              {icon:"🔄",label:"Query Translator",desc:"10 SIEM formats",tab:"translator",color:THEME.purple},
              {icon:"🎯",label:"Attack Simulator",desc:"Realistic log gen",tab:"simulator",color:THEME.danger},
              {icon:"🔍",label:"Alert Triage",desc:"AI verdict engine",tab:"triage",color:THEME.warning},
              {icon:"🌐",label:"Threat Intel",desc:"CISA KEV + APTs",tab:"intel",color:THEME.success},
              {icon:"📖",label:"Use Case Library",desc:mitreCount+"+ techniques",tab:"usecases",color:THEME.orange},
            ].map(a=>(
              <div key={a.tab} onClick={()=>onNav(a.tab)}
                style={{display:"flex",alignItems:"center",gap:10,padding:"9px 12px",borderRadius:8,border:"1px solid "+THEME.border,cursor:"pointer",transition:"all 0.15s"}}
                onMouseEnter={e=>{e.currentTarget.style.borderColor=a.color+"44";e.currentTarget.style.background=a.color+"08";}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor=THEME.border;e.currentTarget.style.background="transparent";}}>
                <div style={{width:32,height:32,borderRadius:7,background:a.color+"12",border:"1px solid "+a.color+"20",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,flexShrink:0}}>{a.icon}</div>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:12,fontWeight:700,color:THEME.text}}>{a.label}</div>
                  <div style={{fontSize:10,color:THEME.textDim}}>{a.desc}</div>
                </div>
                <div style={{fontSize:14,color:THEME.textDim}}>›</div>
              </div>
            ))}
          </div>
        </div>
        {/* Recent Detections */}
        <div style={{...S.card,marginBottom:0}}>
          <div style={{display:"flex",alignItems:"center",marginBottom:14}}>
            <div style={S.cardTitle}><span>📋</span> Recent Detections</div>
            <button style={{...S.btn(),padding:"4px 12px",fontSize:11,marginLeft:"auto"}} onClick={()=>onNav("library")}>View All</button>
          </div>
          {recentDets.length===0?(
            <div style={{textAlign:"center",padding:"32px 20px",color:THEME.textDim}}>
              <div style={{fontSize:32,marginBottom:10}}>🛡</div>
              <div style={{fontSize:13,marginBottom:4,fontWeight:600,color:THEME.text}}>No detections yet</div>
              <div style={{fontSize:11,marginBottom:16}}>Start building with the AI-powered builder</div>
              <button style={{...S.btn("p"),padding:"8px 18px",fontSize:12}} onClick={()=>onNav("builder")}>Build Your First</button>
            </div>
          ):recentDets.map(det=>(
            <div key={det.id} style={{display:"flex",alignItems:"center",gap:10,padding:"10px 0",borderBottom:"1px solid "+THEME.border+":last-child{border:none}"}}>
              <div style={{width:8,height:8,borderRadius:"50%",background:sevColor[det.severity]||THEME.textDim,flexShrink:0}}/>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:13,fontWeight:600,color:THEME.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{det.name}</div>
                <div style={{fontSize:10,color:THEME.textDim,marginTop:1}}>{det.tactic} · {det.tool||det.queryType}</div>
              </div>
              <div style={{display:"flex",gap:4,flexShrink:0}}>
                {det.ads&&<span style={{...S.badge(THEME.accent),fontSize:9}}>ADS</span>}
                {det.score>0&&<span style={{...S.badge(THEME.success),fontSize:9}}>{det.score}/10</span>}
              </div>
            </div>
          ))}
        </div>
        {/* SOC Humor */}
        <div style={{...S.card,marginBottom:0}}>
          <div style={{display:"flex",alignItems:"center",marginBottom:14}}>
            <div style={S.cardTitle}><span>😄</span> SOC Humor</div>
            <span style={{...S.badge(tip.color),fontSize:9,marginLeft:"auto"}}>{tip.cat}</span>
          </div>
          <div style={{flex:1}}>
            <div style={{borderLeft:"3px solid "+tip.color+"33",paddingLeft:12,marginBottom:14}}>
              <div style={{fontSize:13,color:THEME.text,lineHeight:1.7,marginBottom:12}}>{tip.setup}</div>
              <div style={{fontSize:13,color:tip.color,fontWeight:700,fontStyle:"italic",borderLeft:"3px solid "+tip.color,paddingLeft:10,lineHeight:1.6}}>{tip.punchline}</div>
            </div>
            <div style={{fontSize:10,color:THEME.textDim,fontFamily:"'JetBrains Mono',monospace"}}>
              Joke #{tipIndex+1} of {TIPS.length} · refreshes daily
            </div>
          </div>
          <div style={{marginTop:16,paddingTop:14,borderTop:"1px solid "+THEME.border}}>
            <div style={{fontSize:10,color:THEME.textDim,fontWeight:700,letterSpacing:"0.1em",marginBottom:8}}>HELPFUL LINKS</div>
            <div style={{display:"flex",flexDirection:"column",gap:6}}>
              {[
                {label:"ATT&CK Coverage Heatmap",tab:"heatmap",icon:"🗺"},
                {label:"Detection Chain Builder",tab:"chain",icon:"🔗"},
                {label:"Team Library",tab:"team",icon:"👥"},
                {label:"Autopilot (AI Cron)",tab:"autopilot",icon:"🤖"},
              ].map(l=>(
                <div key={l.tab} onClick={()=>onNav(l.tab)} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 10px",borderRadius:6,cursor:"pointer",fontSize:12,color:THEME.textMid,transition:"all 0.15s"}}
                  onMouseEnter={e=>{e.currentTarget.style.background=THEME.accent+"08";e.currentTarget.style.color=THEME.text;}}
                  onMouseLeave={e=>{e.currentTarget.style.background="transparent";e.currentTarget.style.color=THEME.textMid;}}>
                  <span>{l.icon}</span><span>{l.label}</span><span style={{marginLeft:"auto",fontSize:12}}>›</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function AutopilotTab({ user, detections, onSaveDetection, onNav }) {
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
  const [displayName, setDisplayName] = useState("");
  const [defaultSiem, setDefaultSiem] = useState("splunk");
  const [siemKeys, setSiemKeys] = useState({});
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedSiem, setExpandedSiem] = useState(null);
  const [pwStatus, setPwStatus] = useState(null);

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
    if (error) setStatus({ type: "error", msg: "Save failed: " + error.message });
    else setStatus({ type: "success", msg: "Settings saved." });
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
                <div style={{padding:"12px 14px",borderTop:"1px solid "+THEME.border,background:"rgba(0,0,0,0.2)"}}>
                  <label style={S.label}>API Key / Token</label>
                  <div style={{display:"flex",gap:8}}>
                    <input style={{...S.input,fontFamily:"'JetBrains Mono',monospace",fontSize:11}}
                      type="password"
                      placeholder={"Enter "+tool.name+" API key..."}
                      value={siemKeys[tool.id]||""}
                      onChange={e=>setSiemKeys({...siemKeys,[tool.id]:e.target.value})}/>
                    {siemKeys[tool.id]&&(
                      <button style={{...S.btn("d"),padding:"9px 12px"}} onClick={()=>setSiemKeys({...siemKeys,[tool.id]:""})} title="Clear">✕</button>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* GitHub Integration */}
      <div style={S.card}>
        <div style={S.cardTitle}>🐙 GitHub Integration</div>
        <div style={{fontSize:11,color:THEME.textDim,marginBottom:14,lineHeight:1.6}}>
          Store your GitHub token and repo to enable one-click detection push from the Library.
        </div>
        <label style={S.label}>Personal Access Token</label>
        <input style={{...S.input,marginBottom:10,fontFamily:"'JetBrains Mono',monospace",fontSize:11}}
          type="password"
          placeholder="ghp_..."
          value={LS.get("github_token","")}
          onChange={e=>{LS.set("github_token",e.target.value);}}/>
        <label style={S.label}>Repository (owner/repo)</label>
        <input style={S.input}
          placeholder="myorg/detection-rules"
          defaultValue={LS.get("github_repo","")}
          onChange={e=>LS.set("github_repo",e.target.value)}/>
        <div style={{marginTop:8,fontSize:11,color:THEME.textDim}}>Token needs <code style={{fontFamily:"monospace"}}>repo</code> scope. Detections are pushed to <code style={{fontFamily:"monospace"}}>detections/{"<tactic>/<name>.ext"}</code></div>
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

    </div>
  );
}

const NAV_ITEMS=[
  {id:"home",    icon:"🏠",label:"Dashboard",   color:THEME.accent},
  {id:"builder", icon:"🔨",label:"Builder",     color:THEME.accent},
  {id:"simulator",icon:"🎯",label:"Simulator",  color:THEME.danger},
  {id:"usecases",icon:"📚",label:"Use Cases",   color:THEME.purple},
  {id:"translator",icon:"🔄",label:"Translator",color:THEME.purple},
  {id:"explainer",icon:"🔍",label:"Explainer",  color:THEME.warning},
  {id:"library", icon:"📦",label:"Library",     color:THEME.success},
  {id:"heatmap", icon:"🗺", label:"ATT&CK Map", color:THEME.orange},
  {id:"triage",  icon:"🚨",label:"Triage",      color:THEME.danger},
  {id:"chain",   icon:"🧬",label:"Campaign",     color:THEME.danger},
  {id:"intel",   icon:"🌐",label:"Threat Intel",color:THEME.success},
  {id:"github",  icon:"🐙",label:"GitHub",      color:THEME.textMid},
  {id:"team",    icon:"👥",label:"Team",        color:THEME.purple},
  {id:"autopilot",icon:"🤖",label:"Autopilot",   color:THEME.accent},
  {id:"settings", icon:"⚙️",  label:"Settings",   color:THEME.textMid},
];

const NAV_GROUPS=[
  {label:"MAIN",    items:["home"]},
  {label:"BUILD",   items:["builder","simulator","usecases","translator","explainer"]},
  {label:"ANALYZE", items:["library","heatmap","triage","chain"]},
  {label:"INTEL",   items:["intel","github","team","autopilot"]},
  {label:"ACCOUNT", items:["settings"]},
];

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
          {size==="sm"&&<span style={{display:"block",fontSize:Math.round(sz*0.5),color:dim,fontWeight:400,letterSpacing:"0.02em",marginTop:1}}>v5.4</span>}
        </span>
      )}
    </span>
  );
}

function Sidebar({tab,setTab,collapsed,setCollapsed,detections,user,onSignIn,onSignOut,autopilotDrafts=0,kevCount=0}){
  const navMap=NAV_ITEMS.reduce((a,n)=>{a[n.id]=n;return a;},{});
  return(
    <div style={{width:collapsed?64:220,background:THEME.sidebar,borderRight:"1px solid "+THEME.sidebarBorder,display:"flex",flexDirection:"column",height:"100vh",position:"sticky",top:0,flexShrink:0,transition:"width 0.2s ease",overflow:"hidden"}}>
      <div style={{padding:collapsed?"16px 0":"16px 18px",borderBottom:"1px solid "+THEME.sidebarBorder,display:"flex",alignItems:"center",justifyContent:collapsed?"center":"space-between",height:56,flexShrink:0}}>
        {!collapsed&&<DetectIQLogo size="sm" onClick={()=>setTab("home")}/>}
        <button onClick={()=>setCollapsed(!collapsed)} style={{background:"transparent",border:"1px solid "+THEME.sidebarBorder,borderRadius:6,color:THEME.textDim,cursor:"pointer",padding:"4px 7px",fontSize:12,flexShrink:0}}>{collapsed?"›":"‹"}</button>
      </div>
      <div style={{flex:1,overflowY:"auto",padding:"10px 0",overflowX:"hidden"}}>
        {NAV_GROUPS.map(group=>(
          <div key={group.label} style={{marginBottom:4}}>
            {!collapsed&&<div style={{fontSize:9,fontWeight:800,color:THEME.textDim,letterSpacing:"0.15em",padding:"8px 18px 4px"}}>{group.label}</div>}
            {group.items.map(id=>{
              const n=navMap[id];if(!n)return null;
              const active=tab===id;
              return(
                <div key={id} onClick={()=>setTab(id)} title={collapsed?n.label:""}
                  style={{display:"flex",alignItems:"center",gap:10,padding:collapsed?"10px 0":"9px 18px",cursor:"pointer",background:active?"linear-gradient(90deg,"+n.color+"14,transparent)":"transparent",borderLeft:active?"2px solid "+n.color:"2px solid transparent",transition:"all 0.15s",justifyContent:collapsed?"center":"flex-start"}}
                  onMouseEnter={e=>{if(!active)e.currentTarget.style.background=n.color+"08";}}
                  onMouseLeave={e=>{if(!active)e.currentTarget.style.background="transparent";}}>
                  <span style={{fontSize:16,flexShrink:0}}>{n.icon}</span>
                  {!collapsed&&<span style={{fontSize:12,fontWeight:active?700:500,color:active?n.color:THEME.textMid,whiteSpace:"nowrap"}}>{n.label}</span>}
                  {!collapsed&&(()=>{
                    if(id==="library"&&detections.length>0) return <span style={{marginLeft:"auto",fontSize:10,background:THEME.success+"22",color:THEME.success,border:"1px solid "+THEME.success+"33",borderRadius:10,padding:"1px 7px",fontWeight:700}}>{detections.length}</span>;
                    if(id==="autopilot"&&autopilotDrafts>0) return <span style={{marginLeft:"auto",fontSize:10,background:THEME.warning+"22",color:THEME.warning,border:"1px solid "+THEME.warning+"33",borderRadius:10,padding:"1px 7px",fontWeight:700}}>{autopilotDrafts}</span>;
                    if(id==="intel"&&kevCount>0) return <span style={{marginLeft:"auto",fontSize:10,background:THEME.danger+"22",color:THEME.danger,border:"1px solid "+THEME.danger+"33",borderRadius:10,padding:"1px 7px",fontWeight:700}}>NEW</span>;
                    if(id==="builder"&&detections.length===0) return <span style={{marginLeft:"auto",width:7,height:7,borderRadius:"50%",background:THEME.accent,display:"inline-block",animation:"livepulse 1.5s ease-in-out infinite",flexShrink:0}}/>;
                    return null;
                  })()}
                </div>
              );
            })}
          </div>
        ))}
      </div>
      <div style={{borderTop:"1px solid "+THEME.sidebarBorder,padding:collapsed?"12px 0":"12px 14px",flexShrink:0}}>
        {user?(
          <div style={{display:"flex",alignItems:"center",gap:8,justifyContent:collapsed?"center":"flex-start"}}>
            <div style={{width:30,height:30,borderRadius:"50%",background:"linear-gradient(135deg,"+THEME.accent+"30,"+THEME.purple+"30)",border:"1px solid "+THEME.accentDim,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:800,color:THEME.accent,flexShrink:0,cursor:"pointer"}} title="Open Settings" onClick={()=>setTab("settings")}>{user.email.slice(0,2).toUpperCase()}</div>
            {!collapsed&&<div style={{flex:1,minWidth:0}}><div style={{fontSize:11,color:THEME.text,fontWeight:600,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{user.email.split("@")[0]}</div><div style={{fontSize:10,color:THEME.textDim,cursor:"pointer"}} onClick={onSignOut}>Sign out</div></div>}
          </div>
        ):(
          <div style={{display:"flex",justifyContent:collapsed?"center":"flex-start"}}>
            {collapsed?<div onClick={onSignIn} style={{width:30,height:30,borderRadius:"50%",background:THEME.accentGlow,border:"1px solid "+THEME.accentDim,display:"flex",alignItems:"center",justifyContent:"center",cursor:"pointer",fontSize:13}} title="Sign In">👤</div>
            :<button style={{...S.btn("p"),width:"100%",padding:"8px",fontSize:11,justifyContent:"center",display:"flex"}} onClick={onSignIn}>Sign In / Sign Up</button>}
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
  const VALID_TABS=["home","builder","simulator","usecases","translator","explainer","library","heatmap","triage","chain","intel","github","team","autopilot","settings"];
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
  const[detections,setDetections]=useState([]);
  const[dbLoading,setDbLoading]=useState(false);
  const[triagePrefill,setTriagePrefill]=useState("");
  const[explainerPrefill,setExplainerPrefill]=useState({query:"",tool:""});
  const[translatorPrefill,setTranslatorPrefill]=useState({query:"",tool:""});
  const[builderPrefill,setBuilderPrefill]=useState(()=>{if(window.location.pathname!=="/builder")return {scenario:"",tactic:""};const p=new URLSearchParams(window.location.search);return p.get("tactic")?{tactic:decodeURIComponent(p.get("tactic")),scenario:p.get("scenario")?decodeURIComponent(p.get("scenario")):""}:{scenario:"",tactic:""};});
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
    {title:"ADS Builder",desc:"AI-powered detection with full Attack Detection Strategy output — query, behaviors, false positives, tuning guide."},
    {title:"Attack Simulator",desc:"Realistic log simulation across 10 SIEM platforms. Send events directly to Triage for instant analysis."},
    {title:"Campaign Builder",desc:"Full kill-chain campaigns with Red Team commands or Blue Team detection focus. Generate professional reports."},
    {title:"Threat Intel",desc:"Live CISA KEV feed + AI APT profiles. One-click to build detections or simulate attacks from any threat."},
    {title:"Use Case Repository",desc:"216+ MITRE ATT&CK rules with attack story walkthroughs, tuning guides, and false positive guidance."},
    {title:"Detection Library",desc:"Push to Splunk, Elastic, SOAR via webhook. AI enrichment shows attack paths and adjacent coverage gaps."},
    {title:"Query Translator",desc:"Translate detection queries between 10 platforms — Splunk SPL, Sentinel KQL, CrowdStrike CQL, Elastic EQL."},
    {title:"ATT&CK Heatmap",desc:"Visual MITRE coverage map showing tactic and technique coverage. AI gap analysis highlights your priorities."},
    {title:"Alert Triage",desc:"AI verdict engine for security alerts. Paste any raw log and get TRUE/FALSE positive with confidence score."},
  ];
  const ROLES=[
    {role:"SOC Analysts",desc:"Triage alerts faster. AI verdicts on any raw log or SIEM alert with confidence scores and recommended actions.",color:"#00d4ff"},
    {role:"Detection Engineers",desc:"Generate, translate, score and push rules across your entire SIEM stack. ADS framework ensures every rule is production-ready.",color:"#00d4ff"},
    {role:"Threat Hunters",desc:"Build hunt plans from CISA KEV or APT intel. Chain detections across the full kill chain with one click.",color:"#00d4ff"},
    {role:"Red Teamers",desc:"Simulate campaigns with real attacker commands and log artifacts. Export professional campaign debrief reports.",color:"#00d4ff"},
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
            The complete detection engineering workbench. Build AI-powered detections with the ADS framework, translate across 10 SIEMs, simulate real attacks, triage alerts instantly, and track your full MITRE ATT&CK coverage — all in one place.
          </p>
          <div style={{display:"flex",gap:10,flexWrap:"wrap",marginBottom:48}}>
            <button className="lp-btn-primary" onClick={()=>setShowLogin(true)}>Get Started Free</button>
            <button className="lp-btn-secondary" onClick={()=>setDemoMode(true)}>Explore Demo</button>
          </div>
          {/* Stats row */}
          <div style={{display:"flex",alignItems:"center",gap:0}}>
            {[["10","SIEM Platforms"],["216+","Use Cases"],["14","MITRE Tactics"],["ADS","Framework"]].map(([n,l],i,arr)=>(
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
        else if(goal==="simulate")setTab("simulator");
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
      `}</style>
      <div style={{display:"flex",height:"100vh",overflow:"hidden",background:THEME.bg,fontFamily:"'Courier New',monospace",color:THEME.text}}>
        <Sidebar tab={tab} setTab={setTab} collapsed={collapsed} setCollapsed={setCollapsed} detections={detections} user={user} onSignIn={()=>setShowLogin(true)} onSignOut={signOut} autopilotDrafts={LS.get("autopilot_drafts",[]).filter(d=>!LS.get("autopilot_dismissed",{})[d.cve_id]).length} kevCount={0}/>
        <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
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
            <LazyTab id="home" tab={tab} skeleton={<SkeletonDashboard/>}>
              <DashboardHome detections={detections} onNav={setTab} user={user}/>
            </LazyTab>
            <LazyTab id="builder" tab={tab} skeleton={<div style={S.card}><Skeleton width="40%" height={22} style={{marginBottom:16}}/><SkeletonGrid count={2}/></div>}>
              <DetectionBuilder onSave={saveDetection} onSendToTriage={handleSendToTriage} prefill={builderPrefill}/>
            </LazyTab>
            <LazyTab id="simulator" tab={tab} skeleton={<SkeletonGrid count={4}/>}>
              <AttackSimulator onSendToTriage={handleSendToTriage} onSendToBuilder={handleSendToBuilder} prefill={builderPrefill}/>
            </LazyTab>
            <LazyTab id="usecases" tab={tab} skeleton={<SkeletonGrid count={6}/>}>
              <UseCaseRepository onImport={saveDetection} onBuildOn={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("builder");}}/>
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
            <LazyTab id="chain" tab={tab} skeleton={<SkeletonGrid count={3}/>}>
              <AttackChainBuilder onBuildDetection={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab('builder');}}/>
            </LazyTab>
            <LazyTab id="intel" tab={tab} skeleton={<div style={S.grid2}><SkeletonCard/><SkeletonCard/></div>}>
              <ThreatIntel onBuildDetection={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("builder");}} onSimulate={(scenario,tactic)=>{setBuilderPrefill({scenario,tactic});setTab("simulator");}} onHunt={handleHunt}/>
            </LazyTab>
            <LazyTab id="github" tab={tab} skeleton={<SkeletonCard/>}>
              <GitHubExport detections={detections}/>
            </LazyTab>
            <LazyTab id="autopilot" tab={tab} skeleton={<SkeletonCard/>}>
              <AutopilotTab user={user} detections={detections} onSaveDetection={det=>{setDetections(p=>[det,...p]);saveDetection(det);}} onNav={setTab}/>
            </LazyTab>
            <LazyTab id="team" tab={tab} skeleton={<div style={S.grid2}><SkeletonCard/><SkeletonCard/></div>}>
              <TeamWorkspace detections={detections}/>
            </LazyTab>
            <LazyTab id="settings" tab={tab} skeleton={<SkeletonCard/>}>
              <UserSettingsTab user={user} onSignOut={()=>supabase.auth.signOut()}/>
            </LazyTab>
          </div>
        </div>
      </div>
      {showLogin&&<LoginModal onClose={()=>setShowLogin(false)} onDemo={()=>{setDemoMode(true);setShowLogin(false);}}/>}
    </>
  );
}

export default function App(){
  return <AuthProvider><AppInner/></AuthProvider>;
}
