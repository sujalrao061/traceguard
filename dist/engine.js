export const RULES = [
 {id:'TG-001',name:'Repeated authentication failures',severity:'high',description:'Five or more failures for one account and source address within ten minutes.',logic:'COUNT(login_failed) ≥ 5 · same account + IP · 10 minutes',mitre:'T1110 · Brute Force'},
 {id:'TG-002',name:'Successful login after repeated failures',severity:'critical',description:'A successful login preceded by at least five failures from the same account and address within ten minutes.',logic:'≥ 5 login_failed → login_success · same account + IP · 10 minutes',mitre:'T1078 · Valid Accounts'},
 {id:'TG-003',name:'Privileged role assigned',severity:'medium',description:'An administrator role assignment. Validate the change against an approved request.',logic:'event = role_changed AND role = admin',mitre:'T1098 · Account Manipulation'}
];
export const EVENT_TYPES=['login_failed','login_success','role_changed','session_ended'];
export const eventLabel=t=>({login_failed:'Authentication failed',login_success:'Successful sign-in',role_changed:'Administrator role assigned',session_ended:'Session ended'}[t]||t);
export function fixtures(kind='all') {
 const out=[]; let id=0;
 const add=(minute,type,account,ip='192.0.2.18',role='user')=>out.push({id:`EV-${String(++id).padStart(4,'0')}`,timestamp:new Date(Date.UTC(2026,8,28,0,minute)).toISOString(),type,account,ip,role,source:'identity-lab'});
 if(kind==='all'||kind==='normal') for(let i=0;i<128;i++) add(8+i*5,i%4===0?'session_ended':'login_success',`demo-user-${i%12+1}`,`192.0.2.${20+i%12}`);
 if(kind==='all'||kind==='takeover') {for(let i=0;i<9;i++)add(603+i/3,'login_failed','demo-alex','203.0.113.42');add(607,'login_success','demo-alex','203.0.113.42');add(609,'role_changed','demo-alex','203.0.113.42','admin');}
 if(kind==='all'||kind==='brute') for(let i=0;i<8;i++)add(545+i/2,'login_failed','demo-service','198.51.100.76');
 if(kind==='all') {for(let i=0;i<6;i++)add(521+i/2,'login_failed','demo-jamie','203.0.113.91');add(525,'login_success','demo-jamie','203.0.113.91');for(let i=0;i<7;i++)add(470+i/2,'login_failed','demo-robin','198.51.100.12');}
 if(kind==='all'||kind==='privilege')add(563,'role_changed','demo-taylor','192.0.2.64','admin');
 return out.sort((a,b)=>Date.parse(a.timestamp)-Date.parse(b.timestamp));
}
export function validateEvents(input) {
 if(!Array.isArray(input)||input.length===0||input.length>2000)throw new Error('Provide an array of 1–2,000 synthetic events.');
 const allowed=['id','timestamp','type','account','ip','role','source'];const ids=new Set();
 return input.map((e,i)=>{
  const bad=()=>{throw new Error(`Event ${i+1} does not match the synthetic lab schema. Use the sample file; real customer logs are not supported.`);};
  if(!e||typeof e!=='object'||Array.isArray(e)||Object.keys(e).some(k=>!allowed.includes(k)))bad();
  if(!Object.keys(e).every(k=>typeof e[k]==='string'))bad();
  if(!/^EV-[A-Za-z0-9-]{1,24}$/.test(e.id)||ids.has(e.id))bad(); ids.add(e.id);
  if(!/^2026-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(e.timestamp)||!Number.isFinite(Date.parse(e.timestamp)))bad();
  if(new Date(e.timestamp).toISOString()!==(e.timestamp.length===20?e.timestamp.replace('Z','.000Z'):e.timestamp))bad();
  if(!EVENT_TYPES.includes(e.type)||!/^demo-[a-z0-9-]{1,24}$/.test(e.account))bad();
  if(!/^(192\.0\.2|198\.51\.100|203\.0\.113)\.(\d{1,3})$/.test(e.ip)||Number(e.ip.split('.').at(-1))>255)bad();
  if(!['user','admin'].includes(e.role)||e.source!=='identity-lab')bad();
  return Object.fromEntries(allowed.map(k=>[k,e[k]]));
 }).sort((a,b)=>Date.parse(a.timestamp)-Date.parse(b.timestamp));
}
export function detect(events, enabled=new Set(RULES.map(r=>r.id))) {
 const sorted=[...events].sort((a,b)=>Date.parse(a.timestamp)-Date.parse(b.timestamp));const alerts=[];const buckets=new Map();const emitted=new Set();
 const emit=(rule,e,evidence)=>{const key=`${rule.id}:${e.account}:${e.ip}`;if(emitted.has(key))return;emitted.add(key);alerts.push({id:`TG-${1001+alerts.length}`,ruleId:rule.id,title:rule.name,severity:rule.severity,account:e.account,ip:e.ip,time:e.timestamp,evidence:evidence.map(x=>x.id),status:'New',notes:[],report:null});};
 for(const e of sorted){const key=e.account+'|'+e.ip;const previous=(buckets.get(key)||[]).filter(x=>Date.parse(e.timestamp)-Date.parse(x.timestamp)<=600000);buckets.set(key,previous);
  if(e.type==='login_failed'){previous.push(e);if(previous.length>=5&&enabled.has('TG-001'))emit(RULES[0],e,previous);}
  if(e.type==='login_success'&&previous.length>=5&&enabled.has('TG-002'))emit(RULES[1],e,[...previous,e]);
  if(e.type==='role_changed'&&e.role==='admin'&&enabled.has('TG-003'))emit(RULES[2],e,[e]);
 }
 return alerts.sort((a,b)=>({critical:0,high:1,medium:2,low:3}[a.severity]-{critical:0,high:1,medium:2,low:3}[b.severity])||Date.parse(b.time)-Date.parse(a.time));
}
export function investigate(alert,events) {
 const evidence=events.filter(e=>alert.evidence.includes(e.id));
 return {generatedAt:new Date().toISOString(),engine:'Deterministic rules · no AI model',summary:alert.ruleId==='TG-002'?'A successful authentication followed repeated failures from the same account and source. This warrants verification with the account owner; the logs alone do not prove account compromise.':alert.ruleId==='TG-001'?'Repeated authentication failures exceeded the configured threshold. A password attack, a mistyped password, or an outdated service credential could explain the pattern.':'An administrator role was assigned. The event alone does not establish whether the change was authorized.',observations:evidence.map(e=>({id:e.id,text:`${eventLabel(e.type)} for ${e.account} from ${e.ip} at ${e.timestamp}.`})),gaps:['No device fingerprint or MFA result is present.','No approved-change record or account-owner confirmation is available.','This lab does not establish actor identity, location, or intent.'],steps:alert.ruleId==='TG-003'?['Check the approved change request.','Confirm the role assignment with the system owner.','Review subsequent privileged actions.']:['Verify the activity with the account owner.','Review MFA and device records in the source system.','Escalate for human review before changing account access.']};
}
export function exportBrief(a) {
 if(!a.report)throw new Error('Generate an investigation brief first.');
 const r=a.report;
 return {labOnly:true,alert:{id:a.id,ruleId:a.ruleId,severity:a.severity,status:a.status,account:a.account},report:{...r,observations:r.observations.map(o=>({...o,text:o.text.replace(/(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+/g,'[SOURCE IP REMOVED]')}))},notesIncluded:false};
}
export function evaluate() {
 const event=(id,type,minute,account='demo-test',ip='192.0.2.1',role='user')=>({id:`EV-${id}`,timestamp:new Date(Date.UTC(2026,8,28,10,minute)).toISOString(),type,account,ip,role,source:'identity-lab'});
 const fails=Array.from({length:5},(_,i)=>event(i,'login_failed',i));
 const cases=[
  ['Normal sign-ins',fixtures('normal'),[]],['Five failures within window',fails,['TG-001']],['Failure threshold not reached',fails.slice(0,4),[]],
  ['Failures outside time window',fails.map((e,i)=>({...e,timestamp:event(i,'login_failed',i*11).timestamp})),[]],
  ['Success after failures',[...fails,event(5,'login_success',6)],['TG-001','TG-002']],['Success before failures',[event(6,'login_success',-1),...fails],['TG-001']],
  ['Different accounts',fails.map((e,i)=>({...e,account:`demo-user-${i}`})),[]],['Different source addresses',fails.map((e,i)=>({...e,ip:`192.0.2.${i}`})),[]],
  ['Administrator role assigned',[event(9,'role_changed',0,'demo-test','192.0.2.1','admin')],['TG-003']],['Non-admin role change',[event(9,'role_changed',0)],[]],
  ['Unsorted input',[...fails,event(8,'login_success',6)].reverse(),['TG-001','TG-002']],['Duplicate alert suppressed',[...fails,event(7,'login_failed',6)],['TG-001']]
 ];
 return cases.map(([name,events,expected])=>{const actual=detect(events).map(a=>a.ruleId).sort();return {name,expected,actual,pass:JSON.stringify(actual)===JSON.stringify([...expected].sort())};});
}
