import fs from 'node:fs';
let s=fs.readFileSync('dist/app.js','utf8');
const replace=(a,b)=>{if(!s.includes(a))throw Error('Missing target '+a.slice(0,60));s=s.replace(a,b);};
replace("const paths={shield:","const paths={bookmark:'M6 3h12v18l-6-4-6 4z',shield:");
s=s.replaceAll("color:'violet',theme:'midnight',accent:'violet'","color:'emerald',theme:'midnight',accent:'emerald'");
replace("profile:'My profile'}","profile:'My profile',saved:'Saved investigations'}");
replace('const initials=()',"const bookmarks=new Set();\nconst bookmarkKey=a=>[a.ruleId,a.account,a.ip].join('|');\nconst isSaved=a=>bookmarks.has(bookmarkKey(a));\nconst initials=()");
replace("${nav('logs','activity')}","${nav('logs','activity')}${nav('saved','bookmark',alerts.filter(isSaved).length)}");
replace('profile:profileView}[view]','profile:profileView,saved:savedView}[view]');
replace("btn('Back to inbox','alerts')+btn('Export report'", "btn('Back to inbox','alerts')+btn(isSaved(a)?'Saved':'Save investigation','bookmark','bookmark',false,`aria-pressed=\"${isSaved(a)}\"`)+btn('Export report'");
replace('function inbox(){',`function savedView(){const rows=alerts.filter(isSaved);return heading('Saved investigations','Keep the cases you want to revisit close at hand. Bookmarks stay in this session.',btn('Browse alerts','alerts','bell'))+\`<section class="card"><div class="card-head"><h2>Your watchlist</h2><span class="pill">\${rows.length} saved</span></div>\${rows.length?alertTable(rows):'<div class="empty">'+icon('bookmark')+'<h3>Your next investigation starts here</h3><p>Open any alert and choose “Save investigation” to add it to your watchlist.</p></div>'}</section>\`;}
function inbox(){`);
replace("if(name==='save-profile'){",`if(name==='bookmark'&&a){const key=bookmarkKey(a);if(bookmarks.has(key))bookmarks.delete(key);else bookmarks.add(key);log(\`\${a.id} \${isSaved(a)?'saved to':'removed from'} your watchlist.\`);render();toast(isSaved(a)?'Investigation saved for this session.':'Bookmark removed.');return;}
 if(name==='save-profile'){`);
replace("if(name==='compact'){profile.compact", "if(name==='compact'){saveProfileDraft();profile.compact");
replace("const kind=name.split(':')[1];events=", "const kind=name.split(':')[1];bookmarks.clear();events=");
replace('events=imported;alerts=', 'events=imported;bookmarks.clear();alerts=');
replace('current events, alerts, reports, notes, and case decisions', 'current events, alerts, reports, notes, bookmarks, and case decisions');
replace('<div class="profile-mini-note">','<section class="card watchlist-card row-gap"><div class="card-head"><h2>Your watchlist</h2><span class="pill">${alerts.filter(isSaved).length} saved</span></div><div class="card-body"><p class="subtle">Return to the investigations that matter to you.</p>${btn(\'Open saved investigations\',\'saved\',\'bookmark\')}</div></section><div class="profile-mini-note">');
fs.writeFileSync('dist/app.js',s);
