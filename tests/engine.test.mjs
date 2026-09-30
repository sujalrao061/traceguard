import test from 'node:test';
import assert from 'node:assert/strict';
import {fixtures,validateEvents,detect,evaluate,investigate,exportBrief} from '../dist/engine.js';

for(const result of evaluate()) test(result.name,()=>assert.equal(result.pass,true,JSON.stringify(result)));
test('Every built-in fixture validates and roundtrips',()=>{for(const kind of ['all','takeover','brute','normal','privilege'])assert.deepEqual(validateEvents(fixtures(kind)),fixtures(kind));});
test('Sensitive extra fields rejected rather than silently retained',()=>{assert.throws(()=>validateEvents([{...fixtures('takeover')[0],password:'do-not-store'}]));});
test('Real IPs and email accounts rejected',()=>{assert.throws(()=>validateEvents([{...fixtures('takeover')[0],ip:'8.8.8.8'}]));assert.throws(()=>validateEvents([{...fixtures('takeover')[0],account:'customer@example.com'}]));});
test('Markup, invalid timestamps, missing fields, and invalid octets rejected',()=>{for(const patch of [{account:'<img src=x>'},{timestamp:'yesterday'},{ip:'192.0.2.999'},{source:'customer-system'},{id:null}])assert.throws(()=>validateEvents([{...fixtures('takeover')[0],...patch}]));});
test('Duplicate IDs and oversized event arrays rejected',()=>{const e=fixtures('takeover')[0];assert.throws(()=>validateEvents([e,e]));assert.throws(()=>validateEvents(Array(2001).fill(e)));});
test('Calendar rollover rejected',()=>assert.throws(()=>validateEvents([{...fixtures('takeover')[0],timestamp:'2026-02-31T00:00:00Z'}])));
test('Disabled rules cannot emit alerts',()=>assert.equal(detect(fixtures(),new Set()).length,0));
test('Brief citations reference only real supporting events',()=>{const events=fixtures();for(const a of detect(events)){const r=investigate(a,events);assert.ok(r.observations.length);for(const o of r.observations)assert.ok(a.evidence.includes(o.id)&&events.some(e=>e.id===o.id));assert.equal(r.engine,'Deterministic rules · no AI model');}});
test('Synthetic baseline creates eight alerts with two critical',()=>{const a=detect(fixtures());assert.equal(a.length,8);assert.equal(a.filter(x=>x.severity==='critical').length,2);});
test('Export strips source addresses and excludes analyst notes',()=>{const events=fixtures();const a=detect(events)[0];a.report=investigate(a,events);a.notes=[{text:'private-note-marker'}];const out=JSON.stringify(exportBrief(a));assert.ok(!out.includes(a.ip));assert.ok(!out.includes('private-note-marker'));assert.ok(out.includes('[SOURCE IP REMOVED]'));assert.equal(exportBrief(a).notesIncluded,false);});
