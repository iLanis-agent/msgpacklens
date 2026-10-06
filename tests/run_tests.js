/* MsgPackLens node runner: engine decode/encode vs real-msgpack oracle */
'use strict';
const fs = require('fs');
const path = require('path');
const M = require(path.join(__dirname, '..', 'engine.js'));
const items = JSON.parse(fs.readFileSync(path.join(__dirname, 'expected.json'), 'utf8'));

let checks = 0, fails = [];
function chk(c, m){ checks++; if (!c) fails.push(m); }

function revive(v){
  if (Array.isArray(v)) return v.map(revive);
  if (v && typeof v === 'object'){
    if (v.$bigint !== undefined) return BigInt(v.$bigint);
    if (v.$bin_raw !== undefined){
      const h = v.$bin_raw, out = new Uint8Array(h.length/2);
      for (let i=0;i<out.length;i++) out[i]=parseInt(h.substr(i*2,2),16);
      return out;
    }
    const o = {}; for (const k of Object.keys(v)) o[k]=revive(v[k]); return o;
  }
  return v;
}
function nodeKey(n){ return n.start+'|'+n.end+'|'+n.path+'|'+n.type; }

for (const it of items){
  const bytes = M.fromHex(it.hex);
  if (it.error){
    let msg = null;
    try { M.decode(bytes); } catch(e){ msg = e.message; }
    chk(msg === it.error, `${it.name}: error ${JSON.stringify(msg)} != ${JSON.stringify(it.error)}`);
    continue;
  }
  const d = M.decode(bytes);
  chk(JSON.stringify(d.value) === JSON.stringify(it.value), `${it.name}: value ${JSON.stringify(d.value).slice(0,120)} != oracle`);
  const got = d.nodes.map(nodeKey).sort();
  const want = it.nodes.map(nodeKey).sort();
  chk(JSON.stringify(got) === JSON.stringify(want), `${it.name}: nodes differ (got ${got.length}, want ${want.length})\n  got:  ${got.join('\n        ')}\n  want: ${want.join('\n        ')}`);
  chk(d.bytes === bytes.length, `${it.name}: byte count`);
  if (it.encode){
    const enc = M.encode(revive(it.encode));
    chk(M.toHex(enc) === it.hex, `${it.name}: encode ${M.toHex(enc).slice(0,80)} != canonical ${it.hex.slice(0,80)}`);
    // canonical re-decode must also equal the value
    const d2 = M.decode(enc);
    chk(JSON.stringify(d2.value) === JSON.stringify(it.value), `${it.name}: re-decode mismatch`);
  }
}
console.log(`${checks} checks, ${fails.length} failures`);
if (fails.length){ fails.forEach(f => console.log('FAIL', f.slice(0,400))); process.exit(1); }
console.log('ALL PASS');
