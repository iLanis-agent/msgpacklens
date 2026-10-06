/* MsgPackLens engine - MessagePack decoder with byte-span tracking + canonical encoder.
   Full spec: fixints, fixstr/fixarray/fixmap, str8/16/32, bin8/16/32,
   array16/32, map16/32, int8..64, uint8..64, float32/64, nil, bool, ext.
   Decode returns a JSON-safe value plus a node list (path + byte range) for
   byte-level highlighting. Encode produces canonical minimal bytes.
   No dependencies. Browser + node. */
(function(root){
'use strict';

const SAFE = 9007199254740991n;

function toHex(bytes){ return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function fromHex(s){
  const clean = s.replace(/[^0-9a-fA-F]/g,'');
  if (clean.length % 2) throw new Error('odd number of hex digits');
  const out = new Uint8Array(clean.length/2);
  for (let i=0;i<out.length;i++) out[i]=parseInt(clean.substr(i*2,2),16);
  return out;
}
function fromBase64(s){
  const clean = s.replace(/\s+/g,'');
  if (typeof atob !== 'undefined'){
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(clean,'base64'));
}

const TYPE_NAMES = {
  fixint_pos:'positive fixint', fixint_neg:'negative fixint',
  fixstr:'fixstr', fixarray:'fixarray', fixmap:'fixmap',
  nil:'nil', bool:'bool',
  bin8:'bin 8', bin16:'bin 16', bin32:'bin 32',
  ext8:'ext 8', ext16:'ext 16', ext32:'ext 32',
  fixext1:'fixext 1', fixext2:'fixext 2', fixext4:'fixext 4', fixext8:'fixext 8', fixext16:'fixext 16',
  float32:'float 32', float64:'float 64',
  uint8:'uint 8', uint16:'uint 16', uint32:'uint 32', uint64:'uint 64',
  int8:'int 8', int16:'int 16', int32:'int 32', int64:'int 64',
  str8:'str 8', str16:'str 16', str32:'str 32',
  array16:'array 16', array32:'array 32', map16:'map 16', map32:'map 32'
};

function category(type){
  if (/^u?int|^fixint|fixint/.test(type)) return 'int';
  if (/^float/.test(type)) return 'float';
  if (/str/.test(type) && !/ext/.test(type)) return 'str';
  if (/^bin/.test(type)) return 'bin';
  if (/array/.test(type)) return 'array';
  if (/map/.test(type)) return 'map';
  if (/ext/.test(type)) return 'ext';
  return 'atom';
}

function decode(bytes){
  const v = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const nodes = [];
  function need(o, n){
    if (o + n > v.length) throw new Error('truncated: needed ' + (o + n - v.length) + ' more byte(s) at offset ' + o);
  }
  function readValue(o, path){
    need(o, 1);
    const start = o;
    const b = v[o];
    let type, value, headBytes = 1, payloadLen = 0, childrenFrom = 0;
    function u(n){ let x = 0n; for (let i=0;i<n;i++) x = (x << 8n) | BigInt(v[o+1+i]); return x; }
    function i(n){ const x = u(n); const bits = BigInt(n*8); const sign = 1n << (bits - 1n); return (x & sign) ? x - (1n << bits) : x; }
    if (b <= 0x7f){ type='fixint_pos'; value=b; }
    else if (b >= 0xe0){ type='fixint_neg'; value=b-256; }
    else if (b >= 0x80 && b <= 0x8f){ type='fixmap'; return readMap(o, path, b & 0x0f, start, TYPE_NAMES.fixmap); }
    else if (b >= 0x90 && b <= 0x9f){ type='fixarray'; return readArray(o, path, b & 0x0f, start, TYPE_NAMES.fixarray); }
    else if (b >= 0xa0 && b <= 0xbf){ type='fixstr'; payloadLen = b & 0x1f; return readStr(o, path, payloadLen, start, TYPE_NAMES.fixstr); }
    else switch (b){
      case 0xc0: type='nil'; value=null; break;
      case 0xc1: throw new Error('invalid type byte 0xc1 at offset ' + start);
      case 0xc2: type='bool'; value=false; break;
      case 0xc3: type='bool'; value=true; break;
      case 0xc4: case 0xc5: case 0xc6: {
        const nb = b===0xc4?1:b===0xc5?2:4; need(o, 1+nb);
        const len = Number(u(nb)); headBytes = 1+nb;
        need(o+headBytes, len);
        const data = v.slice(o+headBytes, o+headBytes+len);
        const tn = b===0xc4?'bin8':b===0xc5?'bin16':'bin32';
        nodes.push({start:start, end:o+headBytes+len, path:path, type:TYPE_NAMES[tn], desc:'binary, '+len+' bytes'});
        return {value:{$bin:toHex(data), len:len}, end:o+headBytes+len};
      }
      case 0xc7: case 0xc8: case 0xc9: {
        const nb = b===0xc7?1:b===0xc8?2:4; need(o, 1+nb);
        const len = Number(u(nb)); need(o+1+nb, 1);
        const etype = v[o+1+nb]; headBytes = 2+nb;
        need(o+headBytes, len);
        const data = v.slice(o+headBytes, o+headBytes+len);
        const tn = b===0xc7?'ext8':b===0xc8?'ext16':'ext32';
        nodes.push({start:start, end:o+headBytes+len, path:path, type:TYPE_NAMES[tn], desc:'ext type '+etype+', '+len+' bytes'});
        return {value:{$ext:{type:etype, data:toHex(data)}}, end:o+headBytes+len};
      }
      case 0xca: need(o,5); { const dv=new DataView(v.buffer, v.byteOffset+o+1, 4); value=dv.getFloat32(0); type='float32'; headBytes=5; }
        nodes.push({start:start, end:o+5, path:path, type:TYPE_NAMES.float32, desc:String(value)});
        return {value:value, end:o+5};
      case 0xcb: need(o,9); { const dv=new DataView(v.buffer, v.byteOffset+o+1, 8); value=dv.getFloat64(0); type='float64'; headBytes=9; }
        nodes.push({start:start, end:o+9, path:path, type:TYPE_NAMES.float64, desc:String(value)});
        return {value:value, end:o+9};
      case 0xd4: case 0xd5: case 0xd6: case 0xd7: case 0xd8: {
        const len = b===0xd4?1:b===0xd5?2:b===0xd6?4:b===0xd7?8:16; need(o,2);
        const etype = v[o+1]; headBytes = 2;
        need(o+2, len);
        const data = v.slice(o+2, o+2+len);
        const tn = {0xd4:'fixext1',0xd5:'fixext2',0xd6:'fixext4',0xd7:'fixext8',0xd8:'fixext16'}[b];
        nodes.push({start:start, end:o+2+len, path:path, type:TYPE_NAMES[tn], desc:'ext type '+etype+', '+len+' bytes'});
        return {value:{$ext:{type:etype, data:toHex(data)}}, end:o+2+len};
      }
      case 0xd9: case 0xda: case 0xdb: {
        const nb = b===0xd9?1:b===0xda?2:4; need(o, 1+nb);
        const len = Number(u(nb));
        const tn = b===0xd9?'str8':b===0xda?'str16':'str32';
        return readStr(o, path, len, start, TYPE_NAMES[tn], 1+nb);
      }
      case 0xdc: case 0xdd: {
        const nb = b===0xdc?2:4; need(o, 1+nb);
        const len = Number(u(nb));
        return readArray(o, path, len, start, b===0xdc?TYPE_NAMES.array16:TYPE_NAMES.array32, 1+nb);
      }
      case 0xde: case 0xdf: {
        const nb = b===0xde?2:4; need(o, 1+nb);
        const len = Number(u(nb));
        return readMap(o, path, len, start, b===0xde?TYPE_NAMES.map16:TYPE_NAMES.map32, 1+nb);
      }
      case 0xcc: need(o,2); value=Number(u(1)); type='uint8'; headBytes=2; break;
      case 0xcd: need(o,3); value=Number(u(2)); type='uint16'; headBytes=3; break;
      case 0xce: need(o,5); value=Number(u(4)); type='uint32'; headBytes=5; break;
      case 0xcf: need(o,9); { const x=u(8); value = x <= BigInt(SAFE) ? Number(x) : x.toString(); type='uint64'; headBytes=9; } break;
      case 0xd0: need(o,2); value=Number(i(1)); type='int8'; headBytes=2; break;
      case 0xd1: need(o,3); value=Number(i(2)); type='int16'; headBytes=3; break;
      case 0xd2: need(o,5); value=Number(i(4)); type='int32'; headBytes=5; break;
      case 0xd3: need(o,9); { const x=i(8); value = (x >= -SAFE && x <= SAFE) ? Number(x) : x.toString(); type='int64'; headBytes=9; } break;
    }
    nodes.push({start:start, end:o+headBytes, path:path, type:TYPE_NAMES[type]||type, desc:String(value)});
    return {value:value, end:o+headBytes};

    function readStr(o2, path2, len, s2, tn, head){
      const hb = head || 1;
      need(o2+hb, len);
      const raw = v.slice(o2+hb, o2+hb+len);
      let str;
      try { str = new TextDecoder('utf-8', {fatal:true}).decode(raw); }
      catch(e){ throw new Error('invalid utf-8 in string at offset ' + (o2+hb)); }
      nodes.push({start:s2, end:o2+hb+len, path:path2, type:tn, desc:JSON.stringify(str.length>40?str.slice(0,40)+'...':str)});
      return {value:str, end:o2+hb+len};
    }
    function readArray(o2, path2, len, s2, tn, head){
      const hb = head || 1;
      const arr = [];
      let p = o2 + hb;
      for (let idx=0; idx<len; idx++){
        const r = readValue(p, path2 + '[' + idx + ']');
        arr.push(r.value); p = r.end;
      }
      nodes.push({start:s2, end:p, path:path2, type:tn, desc:'array, '+len+' items'});
      return {value:arr, end:p};
    }
    function readMap(o2, path2, len, s2, tn, head){
      const hb = head || 1;
      const obj = {};
      let p = o2 + hb;
      for (let idx=0; idx<len; idx++){
        const kr = readValue(p, path2 + ' <key '+idx+'>');
        p = kr.end;
        const key = (typeof kr.value === 'string' || typeof kr.value === 'number') ? String(kr.value) : JSON.stringify(kr.value);
        const vr = readValue(p, path2 + '.' + key);
        obj[key] = vr.value; p = vr.end;
      }
      nodes.push({start:s2, end:p, path:path2, type:tn, desc:'map, '+len+' entries'});
      return {value:obj, end:p};
    }
  }
  const r = readValue(0, '$');
  if (r.end < v.length) throw new Error((v.length - r.end) + ' trailing byte(s) after first value at offset ' + r.end);
  return {value:r.value, nodes:nodes, bytes:v.length};
}

/* Canonical minimal encoder */
function encode(value){
  const out = [];
  function u(n, x){ for (let i=n-1;i>=0;i--) out.push(Number((BigInt(x) >> BigInt(i*8)) & 0xffn)); }
  function head(b, len, c8, c16, c32){
    if (len < 16 && c8 === null) { out.push(b | len); return; }
    if (len <= 0xff && c8 !== null){ out.push(c8, len); return; }
    if (b !== null && c8 === null && len < 16){ out.push(b | len); return; }
    if (len <= 0xffff){ out.push(c16); u(2, len); return; }
    out.push(c32); u(4, len);
  }
  function put(val){
    if (val === null || val === undefined){ out.push(0xc0); return; }
    if (val === true){ out.push(0xc3); return; }
    if (val === false){ out.push(0xc2); return; }
    if (typeof val === 'bigint'){ putInt(val); return; }
    if (typeof val === 'number'){
      if (Number.isInteger(val) && Math.abs(val) <= SAFE){ putInt(BigInt(val)); return; }
      out.push(0xcb);
      const dv = new DataView(new ArrayBuffer(8)); dv.setFloat64(0, val);
      for (let i=0;i<8;i++) out.push(dv.getUint8(i));
      return;
    }
    if (typeof val === 'string'){
      const raw = new TextEncoder().encode(val);
      if (raw.length < 32) out.push(0xa0 | raw.length);
      else if (raw.length <= 0xff){ out.push(0xd9, raw.length); }
      else if (raw.length <= 0xffff){ out.push(0xda); u(2, raw.length); }
      else { out.push(0xdb); u(4, raw.length); }
      for (const b of raw) out.push(b);
      return;
    }
    if (val instanceof Uint8Array){
      if (val.length <= 0xff){ out.push(0xc4, val.length); }
      else if (val.length <= 0xffff){ out.push(0xc5); u(2, val.length); }
      else { out.push(0xc6); u(4, val.length); }
      for (const b of val) out.push(b);
      return;
    }
    if (Array.isArray(val)){
      if (val.length < 16) out.push(0x90 | val.length);
      else if (val.length <= 0xffff){ out.push(0xdc); u(2, val.length); }
      else { out.push(0xdd); u(4, val.length); }
      for (const item of val) put(item);
      return;
    }
    if (typeof val === 'object'){
      const keys = Object.keys(val);
      if (keys.length < 16) out.push(0x80 | keys.length);
      else if (keys.length <= 0xffff){ out.push(0xde); u(2, keys.length); }
      else { out.push(0xdf); u(4, keys.length); }
      for (const k of keys){ put(k); put(val[k]); }
      return;
    }
    throw new Error('cannot encode type ' + typeof val);
  }
  function putInt(x){
    if (x >= 0n){
      if (x < 128n){ out.push(Number(x)); return; }
      if (x <= 0xffn){ out.push(0xcc, Number(x)); return; }
      if (x <= 0xffffn){ out.push(0xcd); u(2,x); return; }
      if (x <= 0xffffffffn){ out.push(0xce); u(4,x); return; }
      if (x <= 0xffffffffffffffffn){ out.push(0xcf); u(8,x); return; }
      throw new Error('integer too large for msgpack (max uint64)');
    }
    if (x >= -32n){ out.push(0x100 + Number(x)); return; }
    if (x >= -128n){ out.push(0xd0); u(1, x & 0xffn); return; }
    if (x >= -32768n){ out.push(0xd1); u(2, x & 0xffffn); return; }
    if (x >= -2147483648n){ out.push(0xd2); u(4, x & 0xffffffffn); return; }
    if (x >= -9223372036854775808n){ out.push(0xd3); u(8, x & 0xffffffffffffffffn); return; }
    throw new Error('integer too small for msgpack (min int64)');
  }
  put(value);
  return new Uint8Array(out);
}

const api = { decode:decode, encode:encode, toHex:toHex, fromHex:fromHex, fromBase64:fromBase64, category:category };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
root.MsgPackLens = api;
})(typeof self !== 'undefined' ? self : globalThis);
