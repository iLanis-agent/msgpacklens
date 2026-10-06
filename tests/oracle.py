#!/usr/bin/env python3
"""MsgPackLens oracle. Canonical bytes + decoded values come from the real
msgpack library; node spans come from an independent hand-rolled walker
(post-order, same paths/types as the engine contract)."""
import json, struct
import msgpack

def jsval(v):
    """JSON-safe value exactly as the engine returns it."""
    if isinstance(v, bool): return v
    if isinstance(v, int):
        return v if abs(v) <= 9007199254740991 else str(v)
    if isinstance(v, float): return v
    if isinstance(v, str): return v
    if isinstance(v, bytes): return {"$bin": v.hex(), "len": len(v)}
    if isinstance(v, msgpack.ExtType): return {"$ext": {"type": v.code, "data": v.data.hex()}}
    if isinstance(v, list): return [jsval(x) for x in v]
    if isinstance(v, dict): return {str(k): jsval(x) for k, x in v.items()}
    if v is None: return None
    raise TypeError(type(v))

def enc_marker(v):
    """Encode-side value: BigInt/Uint8Array markers so the JS runner can rebuild."""
    if isinstance(v, bool): return v
    if isinstance(v, int):
        return v if abs(v) <= 9007199254740991 else {"$bigint": str(v)}
    if isinstance(v, float): return v
    if isinstance(v, str): return v
    if isinstance(v, bytes): return {"$bin_raw": v.hex()}
    if isinstance(v, list): return [enc_marker(x) for x in v]
    if isinstance(v, dict): return {str(k): enc_marker(x) for k, x in v.items()}
    if v is None: return None
    raise TypeError(type(v))

# ---- independent span walker (mirrors the spec, not the engine) ----
TN = {(0,0x80):'positive fixint',(0xe0,0x100):'negative fixint'}
def walk(b, o=0, path='$', nodes=None):
    if nodes is None: nodes = []
    start = o
    t = b[o]
    def u(n): return int.from_bytes(b[o+1:o+1+n], 'big')
    if t <= 0x7f or t >= 0xe0:
        nodes.append(dict(start=start, end=o+1, path=path, type='positive fixint' if t<=0x7f else 'negative fixint')); return o+1
    if 0x80 <= t <= 0x8f: return w_map(b, o, path, t & 0xf, 'fixmap', 1, nodes)
    if 0x90 <= t <= 0x9f: return w_arr(b, o, path, t & 0xf, 'fixarray', 1, nodes)
    if 0xa0 <= t <= 0xbf: return w_str(b, o, path, t & 0x1f, 'fixstr', 1, nodes)
    simple = {0xc0:('nil',1),0xc2:('bool',1),0xc3:('bool',1),
              0xca:('float 32',5),0xcb:('float 64',9),
              0xcc:('uint 8',2),0xcd:('uint 16',3),0xce:('uint 32',5),0xcf:('uint 64',9),
              0xd0:('int 8',2),0xd1:('int 16',3),0xd2:('int 32',5),0xd3:('int 64',9)}
    if t in simple:
        name, ln = simple[t]
        nodes.append(dict(start=start, end=o+ln, path=path, type=name)); return o+ln
    if t in (0xc4,0xc5,0xc6):
        nb = {0xc4:1,0xc5:2,0xc6:4}[t]; ln = u(nb); name={0xc4:'bin 8',0xc5:'bin 16',0xc6:'bin 32'}[t]
        nodes.append(dict(start=start, end=o+1+nb+ln, path=path, type=name)); return o+1+nb+ln
    if t in (0xc7,0xc8,0xc9):
        nb = {0xc7:1,0xc8:2,0xc9:4}[t]; ln = u(nb); name={0xc7:'ext 8',0xc8:'ext 16',0xc9:'ext 32'}[t]
        nodes.append(dict(start=start, end=o+2+nb+ln, path=path, type=name)); return o+2+nb+ln
    if t in (0xd4,0xd5,0xd6,0xd7,0xd8):
        ln = {0xd4:1,0xd5:2,0xd6:4,0xd7:8,0xd8:16}[t]
        name = {0xd4:'fixext 1',0xd5:'fixext 2',0xd6:'fixext 4',0xd7:'fixext 8',0xd8:'fixext 16'}[t]
        nodes.append(dict(start=start, end=o+2+ln, path=path, type=name)); return o+2+ln
    if t in (0xd9,0xda,0xdb):
        nb = {0xd9:1,0xda:2,0xdb:4}[t]; ln = u(nb)
        return w_str(b, o, path, ln, {0xd9:'str 8',0xda:'str 16',0xdb:'str 32'}[t], 1+nb, nodes)
    if t in (0xdc,0xdd):
        nb = {0xdc:2,0xdd:4}[t]; ln = u(nb)
        return w_arr(b, o, path, ln, {0xdc:'array 16',0xdd:'array 32'}[t], 1+nb, nodes)
    if t in (0xde,0xdf):
        nb = {0xde:2,0xdf:4}[t]; ln = u(nb)
        return w_map(b, o, path, ln, {0xde:'map 16',0xdf:'map 32'}[t], 1+nb, nodes)
    raise ValueError(f'walker hit 0x{t:02x}')
def w_str(b, o, path, ln, name, head, nodes):
    nodes.append(dict(start=o, end=o+head+ln, path=path, type=name)); return o+head+ln
def w_arr(b, o, path, ln, name, head, nodes):
    p = o + head
    for i in range(ln): p = walk(b, p, f'{path}[{i}]', nodes)
    nodes.append(dict(start=o, end=p, path=path, type=name)); return p
def w_map(b, o, path, ln, name, head, nodes):
    p = o + head
    for i in range(ln):
        kend = walk(b, p, f'{path} <key {i}>', nodes)
        # recover the key value to build the engine's path
        kv = msgpack.unpackb(b[p:kend], raw=False)
        key = kv if isinstance(kv,(str,int)) else json.dumps(kv)
        vend = walk(b, kend, f'{path}.{key}', nodes)
        p = vend
    nodes.append(dict(start=o, end=p, path=path, type=name)); return p

CORPUS = [
 ("api_response", {"id":42,"name":"widget","price":19.99,"tags":["new","sale"],"in_stock":True,"meta":None}),
 ("nested", {"a":{"b":{"c":{"d":[1,2,{"e":"f"}]}}}}),
 ("binblob", {"avatar":bytes(range(64)),"sha":bytes(32)}),
 ("ints", {"zero":0,"pos_fix":127,"pos_u8":200,"pos_u16":60000,"pos_u32":70000,"pos_u64":2**62,
           "neg_fix":-32,"neg_i8":-100,"neg_i16":-1000,"neg_i32":-70000,"neg_i40":-2**40,
           "min_i64":-2**63,"max_u64":2**64-1}),
 ("floats", {"f":1.5,"neg":-0.125,"big":1e300,"denorm":5e-324}),
 ("strs", {"empty":"","fix":"hello","s8":"x"*40,"s16":"y"*300,"unicode":"héllo wörld ✓","emoji":"🎉"}),
 ("arrays", {"empty":[],"fix":[1,2,3],"a16":list(range(20))}),
 ("maps", {"empty":{},"m16":{"k%02d"%i:i for i in range(20)}}),
 ("ext_and_bin", {"ts":msgpack.ExtType(42,b'\x00\x00\x00\x01'),"blob":bytes(300)}),
]
EXTRA_BYTES = [
 ("noncanonical", bytes.fromhex('ce00000005') + bytes.fromhex('da00026869')[:0] , None),  # placeholder, replaced below
]

items = []
for name, val in CORPUS:
    packed = msgpack.packb(val, use_bin_type=True)
    nodes = []
    end = walk(packed, 0, '$', nodes)
    assert end == len(packed), name
    unpacked = msgpack.unpackb(packed, raw=False)
    assert jsval(unpacked) == jsval(val), name
    items.append(dict(name=name, hex=packed.hex(), value=jsval(val),
                      encode=None if any(isinstance(x,msgpack.ExtType) for x in ([val]+list(val.values()))) else enc_marker(val),
                      nodes=nodes))
# non-canonical decodes (hand-built bytes)
nc = [
 ("nc_uint32_five", bytes([0xce,0,0,0,5]), 5),
 ("nc_str16_hi", bytes([0xda,0,2])+b'hi', "hi"),
 ("nc_array32", bytes([0xdd,0,0,0,2,0x01,0x02]), [1,2]),
 ("nc_map32", bytes([0xdf,0,0,0,1,0xa1])+b'a'+bytes([1]), {"a":1}),
]
for name, byts, val in nc:
    nodes = []
    walk(byts, 0, '$', nodes)
    assert msgpack.unpackb(byts, raw=False) == val, name
    items.append(dict(name=name, hex=byts.hex(), value=val, encode=None, nodes=nodes))
# error cases
errors = [
 ("err_c1", bytes([0xc1]), "invalid type byte 0xc1 at offset 0"),
 ("err_trunc_str", bytes([0xd9,5])+b'hi', "truncated: needed 3 more byte(s) at offset 2"),
 ("err_trailing", bytes([1,2]), "1 trailing byte(s) after first value at offset 1"),
 ("err_utf8", bytes([0xa1,0xff]), "invalid utf-8 in string at offset 1"),
]
for name, byts, msg in errors:
    items.append(dict(name=name, hex=byts.hex(), error=msg))

json.dump(items, open('tests/expected.json','w'))
print(len(items), 'corpus items')
for it in items:
    print(it['name'], len(bytes.fromhex(it['hex'])), 'bytes', 'ERR' if 'error' in it else '')
