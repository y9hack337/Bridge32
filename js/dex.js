// Minimal DEX reader + in-place bytecode patcher (no structural changes, so every offset stays valid).
// Used for compatibility fixes of old Java games: a patch only overwrites instructions with same-sized replacements,
// then the header checksum and SHA-1 signature are recomputed.
import { td8 } from "./util.js";

// length in 16-bit code units of each opcode (payload pseudo-instructions are handled separately)
const LEN = new Uint8Array(256).fill(1);
function setLen(from, to, n) { for (let i = from; i <= to; i++) LEN[i] = n; }
setLen(0x02, 0x02, 2); setLen(0x03, 0x03, 3); setLen(0x05, 0x05, 2); setLen(0x06, 0x06, 3); setLen(0x08, 0x08, 2); setLen(0x09, 0x09, 3);
setLen(0x13, 0x13, 2); setLen(0x14, 0x14, 3); setLen(0x15, 0x16, 2); setLen(0x17, 0x17, 3); setLen(0x18, 0x18, 5); setLen(0x19, 0x1a, 2);
LEN[0x1b] = 3; setLen(0x1c, 0x1c, 2); setLen(0x1f, 0x20, 2); LEN[0x22] = 2; LEN[0x23] = 2; LEN[0x24] = 3; LEN[0x25] = 3; LEN[0x26] = 3;
LEN[0x29] = 2; LEN[0x2a] = 3; LEN[0x2b] = 3; LEN[0x2c] = 3; setLen(0x2d, 0x3d, 2); setLen(0x44, 0x6d, 2); setLen(0x6e, 0x72, 3); setLen(0x74, 0x78, 3);
setLen(0x90, 0xaf, 2); setLen(0xd0, 0xe2, 2); LEN[0xfa] = 4; LEN[0xfb] = 4; LEN[0xfc] = 3; LEN[0xfd] = 3; LEN[0xfe] = 2; LEN[0xff] = 2;

const uleb = (b, o) => { let r = 0, s = 0, v; do { v = b[o.p++]; r |= (v & 0x7F) << s; s += 7; } while (v & 0x80); return r >>> 0; };

export class Dex {
  constructor(bytes) {
    this.b = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const h = (o) => this.dv.getUint32(o, true);
    if (td8.decode(bytes.subarray(0, 4)) !== "dex\n") throw new Error("not a DEX file");
    this.nStr = h(56); this.strOff = h(60); this.nType = h(64); this.typeOff = h(68); this.nProto = h(72); this.protoOff = h(76);
    this.nMeth = h(88); this.methOff = h(92); this.nClass = h(96); this.classOff = h(100);
    this._str = new Map();
  }
  u32(o) { return this.dv.getUint32(o, true); }
  str(i) {
    if (this._str.has(i)) return this._str.get(i);
    const o = { p: this.u32(this.strOff + 4 * i) };
    uleb(this.b, o);                                    // utf16 length
    let e = o.p; while (this.b[e] !== 0) e++;
    const s = td8.decode(this.b.subarray(o.p, e));
    this._str.set(i, s); return s;
  }
  type(i) { return this.str(this.u32(this.typeOff + 4 * i)); }
  /** {cls, name, proto} of method_ids[i], proto as a descriptor string like (Landroid/content/Intent;I)Z */
  method(i) {
    const o = this.methOff + 8 * i;
    const cls = this.type(this.dv.getUint16(o, true)), pidx = this.dv.getUint16(o + 2, true), name = this.str(this.u32(o + 4));
    const po = this.protoOff + 12 * pidx, ret = this.type(this.u32(po + 4)), po2 = this.u32(po + 8);
    let params = "";
    if (po2) { const n = this.u32(po2); for (let k = 0; k < n; k++) params += this.type(this.dv.getUint16(po2 + 4 + 2 * k, true)); }
    return { cls, name, proto: `(${params})${ret}` };
  }
  findString(text) {
    // string_ids are sorted by (utf16) content, but a linear scan is cheap enough and avoids encoding pitfalls
    for (let i = 0; i < this.nStr; i++) if (this.str(i) === text) return i;
    return -1;
  }
  /** Call fn(methodIdx, codeOff, insnsStart, insnsUnits) for every method that has code. */
  forEachCode(fn) {
    for (let c = 0; c < this.nClass; c++) {
      const cd = this.u32(this.classOff + 32 * c + 24);
      if (!cd) continue;
      const o = { p: cd };
      const sf = uleb(this.b, o), inf = uleb(this.b, o), dm = uleb(this.b, o), vm = uleb(this.b, o);
      for (let k = 0; k < sf + inf; k++) { uleb(this.b, o); uleb(this.b, o); }
      for (const n of [dm, vm]) {
        let idx = 0;
        for (let k = 0; k < n; k++) {
          idx += uleb(this.b, o); uleb(this.b, o); const code = uleb(this.b, o);
          if (code) fn(idx, code, code + 16, this.u32(code + 12));
        }
      }
    }
  }
  /** Walk the instructions of a code item: cb(unitIndex, opcode) with unitIndex relative to insns start. */
  walk(insnsStart, units, cb) {
    let i = 0;
    while (i < units) {
      const u = this.dv.getUint16(insnsStart + 2 * i, true), op = u & 0xFF;
      let len = LEN[op];
      if (op === 0 && u !== 0) {                          // payload pseudo-instructions
        if (u === 0x0100) len = this.dv.getUint16(insnsStart + 2 * i + 2, true) * 2 + 4;
        else if (u === 0x0200) len = this.dv.getUint16(insnsStart + 2 * i + 2, true) * 4 + 2;
        else if (u === 0x0300) len = Math.floor((this.dv.getUint16(insnsStart + 2 * i + 2, true) * this.u32(insnsStart + 2 * i + 4) + 1) / 2) + 4;
      } else if (cb(i, op) === false) return;
      i += len;
    }
  }
  /** Recompute the Adler-32 checksum and SHA-1 signature of the header. Async because of WebCrypto. */
  async fixHeader() {
    const b = this.b;
    const sig = new Uint8Array(await crypto.subtle.digest("SHA-1", b.subarray(32)));
    b.set(sig, 12);
    let a = 1, s2 = 0;
    for (let i = 12; i < b.length;) {
      const end = Math.min(b.length, i + 5552);
      for (; i < end; i++) { a += b[i]; s2 += a; }
      a %= 65521; s2 %= 65521;
    }
    this.dv.setUint32(8, ((s2 << 16) | a) >>> 0, true);
  }
}
