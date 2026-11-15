// Tiny ELF header reader: classifies native libraries and lists their imported / exported symbols.
import { td8 } from "./util.js";

export const EM_ARM = 40, EM_AARCH64 = 183, EM_386 = 3, EM_X86_64 = 62, EM_MIPS = 8;
const PT_LOAD = 1, PT_DYNAMIC = 2, PT_TLS = 7, DT_NEEDED = 1, DT_STRTAB = 5, DT_SONAME = 14, DT_NULL = 0;

export class ElfInfo {
  constructor(data) {
    this.ok = false; this.machine = 0; this.bits = 0; this.needed = []; this.soname = null; this.flags = 0;
    this.hasTls = false; this.undef = []; this.defined = new Set();
    if (data.length < 52 || data[0] !== 0x7F || data[1] !== 0x45 || data[2] !== 0x4C || data[3] !== 0x46) return;
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.bits = data[4] === 1 ? 32 : 64;
    const b32 = this.bits === 32;
    let phoff, shoff, phentsize, phnum;
    this.machine = dv.getUint16(18, true);
    if (b32) { shoff = dv.getUint32(32, true); phoff = dv.getUint32(28, true); this.flags = dv.getUint32(36, true); phentsize = dv.getUint16(42, true); phnum = dv.getUint16(44, true); }
    else { phoff = Number(dv.getBigUint64(32, true)); shoff = Number(dv.getBigUint64(40, true)); this.flags = dv.getUint32(48, true); phentsize = dv.getUint16(54, true); phnum = dv.getUint16(56, true); }
    try { this._dynsym(data, dv, shoff); } catch (e) { /* symbol tables are optional */ }
    const loads = []; let dyn = null;
    for (let i = 0; i < phnum; i++) {
      const o = phoff + i * phentsize;
      const type = dv.getUint32(o, true);
      let off, va, fsz;
      if (b32) { off = dv.getUint32(o + 4, true); va = dv.getUint32(o + 8, true); fsz = dv.getUint32(o + 16, true); }
      else { off = Number(dv.getBigUint64(o + 8, true)); va = Number(dv.getBigUint64(o + 16, true)); fsz = Number(dv.getBigUint64(o + 32, true)); }
      if (type === PT_LOAD) loads.push([va, off, fsz]);
      else if (type === PT_DYNAMIC) dyn = [off, fsz];
      else if (type === PT_TLS) this.hasTls = true;
    }
    const v2o = (v) => { for (const [va, off, fsz] of loads) if (va <= v && v < va + fsz) return v - va + off; return null; };
    if (dyn) {
      const esz = b32 ? 8 : 16, ents = [];
      for (let o = dyn[0]; o < dyn[0] + dyn[1]; o += esz) {
        const tag = b32 ? dv.getInt32(o, true) : Number(dv.getBigInt64(o, true));
        const val = b32 ? dv.getUint32(o + 4, true) : Number(dv.getBigUint64(o + 8, true));
        if (tag === DT_NULL) break;
        ents.push([tag, val]);
      }
      const st = ents.find(([t]) => t === DT_STRTAB);
      const so = st ? v2o(st[1]) : null;
      if (so !== null) {
        const s = (off) => { let e = so + off; while (data[e] !== 0) e++; return td8.decode(data.subarray(so + off, e)); };
        for (const [t, v] of ents) {
          if (t === DT_NEEDED) this.needed.push(s(v));
          else if (t === DT_SONAME) this.soname = s(v);
        }
      }
    }
    this.ok = true;
  }

  _dynsym(data, dv, shoff) {
    if (!shoff || this.bits !== 32) return;
    const shentsize = dv.getUint16(46, true), shnum = dv.getUint16(48, true);
    const secs = [];
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * shentsize;
      secs.push({ type: dv.getUint32(o + 4, true), off: dv.getUint32(o + 16, true), size: dv.getUint32(o + 20, true), link: dv.getUint32(o + 24, true), entsize: dv.getUint32(o + 36, true) });
    }
    for (const s of secs) {
      if (s.type !== 11 || !s.entsize) continue;               // SHT_DYNSYM
      const stroff = secs[s.link].off;
      for (let o = s.off + s.entsize; o < s.off + s.size; o += s.entsize) {
        const stName = dv.getUint32(o, true), info = data[o + 12], shndx = dv.getUint16(o + 14, true);
        let e = stroff + stName; while (data[e] !== 0) e++;
        const name = td8.decode(data.subarray(stroff + stName, e));
        if (!name) continue;
        if (shndx === 0) this.undef.push([name, (info >> 4) === 2]);   // STB_WEAK
        else this.defined.add(name);
      }
    }
  }

  get hardfp() { return this.machine === EM_ARM && !!(this.flags & 0x400); }
}
