// Reader / writer for Android binary XML (AndroidManifest.xml).
// The document is parsed into a flat list of events that refer to plain strings, so edits never have to care about
// string pool indices; dumps() rebuilds the string pool and the resource id map from scratch.
import { te, td8, td16, ByteWriter } from "./util.js";

const RES_STRING_POOL = 0x0001, RES_XML = 0x0003, RES_XML_START_NS = 0x0100, RES_XML_END_NS = 0x0101,
  RES_XML_START_ELEMENT = 0x0102, RES_XML_END_ELEMENT = 0x0103, RES_XML_CDATA = 0x0104, RES_XML_RESOURCE_MAP = 0x0180;
export const TYPE_NULL = 0x00, TYPE_REFERENCE = 0x01, TYPE_STRING = 0x03, TYPE_INT_DEC = 0x10, TYPE_INT_HEX = 0x11, TYPE_INT_BOOLEAN = 0x12;
export const ANDROID_NS = "http://schemas.android.com/apk/res/android";

export const ATTR = {
  name: 0x01010003, label: 0x01010001, icon: 0x01010002, versionCode: 0x0101021b, versionName: 0x0101021c,
  minSdkVersion: 0x0101020c, targetSdkVersion: 0x01010270, maxSdkVersion: 0x01010271,
  extractNativeLibs: 0x010104ea, requestLegacyExternalStorage: 0x01010603, usesCleartextTraffic: 0x010104ec,
  debuggable: 0x0101000f, hasCode: 0x0101000c, exported: 0x01010010, authorities: 0x01010018,
  enabled: 0x0101000e, process: 0x01010011, installLocation: 0x0101001c, largeHeap: 0x0101059a,
  allowBackup: 0x01010280, isGame: 0x010103f4, preserveLegacyExternalStorage: 0x01010658, initOrder: 0x0101001a,
  multiprocess: 0x01010013, required: 0x0101028e, glEsVersion: 0x01010281, configChanges: 0x0101001f,
};

export class Attr {
  constructor(ns, name, resid, raw, vtype, data) { Object.assign(this, { ns, name, resid, raw, vtype, data }); }
  get value() {
    if (this.vtype === TYPE_STRING) return this.raw;
    if (this.vtype === TYPE_INT_BOOLEAN) return !!this.data;
    if (this.vtype === TYPE_INT_DEC || this.vtype === TYPE_INT_HEX) return this.data < 0x80000000 ? this.data : this.data - 4294967296;
    return this.data;
  }
  setString(s) { this.vtype = TYPE_STRING; this.raw = s; this.data = 0; }
  setInt(v) { this.vtype = TYPE_INT_DEC; this.raw = null; this.data = v >>> 0; }
  setBool(v) { this.vtype = TYPE_INT_BOOLEAN; this.raw = null; this.data = v ? 0xFFFFFFFF : 0; }
}

export class Element {
  constructor(ev) { this.ev = ev; }
  get tag() { return this.ev.name; }
  /** ns === null matches an attribute of any namespace. */
  get(name, ns = ANDROID_NS) { return this.ev.attrs.find((a) => a.name === name && (ns === null || a.ns === ns)) || null; }
  set(name, value, ns = ANDROID_NS) {
    let a = this.get(name, ns);
    if (!a) {
      const resid = ns === ANDROID_NS ? (ATTR[name] || 0) : 0;
      a = new Attr(ns, name, resid, null, TYPE_NULL, 0);
      this.ev.attrs.push(a);
      // attributes with resource ids stay sorted by id (aapt convention, required by some parsers)
      this.ev.attrs.sort((x, y) => ((x.resid === 0) - (y.resid === 0)) || (x.resid - y.resid));
    }
    if (typeof value === "boolean") a.setBool(value);
    else if (typeof value === "number") a.setInt(value);
    else a.setString(value);
    return a;
  }
}

function readPool(dv, buf, off) {
  const size = dv.getUint32(off + 4, true);
  const scount = dv.getUint32(off + 8, true), flags = dv.getUint32(off + 16, true), sstart = dv.getUint32(off + 20, true);
  const utf8 = !!(flags & 0x100);
  const strings = [];
  for (let i = 0; i < scount; i++) {
    let p = off + sstart + dv.getUint32(off + 28 + 4 * i, true);
    if (utf8) {
      let n = buf[p++]; if (n & 0x80) n = ((n & 0x7F) << 8) | buf[p++];
      let bl = buf[p++]; if (bl & 0x80) bl = ((bl & 0x7F) << 8) | buf[p++];
      strings.push(td8.decode(buf.subarray(p, p + bl)));
    } else {
      let n = dv.getUint16(p, true); p += 2;
      if (n & 0x8000) { n = ((n & 0x7FFF) << 16) | dv.getUint16(p, true); p += 2; }
      strings.push(td16.decode(buf.subarray(p, p + 2 * n)));
    }
  }
  return { strings, utf8, size };
}

export function loads(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (dv.getUint16(0, true) !== RES_XML) throw new Error("not a binary XML document");
  let pos = dv.getUint16(2, true);
  let strings = [], utf8 = true, resmap = [];
  const events = [];
  const str = (i) => (i >= 0 ? strings[i] : null);
  while (pos < buf.length) {
    const ctype = dv.getUint16(pos, true), chsize = dv.getUint16(pos + 2, true), csize = dv.getUint32(pos + 4, true);
    if (csize === 0) break;
    if (ctype === RES_STRING_POOL) { const p = readPool(dv, buf, pos); strings = p.strings; utf8 = p.utf8; }
    else if (ctype === RES_XML_RESOURCE_MAP) { resmap = []; for (let o = pos + chsize; o < pos + csize; o += 4) resmap.push(dv.getUint32(o, true)); }
    else if (ctype === RES_XML_START_NS || ctype === RES_XML_END_NS) {
      events.push({ kind: ctype === RES_XML_START_NS ? "ns" : "endns", line: dv.getUint32(pos + 8, true), prefix: str(dv.getInt32(pos + 16, true)), uri: str(dv.getInt32(pos + 20, true)) });
    } else if (ctype === RES_XML_START_ELEMENT) {
      const line = dv.getUint32(pos + 8, true), ns = dv.getInt32(pos + 16, true), name = dv.getInt32(pos + 20, true);
      const astart = dv.getUint16(pos + 24, true), asize = dv.getUint16(pos + 26, true), acount = dv.getUint16(pos + 28, true);
      const attrs = [];
      const ap = pos + 16 + astart;
      for (let i = 0; i < acount; i++) {
        const o = ap + i * asize;
        const ans = dv.getInt32(o, true), aname = dv.getInt32(o + 4, true), araw = dv.getInt32(o + 8, true), vtype = dv.getUint8(o + 15), vdata = dv.getUint32(o + 16, true);
        attrs.push(new Attr(str(ans), strings[aname], aname >= 0 && aname < resmap.length ? resmap[aname] : 0,
                            araw >= 0 && vtype === TYPE_STRING ? strings[araw] : null, vtype, vtype !== TYPE_STRING ? vdata : 0));
      }
      events.push({ kind: "start", line, ns: str(ns), name: strings[name], attrs });
    } else if (ctype === RES_XML_END_ELEMENT) {
      events.push({ kind: "end", line: dv.getUint32(pos + 8, true), ns: str(dv.getInt32(pos + 16, true)), name: strings[dv.getInt32(pos + 20, true)] });
    } else if (ctype === RES_XML_CDATA) {
      events.push({ kind: "cdata", line: dv.getUint32(pos + 8, true), text: strings[dv.getInt32(pos + 16, true)] });
    }
    pos += csize;
  }
  return new Document(events, utf8);
}

export class Document {
  constructor(events, utf8 = true) { this.events = events; this.utf8 = utf8; }
  elements(tag = null) { return this.events.filter((e) => e.kind === "start" && (tag === null || e.name === tag)).map((e) => new Element(e)); }
  root() { return this.elements()[0]; }

  /** Insert events right before the end tag of the first `parentTag` element. */
  insertBeforeEnd(parentTag, newEvents) {
    let start = -1, depth = 0;
    for (let i = 0; i < this.events.length; i++) {
      const e = this.events[i];
      if (start < 0 && e.kind === "start" && e.name === parentTag) { start = i; depth = 1; continue; }
      if (start >= 0) {
        if (e.kind === "start") depth++;
        else if (e.kind === "end" && --depth === 0) { this.events.splice(i, 0, ...newEvents); return; }
      }
    }
    throw new Error(`no <${parentTag}> element`);
  }

  dumps() {
    // string pool: attribute names that carry a resource id go first, in resource id map order
    const resNames = [], seen = new Set();
    for (const e of this.events) {
      if (e.kind !== "start") continue;
      for (const a of e.attrs) if (a.resid && !seen.has(a.name)) { seen.add(a.name); resNames.push([a.name, a.resid]); }
    }
    const pool = resNames.map(([n]) => n), resmap = resNames.map(([, r]) => r);
    const index = new Map(pool.map((s, i) => [s, i]));
    const sid = (s) => {
      if (s === null || s === undefined) return -1;
      if (!index.has(s)) { index.set(s, pool.length); pool.push(s); }
      return index.get(s);
    };
    const body = new ByteWriter(4096);
    const chunk = (ctype, line, payload) => {
      body.u16(ctype).u16(16).u32(16 + payload.length).u32(line).u32(0xFFFFFFFF).bytes(payload);
    };
    for (const e of this.events) {
      if (e.kind === "ns" || e.kind === "endns") {
        chunk(e.kind === "ns" ? RES_XML_START_NS : RES_XML_END_NS, e.line, new ByteWriter(8).i32(sid(e.prefix)).i32(sid(e.uri)).get());
      } else if (e.kind === "start") {
        const at = new ByteWriter(64);
        let idi = 0; const ci = 0, si = 0;
        e.attrs.forEach((a, n) => {
          if (a.name === "id" && a.ns === ANDROID_NS) idi = n + 1;
          const nsI = sid(a.ns), nmI = sid(a.name);
          if (a.vtype === TYPE_STRING) { const s = sid(a.raw); at.i32(nsI).i32(nmI).i32(s).u16(8).u8(0).u8(TYPE_STRING).u32(s); }
          else at.i32(nsI).i32(nmI).i32(-1).u16(8).u8(0).u8(a.vtype).u32(a.data);
        });
        const ext = new ByteWriter(20).i32(sid(e.ns)).i32(sid(e.name)).u16(20).u16(20).u16(e.attrs.length).u16(idi).u16(ci).u16(si);
        chunk(RES_XML_START_ELEMENT, e.line, new Uint8Array([...ext.get(), ...at.get()]));
      } else if (e.kind === "end") {
        chunk(RES_XML_END_ELEMENT, e.line, new ByteWriter(8).i32(sid(e.ns)).i32(sid(e.name)).get());
      } else if (e.kind === "cdata") {
        chunk(RES_XML_CDATA, e.line, new ByteWriter(12).i32(sid(e.text)).u16(8).u8(0).u8(0).u32(0).get());
      }
    }
    // pool chunk
    const data = new ByteWriter(1024), offs = [];
    for (const s of pool) {
      offs.push(data.len);
      if (this.utf8) {
        const b = te.encode(s), nchar = [...s].length;
        if (nchar > 0x7F) data.u16be(0x8000 | nchar); else data.u8(nchar);
        if (b.length > 0x7F) data.u16be(0x8000 | b.length); else data.u8(b.length);
        data.bytes(b).u8(0);
      } else {
        const n = s.length;
        if (n > 0x7FFF) data.u16(0x8000 | (n >> 16)).u16(n & 0xFFFF); else data.u16(n);
        for (let i = 0; i < n; i++) data.u16(s.charCodeAt(i));
        data.u16(0);
      }
    }
    while (data.len % 4) data.u8(0);
    const sstart = 28 + 4 * pool.length;
    const out = new ByteWriter(4096 + body.len + data.len);
    const poolSize = sstart + data.len, resSize = resmap.length ? 8 + 4 * resmap.length : 0;
    out.u16(RES_XML).u16(8).u32(8 + poolSize + resSize + body.len);
    out.u16(RES_STRING_POOL).u16(28).u32(poolSize).u32(pool.length).u32(0).u32(this.utf8 ? 0x100 : 0).u32(sstart).u32(0);
    for (const o of offs) out.u32(o);
    out.bytes(data.get());
    if (resmap.length) { out.u16(RES_XML_RESOURCE_MAP).u16(8).u32(resSize); for (const r of resmap) out.u32(r); }
    out.bytes(body.get());
    return out.get();
  }
}
