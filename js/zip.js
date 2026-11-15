// Raw ZIP access: entries are copied without re-compression, stored entries are aligned (4 bytes, 16 KB for .so).
import { te, td8, crc32, inflateRaw, deflateRaw, ByteWriter } from "./util.js";

export class Entry {
  constructor(o) { Object.assign(this, { extra: null, comment: new Uint8Array(0), attrs: 0, versionMade: 20, align: 0 }, o); }
}

function dosNow() {
  const d = new Date();
  return [(d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
          ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()];
}

export class Archive {
  constructor(buf) {
    this.entries = [];
    if (buf) this._load(buf);
  }

  _load(buf) {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
      if (dv.getUint32(i, true) === 0x06054B50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error("not a zip file");
    const total = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
    if (total === 0xFFFF || cdOff === 0xFFFFFFFF) throw new Error("ZIP64 archives are not supported");
    let p = cdOff;
    for (let i = 0; i < total; i++) {
      if (dv.getUint32(p, true) !== 0x02014B50) throw new Error("corrupt central directory");
      const vmade = dv.getUint16(p + 4, true), flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true);
      const mtime = dv.getUint16(p + 12, true), mdate = dv.getUint16(p + 14, true), crc = dv.getUint32(p + 16, true);
      const csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
      const nlen = dv.getUint16(p + 28, true), xlen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
      const eattr = dv.getUint32(p + 38, true), loff = dv.getUint32(p + 42, true);
      const name = td8.decode(buf.subarray(p + 46, p + 46 + nlen));
      const comment = buf.slice(p + 46 + nlen + xlen, p + 46 + nlen + xlen + clen);
      const lnlen = dv.getUint16(loff + 26, true), lxlen = dv.getUint16(loff + 28, true);
      const ds = loff + 30 + lnlen + lxlen;
      this.entries.push(new Entry({ name, method, crc, csize, usize, flags: flags & ~0x8, dostime: mtime, dosdate: mdate,
                                    comment, attrs: eattr, versionMade: vmade, data: buf.subarray(ds, ds + csize) }));
      p += 46 + nlen + xlen + clen;
    }
  }

  get(name) { return this.entries.find((e) => e.name === name) || null; }
  names() { return this.entries.map((e) => e.name); }

  async read(name) {
    const e = this.get(name);
    if (!e) throw new Error("missing entry " + name);
    return e.method === 0 ? e.data : inflateRaw(e.data);
  }

  remove(pred) { this.entries = this.entries.filter((e) => !pred(e.name)); }

  async set(name, data, compress = true) {
    this.remove((n) => n === name);
    let method = 0, comp = data;
    if (compress && data.length > 64) {
      const c = await deflateRaw(data);
      if (c.length < data.length) { method = 8; comp = c; }
    }
    const [dt, dd] = dosNow();
    this.entries.push(new Entry({ name, method, crc: crc32(data), csize: comp.length, usize: data.length, flags: 0x800, dostime: dt, dosdate: dd, data: comp }));
  }

  /** Lay the archive out as {local, cd}: the local file records and the central directory. The EOCD is made by eocd(). */
  build(align4 = true, soAlign = 16384) {
    const plan = [];
    let off = 0;
    for (const e of this.entries) {
      const nb = te.encode(e.name);
      let align = e.align || 0;
      if (e.method === 0 && !align) align = e.name.endsWith(".so") ? soAlign : (align4 ? 4 : 0);
      const pad = align ? (align - ((off + 30 + nb.length) % align)) % align : 0;
      plan.push({ e, nb, pad, off });
      off += 30 + nb.length + pad + e.data.length;
    }
    const local = new Uint8Array(off);
    const dv = new DataView(local.buffer);
    const cd = new ByteWriter(this.entries.length * 80 + 1024);
    for (const { e, nb, pad, off: o } of plan) {
      const flags = e.flags | (nb.length !== e.name.length ? 0x800 : 0);
      dv.setUint32(o, 0x04034B50, true); dv.setUint16(o + 4, 20, true); dv.setUint16(o + 6, flags, true); dv.setUint16(o + 8, e.method, true);
      dv.setUint16(o + 10, e.dostime, true); dv.setUint16(o + 12, e.dosdate, true); dv.setUint32(o + 14, e.crc, true);
      dv.setUint32(o + 18, e.csize, true); dv.setUint32(o + 22, e.usize, true); dv.setUint16(o + 26, nb.length, true); dv.setUint16(o + 28, pad, true);
      local.set(nb, o + 30);
      local.set(e.data, o + 30 + nb.length + pad);
      cd.u32(0x02014B50).u16(e.versionMade || 20).u16(20).u16(flags).u16(e.method).u16(e.dostime).u16(e.dosdate).u32(e.crc)
        .u32(e.csize).u32(e.usize).u16(nb.length).u16(0).u16(e.comment.length).u16(0).u16(0).u32(e.attrs).u32(o).bytes(nb).bytes(e.comment);
    }
    return { local, cd: cd.get() };
  }
}

export function eocd(count, cdSize, cdOffset) {
  return new ByteWriter(22).u32(0x06054B50).u16(0).u16(0).u16(count).u16(count).u32(cdSize).u32(cdOffset).u16(0).get();
}
