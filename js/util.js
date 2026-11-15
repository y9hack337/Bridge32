// Small helpers shared by the patcher modules (browser and Node 18+).
export const te = new TextEncoder();
export const td8 = new TextDecoder("utf-8");
export const td16 = new TextDecoder("utf-16le");

export class ByteWriter {
  constructor(cap = 1024) { this.buf = new Uint8Array(cap); this.len = 0; this.dv = new DataView(this.buf.buffer); }
  _need(n) {
    if (this.len + n <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < this.len + n) cap *= 2;
    const nb = new Uint8Array(cap); nb.set(this.buf.subarray(0, this.len));
    this.buf = nb; this.dv = new DataView(nb.buffer);
  }
  u8(v) { this._need(1); this.buf[this.len++] = v & 0xFF; return this; }
  u16(v) { this._need(2); this.dv.setUint16(this.len, v & 0xFFFF, true); this.len += 2; return this; }
  u16be(v) { this._need(2); this.dv.setUint16(this.len, v & 0xFFFF, false); this.len += 2; return this; }
  u32(v) { this._need(4); this.dv.setUint32(this.len, v >>> 0, true); this.len += 4; return this; }
  i32(v) { this._need(4); this.dv.setInt32(this.len, v | 0, true); this.len += 4; return this; }
  u64(v) { this._need(8); this.dv.setBigUint64(this.len, BigInt(v), true); this.len += 8; return this; }
  bytes(b) { this._need(b.length); this.buf.set(b, this.len); this.len += b.length; return this; }
  zeros(n) { this._need(n); this.len += n; return this; }
  get() { return this.buf.slice(0, this.len); }
}

export function concat(arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

let crcTable = null;
export function crc32(u8) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = 0xFFFFFFFF;
  for (let i = 0; i < u8.length; i++) c = crcTable[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

async function viaStream(u8, stream) {
  const out = new Response(new Blob([u8]).stream().pipeThrough(stream));
  return new Uint8Array(await out.arrayBuffer());
}
export const inflateRaw = (u8) => viaStream(u8, new DecompressionStream("deflate-raw"));
export const deflateRaw = (u8) => viaStream(u8, new CompressionStream("deflate-raw"));

export const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest("SHA-256", u8));
