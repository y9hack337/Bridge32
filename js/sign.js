// APK Signature Scheme v2 signing with WebCrypto (RSA-2048, SHA-256). Needs no server and no Java.
// v2 is verified by every Android from 7.0 on, which is all the phones this tool is meant for.
import { te, ByteWriter, concat, sha256 } from "./util.js";
import { eocd as makeEocd } from "./zip.js";

// ------------------------------------------------------------------------------------------ DER
const lenBytes = (n) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255]);
const der = (tag, ...parts) => { const c = concat(parts); return concat([new Uint8Array([tag, ...lenBytes(c.length)]), c]); };
const seq = (...p) => der(0x30, ...p), set = (...p) => der(0x31, ...p);
const oid = (s) => {
  const a = s.split(".").map(Number), out = [a[0] * 40 + a[1]];
  for (const n of a.slice(2)) { const b = [n & 0x7F]; for (let v = n >> 7; v; v >>= 7) b.unshift((v & 0x7F) | 0x80); out.push(...b); }
  return der(0x06, new Uint8Array(out));
};
const SHA256_RSA = seq(oid("1.2.840.113549.1.1.11"), der(0x05));

function buildTbs(spki, serial) {
  const name = seq(set(seq(oid("2.5.4.3"), der(0x0C, te.encode("Bridge32 patcher")))));
  return seq(
    der(0xA0, der(0x02, new Uint8Array([2]))),
    der(0x02, serial),
    SHA256_RSA,
    name,
    seq(der(0x17, te.encode("240101000000Z")), der(0x18, te.encode("21240101000000Z"))),
    name,
    spki);
}

// ------------------------------------------------------------------------------------------ key handling
const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

export async function createIdentity() {
  const kp = await crypto.subtle.generateKey({ ...RSA, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
  const serial = crypto.getRandomValues(new Uint8Array(8)); serial[0] &= 0x7F; serial[0] |= 0x01;
  const tbs = buildTbs(spki, serial);
  const sig = new Uint8Array(await crypto.subtle.sign(RSA, kp.privateKey, tbs));
  const cert = seq(tbs, SHA256_RSA, der(0x03, new Uint8Array([0]), sig));
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  return { privateKey: kp.privateKey, spki, cert, jwk, certB64: b64(cert) };
}

export async function restoreIdentity(saved) {
  const privateKey = await crypto.subtle.importKey("jwk", saved.jwk, RSA, true, ["sign"]);
  const cert = unb64(saved.certB64);
  // the SubjectPublicKeyInfo is embedded in the certificate; re-derive it from the public part of the JWK
  const pub = await crypto.subtle.importKey("jwk", { kty: "RSA", n: saved.jwk.n, e: saved.jwk.e, alg: "RS256", ext: true }, RSA, true, ["verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pub));
  return { privateKey, spki, cert, jwk: saved.jwk, certB64: saved.certB64 };
}

const b64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// ------------------------------------------------------------------------------------------ v2 block
const CHUNK = 1024 * 1024;

async function sectionDigests(sec) {
  const n = Math.max(1, Math.ceil(sec.length / CHUNK));
  const out = new Array(n);
  for (let base = 0; base < n; base += 16) {
    await Promise.all(Array.from({ length: Math.min(16, n - base) }, async (_, k) => {
      const i = base + k, part = sec.subarray(i * CHUNK, Math.min(sec.length, (i + 1) * CHUNK));
      const buf = new Uint8Array(5 + part.length);
      buf[0] = 0xA5; new DataView(buf.buffer).setUint32(1, part.length, true); buf.set(part, 5);
      out[i] = await sha256(buf);
    }));
  }
  return out;
}

const lp = (u8) => new ByteWriter(4 + u8.length).u32(u8.length).bytes(u8).get();     // length-prefixed

/** Sign the archive laid out as {local, cd, count}; returns the parts of the finished APK. */
export async function signApk({ local, cd, count }, identity) {
  const eocdForDigest = makeEocd(count, cd.length, local.length);
  const chunks = [...await sectionDigests(local), ...await sectionDigests(cd), ...await sectionDigests(eocdForDigest)];
  const top = new Uint8Array(5 + 32 * chunks.length);
  top[0] = 0x5A; new DataView(top.buffer).setUint32(1, chunks.length, true);
  chunks.forEach((c, i) => top.set(c, 5 + 32 * i));
  const digest = await sha256(top);

  const algo = 0x0103;                                   // RSASSA-PKCS1-v1_5 with SHA2-256
  const digestItem = new ByteWriter(48).u32(algo).u32(digest.length).bytes(digest).get();
  const signedData = concat([lp(lp(digestItem)), lp(lp(identity.cert)), lp(new Uint8Array(0))]);
  const signature = new Uint8Array(await crypto.subtle.sign(RSA, identity.privateKey, signedData));
  const sigItem = new ByteWriter(300).u32(algo).u32(signature.length).bytes(signature).get();
  const signer = concat([lp(signedData), lp(lp(sigItem)), lp(identity.spki)]);
  const value = lp(lp(signer));

  // APK Signing Block: size, ID-value pairs, size, magic - padded so that the whole block is a multiple of 4096 bytes
  const pair = (id, v) => new ByteWriter(12 + v.length).u64(4 + v.length).u32(id).bytes(v).get();
  const v2 = pair(0x7109871A, value);
  const padLen = (4096 - ((32 + v2.length + 12) % 4096)) % 4096;
  const pad = pair(0x42726577, new Uint8Array(padLen));
  const size = v2.length + pad.length + 24;
  const block = new ByteWriter(size + 8).u64(size).bytes(v2).bytes(pad).u64(size).bytes(te.encode("APK Sig Block 42")).get();

  return [local, block, cd, makeEocd(count, cd.length, local.length + block.length)];
}
