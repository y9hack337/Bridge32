// The patching pipeline (a port of patcher/apk64/patch.py): everything happens on the Uint8Array of the APK.
import { td8, te } from "./util.js";
import { Archive } from "./zip.js";
import * as axml from "./axml.js";
import { ElfInfo, EM_ARM } from "./elf.js";
import { signApk } from "./sign.js";
import { patchJavaCompat } from "./compat.js";

const MARKER = te.encode("APK64GUEST:");
const MIN_INSTALLABLE_TARGET = 28;      // Android 15+ refuses to install targets below 24; Android 16 warns on every launch below 28
const COMPONENTS = ["application", "activity", "activity-alias", "service", "receiver", "provider", "instrumentation"];
// libraries the runtime provides itself (guest imports of these names are bound to host implementations)
const SYSTEM_LIBS = new Set(["libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so", "libstdc++.so", "libandroid.so", "libEGL.so", "libGLESv1_CM.so",
  "libGLESv2.so", "libGLESv3.so", "libOpenSLES.so", "libjnigraphics.so", "libmediandk.so", "libnativewindow.so", "libvulkan.so", "libcutils.so", "libutils.so", "libbinder.so", "libstagefright.so", "libEGL_adreno.so"]);

export class PatchError extends Error {}

/** Parse the APK and gather what the patcher needs to know about it. */
export async function analyze(apk) {
  let ar;
  try { ar = new Archive(apk); } catch (e) { throw new PatchError("This file is not a valid ZIP/APK (" + e.message + ")"); }
  if (!ar.get("AndroidManifest.xml")) {
    if (ar.names().some((n) => n.endsWith(".apk"))) throw new PatchError("This is a bundle with several APKs (XAPK/APKS). Choose the base game APK inside it.");
    if (ar.get("base/manifest/AndroidManifest.xml")) throw new PatchError("This is an Android App Bundle (.aab), not an installable APK.");
    throw new PatchError("AndroidManifest.xml not found: this is not an APK.");
  }
  const a = { ar, libs: {}, info32: {} };
  for (const e of ar.entries) {
    if (e.name.startsWith("lib/") && e.name.endsWith(".so")) {
      const parts = e.name.split("/");
      if (parts.length === 3) (a.libs[parts[1]] ||= {})[parts[2]] = e;
    }
  }
  a.abis = Object.keys(a.libs).sort();
  a.hasArm64 = "arm64-v8a" in a.libs;
  a.arm32Dir = "armeabi-v7a" in a.libs ? "armeabi-v7a" : ("armeabi" in a.libs ? "armeabi" : null);
  a.arm32 = a.arm32Dir ? a.libs[a.arm32Dir] : {};
  for (const name of Object.keys(a.arm32)) a.info32[name] = new ElfInfo(await ar.read("lib/" + a.arm32Dir + "/" + name));
  a.manifest = axml.loads(await ar.read("AndroidManifest.xml"));
  return a;
}

export function parseSymbols(text) { return new Set(text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)); }

/** {library: [missing system libraries, unimplemented imports, weak ones]} for the 32-bit libraries of an analysed APK. */
export function importProblems(a, syms) {
  if (!syms) return null;
  const exported = new Set();
  for (const info of Object.values(a.info32)) for (const n of info.defined) exported.add(n);
  const res = {};
  for (const name of Object.keys(a.info32).sort()) {
    const info = a.info32[name];
    const missingLibs = info.needed.filter((n) => !SYSTEM_LIBS.has(n) && !(n in a.info32));
    const unresolved = [...new Set(info.undef.filter(([n, weak]) => !weak && !syms.has(n) && !exported.has(n)).map(([n]) => n))].sort();
    const weak = [...new Set(info.undef.filter(([n, weak]) => weak && !syms.has(n) && !exported.has(n)).map(([n]) => n))].sort();
    res[name] = [missingLibs, unresolved, weak];
  }
  return res;
}

/** A plain summary object for the UI. */
export function describe(a, syms) {
  const root = a.manifest.root();
  const sdk = a.manifest.elements("uses-sdk");
  const at = (el, n) => (el && el.get(n) ? el.get(n).value : null);
  const kind = a.hasArm64 ? "arm64" : a.arm32Dir && Object.keys(a.arm32).length ? "arm32" : !a.abis.length ? "java" : "unsupported";
  const probs = importProblems(a, syms);
  let missing = 0, warnings = [];
  if (probs) {
    for (const [lib, [ml, un]] of Object.entries(probs)) {
      missing += un.length;
      for (const m of ml) warnings.push(`${lib} needs ${m}, which is neither in the APK nor provided by the runtime`);
      if (un.length) warnings.push(`${lib} imports ${un.length} function(s) the runtime does not implement: ${un.slice(0, 40).join(", ")}${un.length > 40 ? " …" : ""}`);
    }
  }
  for (const [n, i] of Object.entries(a.info32)) {
    if (i.hardfp) warnings.push(`${n} uses the hard-float ABI (not supported yet)`);
    if (["libmono.so", "libunity.so", "libil2cpp.so"].includes(n)) warnings.push(`Unity engine detected (${n}): translation of runtime-generated code is experimental`);
  }
  return {
    pkg: at(root, "package") ?? root.get("package", null)?.value, versionName: at(root, "versionName"), versionCode: at(root, "versionCode"),
    minSdk: at(sdk[0], "minSdkVersion"), targetSdk: at(sdk[0], "targetSdkVersion"),
    abis: a.abis, kind, libCount: Object.keys(a.info32).length, unimplemented: missing, warnings, haveSymbols: !!probs,
  };
}

// ------------------------------------------------------------------------------------------ manifest
function expandNames(doc, pkg) {
  for (const tag of COMPONENTS) {
    for (const el of doc.elements(tag)) {
      for (const attr of ["name", "targetActivity", "backupAgent", "manageSpaceActivity", "parentActivityName"]) {
        const at = el.get(attr);
        if (at && at.vtype === axml.TYPE_STRING && at.raw) {
          const v = at.raw;
          if (v.startsWith(".")) at.setString(pkg + v);
          else if ((!v.includes(".") && tag !== "application") || (!v.includes(".") && tag === "application" && attr === "name")) at.setString(pkg + "." + v);
        }
      }
    }
  }
}

function renamePackage(doc, oldName, newName, log) {
  expandNames(doc, oldName);
  for (const el of doc.elements("provider")) {
    const at = el.get("authorities");
    if (at && at.raw) at.setString(at.raw.split(";").map((x) => (x.includes(oldName) ? x.split(oldName).join(newName) : x + "." + newName.split(".").pop())).join(";"));
  }
  for (const tag of ["permission", "uses-permission", "permission-group", "permission-tree"]) {
    for (const el of doc.elements(tag)) {
      const at = el.get("name");
      if (at && at.raw && at.raw.startsWith(oldName + ".")) at.setString(newName + at.raw.slice(oldName.length));
    }
  }
  for (const el of doc.elements("manifest")) el.get("package", null).setString(newName);
  log(`renamed package ${oldName} -> ${newName}`);
}

function addUsesLibrary(doc, name, log) {
  if (doc.elements("uses-library").some((el) => el.get("name")?.raw === name)) return;
  if (!doc.elements("application").length) return;
  const A = axml.ANDROID_NS;
  doc.insertBeforeEnd("application", [
    { kind: "start", line: 1, ns: null, name: "uses-library", attrs: [
      new axml.Attr(A, "name", axml.ATTR.name, name, axml.TYPE_STRING, 0),
      new axml.Attr(A, "required", axml.ATTR.required, null, axml.TYPE_INT_BOOLEAN, 0)] },
    { kind: "end", line: 1, ns: null, name: "uses-library" }]);
  log(`added <uses-library ${name}> (required=false)`);
}

function patchManifest(doc, opts, log) {
  const root = doc.root();
  const pkg = root.get("package", null).value;
  let sdk = doc.elements("uses-sdk");
  if (!sdk.length) {
    const idx = doc.events.findIndex((e) => e.kind === "start" && e.name === "manifest") + 1;
    doc.events.splice(idx, 0, { kind: "start", line: 1, ns: null, name: "uses-sdk", attrs: [] }, { kind: "end", line: 1, ns: null, name: "uses-sdk" });
    sdk = doc.elements("uses-sdk");
  }
  const us = sdk[0];
  const tgt = us.get("targetSdkVersion"), mn = us.get("minSdkVersion");
  const curT = tgt && typeof tgt.value === "number" ? tgt.value : (mn && typeof mn.value === "number" ? mn.value : 1);
  const wantT = opts.targetSdk || Math.max(curT, MIN_INSTALLABLE_TARGET);
  if (wantT !== curT || !tgt) {
    us.set("targetSdkVersion", wantT);
    log(`targetSdkVersion ${curT} -> ${wantT}`);
    const app = doc.elements("application");
    if (curT < 28 && 28 <= wantT && app.length && !app[0].get("usesCleartextTraffic")) {
      app[0].set("usesCleartextTraffic", true);        // targets from 28 on block plain HTTP unless allowed
      log("usesCleartextTraffic=true (kept the old network behaviour)");
    }
  }
  // Targets from 23 on lose the Apache HTTP classes (org.apache.http.*) that old games link against: ask for the legacy library.
  if (curT < 23 && wantT >= 23 && opts.legacyHttp !== false) addUsesLibrary(doc, "org.apache.http.legacy", log);
  if (opts.minSdk) us.set("minSdkVersion", opts.minSdk);
  if (opts.debuggable != null && doc.elements("application").length) doc.elements("application")[0].set("debuggable", !!opts.debuggable);
  if (opts.package && opts.package !== pkg) renamePackage(doc, pkg, opts.package, log);
  return pkg;
}

function makeProxy(template, guestName) {
  const nb = te.encode(guestName);
  if (nb.length > 96) throw new PatchError("library name too long: " + guestName);
  let i = -1;
  outer: for (let k = 0; k <= template.length - MARKER.length; k++) {
    for (let j = 0; j < MARKER.length; j++) if (template[k + j] !== MARKER[j]) continue outer;
    i = k; break;
  }
  if (i < 0) throw new PatchError("proxy template is corrupt");
  const out = template.slice();
  out.fill(0, i + MARKER.length, i + MARKER.length + 100);
  out.set(nb, i + MARKER.length);
  return out;
}

/**
 * resources.arsc carries the package name too; apps resolve their own resources by name (Resources.getIdentifier(name, type, getPackageName())),
 * which silently returns 0 for a renamed package. Rewrite the name of the application package chunk (id 0x7f).
 */
export function renameArscPackage(arsc, oldName, newName) {
  if (newName.length > 127) throw new PatchError("package name too long: " + newName);
  const out = arsc.slice(), dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  if (dv.getUint16(0, true) !== 0x0002) return null;                      // not a resource table
  let pos = dv.getUint16(2, true), changed = 0;
  while (pos + 8 <= out.length) {
    const type = dv.getUint16(pos, true), size = dv.getUint32(pos + 4, true);
    if (size < 8) break;
    if (type === 0x0200 && dv.getUint32(pos + 8, true) === 0x7f) {         // RES_TABLE_PACKAGE
      let cur = "";
      for (let i = 0; i < 128; i++) { const ch = dv.getUint16(pos + 12 + 2 * i, true); if (!ch) break; cur += String.fromCharCode(ch); }
      if (cur === oldName) {
        for (let i = 0; i < 128; i++) dv.setUint16(pos + 12 + 2 * i, i < newName.length ? newName.charCodeAt(i) : 0, true);
        changed++;
      }
    }
    pos += size;
  }
  return changed ? out : null;
}

export function validPackageName(s) { return /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(s); }

/**
 * Patch an analysed APK. `runtime` = {lib: libapk64.so, proxy: libapk64proxy.so, symbols: Set|null}, `identity` = signing identity.
 * Returns {parts, report}; `parts` are the pieces of the signed APK (concatenate them in order).
 */
export async function patchApk(a, runtime, identity, opts = {}, log = () => {}, tick = async () => {}) {
  const ar = a.ar;
  const report = { bridge: false, libs: [], warnings: [] };
  const pkg = patchManifest(a.manifest, opts, log);
  if (opts.javaCompat !== false) report.javaFixes = await patchJavaCompat(ar, log);
  const needsBridge = (Object.keys(a.arm32).length && !a.hasArm64) || (opts.forceBridge && Object.keys(a.arm32).length);
  if (needsBridge) {
    report.bridge = true;
    for (const name of Object.keys(a.arm32).sort()) {
      const info = a.info32[name];
      if (!info.ok || info.machine !== EM_ARM) { report.warnings.push(`${name} is not a 32-bit ARM library, skipped`); continue; }
      if (info.hardfp) report.warnings.push(`${name} uses the hard-float ABI (not supported yet)`);
      await ar.set("lib/arm64-v8a/" + name, makeProxy(runtime.proxy, name), true);
      report.libs.push(name);
    }
    await ar.set("lib/arm64-v8a/libapk64.so", runtime.lib, true);
    for (const w of describe(a, runtime.symbols).warnings) report.warnings.push(w);
    log(`bridge: ${report.libs.length} proxy libraries + runtime (${runtime.lib.length >> 10} KB)`);
    if (!opts.keepAbis) {
      for (const abi of Object.keys(a.libs)) {
        if (abi !== "arm64-v8a" && abi !== a.arm32Dir) { ar.remove((n) => n.startsWith(`lib/${abi}/`)); log("removed unused ABI " + abi); }
      }
      if (a.arm32Dir === "armeabi" && "armeabi-v7a" in a.libs) ar.remove((n) => n.startsWith("lib/armeabi/"));
    }
  } else if (a.hasArm64) log("arm64-v8a libraries present: no translation needed");
  else log("no native code: pure Java application");

  if (opts.package && opts.package !== pkg && ar.get("resources.arsc")) {
    const arsc = renameArscPackage(await ar.read("resources.arsc"), pkg, opts.package);
    if (arsc) { await ar.set("resources.arsc", arsc, false); log("resources.arsc: package name updated"); }     // must stay stored (Android 11+)
  }
  await ar.set("AndroidManifest.xml", a.manifest.dumps(), true);
  ar.remove((n) => n.startsWith("META-INF/") && (/\.(SF|RSA|DSA|EC)$/.test(n) || n.endsWith("MANIFEST.MF") || n.toUpperCase().startsWith("META-INF/CERT")));
  ar.remove((n) => n === "stamp-cert-sha256");
  await tick("pack");
  const { local, cd } = ar.build();
  await tick("sign");
  const parts = await signApk({ local, cd, count: ar.entries.length }, identity);
  report.package = opts.package || pkg;
  report.size = parts.reduce((s, p) => s + p.length, 0);
  log("signed (APK Signature Scheme v2)");
  return { parts, report };
}
