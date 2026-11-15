// Node runner for the browser patcher (same modules): node test/cli.mjs in.apk out.apk [--package com.x.y] [--info]
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyze, describe, patchApk, parseSymbols } from "../js/patcher.js";
import { createIdentity, restoreIdentity } from "../js/sign.js";
import { existsSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const [inp, out] = args.filter((a, i) => !a.startsWith("--") && !args[i - 1]?.startsWith("--"));
const data = (n) => new Uint8Array(readFileSync(join(here, "..", "data", n)));
const syms = parseSymbols(readFileSync(join(here, "..", "data", "runtime_symbols.txt"), "utf8"));

const t0 = Date.now();
const a = await analyze(new Uint8Array(readFileSync(inp)));
console.log(JSON.stringify(describe(a, syms), null, 1));
if (args.includes("--info")) process.exit(0);
// a persistent test key (.test_key.json, or $BRIDGE32_KEY) so that reinstalling over a previous build works
const keyFile = process.env.BRIDGE32_KEY || join(here, "..", ".test_key.json");
let identity;
if (existsSync(keyFile)) identity = await restoreIdentity(JSON.parse(readFileSync(keyFile, "utf8")));
else { identity = await createIdentity(); writeFileSync(keyFile, JSON.stringify({ jwk: identity.jwk, certB64: identity.certB64 })); }
const { parts, report } = await patchApk(a, { lib: data("libapk64.so"), proxy: data("libapk64proxy.so"), symbols: syms }, identity,
  { package: opt("--package"), debuggable: args.includes("--debuggable") ? true : undefined, targetSdk: opt("--target-sdk") ? +opt("--target-sdk") : undefined }, (m) => console.log("  " + m));
writeFileSync(out, Buffer.concat(parts));
console.log(`wrote ${out} (${(report.size / 1048576).toFixed(1)} MB) in ${Date.now() - t0} ms; warnings: ${report.warnings.length}`);
