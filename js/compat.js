// Compatibility fixes for the Java side of old games (bytecode patches that keep every offset in the DEX unchanged).
import { Dex } from "./dex.js";

const BILLING_ACTION = "com.android.vending.billing.MarketBillingService.BIND";
const BIND_PROTO = "(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z";

/**
 * The original Android Market billing (IAB v2) binds an implicit Intent; since Android 5 that throws
 * IllegalArgumentException for apps targeting 21+ and crashes the game. The service is long gone anyway, so the
 * bindService() call inside code that uses that action is replaced by `false` (the game treats it as "billing not available").
 * Returns the number of patched call sites.
 */
function fixMarketBilling(dex) {
  const sid = dex.findString(BILLING_ACTION);
  if (sid < 0) return 0;
  let patched = 0;
  dex.forEachCode((midx, code, start, units) => {
    let usesAction = false;
    const calls = [];
    dex.walk(start, units, (i, op) => {
      const o = start + 2 * i;
      if (op === 0x1a && dex.dv.getUint16(o + 2, true) === sid) usesAction = true;
      else if (op === 0x1b && dex.u32(o + 2) === sid) usesAction = true;
      else if (op >= 0x6e && op <= 0x72) {
        const m = dex.method(dex.dv.getUint16(o + 2, true));
        if (m.name === "bindService" && m.proto === BIND_PROTO) calls.push(i);
      }
    });
    if (!usesAction) return;
    for (const i of calls) {
      const o = start + 2 * i, next = i + 3 < units ? dex.dv.getUint16(o + 6, true) : 0;
      const hasResult = (next & 0xFF) === 0x0A;
      for (let k = 0; k < (hasResult ? 4 : 3); k++) dex.dv.setUint16(o + 2 * k, 0, true);        // nops over the invoke (and its move-result)
      if (hasResult) {                                                                            // move-result vAA -> const vAA, 0
        const reg = next >> 8;
        if (reg < 16) dex.dv.setUint16(o, 0x12 | (reg << 8), true);                               // const/4 vA, #0
        else dex.dv.setUint16(o, 0x13 | (reg << 8), true);                                        // const/16 vAA, #0 (next unit is already 0)
      }
      patched++;
    }
  });
  return patched;
}

/** Apply every Java compatibility fix to the classes*.dex files of an archive. */
export async function patchJavaCompat(ar, log) {
  let total = 0;
  for (const e of [...ar.entries]) {
    if (!/^classes\d*\.dex$/.test(e.name)) continue;
    const bytes = (await ar.read(e.name)).slice();            // a private copy: the archive may hand out views of the input
    let dex;
    try { dex = new Dex(bytes); } catch { continue; }
    const n = fixMarketBilling(dex);
    if (!n) continue;
    await dex.fixHeader();
    await ar.set(e.name, bytes, true);
    total += n;
    log(`${e.name}: replaced ${n} implicit bindService call(s) of the old Market billing (rejected by Android 5+)`);
  }
  return total;
}
