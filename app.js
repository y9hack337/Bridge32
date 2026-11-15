import { analyze, describe, patchApk, parseSymbols, validPackageName, PatchError } from "./js/patcher.js";
import { createIdentity, restoreIdentity } from "./js/sign.js";

// ------------------------------------------------------------------------------------------ i18n
const T = {
  ru: {
    title: "Старые игры — на новых телефонах",
    lead: "Выберите APK 32-битной игры. Патч выполнится прямо в браузере, файл никуда не загружается.",
    drop: "Перетащите APK сюда", dropOr: "или нажмите, чтобы выбрать файл",
    options: "Параметры", compat: "Исправить старый Java-код (Apache HTTP, биллинг) — нужно играм, которые иначе вылетают при запуске", changes: "Что изменено", rename: "Установить рядом с оригиналом (сменить имя пакета)", keepAbis: "Оставить библиотеки x86/mips",
    patch: "Пропатчить", other: "Другой файл", download: "Скачать",
    howT: "Как это работает",
    how: "К игре добавляется небольшая прослойка Bridge32 — транслятор 32-битного ARM-кода в arm64 с поддержкой системных вызовов Android. Исходные библиотеки остаются в APK, манифест исправляется под новые версии Android, и пакет подписывается.",
    limitsT: "Что важно знать",
    limits: "Подходят нативные игры на движках вроде Fusion и Cocos; игры на Unity и сложные движки — экспериментально. Если игра обращается к системной функции, которой нет в прослойке, мы предупредим об этом заранее.",
    keyT: "Подпись и обновления",
    key: "Ключ подписи создаётся один раз и хранится только в вашем браузере, поэтому повторные патчи ставятся поверх друг друга. Если очистить данные сайта, ключ изменится — тогда прежнюю версию придётся удалить. Сохраните ключ, чтобы не потерять его.",
    keyExp: "Сохранить ключ", keyImp: "Загрузить ключ", keyBad: "Не удалось прочитать ключ",
    foot: "Всё выполняется локально в вашем браузере.",
    vArm32: "32-бит ARM · нужна трансляция", vArm64: "Уже arm64", vJava: "Чистая Java", vNone: "Нельзя перенести",
    ver: "версия", abis: "ABI", noAbis: "нет нативного кода",
    sReading: "Читаю файл…", sLoading: "Загружаю среду выполнения…", sPatching: "Патчу манифест и библиотеки…", sPack: "Собираю APK…", sSign: "Подписываю…",
    sReady: "Готово", sReadyMeta: (n, mb) => `Готово · ${mb} МБ · ${n}`,
    hintRename: "Установите файл на телефон. Игра появится как отдельное приложение рядом с оригиналом.",
    hintReplace: "Установите файл на телефон. Если на нём стоит оригинал — сначала удалите его: подпись отличается.",
    errNone: "В APK нет ARM-библиотек: трансляция невозможна.", errPkg: "Некорректное имя пакета", errGeneric: "Не удалось обработать файл: ",
    warnHead: "Возможны проблемы",
  },
  en: {
    title: "Old games on new phones",
    lead: "Choose the APK of a 32-bit game. It is patched right in your browser; the file never leaves your device.",
    drop: "Drop an APK here", dropOr: "or click to choose a file",
    options: "Options", compat: "Fix old Java code (Apache HTTP, billing) — needed by games that otherwise crash on launch", changes: "What was changed", rename: "Install next to the original (change package name)", keepAbis: "Keep x86/mips libraries",
    patch: "Patch", other: "Another file", download: "Download",
    howT: "How it works",
    how: "A small Bridge32 layer is added to the game: a translator that runs 32-bit ARM code on arm64 and provides Android's system calls. The original libraries stay in the APK, the manifest is updated for current Android versions, and the package is signed.",
    limitsT: "Good to know",
    limits: "Native games on engines such as Fusion and Cocos work best; Unity and complex engines are experimental. If a game calls a system function the layer lacks, you are warned in advance.",
    keyT: "Signature and updates",
    key: "The signing key is created once and kept only in your browser, so repeated patches install over each other. If you clear the site's data the key changes and the previous version has to be uninstalled first. Save the key so you don't lose it.",
    keyExp: "Save key", keyImp: "Load key", keyBad: "Could not read the key",
    foot: "Everything runs locally in your browser.",
    vArm32: "32-bit ARM · needs translation", vArm64: "Already arm64", vJava: "Pure Java", vNone: "Cannot be ported",
    ver: "version", abis: "ABIs", noAbis: "no native code",
    sReading: "Reading the file…", sLoading: "Loading the runtime…", sPatching: "Patching manifest and libraries…", sPack: "Building the APK…", sSign: "Signing…",
    sReady: "Done", sReadyMeta: (n, mb) => `Done · ${mb} MB · ${n}`,
    hintRename: "Install the file on your phone. The game appears as a separate app next to the original.",
    hintReplace: "Install the file on your phone. If the original is installed, uninstall it first: the signature differs.",
    errNone: "The APK has no ARM libraries: it cannot be translated.", errPkg: "Invalid package name", errGeneric: "Could not process the file: ",
    warnHead: "Possible problems",
  },
};
const safe = (f, d) => { try { return f(); } catch { return d; } };
let lang = safe(() => localStorage.getItem("bridge32.lang"), null) || (/^(ru|uk|be)/i.test(navigator.language) ? "ru" : "en");
const t = (k, ...a) => (typeof T[lang][k] === "function" ? T[lang][k](...a) : T[lang][k]);

const $ = (id) => document.getElementById(id);
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $("lang").textContent = lang === "ru" ? "EN" : "RU";
  if (state.info) renderInfo();
  renderStatus();
}

// ------------------------------------------------------------------------------------------ state
const state = { file: null, bytes: null, info: null, url: null, busy: false };
let assets = null;

async function loadAssets() {
  if (!assets) {
    assets = (async () => {
      const get = async (n) => { const r = await fetch("data/" + n); if (!r.ok) throw new Error(n + ": HTTP " + r.status); return r; };
      const [lib, proxy, syms] = await Promise.all([get("libapk64.so"), get("libapk64proxy.so"), get("runtime_symbols.txt")]);
      return { lib: new Uint8Array(await lib.arrayBuffer()), proxy: new Uint8Array(await proxy.arrayBuffer()), symbols: parseSymbols(await syms.text()) };
    })();
    assets.catch(() => { assets = null; });
  }
  return assets;
}

const KEY = "bridge32.identity";
async function getIdentity() {
  const saved = safe(() => JSON.parse(localStorage.getItem(KEY)), null);
  if (saved) { try { return await restoreIdentity(saved); } catch { /* regenerate below */ } }
  const id = await createIdentity();
  safe(() => localStorage.setItem(KEY, JSON.stringify({ jwk: id.jwk, certB64: id.certB64 })));
  return id;
}

// ------------------------------------------------------------------------------------------ UI
const frame = () => new Promise((r) => setTimeout(r, 24));
let statusState = { key: "", err: false, raw: "" };
function renderStatus() { const s = $("status"); s.textContent = statusState.raw || (statusState.key ? t(statusState.key) : ""); s.classList.toggle("err", statusState.err); }
/** `msg` is a translation key, or free text when `raw` is true (error messages). */
function status(msg, err = false, raw = false) { statusState = { key: raw ? "" : msg, err, raw: raw ? msg : "" }; renderStatus(); }
function progress(p) { $("prog").hidden = p === null; if (p !== null) $("bar").style.width = Math.round(p * 100) + "%"; }

function defaultPackage(pkg) { return "com.bridge32." + pkg.split(".").pop().toLowerCase().replace(/[^a-z0-9_]/g, ""); }

function renderInfo() {
  const i = state.info;
  $("pkg").textContent = i.pkg;
  $("sub").textContent = `${t("ver")} ${i.versionName ?? "?"} (${i.versionCode ?? "?"}) · ${state.file.name} · ${(state.file.size / 1048576).toFixed(1)} ${lang === "ru" ? "МБ" : "MB"}`;
  const v = { arm32: ["vArm32", "warn"], arm64: ["vArm64", "ok"], java: ["vJava", "ok"], unsupported: ["vNone", "bad"] }[i.kind];
  const b = $("verdict"); b.textContent = t(v[0]); b.className = "badge " + v[1];
  $("abis").replaceChildren(...(i.abis.length ? i.abis : [t("noAbis")]).map((a) => Object.assign(document.createElement("span"), { textContent: a })));
  const w = $("warns");
  w.hidden = !i.warnings.length;
  w.replaceChildren(...i.warnings.map((x) => Object.assign(document.createElement("li"), { textContent: x })));
  $("go").disabled = i.kind === "unsupported" || state.busy;
  if (i.kind === "unsupported") status("errNone", true);
}

function validatePkg() {
  const on = $("rename").checked, el = $("newpkg");
  el.hidden = !on;
  const bad = on && !validPackageName(el.value.trim());
  el.classList.toggle("invalid", bad);
  $("go").disabled = bad || state.busy || state.info?.kind === "unsupported";
}

function reset() {
  if (state.url) { URL.revokeObjectURL(state.url); state.url = null; }
  Object.assign(state, { file: null, bytes: null, info: null });
  $("card").hidden = true; $("drop").hidden = false; $("result").hidden = true; $("again").hidden = true;
  $("file").value = ""; status(""); progress(null);
}

async function onFile(file) {
  if (!file || state.busy) return;
  reset();
  state.file = file;
  $("drop").hidden = true; $("card").hidden = false;
  $("pkg").textContent = file.name; $("sub").textContent = ""; $("abis").replaceChildren(); $("warns").hidden = true; $("verdict").textContent = ""; $("verdict").className = "badge";
  $("go").disabled = true; $("again").hidden = false;
  status("sReading");
  try {
    state.bytes = new Uint8Array(await file.arrayBuffer());
    const [a, rt] = await Promise.all([analyze(state.bytes), loadAssets()]);
    state.info = describe(a, rt.symbols);
    $("newpkg").value = defaultPackage(state.info.pkg);
    status("");
    renderInfo(); validatePkg();
  } catch (e) {
    console.error(e);
    $("go").disabled = true;
    status(e instanceof PatchError ? e.message : t("errGeneric") + e.message, true, true);
  }
}

async function patch() {
  if (state.busy || !state.bytes) return;
  state.busy = true; $("go").disabled = true; $("result").hidden = true; $("again").disabled = true;
  try {
    status("sLoading"); progress(0.08); await frame();
    const rt = await loadAssets();
    const identity = await getIdentity();
    status("sPatching"); progress(0.25); await frame();
    const a = await analyze(state.bytes);                       // a fresh archive: patching mutates it
    const rename = $("rename").checked;
    const opts = { package: rename ? $("newpkg").value.trim() : undefined, keepAbis: $("keepabis").checked, javaCompat: $("compat").checked };
    const changes = [];
    const stages = { pack: ["sPack", 0.6], sign: ["sSign", 0.78] };
    const { parts, report } = await patchApk(a, rt, identity, opts, (m) => changes.push(m), async (s) => { status(stages[s][0]); progress(stages[s][1]); await frame(); });
    const blob = new Blob(parts, { type: "application/vnd.android.package-archive" });
    if (state.url) URL.revokeObjectURL(state.url);
    state.url = URL.createObjectURL(blob);
    const name = state.file.name.replace(/\.apk$/i, "") + "_arm64.apk";
    Object.assign($("dl"), { href: state.url, download: name });
    $("dlname").textContent = `${(blob.size / 1048576).toFixed(1)} ${lang === "ru" ? "МБ" : "MB"}`;
    $("hint").textContent = rename ? t("hintRename") : t("hintReplace");
    $("changes").replaceChildren(...changes.map((x) => Object.assign(document.createElement("li"), { textContent: x })));
    $("result").hidden = false; progress(1); status("sReady");
    if (report.warnings.length) { $("warns").hidden = false; $("warns").replaceChildren(...report.warnings.map((x) => Object.assign(document.createElement("li"), { textContent: x }))); }
  } catch (e) {
    console.error(e); progress(null);
    status(e instanceof PatchError ? e.message : t("errGeneric") + e.message, true, true);
  } finally {
    state.busy = false; $("again").disabled = false; validatePkg();
  }
}

// ------------------------------------------------------------------------------------------ wiring
const drop = $("drop"), picker = $("file");
drop.addEventListener("click", () => picker.click());
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
picker.addEventListener("change", () => onFile(picker.files[0]));
for (const ev of ["dragenter", "dragover"]) window.addEventListener(ev, (e) => { e.preventDefault(); if (!$("drop").hidden) drop.classList.add("over"); });
for (const ev of ["dragleave", "drop"]) window.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); });
window.addEventListener("drop", (e) => onFile(e.dataTransfer?.files?.[0]));
$("go").addEventListener("click", patch);
$("again").addEventListener("click", reset);
$("rename").addEventListener("change", validatePkg);
$("newpkg").addEventListener("input", validatePkg);
$("lang").addEventListener("click", () => { lang = lang === "ru" ? "en" : "ru"; safe(() => localStorage.setItem("bridge32.lang", lang)); applyLang(); });

$("keyexp").addEventListener("click", async () => {
  const id = await getIdentity();
  const url = URL.createObjectURL(new Blob([JSON.stringify({ jwk: id.jwk, certB64: id.certB64 })], { type: "application/json" }));
  Object.assign(document.createElement("a"), { href: url, download: "bridge32-key.json" }).click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
});
$("keyimp").addEventListener("click", () => $("keyfile").click());
$("keyfile").addEventListener("change", async (e) => {
  try {
    const saved = JSON.parse(await e.target.files[0].text());
    await restoreIdentity(saved);
    localStorage.setItem(KEY, JSON.stringify({ jwk: saved.jwk, certB64: saved.certB64 }));
  } catch { alert(t("keyBad")); }
  e.target.value = "";
});

applyLang();
loadAssets().catch(() => {});
