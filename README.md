# Bridge32

Run old 32-bit ARM Android games on arm64-only phones. This repository is the **in-browser patcher**: pick an APK,
and it is patched and signed locally — nothing is uploaded anywhere.

**Live site:** https://y9hack337.github.io/Bridge32/

## How it works

Bridge32 adds a small translation layer to the game: an ARMv7 interpreter with an AArch64 JIT, plus a reimplementation of
the Android/bionic APIs the game links against. The original libraries stay in the APK, the manifest is updated for
current Android versions, old Java-side incompatibilities are fixed (legacy Apache HTTP, the retired Market billing), and
the package is signed with APK Signature Scheme v2 (WebCrypto, RSA-2048). The signing key is created once and kept in your
browser; use *Signature and updates* on the page to back it up.

Works best with native games on engines such as Fusion and Cocos; Unity and other heavy engines are experimental. The page
tells you in advance if a game imports a system function the layer does not provide.

## Layout

```
index.html, style.css, app.js     the page
js/                               the patcher: zip.js, axml.js, dex.js, compat.js, elf.js, sign.js, patcher.js
data/                             libapk64.so, libapk64proxy.so (the runtime), runtime_symbols.txt
test/cli.mjs                      the same code under Node: node test/cli.mjs in.apk out.apk [--package com.x.y]
```

Requirements for visitors: a current browser (Chrome/Edge 103+, Firefox 113+, Safari 16.4+).

## Verify an output

```
node test/cli.mjs game.apk out.apk
apksigner verify --min-sdk-version 24 out.apk
```

This repository contains no game files; you bring your own APK, and it never leaves your device.
