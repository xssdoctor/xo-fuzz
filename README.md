# xo-fuzz

**Cross-origin fuzzers for browsers, in the style of Gareth Heyes' cross-domain enumerators.**

Twenty years ago, getting another site's `Function` took a single property that should have been blocked:

```js
iframe.contentWindow.location.constructor   // Opera returned the victim's Location constructor
newWin.closed.constructor.constructor       // IE returned the victim's Function
```

One leaked object, two hops up the constructor chain, and you could run code as the other site: a universal XSS (uXSS). xo-fuzz automates the hunt for that kind of bug in modern browsers. It reaches into cross-origin windows every way it can, records exactly what comes back, and flags anything that belongs to the other site.

| | **Property fuzzer** (v1) | **Lifecycle fuzzer** (v2) |
|---|---|---|
| File | `xo-fuzz.js` → `xoFuzz()` | `xo-lifecycle.js` → `xoLife()` |
| Question | In its normal state, does every cross-origin object follow the spec, for every property and operation? | If I grab references at moment X, tear the frame down with Y, and probe at Z, can I still reach anything? |
| Size of a run | ~24,000 operations | 720-case matrix, coverage-guided |
| Finds | Allowlist violations, realm leaks | Teardown and timing leaks, new code paths |

Both are single files with no dependencies. Paste either one into any browser's devtools console and run it.

---

## Contents

- [Quick start](#quick-start)
- [Background: why `.constructor.constructor`](#background-why-constructorconstructor)
- [How it works](#how-it-works)
- [Property fuzzer (v1)](#property-fuzzer-v1)
- [Lifecycle fuzzer (v2)](#lifecycle-fuzzer-v2)
- [Reading the results](#reading-the-results)
- [Local lab](#local-lab)
- [Cross-browser workflow](#cross-browser-workflow)
- [Results so far](#results-so-far)
- [Lessons learned](#lessons-learned)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Files](#files)
- [Credits and responsible use](#credits-and-responsible-use)

---

## Quick start

### In any browser console (no setup)

1. Open devtools on any page. Chrome and Firefox make you type `allow pasting` before the first paste.
2. Paste the whole of `xo-fuzz.js` or `xo-lifecycle.js`.
3. Run it:

```js
// Property fuzzer
await xoFuzz()                                       // frames https://example.com/
await xoFuzz({ target: 'https://other.site/' })      // any cross-origin page
await xoFuzz({ popup: true })                        // also fuzz a window.open() popup

// Lifecycle fuzzer
await xoLife()                                       // 300 cases against https://example.com/
await xoLife({ target: 'https://other.site/', iterations: 1000 })
await xoLife.replay('load/remove/sync/0')            // reproduce one case, verbose

// Save the last report as JSON, named after the browser
xoFuzz.download()
xoLife.download()
```

Results print as `console.table`s with a one-line summary above. If a console won't accept top-level `await`, use `xoFuzz().then(r => console.log(r.counts))`.

### In the local lab (two origins, autorun, saved reports)

```bash
cd xo-fuzz
bun serve.ts
```

| URL | What it does |
|---|---|
| `http://127.0.0.1:8000/` | Property fuzzer UI |
| `http://127.0.0.1:8000/life.html` | Lifecycle fuzzer UI |
| add `?autorun=1` | Run on load and save `results/<fuzzer>-<browser>.json` |

See [Local lab](#local-lab).

---

## Background: why `.constructor.constructor`

### Realms

Every JavaScript object belongs to a **realm**: one global environment with its own `Object`, `Function`, `Array.prototype` and so on. Each window and iframe is its own realm. Walking up the constructor chain always lands in the realm that created the object:

```js
value.constructor              // that realm's Boolean / Object / Location / ...
value.constructor.constructor  // that realm's Function
```

`Function(code)` compiles code in **its own** realm's global scope. So any object that crosses from a victim window into yours is a potential way in: climb to its `Function`, and your code runs as the victim.

### Gareth's Opera bug, hop by hop

```js
iframe.contentWindow.location.constructor.prototype
  .__defineGetter__.constructor('[].constructor.prototype.join=function(){alert("PWND:"+document.body.innerHTML)}')();
```

| Hop | Allowed cross-origin? | What it returns |
|---|---|---|
| `iframe.contentWindow` | ✅ | The frame's WindowProxy |
| `.location` | ✅ | The frame's `Location` (allowed, so you can navigate it) |
| `.constructor` | ❌ **the bug** | Should throw `SecurityError`; Opera returned the victim's `Location` constructor |
| `.prototype.__defineGetter__` | normal JS | Any built-in function from the victim realm |
| `.constructor` | normal JS | The victim realm's `Function` |
| `('...')()` | normal JS | Runs in the victim realm |

Opera checked access by **who was calling** (the call stack), so the injected code could compute `1+1` but not read `document`. The workaround was to overwrite the victim realm's `Array.prototype.join`. When the victim page's own code later called it, the access check passed.

### What changed since

The HTML spec now pins down exactly what a cross-origin object exposes:

| Object | Readable | Writable |
|---|---|---|
| `Window` | `window`, `self`, `location`, `close`, `closed`, `focus`, `blur`, `frames`, `length`, `top`, `opener`, `parent`, `postMessage`, child frame indexes and names | `location` |
| `Location` | `replace` | `href` (write only) |

- `then`, `Symbol.toStringTag`, `Symbol.hasInstance` and `Symbol.isConcatSpreadable` return `undefined` instead of throwing, so `await win`, `Object.prototype.toString.call(win)` and `instanceof` don't crash.
- **Everything else must throw `SecurityError`.**
- The getter and setter functions handed out for allowed properties are created in the **caller's** realm, so even they can't be climbed.

That closes the class, provided browsers implement it exactly, in every state an object can be in. xo-fuzz checks exactly that.

---

## How it works

Both fuzzers share three ideas.

**1. Compare against the spec, not intuition.** Every operation has an expected outcome from the allowlist above. Anything that succeeds when it should throw is flagged.

**2. Check the realm of everything that comes back.** Every returned value and every **thrown error object** goes through the same check:

```
x.constructor.constructor  ──►  is it our Function?
        │ no
        ▼
F('return self.origin')()  ──►  the target's origin?  ──►  LEAK
                               a same-origin realm?   ──►  ignore (e.g. about:blank)
                               anything else?         ──►  FOREIGN
```

Property descriptors are unpacked too, so a getter created in the wrong realm is caught.

**3. Don't trust the page you run on.** `Function`, `Reflect.ownKeys`, `Object.getPrototypeOf`, `Object.prototype.toString` and the other built-ins are captured when the script loads, so a page that has patched its own prototypes can't skew the results.

---

## Property fuzzer (v1)

`xoFuzz()` takes every cross-origin object it can reach and tries every property name on it, with every operation.

### Stages

| Stage | Objects fuzzed | Why |
|---|---|---|
| `iframe` | `contentWindow`, its `location`, and `frames[0]` and its `location` when present | The normal case, plus a nested frame |
| `detached` | The same window and `location`, kept after the `<iframe>` is removed | A detached WindowProxy goes through different code |
| `stale` | `Function`, `location`, `document` grabbed from the frame's initial same-origin `about:blank`, used after it navigates to the target | Do old same-origin references end up pointing at the new cross-origin document? |
| `popup` | A `window.open()` window and its `location` (`popup: true`) | Popups go through different code from iframes |

### Operations per property

| Operation | Allowlisted key | Any other key |
|---|---|---|
| `obj[key]` | value (`undefined` for fallback keys) | `SecurityError` |
| `key in obj` | `true` / `false` | `SecurityError` |
| `Object.getOwnPropertyDescriptor(obj, key)` | descriptor | `SecurityError` |
| `obj[key] = 'xo-fuzz'` | skipped | `SecurityError` |
| `delete obj[key]` | `SecurityError` | `SecurityError` |
| `Object.defineProperty(obj, key, …)` | `SecurityError` | `SecurityError` |

Writes to `window.location` and `location.href` are never attempted: they would navigate the target away mid-run.

### Object-level operations

| Operation | Spec |
|---|---|
| `Object.getPrototypeOf` | `null` |
| `Reflect.setPrototypeOf(obj, {})` | `false` |
| `Object.isExtensible` | `true` |
| `Reflect.preventExtensions` | `false` |
| `Reflect.ownKeys` | allowlisted keys, fallback keys and frame indexes only |
| `Object.prototype.toString.call` | `"[object Object]"` |
| `String(obj)`, `JSON.stringify(obj)` | `SecurityError` |

### Candidate keys

Built at runtime from the fuzzer's own page, so it adapts to each browser: `Reflect.ownKeys` of `window`, `Window.prototype`, the WindowProperties object, `EventTarget.prototype`, `Location.prototype` and `Object.prototype`, plus every well-known `Symbol` and a few extras (`__proto__`, `constructor`, `then`, `toJSON`, `__defineGetter__`, `0`, `kid`, a name that doesn't exist, …). That's about 1,000 keys per window target in Chrome.

### Child frames

Child frame indexes and names are allowed by the spec, but names can't be learned across origins. The fuzzer reads the allowed `length`, collects `obj[0 … length-1]`, and accepts any named read that returns one of those windows. Pages with named iframes don't produce false positives.

### Options

```js
const report = await xoFuzz({
  target: 'https://example.com/',  // default; http://<host>:<port+1>/target.html when run from localhost
  popup: false,                    // also fuzz a window.open() popup
  popupWindow: undefined,          // or pass an already-opened window (see below)
  loadTimeout: 10000,              // ms to wait for a frame's load event
  settle: 1000,                    // ms after load for nested frames
  container: document.body,        // where temporary iframes go
  quiet: false,                    // true: no console output
});
```

The target must be cross-origin to the page you run on, otherwise `xoFuzz` throws. `window.open` usually works from the console. From your own page, open the popup synchronously inside a click handler and pass it in:

```js
button.onclick = () => xoFuzz({ popupWindow: window.open(target, 'xofuzz', 'width=400,height=300') });
```

### Report

```js
{
  ua, from, target, date,
  counts: { LEAK: 0, FOREIGN: 0, SPEC: 0, info: 12, ok: 16605 },
  rows: [ { sev, stage, target, op, key, outcome, detail } ],   // most severe first
}
```

Also stored in `window.xoFuzzReport`. In the Chrome or Firefox console, run `copy(JSON.stringify(xoFuzzReport))` to put it on the clipboard.

---

## Lifecycle fuzzer (v2)

On current browsers v1 comes back clean in the normal state. The remaining risk is in **timing and teardown**: what happens to references you're holding when the frame they came from is removed, moved or navigated at an awkward moment.

v1 already hinted at this. In Chrome, a detached window blocks access with a different error message from a live one. The outcome is the same, but it comes from separate code.

### Anatomy of a case

```
create iframe ──► CAPTURE refs ──(delay ms)──► TEARDOWN ──(timing)──► PROBE refs
                  blank | load |               remove | moveBefore |   sync | microtask |
                  settled                      adoptNode | …           timeout0 | raf | late
```

Every case is a **recipe**, written `capture/teardown/timing/delay`, e.g. `settled/moveBefore/raf/20`.

| Part | Value | Meaning |
|---|---|---|
| **capture** | `blank` | Grab `Function`, `document` and `location` from the initial same-origin `about:blank`, then point `src` at the target. The teardown lands mid-navigation |
| | `load` | Grab refs inside the iframe's `load` event |
| | `settled` | Grab refs after `load` plus `settle` ms, so nested frames exist |
| **teardown** (after `delay` ms; `0` = synchronously, e.g. inside the `load` handler) | `none` | Control |
| | `remove` | `iframe.remove()` |
| | `reinsert` | Remove and re-append. The frame reloads, and old refs point at the discarded one |
| | `moveBefore` | `Element.prototype.moveBefore()`: a new **atomic move** that changes the parent without tearing the frame down. Skipped where unsupported |
| | `adoptNode` | Move the iframe into another (same-origin) document |
| | `navigate-blank` | `iframe.src = 'about:blank'` (the frame becomes same-origin with us) |
| | `navigate-srcdoc` | `iframe.srcdoc = …` (same) |
| | `body-clear` | `container.innerHTML = ''`, removal through the HTML parser |
| **timing** | `sync`, `microtask`, `timeout0`, `raf`, `late` | When probes run after teardown. `late` = 300 ms; `raf` falls back to 200 ms in background tabs |
| **delay** | `0`, `1`, `5`, `20`, `50`, `150` | Plus random delays from mutants |

The full matrix is 3 × 8 × 5 × 6 = **720 cases**, visited in a seeded random order. The same `seed` gives the same run.

### Fast probes

Each case runs about 20 targeted probes instead of v1's 1,000-key sweep:

| Ref | What | Allowed probes | Must-throw probes |
|---|---|---|---|
| `w` | the iframe's WindowProxy | `closed`, `length`, `frames[0]`, `getOwnPropertyDescriptor(w,'location').get` | `constructor`, `document`, `name`, `location.href`, `String(w)` |
| `loc` | its `Location` | `replace`, `getOwnPropertyDescriptor(loc,'href').set` | `constructor`, `href`, `origin`, `String(loc)` |
| `kid`, `kidLoc` | nested frame and its `Location` | `location` | `constructor`, `document`, `href` |
| `oldF`, `oldDoc`, `oldLoc` | from the initial `about:blank` (`blank` capture) | `oldF('return location.href')()`, `oldF('return document.body.innerHTML')()`, `oldDoc.URL`, `oldDoc.body.innerHTML`, `oldLoc.href`, all checked for target content | |

Every value and every thrown error also goes through the [realm check](#how-it-works).

### Error messages as coverage

A black-box browser gives you no code coverage. **Error messages are a cheap stand-in**: when the same operation produces a different message, it went through a different code path.

Every probe outcome becomes a **signature**:

```
ok:function
SecurityError:Failed to read a named property '<s>' from '<s>': Blocked a frame with origin "<s>" …
TypeError:no access
```

Quoted strings, URLs and numbers become placeholders, so only the code path is left. The teardown's own result is recorded the same way (`teardown:moveBefore → ok`), so a teardown that throws is visible.

**Coverage guidance:** when a case produces a signature never seen before, two **mutants** (same recipe, random nearby delay) jump to the front of the queue. The run drifts towards timings that reach new code.

### Options

```js
await xoLife({
  target: 'https://example.com/',  // same defaults as xoFuzz
  iterations: 300,                 // cases to run; the full matrix is 720, plus mutants
  seed: 1,                         // case order
  loadTimeout: 10000,              // ms before a case counts as timed out
  settle: 500,                     // ms after load for the "settled" capture
  container: document.body,
  quiet: false,
  onProgress: ({ ran, total, findings }) => {},
});

await xoLife.replay('settled/adoptNode/microtask/5', { target, repeat: 5 });
```

### Report

```js
{
  kind: 'lifecycle', ua, from, target, date, seed,
  cases, matrix, mutants, timeouts, seconds,
  skipped,                                            // e.g. moveBefore where unsupported
  signatures,                                         // distinct (probe, signature) pairs
  findings: [ { sev, probe, detail, recipe, teardown } ],
  coverage: [ { probe, outcomes, signature, count, firstSeen } ],
}
```

The console prints the findings plus every probe with **more than one outcome**: the places where the browser took different paths. Each row names the first recipe that hit it, ready for `xoLife.replay`.

---

## Reading the results

### Severity

| Severity | Fuzzer | Meaning | What to do |
|---|---|---|---|
| `LEAK` | both | Code ran as the target origin, or a probe returned target content (its origin or `XO-FUZZ-SECRET`) | A uXSS-class bug. Reduce it to a minimal test case and report it to the browser vendor |
| `FOREIGN` | both | Reached a `Function` from a realm that's neither ours nor known same-origin | Find out whose realm it is, and whether it can be steered to the target |
| `SPEC` | v1 | A must-throw operation didn't throw, or an object operation returned the wrong value | The interesting differences. Read `detail` |
| `ANOMALY` | v2 | A must-throw probe succeeded on a ref that must still be cross-origin (`loc`, `kid`, `kidLoc` always; `w` when captured after load and not navigated to `about:blank`/`srcdoc`) | Replay the recipe, then reduce it |
| `info` | v1 | An allowed operation threw | Browser is stricter than the spec. Not exploitable alone; useful when comparing browsers |
| `ok` | v1 | As the spec requires | Hidden by default |

### v1 columns

| Column | Content |
|---|---|
| `stage` | `iframe`, `detached`, `stale`, `popup` |
| `target` | Object fuzzed, e.g. `contentWindow.location` |
| `op` | `get`, `in`, `getOwnPropertyDescriptor`, `set`, `delete`, `defineProperty`, an object operation, `realm` or `stale-ref` |
| `key` | Property name, or `-` for object-level operations |
| `outcome` | `blocked`, `allowed`, `no throw (spec requires SecurityError)`, … |
| `detail` | Value type or error message; for `realm` rows, what `F('return self.origin')()` returned |

### What a hit would look like

The Opera bug, as xo-fuzz would report it:

```
SPEC | iframe | contentWindow.location | get   | constructor | no throw (spec requires SecurityError) | function Location
LEAK | iframe | contentWindow.location | realm | contentWindow.location[constructor] via get | foreign Function reachable | … → https://victim.example
```

### Noise

- Console lines from the page or your extensions are unrelated.
- A target that blocks framing (`X-Frame-Options`, CSP `frame-ancestors`) loads the browser's error page instead. The fuzzer carries on after `loadTimeout`. The error page is still cross-origin, so the run is valid, but it's testing the error page, not the target.

---

## Local lab

`serve.ts` (requires [bun](https://bun.sh)) runs two origins on `127.0.0.1`:

| Port | Role | Serves |
|---|---|---|
| `8000` | attacker | `fuzz.html`, `life.html`, `xo-fuzz.js`, `xo-lifecycle.js`, `POST /report` |
| `8001` | victim | `target.html` |

Different ports make different **origins**, so every access from `:8000` to `:8001` is cross-origin. They are the same **site**, though, because site ignores the port. For cross-site behaviour (site isolation, separate processes), set `?target=` to an external URL.

`target.html` provides:
- the text `XO-FUZZ-SECRET` and `window.secret = 'XO-FUZZ-SECRET'` as leak markers
- one nested iframe named `kid`, so indexed and named frame access get exercised

### UIs

| Page | Controls |
|---|---|
| `fuzz.html` | target, **run**, **run + popup**, show all rows, export JSON |
| `life.html` | target, iterations, seed, **run**, **replay ×5**, export JSON; tables of findings and of probes with more than one outcome |

URL parameters: `?target=…`, `?autorun=1`, `?label=NAME`, and `?iterations=N` (`life.html` only). Autorun POSTs the report to `/report`, which saves it as `results/props-<label>.json` or `results/lifecycle-<label>.json`. Without a label, the name comes from the user agent (`props-Chrome-156.json`), and every Chromium browser then claims to be Chrome. Always pass `?label=` when testing more than one browser per engine.

### Headless

```bash
# Chrome
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
  --user-data-dir=/tmp/xo-chrome --virtual-time-budget=900000 \
  --dump-dom "http://127.0.0.1:8000/life.html?autorun=1&iterations=1000" > /dev/null

# Firefox
/Applications/Firefox.app/Contents/MacOS/firefox --headless --new-instance \
  --profile "$(mktemp -d)" "http://127.0.0.1:8000/life.html?autorun=1&iterations=1000"
```

Safari has no headless mode; open the autorun URL by hand.

> **Watch the timeouts.** Chrome's `--virtual-time-budget` fast-forwards timers and can make frame loads time out partway through a run. Lifecycle results with `timeouts > 0` aren't reliable; rerun them in real time (a normal window, or headless without the flag).

---

## Cross-browser workflow

The best leads come from browsers disagreeing.

1. Run both autorun URLs in Chrome, Firefox and Safari, or use `xoFuzz.download()` / `xoLife.download()` from the console.
2. Diff two reports:

```bash
# property reports: compare rows
bun -e '
const [a, b] = await Promise.all(process.argv.slice(1).map(f => Bun.file(f).json()));
const key = r => [r.stage, r.target, r.op, r.key, r.sev, r.outcome].join(" | ");
const A = new Set(a.rows.map(key)), B = new Set(b.rows.map(key));
for (const k of A) if (!B.has(k)) console.log("only A:", k);
for (const k of B) if (!A.has(k)) console.log("only B:", k);
' results/props-Chrome-156.json results/props-Firefox-145.json

# lifecycle reports: compare code paths
bun -e '
const [a, b] = await Promise.all(process.argv.slice(1).map(f => Bun.file(f).json()));
const key = r => [r.probe, r.signature].join(" | ");
const A = new Set(a.coverage.map(key)), B = new Set(b.coverage.map(key));
for (const k of A) if (!B.has(k)) console.log("only A:", k);
for (const k of B) if (!A.has(k)) console.log("only B:", k);
' results/lifecycle-Chrome-156.json results/lifecycle-Firefox-145.json
```

3. Triage:
   - **Looser** in one browser (`SPEC`, `ANOMALY`, `FOREIGN`, `LEAK`): dig in.
   - **Stricter** in one browser (`info`): note it; it's a spec disagreement, not a hole.
   - **A code path only one browser reaches**: replay the recipe in both and compare.

---

## Results so far

### Chrome 156 (macOS): property fuzzer

| Run | LEAK | FOREIGN | SPEC | info | ok |
|---|---|---|---|---|---|
| Local lab, `:8000` → `:8001` | 0 | 0 | 0 | 18 | 23,879 |
| Pasted on a `file://` page, with popup | 0 | 0 | 0 | 19 | 23,843 |
| Pasted on `https://xssdoctor.com` → `https://example.com` | 0 | 0 | 0 | 12 | 16,605 |

Every `info` row is one of these, repeated across window and `location` targets (live and detached):

| Operation | Spec | Chrome |
|---|---|---|
| `Reflect.setPrototypeOf(win, {})` | `false` | throws `SecurityError` |
| `Reflect.preventExtensions(win)` | `false` | throws `SecurityError` |
| `'then' in win` | `false` | throws, even though `win.then` correctly returns `undefined` |
| `'kid' in win` (named child frame) | `true` | throws, even though `win.kid` works |

All four are Chrome being **stricter** than the spec, so none is exploitable. `then` and `kid` are good examples of two paths that should agree (`get` and `in`) giving different answers.

### Chrome 156 (macOS): lifecycle fuzzer

Full matrix: **738 cases** (18 mutants), about 4 minutes, **0 findings, 0 timeouts, 55 signatures**. All eight teardowns ran, `moveBefore` and `adoptNode` included.

The coverage table shows Chrome taking separate code paths:

| Probe | Signature | First recipe | State |
|---|---|---|---|
| `w.constructor` | `SecurityError: … Blocked a frame with origin "<s>" …` | `settled/none/raf/20` | live frame |
| `w.constructor` | `SecurityError: … An attempt was made to break through the security policy …` | `load/reinsert/timeout0/0` | detached frame |
| `w.constructor` | `ok:function` | `settled/navigate-blank/timeout0/150` | now same-origin, as expected |
| `w.frames[0]` | `TypeError: Cannot read properties of null` | `load/reinsert/timeout0/0` | detached frame has no `frames` |
| `oldF('return location.href')()` | `TypeError: no access` | `blank/remove/sync/1` | dead `about:blank` realm |

The last row is Chrome's defence against Gareth's old trick of keeping a function from a realm that's gone: once the initial `about:blank` is replaced or removed, calling a `Function` from its realm throws `TypeError: no access`.

### 19 browsers, 3 engines (2026-10-31)

Full write-up: [`results/CROSS-BROWSER.md`](results/CROSS-BROWSER.md). Reports: `results/props-<browser>.json` and `results/lifecycle-<browser>.json`.

- **0 LEAK and 0 FOREIGN in every browser.** Every lifecycle run had 0 timeouts.
- **Engine decides everything.** Every Chromium browser matches Chrome row for row and signature for signature: Canary, ungoogled Chromium, Edge, Opera, Opera GX, Brave, Vivaldi, Comet, Arc and Yandex. Every Gecko browser matches Firefox: Nightly, Zen, LibreWolf, Floorp, Waterfox. Orion matches Safari.
- **Gecko follows the spec exactly**, with 0 `info` rows. **WebKit** throws on `'href' in location`, 3 rows. **Chromium** has the 18 rows above. WebKit lacks `moveBefore`, so it runs 644 lifecycle cases instead of 740.
- **The one outlier is Yandex.** It adds `setWindowPriority` to the cross-origin window allowlist. You can call it cross-origin with `'high'`, `'low'`, `'normal'` or `'default'`, but the function object belongs to the caller's realm, so `constructor.constructor` doesn't reach the victim. See `results/probe-yandex-setWindowPriority.*`.

---

## Lessons learned

**`location.origin` is not the document's origin.** The first lifecycle run reported 111 `FOREIGN` findings, all after `navigate-blank` and `navigate-srcdoc`. The realm check asked `Function('return location.origin')()` and got `"null"`:

- `location.origin` comes from the **URL**. `about:blank` and `about:srcdoc` have opaque URL origins, so it's `"null"`.
- `self.origin` is the **document's** origin, which `about:blank` and `srcdoc` frames inherit from their parent.

Both fuzzers now use `self.origin`. Keep this in mind in any origin check you write.

**Different error messages mean different code.** The detached-window message in v1 led to the whole lifecycle fuzzer. Treat a new error message as a lead.

**Stricter isn't safe by default, but it isn't a bug.** `info` rows can't leak on their own. They're useful for showing where implementations diverge from the spec, which is where looser behaviour tends to hide in *other* browsers.

---

## Limitations

- **Standard cross-origin objects only.** No `postMessage` payloads, `MessagePort`, `BroadcastChannel`, workers, extension or Electron boundaries.
- **Allowed methods are read, never called.** `close`, `focus`, `blur`, `postMessage` and `replace` aren't invoked, so their return values aren't checked.
- **No navigation writes.** `window.location` and `location.href` are skipped to keep the target in place.
- **Event-loop granularity.** The lifecycle fuzzer times things with timers, microtasks and animation frames. Races within a single browser task need crash-level tooling.
- **No crash detection yet.** Teardown races more often show up as memory-safety crashes than as clean leaks. A crashed tab just stops the run.
- **Same-site by default in the lab.** Use an external `target` for cross-site behaviour.
- **`about:blank` stale references are a regression check.** Modern browsers create a fresh Window on cross-origin navigation, so a hit there would be a serious regression rather than an expected find.

---

## Roadmap

- **Crash detection.** A heartbeat to `serve.ts` before each lifecycle case; if heartbeats stop, the last recipe probably crashed the tab. Pair it with an ASan build of Chromium or Firefox to turn silent memory corruption into readable crash reports. This is where the real money is.
- **More capture points.** Inside a target's `pagehide`/`unload` (with a target you control), from a nested frame's `load` handler, inside a `MutationObserver` callback.
- **More targets.** `window.opener` from a page the target opened, `top`/`parent` from inside a cross-origin frame, sandboxed iframes (opaque origins), `blob:` and `data:` frames, fenced frames.
- **History and bfcache.** Navigate away and back, then probe references kept from before.
- **`document.domain`.** Where browsers still allow it, check that access is granted and revoked correctly.
- **Call the allowed methods** with unusual arguments and run the realm check on what comes back or is thrown.
- **Other boundaries.** The realm check works on any boundary: AngularJS-style expression sandboxes, Node `vm`, Electron preload bridges, extension content-script worlds.

---

## Files

| File | Purpose |
|---|---|
| `xo-fuzz.js` | Property fuzzer (v1). Standalone, defines `window.xoFuzz` |
| `xo-lifecycle.js` | Lifecycle fuzzer (v2). Standalone, defines `window.xoLife` |
| `fuzz.html` | Lab UI for v1 |
| `life.html` | Lab UI for v2 |
| `target.html` | Lab victim page: leak markers, nested `kid` frame |
| `serve.ts` | Lab server: attacker `:8000`, victim `:8001`, `POST /report` |
| `results/` | Saved reports: `props-<browser>.json`, `lifecycle-<browser>.json` |

---

## Credits and responsible use

Technique and inspiration: **Gareth Heyes** ([@garethheyes](https://x.com/garethheyes)): the Opera cross-domain `Location` constructor leak ([write-up](https://thespanner.co.uk/opera-x-domain-with-video-tutorial)), the IE `closed.constructor.constructor` uXSS, and the idea of poisoning the JavaScript environment so trusted code runs yours.

Spec: [HTML Standard: cross-origin objects](https://html.spec.whatwg.org/#cross-origin-objects).

**Only fuzz targets you're allowed to test.** The fuzzers attempt writes, deletes and property definitions on the target's window and `location`. In a spec-compliant browser every one of them throws, but in a buggy browser they would really change the target page. Report browser bugs through the vendor's security program (Chrome VRP, Mozilla, Apple).
