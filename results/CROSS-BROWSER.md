# Cross-browser run — 2026-10-31

These results come from one run of both fuzzers on a MacBook Pro (Apple Silicon, macOS 27).

- **Origins:** the attacker page was on `127.0.0.1:8000` and the target on `127.0.0.1:8001`.
- **Property fuzzer:** `fuzz.html?autorun=1&label=<browser>`, default settings.
- **Lifecycle fuzzer:** `life.html?autorun=1&label=<browser>&iterations=1000`, seed 1.
- **Profiles:** every browser ran in a temporary profile, except Safari, Orion and Arc, which were opened normally.
- **Other files:** `pro-run.log` is the raw driver log. `props-Chrome-156.json` and `lifecycle-Chrome-156.json` are older local headless runs and are not part of this set.

## Results

19 browsers were tested on 3 engines. There are **0 LEAK and 0 FOREIGN findings** in any browser, and 0 timeouts in every lifecycle run.

| Browser | Version | Props: SPEC / info / ok | Lifecycle cases | Signatures |
|---|---|---|---|---|
| Chrome | 156 | 0 / 18 / 23,879 | 740 | 56 |
| Chrome Canary | 159 | 0 / 18 / 23,987 | 740 | 56 |
| Chromium (ungoogled) | 155 | 0 / 18 / 23,879 | 740 | 56 |
| Edge | 156 | 0 / 18 / 23,861 | 740 | 56 |
| Opera | 139 (Chromium 155) | 0 / 18 / 23,951 | 738 | 56 |
| Opera GX | 138 (Chromium 154) | 0 / 18 / 23,897 | 738 | 56 |
| Brave | Chromium 156 | 0 / 18 / 23,627 | 740 | 56 |
| Vivaldi | Chromium 152 | 0 / 18 / 23,951 | 738 | 56 |
| Comet (Perplexity) | Chromium 156 | 0 / 18 / 23,879 | 740 | 56 |
| Arc | Chromium 145 | 0 / 18 / 23,429 | 740 | 56 |
| **Yandex** | 26.10 (Chromium 152) | **3** / 18 / 24,110 | 738 | 55 |
| Firefox | 144 | 0 / 0 / 17,867 | 736 | 42 |
| Firefox Nightly | 161 | 0 / 0 / 20,261 | 736 | 42 |
| Zen | Gecko 158 | 0 / 0 / 19,343 | 736 | 42 |
| LibreWolf | Gecko 158 | 0 / 0 / 18,353 | 736 | 42 |
| Floorp | Gecko 159 | 0 / 0 / 19,379 | 736 | 42 |
| Waterfox | Gecko 153 | 0 / 0 / 19,325 | 736 | 42 |
| Safari | 27.0.1 | 0 / 3 / 20,366 | 644 | 39 |
| Orion | WebKit 26.0 | 0 / 3 / 20,312 | 644 | 39 |

### Each engine behaves the same in every browser built on it

Each browser's rows and coverage signatures were compared with its engine's reference browser: Chrome, Firefox or Safari.

- **Chromium:** all ten browsers match Chrome row for row and signature for signature, except Yandex, covered below.
- **Gecko:** all five match Firefox.
- **WebKit:** Orion matches Safari.

Every browser on an engine inherits the same cross-origin behaviour. Browser vendors rarely change this layer.

### Engines differ from one another

| | Chromium | Gecko | WebKit |
|---|---|---|---|
| info rows (stricter than spec) | 18 | 0 | 3 |
| lifecycle signatures | 56 | 42 | 39 |
| `moveBefore` | yes | yes | not supported, 90 cases skipped |

- **Gecko** follows the spec exactly and reports zero deviations.
- **WebKit** throws on `'href' in location` cross-origin, 3 rows.
- **Chromium** has the 18 stricter-than-spec rows described in the README.

### Yandex adds a cross-origin method: `setWindowPriority`

`Reflect.ownKeys()` on a cross-origin window in Yandex returns one key that isn't on the HTML spec's allowlist, `setWindowPriority`. A targeted probe (`probe-yandex-setWindowPriority.html`, output in `probe-yandex-setWindowPriority.json`) found the following:

- It's visible on live, nested and detached cross-origin windows, with descriptor `{writable: false, enumerable: false, configurable: true}`. The page's own `window` doesn't have it.
- It can be **called cross-origin**. `setWindowPriority('high' | 'low' | 'normal' | 'default')` returns `undefined` with no SecurityError, and other strings throw an enum TypeError.
- The function object belongs to the **caller's** realm: `f.constructor('return self.origin')()` returns the attacker's origin. So there's no `constructor.constructor` path into the victim, and this is not a uXSS.

What the call actually does, presumably tab or process scheduling priority, hasn't been measured. In practice it's a non-standard cross-origin write: any page can change the priority of a window it holds a reference to.

The only other difference between Yandex and Chrome is one lifecycle signature: a `w.frames[0]` SecurityError race that happened in 2 of Chrome's 740 cases and in none of Yandex's. That's timing, not engine behaviour.

## Not tested

| Browser | Why |
|---|---|
| Thorium | The `thorium` Homebrew cask installs **Thorium Reader**, an e-book reader, not the browser. The browser's cask (`alex313031-thorium`) has been disabled because it fails Gatekeeper. |
| ChatGPT Atlas | The installed build (1.2025.344.9) has a **revoked** signing certificate. macOS moved it to the Trash on launch. It was restored to /Applications afterwards; it needs updating from OpenAI. |
| Tor Browser | Never navigated to the test page, even with `TOR_PROVIDER=none`, because of its connection lockdown. Gecko is covered by six other browsers. |
| SigmaOS, DuckDuckGo | Both launch but never load the URL, almost certainly because of a first-run onboarding or sign-in screen that can't be dismissed without someone at the machine. WebKit is covered by Safari and Orion. |
| Mullvad Browser | The cask download returned 404 upstream. |
| Safari Technology Preview | It's a `.pkg` cask, and installing it needs sudo. |
| Dia, Ladybird | No Homebrew cask. |

## Run notes

These are the problems hit in the first pass, and how each was confirmed fixed:

- **Vivaldi (props) and Comet:** a fresh profile shows a welcome page and drops the URL passed on the command line. Fixed by rerunning with `--remote-debugging-port` and opening the page through `PUT /json/new`.
- **Waterfox (lifecycle):** a launch would sometimes never request the page. A plain relaunch worked.
- **Orion (lifecycle):** the first pass had 6 timeouts and ran 3× slower than Safari, consistent with a throttled background window. The rerun had 0 timeouts and matches Safari exactly; it replaced the first pass.
