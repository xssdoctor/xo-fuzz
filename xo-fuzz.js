/*
  xo-fuzz: cross-origin property fuzzer, in the style of Gareth Heyes' old cross-domain enumerators.

  Standalone: paste into the devtools console of any browser, on any page, then:
      await xoFuzz()                                   // frames https://example.com/
      await xoFuzz({ target: 'https://other.site/' })  // any cross-origin page
      await xoFuzz({ popup: true })                    // also fuzz a window.open() popup
  Results go to console.table; the full report is returned and kept in window.xoFuzzReport
  (Chrome/Firefox: copy(JSON.stringify(xoFuzzReport)) to put it on the clipboard).

  For every cross-origin object it can reach (iframe window, location, nested frame, popup,
  detached frame, stale refs), it tries get / in / getOwnPropertyDescriptor / set / delete /
  defineProperty for every property name the browser knows, and compares the result with the
  HTML spec allowlist (CrossOriginProperties). Every value or error object it gets back goes
  through the Function-identity check: x.constructor.constructor !== Function means a foreign
  realm leaked, and Function('return self.origin')() shows whether it's the victim's.

  Severity: LEAK    = code ran in the victim origin
            FOREIGN = got a Function from another realm (not confirmed victim)
            SPEC    = behaviour differs from the spec (no throw where one was required)
            info    = an allowlisted operation threw (over-restrictive; usually harmless)
*/
(() => {
  // Capture built-ins up front so a page that has patched them can't skew the results.
  const OWN_FUNCTION = Function;
  const { getPrototypeOf, getOwnPropertyDescriptor, defineProperty, isExtensible, getOwnPropertyNames } = Object;
  const objToString = Object.prototype.toString;
  const { ownKeys, setPrototypeOf, preventExtensions } = Reflect;

  const MARKER = 'XO-FUZZ-SECRET';
  const SEVERITIES = ['LEAK', 'FOREIGN', 'SPEC', 'info', 'ok'];

  // HTML spec CrossOriginProperties + CrossOriginPropertyFallback.
  const FALLBACK = new Set(['then', Symbol.toStringTag, Symbol.hasInstance, Symbol.isConcatSpreadable]);
  const ALLOW = {
    window: {
      get: ['window', 'self', 'location', 'close', 'closed', 'focus', 'blur', 'frames', 'length', 'top', 'opener', 'parent', 'postMessage'],
      set: ['location'],
    },
    location: { get: ['replace'], set: ['href'] },
  };
  const WELL_KNOWN_SYMBOLS = getOwnPropertyNames(Symbol).map(n => Symbol[n]).filter(s => typeof s === 'symbol');

  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const attempt = fn => { try { return { ok: true, value: fn() }; } catch (error) { return { ok: false, error }; } };
  const keyName = k => typeof k === 'symbol' ? k.toString() : k;
  const errName = e => { try { return `${e.name}: ${String(e.message).slice(0, 100)}`; } catch { return String(e); } };

  function describe(v) {
    try {
      if (v === null) return 'null';
      if (typeof v === 'symbol') return v.toString();
      if (typeof v === 'function') return `function ${attempt(() => v.name).value ?? '?'}`;
      if (typeof v === 'object') return attempt(() => objToString.call(v)).value ?? '[object ?]';
      return `${typeof v} ${String(v).slice(0, 80)}`;
    } catch { return '?'; }
  }

  function candidateKeys(kind) {
    const keys = new Set(['__proto__', 'constructor', 'then', 'toJSON', 'valueOf', 'toString',
      '__defineGetter__', '__lookupGetter__', '0', '1', 'kid', 'secret', 'xoFuzzNonexistent', ...WELL_KNOWN_SYMBOLS]);
    const sources = kind === 'window'
      ? [window, Window.prototype, getPrototypeOf(Window.prototype), EventTarget.prototype, Object.prototype]
      : [location, Location.prototype, Object.prototype];
    for (const o of sources) for (const k of ownKeys(o)) keys.add(k);
    return [...keys];
  }

  // Function-identity check: walk .constructor.constructor and see whose Function comes back.
  function realmFunction(v) {
    const r = attempt(() => v.constructor.constructor);
    return r.ok && typeof r.value === 'function' ? r.value : null;
  }

  async function xoFuzz(opts = {}) {
    const local = /^(127\.0\.0\.1|localhost)$/.test(location.hostname) && location.port;
    const target = opts.target || (local ? `${location.protocol}//${location.hostname}:${Number(location.port) + 1}/target.html` : 'https://example.com/');
    const targetOrigin = new URL(target).origin;
    const loadTimeout = opts.loadTimeout ?? 10000;
    const settle = opts.settle ?? 1000;
    const host = opts.container || document.body || document.documentElement;
    const rows = [];
    let seen;

    if (targetOrigin === location.origin) throw new Error(`target ${targetOrigin} is same-origin with this page; pick a cross-origin target`);

    const add = (sev, ctx, op, key, outcome, detail = '') =>
      rows.push({ sev, stage: ctx.stage, target: ctx.label, op, key: String(key), outcome, detail });

    function inspectValue(ctx, path, v, depth = 0) {
      if (v === null || (typeof v !== 'object' && typeof v !== 'function')) return;
      if (seen.has(v)) return;
      seen.add(v);
      const F = realmFunction(v);
      if (!F || F === OWN_FUNCTION) return;
      // self.origin, not location.origin: about:blank/srcdoc realms report location.origin "null".
      const r = attempt(() => String(F('return self.origin')()));
      const origin = r.ok ? r.value : `blocked (${errName(r.error)})`;
      add(origin === targetOrigin ? 'LEAK' : 'FOREIGN', ctx, 'realm', path, 'foreign Function reachable',
        `x.constructor.constructor('return self.origin')() → ${origin}`);
      if (depth >= 2) return;
      const keys = (attempt(() => ownKeys(v)).value || []).slice(0, 200);
      for (const k of keys) {
        const c = attempt(() => v[k]);
        if (c.ok) inspectValue(ctx, `${path}.${keyName(k)}`, c.value, depth + 1);
      }
    }

    // isAllowedValue: a non-allowlisted key is still fine if it yields an allowed value
    // (child frame names can't be learned cross-origin, but they resolve to child windows).
    function check(ctx, op, key, fn, expectOk, isAllowedValue = () => false) {
      const name = keyName(key);
      const path = `${ctx.label}[${name}] via ${op}`;
      const r = attempt(fn);
      if (r.ok && !expectOk && isAllowedValue(op === 'getOwnPropertyDescriptor' ? r.value?.value : r.value)) {
        add('ok', ctx, op, name, 'allowed (child frame name)', describe(r.value));
      } else if (r.ok) {
        add(expectOk ? 'ok' : 'SPEC', ctx, op, name, expectOk ? 'allowed' : 'no throw (spec requires SecurityError)', describe(r.value));
        if (op === 'getOwnPropertyDescriptor' && r.value) {
          for (const f of ['value', 'get', 'set']) inspectValue(ctx, `${path}.${f}`, r.value[f]);
        } else {
          inspectValue(ctx, path, r.value);
        }
      } else {
        add(expectOk ? 'info' : 'ok', ctx, op, name, expectOk ? 'threw on allowlisted op' : 'blocked', errName(r.error));
        inspectValue(ctx, `${path} (thrown error)`, r.error);
      }
    }

    function fuzzTarget(stage, label, obj, kind) {
      const ctx = { stage, label };
      seen = new WeakSet();
      if (obj == null) { add('info', ctx, '-', '-', 'target unavailable'); return; }
      // Child frames are allowlisted too: indexes via the allowlisted .length, names by the value they return.
      const childCount = kind === 'window' ? attempt(() => obj.length).value || 0 : 0;
      const indexes = Array.from({ length: childCount }, (_, i) => String(i));
      const children = indexes.map(i => attempt(() => obj[i]).value);
      const isChild = v => v != null && children.includes(v);
      const allow = { get: new Set([...ALLOW[kind].get, ...indexes]), set: new Set(ALLOW[kind].set) };
      const SENTINEL = 'xo-fuzz';

      // Object-level traps. [op, expected-to-succeed, check-on-result]
      const objectOps = {
        getPrototypeOf: [() => getPrototypeOf(obj), true, v => v === null],
        setPrototypeOf: [() => setPrototypeOf(obj, {}), true, v => v === false],
        isExtensible: [() => isExtensible(obj), true, v => v === true],
        preventExtensions: [() => preventExtensions(obj), true, v => v === false],
        ownKeys: [() => ownKeys(obj), true,
          v => v.every(k => allow.get.has(k) || allow.set.has(k) || FALLBACK.has(k) || /^\d+$/.test(k))],
        'Object.prototype.toString': [() => objToString.call(obj), true, v => v === '[object Object]'],
        'String()': [() => String(obj), false],
        'JSON.stringify': [() => JSON.stringify(obj), false],
      };
      for (const [op, [fn, expectOk, valid]] of Object.entries(objectOps)) {
        const r = attempt(fn);
        if (r.ok && !expectOk) add('SPEC', ctx, op, '-', 'no throw (spec requires SecurityError)', describe(r.value));
        else if (r.ok && valid && !valid(r.value)) add('SPEC', ctx, op, '-', 'unexpected result', Array.isArray(r.value) ? r.value.map(keyName).join(', ') : describe(r.value));
        else if (!r.ok && expectOk) add('info', ctx, op, '-', 'threw', errName(r.error));
        else add('ok', ctx, op, '-', r.ok ? 'as spec' : 'blocked', r.ok ? describe(r.value) : errName(r.error));
        if (r.ok) inspectValue(ctx, `${label} ${op}`, r.value);
        else inspectValue(ctx, `${label} ${op} (thrown error)`, r.error);
      }

      for (const key of candidateKeys(kind)) {
        const getOk = allow.get.has(key) || FALLBACK.has(key);
        const descOk = getOk || allow.set.has(key);
        check(ctx, 'get', key, () => obj[key], getOk, isChild);
        check(ctx, 'in', key, () => key in obj, descOk, v => v === true && isChild(attempt(() => obj[key]).value));
        check(ctx, 'getOwnPropertyDescriptor', key, () => getOwnPropertyDescriptor(obj, key), descOk, isChild);
        // Never set window.location / location.href: that navigates the target away mid-run.
        if (!allow.set.has(key)) check(ctx, 'set', key, () => { obj[key] = SENTINEL; }, false);
        check(ctx, 'delete', key, () => delete obj[key], false);
        check(ctx, 'defineProperty', key, () => defineProperty(obj, key, { value: SENTINEL, configurable: true }), false);
      }
    }

    function waitLoad(f, src) {
      return new Promise(resolve => {
        const t = setTimeout(resolve, loadTimeout); // X-Frame-Options / CSP may never fire load
        f.addEventListener('load', () => { clearTimeout(t); resolve(); }, { once: true });
        if (src) f.src = src;
      });
    }

    function makeFrame() {
      const f = document.createElement('iframe');
      f.style.cssText = 'width:200px;height:80px;position:fixed;bottom:0;right:0;opacity:.3;z-index:2147483647';
      host.append(f);
      return f;
    }

    async function stageIframe() {
      const f = makeFrame();
      await waitLoad(f, target);
      await sleep(settle); // let nested frames load
      const w = f.contentWindow;
      fuzzTarget('iframe', 'contentWindow', w, 'window');
      fuzzTarget('iframe', 'contentWindow.location', w.location, 'location');
      const kid = attempt(() => w.frames[0]).value;
      if (kid) {
        fuzzTarget('iframe', 'contentWindow.frames[0]', kid, 'window');
        fuzzTarget('iframe', 'contentWindow.frames[0].location', attempt(() => kid.location).value, 'location');
      }
      return f;
    }

    // Keep references, remove the iframe, fuzz the now-detached WindowProxy and Location.
    async function stageDetached(f) {
      const w = f.contentWindow;
      const loc = w.location;
      f.remove();
      await sleep(100);
      fuzzTarget('detached', 'removed iframe window', w, 'window');
      fuzzTarget('detached', 'removed iframe location', loc, 'location');
    }

    // Grab same-origin objects from the initial about:blank, navigate the frame cross-origin,
    // then see if any of the old references now resolve to the victim document.
    async function stageStale() {
      const ctx = { stage: 'stale', label: 'about:blank refs after cross-origin nav' };
      const f = makeFrame();
      const w = f.contentWindow;
      const old = { Function: w.Function, location: w.location, document: w.document };
      await waitLoad(f, target);
      await sleep(settle / 2);
      const probes = {
        "oldFunction('return location.href')()": () => old.Function('return location.href')(),
        "oldFunction('return document.body.innerHTML')()": () => old.Function('return document.body && document.body.innerHTML')(),
        'oldLocation.href': () => old.location.href,
        'oldDocument.URL': () => old.document.URL,
        'oldDocument.body.innerHTML': () => old.document.body && old.document.body.innerHTML,
      };
      for (const [name, fn] of Object.entries(probes)) {
        const r = attempt(fn);
        const s = r.ok ? String(r.value) : errName(r.error);
        const leaked = r.ok && (s.includes(targetOrigin) || s.includes(MARKER));
        add(leaked ? 'LEAK' : 'ok', ctx, 'stale-ref', name, r.ok ? 'returned' : 'threw', s.slice(0, 120));
      }
      seen = new WeakSet();
      inspectValue(ctx, 'stale contentWindow', w);
      f.remove();
    }

    async function stagePopup(p) {
      const ctx = { stage: 'popup', label: 'window.open()' };
      if (!p) { add('info', ctx, '-', '-', 'popup blocked'); return; }
      await sleep(Math.max(2000, settle));
      fuzzTarget('popup', 'window.open()', p, 'window');
      fuzzTarget('popup', 'popup.location', attempt(() => p.location).value, 'location');
      p.close();
    }

    // window.open first, while we may still be inside a user gesture.
    const popup = opts.popupWindow ?? (opts.popup ? window.open(target, 'xofuzz', 'width=400,height=300') : undefined);
    const f = await stageIframe();
    await stageDetached(f);
    await stageStale();
    if (popup !== undefined) await stagePopup(popup);

    const counts = Object.fromEntries(SEVERITIES.map(s => [s, rows.filter(r => r.sev === s).length]));
    rows.sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev));
    const report = { ua: navigator.userAgent, from: location.origin, target: targetOrigin, date: new Date().toISOString(), counts, rows };
    window.xoFuzzReport = report;
    if (!opts.quiet) {
      console.log(`[xo-fuzz] ${location.origin} → ${targetOrigin}`, counts);
      console.table(rows.filter(r => r.sev !== 'ok'));
    }
    return report;
  }

  // Save a report (or the last one) as a JSON file named after the browser, for cross-browser diffing.
  xoFuzz.download = (report = window.xoFuzzReport) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `xo-fuzz-${report.ua.match(/(Firefox|Edg|Chrome|Version)\/\d+/)?.[0].replace('Version', 'Safari').replace('/', '-') ?? 'browser'}.json`;
    a.click();
  };
  xoFuzz.SEVERITIES = SEVERITIES;

  window.xoFuzz = xoFuzz;
})();
