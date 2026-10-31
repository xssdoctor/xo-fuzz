/*
  xo-lifecycle: lifecycle fuzzer for cross-origin frames (xo-fuzz v2).

  v1 (xo-fuzz.js) asks: in its normal state, does every property of a cross-origin object follow
  the spec? v2 asks: if I grab references at moment X, tear the frame down with action Y, and
  probe at moment Z, can I still reach anything I shouldn't?

  Standalone: paste into the devtools console of any browser, on any page, then:
      await xoLife()                                       // frames https://example.com/
      await xoLife({ target: 'https://other.site/', iterations: 500 })
      await xoLife.replay('load/remove/sync/0')            // re-run one case, verbose
  The report is returned and kept in window.xoLifeReport; xoLife.download() saves it.

  Each case is a recipe  capture/teardown/timing/delay:
    capture   when references are grabbed: blank (initial about:blank, then src set),
              load (in the load event), settled (after load + nested frames)
    teardown  what happens to the iframe `delay` ms later (0 = synchronously, inside the
              capture moment): none (control), remove, reinsert, moveBefore, adoptNode,
              navigate-blank, navigate-srcdoc, body-clear
    timing    when the probes run after teardown: sync, microtask, timeout0, raf, late

  Every probe's outcome is reduced to a signature: "ok:<type>" or "<ErrorName>:<message template>"
  (quoted strings, URLs and numbers replaced). A signature never seen before means the browser
  took a different code path, so cases that produce one get mutated (new random delays) and
  re-queued. That's the coverage signal.

  Findings:
    LEAK     a probe returned target content (the target origin or XO-FUZZ-SECRET), or a
             reachable Function ran as the target origin
    FOREIGN  a Function from a realm that's neither ours nor known same-origin was reachable
    ANOMALY  a non-allowlisted probe succeeded on a reference that must still be cross-origin
*/
(() => {
  const OWN_FUNCTION = Function;
  const { getOwnPropertyDescriptor } = Object;
  const objToString = Object.prototype.toString;

  const MARKER = 'XO-FUZZ-SECRET';
  const CAPTURES = ['blank', 'load', 'settled'];
  const TEARDOWNS = ['none', 'remove', 'reinsert', 'moveBefore', 'adoptNode', 'navigate-blank', 'navigate-srcdoc', 'body-clear'];
  const TIMINGS = ['sync', 'microtask', 'timeout0', 'raf', 'late'];
  const DELAYS = [0, 1, 5, 20, 50, 150];
  // After these teardowns the frame legitimately becomes same-origin with us, so w may be readable.
  const SAME_ORIGIN_AFTER = new Set(['navigate-blank', 'navigate-srcdoc']);

  // Fast probe set. `allowed` = the operation is permitted on a cross-origin object.
  // Refs: w / loc / kid / kidLoc are grabbed after load (cross-origin); oldF / oldDoc / oldLoc
  // come from the initial same-origin about:blank (capture "blank") and are checked for content.
  const PROBES = [
    { ref: 'w', name: 'closed', allowed: true, fn: o => o.closed },
    { ref: 'w', name: 'length', allowed: true, fn: o => o.length },
    { ref: 'w', name: 'frames[0]', allowed: true, fn: o => o.frames[0] },
    { ref: 'w', name: 'gOPD(location).get', allowed: true, fn: o => getOwnPropertyDescriptor(o, 'location').get },
    { ref: 'w', name: 'constructor', allowed: false, fn: o => o.constructor },
    { ref: 'w', name: 'document', allowed: false, fn: o => o.document },
    { ref: 'w', name: 'name', allowed: false, fn: o => o.name },
    { ref: 'w', name: 'location.href', allowed: false, fn: o => o.location.href },
    { ref: 'w', name: 'String()', allowed: false, fn: o => String(o) },
    { ref: 'loc', name: 'replace', allowed: true, fn: o => o.replace },
    { ref: 'loc', name: 'gOPD(href).set', allowed: true, fn: o => getOwnPropertyDescriptor(o, 'href').set },
    { ref: 'loc', name: 'constructor', allowed: false, fn: o => o.constructor },
    { ref: 'loc', name: 'href', allowed: false, fn: o => o.href },
    { ref: 'loc', name: 'origin', allowed: false, fn: o => o.origin },
    { ref: 'loc', name: 'String()', allowed: false, fn: o => String(o) },
    { ref: 'kid', name: 'location', allowed: true, fn: o => o.location },
    { ref: 'kid', name: 'constructor', allowed: false, fn: o => o.constructor },
    { ref: 'kid', name: 'document', allowed: false, fn: o => o.document },
    { ref: 'kidLoc', name: 'constructor', allowed: false, fn: o => o.constructor },
    { ref: 'kidLoc', name: 'href', allowed: false, fn: o => o.href },
    { ref: 'oldF', name: "('return location.href')()", allowed: true, fn: F => F('return location.href')() },
    { ref: 'oldF', name: "('return document.body.innerHTML')()", allowed: true, fn: F => F('return document.body && document.body.innerHTML')() },
    { ref: 'oldDoc', name: 'URL', allowed: true, fn: d => d.URL },
    { ref: 'oldDoc', name: 'body.innerHTML', allowed: true, fn: d => d.body && d.body.innerHTML },
    { ref: 'oldLoc', name: 'href', allowed: true, fn: l => l.href },
  ];

  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const attempt = fn => { try { return { ok: true, value: fn() }; } catch (error) { return { ok: false, error }; } };
  const errName = e => { try { return `${e.name}: ${String(e.message).slice(0, 100)}`; } catch { return String(e); } };

  function describe(v) {
    try {
      if (v === null) return 'null';
      if (typeof v === 'function') return `function ${attempt(() => v.name).value ?? '?'}`;
      if (typeof v === 'object') return attempt(() => objToString.call(v)).value ?? '[object ?]';
      return `${typeof v} ${String(v).slice(0, 80)}`;
    } catch { return '?'; }
  }

  // Message template: strip the parts that vary per run so only the code path is left.
  const template = msg => String(msg)
    .replace(/[a-z][\w+.-]*:\/\/[^\s"'`]+/gi, '<url>')
    .replace(/"[^"]*"/g, '"<s>"')
    .replace(/'[^']*'/g, "'<s>'")
    .replace(/\d+/g, '<n>')
    .slice(0, 160);

  function signature(r) {
    if (r.ok) return `ok:${r.value === null ? 'null' : typeof r.value}`;
    const e = r.error;
    const name = attempt(() => e.name).value ?? typeof e;
    const message = attempt(() => e.message).value ?? e;
    return `${name}:${template(message)}`;
  }

  // Seeded PRNG (mulberry32) so a run with the same seed visits cases in the same order.
  function rng(seed) {
    let a = seed >>> 0;
    return () => {
      a = (a + 0x6D2B79F5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  const recipeId = r => `${r.capture}/${r.teardown}/${r.timing}/${r.delay}`;
  function parseRecipe(id) {
    const [capture, teardown, timing, delay] = id.split('/');
    if (!CAPTURES.includes(capture) || !TEARDOWNS.includes(teardown) || !TIMINGS.includes(timing) || !(Number(delay) >= 0)) {
      throw new Error(`bad recipe "${id}": expected capture/teardown/timing/delay, e.g. load/remove/sync/0`);
    }
    return { capture, teardown, timing, delay: Number(delay) };
  }

  function setup(opts = {}) {
    const local = /^(127\.0\.0\.1|localhost)$/.test(location.hostname) && location.port;
    const target = opts.target || (local ? `${location.protocol}//${location.hostname}:${Number(location.port) + 1}/target.html` : 'https://example.com/');
    const targetOrigin = new URL(target).origin;
    if (targetOrigin === location.origin) throw new Error(`target ${targetOrigin} is same-origin with this page; pick a cross-origin target`);
    const loadTimeout = opts.loadTimeout ?? 10000;
    const settle = opts.settle ?? 500;
    const host = document.createElement('div');
    host.style.cssText = 'position:fixed;bottom:0;right:0;width:220px;opacity:.3;z-index:2147483647;pointer-events:none';
    (opts.container || document.body || document.documentElement).append(host);

    // Same-origin helper document for the adoptNode teardown (iframe moved into another document).
    const helper = document.createElement('iframe');
    host.append(helper);
    const helperDoc = helper.contentDocument;
    const moveBeforeSupported = typeof Element.prototype.moveBefore === 'function';

    function teardown(kind, f, box) {
      const r = attempt(() => {
        switch (kind) {
          case 'none': return;
          case 'remove': f.remove(); return;
          case 'reinsert': f.remove(); box.append(f); return;
          case 'moveBefore': {
            const other = document.createElement('div');
            host.append(other);
            other.moveBefore(f, null);
            return;
          }
          case 'adoptNode': helperDoc.body.append(helperDoc.adoptNode(f)); return;
          case 'navigate-blank': f.src = 'about:blank'; return;
          case 'navigate-srcdoc': f.srcdoc = '<p>srcdoc</p>'; return;
          case 'body-clear': box.innerHTML = ''; return;
        }
      });
      return r.ok ? 'ok' : `threw ${errName(r.error)}`;
    }

    function schedule(timing, fn) {
      switch (timing) {
        case 'sync': return fn();
        case 'microtask': return queueMicrotask(fn);
        case 'timeout0': return setTimeout(fn, 0);
        case 'late': return setTimeout(fn, 300);
        case 'raf': {
          // rAF doesn't fire in background tabs / headless; fall back after 200ms.
          let done = false;
          const once = () => { if (!done) { done = true; fn(); } };
          requestAnimationFrame(once);
          return setTimeout(once, 200);
        }
      }
    }

    // Returns the origin a reachable foreign Function runs as, or null if the value's realm is
    // ours or a known same-origin realm.
    function realmOrigin(v, sameOriginFns) {
      if (v === null || (typeof v !== 'object' && typeof v !== 'function')) return null;
      const F = attempt(() => v.constructor.constructor).value;
      if (typeof F !== 'function' || sameOriginFns.has(F)) return null;
      // self.origin, not location.origin: about:blank/srcdoc realms report location.origin "null".
      const r = attempt(() => String(F('return self.origin')()));
      if (r.ok && r.value === location.origin) return null; // e.g. an about:blank / srcdoc realm
      return r.ok ? r.value : `blocked (${errName(r.error)})`;
    }

    function probe(refs, recipe) {
      const results = [];
      const findings = [];
      const sameOriginFns = new Set([OWN_FUNCTION, refs.oldF]);
      const mustStayCrossOrigin = ref =>
        ref === 'loc' || ref === 'kid' || ref === 'kidLoc' ||
        (ref === 'w' && recipe.capture !== 'blank' && !SAME_ORIGIN_AFTER.has(recipe.teardown));

      for (const p of PROBES) {
        const obj = refs[p.ref];
        if (obj == null) continue;
        const r = attempt(() => p.fn(obj));
        const probeName = `${p.ref}.${p.name}`;
        const sig = signature(r);
        results.push({ probe: probeName, sig, value: r.ok ? describe(r.value) : errName(r.error) });

        if (r.ok && typeof r.value === 'string' && (r.value.includes(targetOrigin) || r.value.includes(MARKER))) {
          findings.push({ sev: 'LEAK', probe: probeName, detail: `returned target content: ${r.value.slice(0, 120)}` });
        }
        if (r.ok && !p.allowed && mustStayCrossOrigin(p.ref)) {
          findings.push({ sev: 'ANOMALY', probe: probeName, detail: `no SecurityError on a cross-origin ref: ${describe(r.value)}` });
        }
        const origin = realmOrigin(r.ok ? r.value : r.error, sameOriginFns);
        if (origin) {
          findings.push({
            sev: origin === targetOrigin ? 'LEAK' : 'FOREIGN', probe: probeName,
            detail: `${r.ok ? 'value' : 'thrown error'}.constructor.constructor('return self.origin')() → ${origin}`,
          });
        }
      }
      return { results, findings };
    }

    async function runCase(recipe) {
      const box = document.createElement('div');
      host.append(box);
      const f = document.createElement('iframe');
      const refs = {};
      let teardownResult = 'not reached';

      const outcome = await new Promise(resolve => {
        const guard = setTimeout(() => resolve(null), loadTimeout + settle + 1000);
        const finish = () => { clearTimeout(guard); resolve(probe(refs, recipe)); };
        const teardownThenProbe = () => {
          const go = () => { teardownResult = teardown(recipe.teardown, f, box); schedule(recipe.timing, finish); };
          recipe.delay ? setTimeout(go, recipe.delay) : go();
        };
        const grab = () => {
          refs.w = f.contentWindow;
          refs.loc = attempt(() => refs.w.location).value;
          refs.kid = attempt(() => refs.w.frames[0]).value;
          refs.kidLoc = refs.kid && attempt(() => refs.kid.location).value;
        };

        if (recipe.capture === 'blank') {
          box.append(f);
          const w = f.contentWindow;
          Object.assign(refs, { w, oldF: w.Function, oldDoc: w.document, oldLoc: w.location });
          f.src = target;
          teardownThenProbe();
        } else {
          f.addEventListener('load', () => {
            if (recipe.capture === 'load') { grab(); teardownThenProbe(); }
            else setTimeout(() => { grab(); teardownThenProbe(); }, settle);
          }, { once: true });
          f.src = target;
          box.append(f);
        }
      });

      f.remove();
      box.remove();
      return { id: recipeId(recipe), recipe, teardownResult, timedOut: !outcome, ...(outcome || { results: [], findings: [] }) };
    }

    const cleanup = () => host.remove();
    return { target, targetOrigin, runCase, cleanup, moveBeforeSupported };
  }

  async function xoLife(opts = {}) {
    const ctx = setup(opts);
    const random = rng(opts.seed ?? 1);
    const iterations = opts.iterations ?? 300;
    const skipped = ctx.moveBeforeSupported ? [] : ['moveBefore (Element.prototype.moveBefore not supported)'];

    const matrix = [];
    for (const capture of CAPTURES) for (const teardown of TEARDOWNS) for (const timing of TIMINGS) for (const delay of DELAYS) {
      if (teardown === 'moveBefore' && !ctx.moveBeforeSupported) continue;
      matrix.push({ capture, teardown, timing, delay });
    }
    for (let i = matrix.length - 1; i > 0; i--) {
      const j = Math.floor(random() * (i + 1));
      [matrix[i], matrix[j]] = [matrix[j], matrix[i]];
    }

    const queue = [...matrix];
    const coverage = new Map(); // probe -> Map(signature -> { count, first })
    const findings = [];
    const seenFindings = new Set();
    let ran = 0, timeouts = 0, mutants = 0;
    const started = performance.now();

    while (queue.length && ran < iterations) {
      const recipe = queue.shift();
      const res = await ctx.runCase(recipe);
      ran++;
      if (res.timedOut) timeouts++;

      let novel = 0;
      // The teardown's own outcome counts as coverage too, so a teardown that throws is visible.
      const teardownSig = { probe: `teardown:${recipe.teardown}`, sig: res.timedOut ? 'timed out' : res.teardownResult };
      for (const { probe, sig } of [teardownSig, ...res.results]) {
        if (!coverage.has(probe)) coverage.set(probe, new Map());
        const sigs = coverage.get(probe);
        if (!sigs.has(sig)) { sigs.set(sig, { count: 0, first: res.id }); novel++; }
        sigs.get(sig).count++;
      }
      for (const f of res.findings) {
        const key = `${f.sev}|${f.probe}|${res.id}`;
        if (seenFindings.has(key)) continue;
        seenFindings.add(key);
        findings.push({ ...f, recipe: res.id, teardown: res.teardownResult });
      }
      // Coverage-guided: a case that hit a new code path gets two mutants with nearby random delays.
      if (novel && ran > 1) {
        for (let i = 0; i < 2; i++) {
          queue.unshift({ ...recipe, delay: Math.floor(random() * Math.max(10, recipe.delay * 2 + 1)) });
          mutants++;
        }
      }
      if (opts.onProgress) opts.onProgress({ ran, total: Math.min(iterations, ran + queue.length), findings: findings.length });
    }
    ctx.cleanup();

    const coverageRows = [];
    for (const [probe, sigs] of coverage) {
      for (const [sig, { count, first }] of sigs) coverageRows.push({ probe, outcomes: sigs.size, signature: sig, count, firstSeen: first });
    }
    const signatures = coverageRows.length;
    const divergent = coverageRows.filter(r => r.outcomes > 1);
    const report = {
      kind: 'lifecycle', ua: navigator.userAgent, from: location.origin, target: ctx.targetOrigin,
      date: new Date().toISOString(), seed: opts.seed ?? 1,
      cases: ran, matrix: matrix.length, mutants, timeouts, seconds: Math.round((performance.now() - started) / 1000),
      skipped, signatures, findings, coverage: coverageRows,
    };
    window.xoLifeReport = report;

    if (!opts.quiet) {
      const counts = ['LEAK', 'FOREIGN', 'ANOMALY'].map(s => `${s}: ${findings.filter(f => f.sev === s).length}`).join('  ');
      console.log(`[xo-lifecycle] ${location.origin} → ${ctx.targetOrigin}  ${ran} cases (${mutants} mutants, ${timeouts} timeouts) in ${report.seconds}s  ${signatures} signatures  ${counts}`);
      if (skipped.length) console.log('[xo-lifecycle] skipped:', skipped.join(', '));
      if (findings.length) console.table(findings);
      console.log('[xo-lifecycle] probes with more than one outcome (different code paths):');
      console.table(divergent.map(({ probe, signature, count, firstSeen }) => ({ probe, signature, count, firstSeen })));
    }
    return report;
  }

  // Re-run one recipe `repeat` times and print every probe result, to reproduce a hit.
  xoLife.replay = async (id, opts = {}) => {
    const recipe = typeof id === 'string' ? parseRecipe(id) : id;
    const ctx = setup(opts);
    const runs = [];
    for (let i = 0; i < (opts.repeat ?? 5); i++) runs.push(await ctx.runCase(recipe));
    ctx.cleanup();
    if (!opts.quiet) {
      runs.forEach((r, i) => {
        console.log(`[xo-lifecycle] replay ${recipeId(recipe)} #${i + 1}: teardown ${r.teardownResult}${r.timedOut ? ', TIMED OUT' : ''}, ${r.findings.length} findings`);
        console.table(r.results);
        if (r.findings.length) console.table(r.findings);
      });
    }
    return runs;
  };

  xoLife.download = (report = window.xoLifeReport) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `xo-lifecycle-${report.ua.match(/(Firefox|Edg|Chrome|Version)\/\d+/)?.[0].replace('Version', 'Safari').replace('/', '-') ?? 'browser'}.json`;
    a.click();
  };
  Object.assign(xoLife, { CAPTURES, TEARDOWNS, TIMINGS, DELAYS, PROBES });

  window.xoLife = xoLife;
})();
