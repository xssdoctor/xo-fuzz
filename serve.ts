// Serves the fuzzer on :8000 (attacker origin) and the target on :8001 (victim origin).
// Different ports = different origins, so every access from :8000 into :8001 is cross-origin.
const FILES: Record<string, string> = {
  "/": "fuzz.html",
  "/fuzz.html": "fuzz.html",
  "/target.html": "target.html",
  "/xo-fuzz.js": "xo-fuzz.js",
  "/life.html": "life.html",
  "/xo-lifecycle.js": "xo-lifecycle.js",
};

for (const port of [8000, 8001]) {
  Bun.serve({
    hostname: "127.0.0.1",
    port,
    async fetch(req) {
      const { pathname } = new URL(req.url);
      // ?autorun runs POST their reports here, one file per fuzzer and browser, for diffing.
      if (pathname === "/report" && req.method === "POST") {
        const report = await req.json();
        const browser = report.ua.match(/(Firefox|Edg|Chrome|Version)\/\d+/)?.[0].replace("Version", "Safari").replace("/", "-") ?? "unknown";
        const label = report.label ? String(report.label).replace(/[^\w.-]+/g, "-") : browser;
        const name = `${report.kind ?? "props"}-${label}.json`;
        await Bun.write(`${import.meta.dir}/results/${name}`, JSON.stringify(report, null, 2));
        console.log(`saved results/${name} (${(report.rows ?? report.findings).length} rows)`);
        return new Response("ok");
      }
      const file = FILES[pathname];
      return file
        ? new Response(Bun.file(`${import.meta.dir}/${file}`))
        : new Response("not found", { status: 404 });
    },
  });
}

console.log("fuzzer: http://127.0.0.1:8000/");
console.log("lifecycle: http://127.0.0.1:8000/life.html");
console.log("target: http://127.0.0.1:8001/target.html");
