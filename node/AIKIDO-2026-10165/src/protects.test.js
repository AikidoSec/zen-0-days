const { test } = require("node:test");
const { equal } = require("node:assert");

test("Vulnerable to Code Injection", async () => {
  process.env.AIKIDO_BLOCK = "true";
  process.env.AIKIDO_DEBUG = "true";

  require("@aikidosec/firewall");
  const http = require("http");
  const { URL } = require("url");
  const { DateTime, Duration } = require("luxon");
  const { dateLiteral, compileToJavaScript } = require("@enspirit/elo");

  let testLogs = [];
  console.test = (...args) => {
    testLogs.push(args.join(" "));
  };

  let consoleLogs = [];
  const originalConsoleLog = console.log;
  for (const method of ["log", "error", "warn"]) {
    console[method] = (...args) => {
      consoleLogs.push(args.join(" "));
      originalConsoleLog.apply(console, args);
    };
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost:3000");

    if (url.pathname === "/evaluate") {
      const dateInput = url.searchParams.get("date");

      if (!dateInput) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Missing ?date= parameter");
        return;
      }

      try {
        // Developer constructs AST programmatically with user input
        const ast = dateLiteral(dateInput);
        const jsCode = compileToJavaScript(ast);
        console.log("Generated JS:", jsCode);

        // Same as what compile() does internally (compile.ts line 76)
        const factory = new Function(
          "DateTime",
          "Duration",
          "return " + jsCode,
        );
        const fn = factory(DateTime, Duration);
        const result = fn(null);

        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("Result: " + result);
      } catch (err) {
        console.log("Blocked:", err.message);
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Blocked: " + err.message);
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  });

  const port = 3001;

  await new Promise((resolve) => server.listen(port, resolve));
  console.log(`Server running at http://localhost:${port}/`);

  // Simulate an attack with malicious input
  const response = await fetch(
    `http://localhost:${port}/evaluate?date=2023-01-01')%2B(function()%7Bconsole.test('HACKED')%3Bconsole.log('works')%3B%7D)()%2Bd('2023-01-01`,
  );

  equal(response.status, 500);

  // Check that the malicious code did NOT execute
  const logsContainHacked = testLogs.some((log) => log.includes("HACKED"));
  equal(logsContainHacked, false);

  // Check that console logged Zen blocked the attack
  const logsContainBlocked = consoleLogs.some((log) =>
    log.includes("Zen has blocked a JavaScript injection:"),
  );
  equal(logsContainBlocked, true);

  server.close();
});
