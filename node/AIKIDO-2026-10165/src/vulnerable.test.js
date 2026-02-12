const { test } = require("node:test");
const { equal } = require("node:assert");

test("Vulnerable to Code Injection", async () => {
  const http = require("http");
  const { URL } = require("url");
  const { DateTime, Duration } = require("luxon");
  const { dateLiteral, compileToJavaScript } = require("@enspirit/elo");

  let testLogs = [];
  console.test = (...args) => {
    testLogs.push(args.join(" "));
  };

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

  const port = 3002;

  await new Promise((resolve) => server.listen(port, resolve));
  console.log(`Server running at http://localhost:${port}/`);

  // Simulate an attack with malicious input
  const response = await fetch(
    `http://localhost:${port}/evaluate?date=2023-01-01')%2B(function()%7Bconsole.test('HACKED')%3Bconsole.log('works')%3B%7D)()%2Bd('2023-01-01`,
  );

  equal(response.status, 500);

  // Check if the malicious code executed
  const logsContainHacked = testLogs.some((log) => log.includes("HACKED"));
  equal(logsContainHacked, true);

  server.close();
});
