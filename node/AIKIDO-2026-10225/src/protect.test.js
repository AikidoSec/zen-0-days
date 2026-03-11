const { test } = require("node:test");
const { equal } = require("node:assert");

test("Zen prevents SQL injection", async () => {
  process.env.AIKIDO_BLOCK = "true";
  require("@aikidosec/firewall");

  const mysql2 = require("mysql2/promise");
  const http = require("http");

  const connection = await mysql2.createConnection({
    host: "127.0.0.1",
    user: "root",
    password: "mypassword",
    database: "catsdb",
  });

  await connection.execute(
    "CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255))",
  );

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");

    if (url.pathname === "/login") {
      try {
        const email = url.searchParams.get("email");
        if (!email) {
          res.writeHead(400, { "Content-Type": "text/plain" });
          res.end("Missing ?email= parameter");
          return;
        }

        const [rows] = await connection.execute(
          "SELECT * FROM users WHERE email = ?",
          // Insecure
          [JSON.parse(email)],
        );

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(rows));
      } catch (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end(err.message);
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  });

  const port = 4001;

  await new Promise((resolve) => server.listen(port, resolve));
  console.log(`Server running at http://localhost:${port}/`);

  // Simulate an attack with malicious input
  const response = await fetch(
    `http://localhost:${port}/login?email=${encodeURIComponent(JSON.stringify({ email: 1 }))}`,
  );

  equal(response.status, 500);

  server.close();
  connection.end();
});
