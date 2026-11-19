const { exec } = require("child_process");
const express = require("express");
const app = express();

app.get("/whois", (req, res) => {
  exec("whois " + req.query.domain, (err, stdout) => res.send(stdout));
});
