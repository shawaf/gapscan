const { execFile } = require("child_process");
const express = require("express");
const app = express();

app.get("/version", (req, res) => {
  execFile("git", ["rev-parse", "--short", "HEAD"], (err, stdout) => res.send(stdout));
});
