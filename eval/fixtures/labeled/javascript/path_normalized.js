const fs = require("fs");
const path = require("path");
const express = require("express");
const app = express();
const ROOT = path.resolve("/srv/public");

app.get("/files", (req, res) => {
  const target = path.resolve(ROOT, req.query.name);
  if (!target.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  fs.readFile(target, (err, data) => res.send(data));
});
