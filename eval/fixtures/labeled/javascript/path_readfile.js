const fs = require("fs");
const express = require("express");
const app = express();

app.get("/files", (req, res) => {
  fs.readFile("/srv/public/" + req.query.name, (err, data) => res.send(data));
});
