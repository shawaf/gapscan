const express = require("express");
const app = express();

app.post("/import", express.text(), (req, res) => {
  const data = JSON.parse(req.body);
  res.json({ keys: Object.keys(data) });
});
