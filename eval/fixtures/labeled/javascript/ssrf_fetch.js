const express = require("express");
const app = express();

app.get("/proxy", async (req, res) => {
  const upstream = await fetch(req.query.url);
  res.send(await upstream.text());
});
