const express = require("express");
const app = express();

app.post("/calc", express.json(), (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});
