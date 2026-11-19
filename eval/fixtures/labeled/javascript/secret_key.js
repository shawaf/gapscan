const jwt = require("jsonwebtoken");

const jwtSecret = "7f3a9c1e5b2d48f6a0c7e9d1b3f5a7c9";

function sign(user) {
  return jwt.sign({ sub: user.id }, jwtSecret, { expiresIn: "1h" });
}

module.exports = { sign };
