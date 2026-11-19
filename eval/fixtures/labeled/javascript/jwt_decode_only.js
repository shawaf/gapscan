const jwt = require("jsonwebtoken");

function currentUser(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const claims = jwt.decode(token);
  return claims && claims.sub;
}

module.exports = { currentUser };
