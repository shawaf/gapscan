const jwt = require("jsonwebtoken");

function currentUser(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] }).sub;
  } catch (err) {
    return null;
  }
}

module.exports = { currentUser };
