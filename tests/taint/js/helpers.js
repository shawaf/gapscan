const path = require("path");

function joinPath(base, name) {
  return base + "/" + name;
}

function render(who) {
  return "<h1>Hello " + who + "</h1>";
}

module.exports = { joinPath, render };
