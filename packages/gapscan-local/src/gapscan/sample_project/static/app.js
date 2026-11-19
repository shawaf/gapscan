// Browser code with deliberate mistakes.
const params = new URLSearchParams(location.search);
document.getElementById("greeting").innerHTML = "Hello " + params.get("name"); // script injection (XSS)
const result = eval(params.get("calc")); // user text run as code
localStorage.setItem("token", "abc123"); // a token kept where any script can read it
