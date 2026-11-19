const params = new URLSearchParams(window.location.search);
const greeting = document.getElementById("greeting");
greeting.innerHTML = "Welcome back, " + params.get("name");
