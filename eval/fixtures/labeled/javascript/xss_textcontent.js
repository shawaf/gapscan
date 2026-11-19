const params = new URLSearchParams(window.location.search);
const greeting = document.getElementById("greeting");
greeting.textContent = "Welcome back, " + params.get("name");
