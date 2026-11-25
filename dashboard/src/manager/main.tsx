import { render } from "preact";
import { App } from "./App";
import { initUi } from "../ui";
import "./manager.css";
import "./manager-soft.css";
import "./manager-glass.css";
import "./manager-gapscan.css";
import "./manager-midnight.css";

initUi();

render(<App />, document.getElementById("app")!);
