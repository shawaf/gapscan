import { render } from "preact";
import { App } from "./App";
import { initUi } from "../ui";
import "./manager.css";
import "./manager-soft.css";
import "./manager-glass.css";

initUi();

render(<App />, document.getElementById("app")!);
