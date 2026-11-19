import { render } from "preact";
import { App } from "./App";
import { initUi } from "./ui";

initUi();

render(<App />, document.getElementById("app")!);
