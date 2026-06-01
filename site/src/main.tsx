import { createElement, Router, Route } from "@asymmetric-effort/specifyjs";
import { createRoot } from "@asymmetric-effort/specifyjs/dom";
import "./styles.css";

import { Nav } from "./components/Nav";
import { Footer } from "./components/Footer";
import { Home } from "./pages/Home";
import { Usage } from "./pages/Usage";
import { Configuration } from "./pages/Configuration";
import { Rules } from "./pages/Rules";
import { Output } from "./pages/Output";

function App() {
  return (
    <Router>
      <Nav />
      <main class="main">
        <Route path="/" exact component={Home} />
        <Route path="/usage" component={Usage} />
        <Route path="/configuration" component={Configuration} />
        <Route path="/rules" component={Rules} />
        <Route path="/output" component={Output} />
      </main>
      <Footer />
    </Router>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
