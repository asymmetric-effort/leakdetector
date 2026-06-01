import { HomePage } from "./pages/home.js";
import { UsagePage } from "./pages/usage.js";
import { ConfigurationPage } from "./pages/configuration.js";
import { RulesPage } from "./pages/rules.js";
import { OutputPage } from "./pages/output.js";

declare const __APP_VERSION__: string;
const VERSION = typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "0.0.0";

type PageComponent = () => string;

const ROUTES: Record<string, PageComponent> = Object.create(null);
ROUTES["/"] = HomePage;
ROUTES["/usage"] = UsagePage;
ROUTES["/configuration"] = ConfigurationPage;
ROUTES["/rules"] = RulesPage;
ROUTES["/output"] = OutputPage;

function getPath(): string {
  const hash = window.location.hash.replace(/^#\/?/, "/");
  return hash === "" ? "/" : hash;
}

function renderNav(currentPath: string): string {
  const links = [
    { to: "/", label: "Home", exact: true },
    { to: "/usage", label: "Usage" },
    { to: "/configuration", label: "Configuration" },
    { to: "/rules", label: "Rules" },
    { to: "/output", label: "Output" },
  ];

  const navLinks = links
    .map((link) => {
      const isActive = link.exact
        ? currentPath === link.to
        : currentPath.startsWith(link.to);
      return `<a href="#${link.to}" class="${isActive ? "active" : ""}">${link.label}</a>`;
    })
    .join("");

  return `<nav class="nav">
    <a href="#/" class="nav-brand">
      <img src="/logo.png" alt="leakdetector logo">
      leakdetector
    </a>
    <div class="nav-links">${navLinks}</div>
  </nav>`;
}

function renderFooter(): string {
  return `<footer class="footer" role="contentinfo">
    <div class="footer-inner">
      <span>v${VERSION}</span>
      <span>MIT License \u00A9 2026 Asymmetric Effort, LLC</span>
      <span>
        <a href="https://github.com/asymmetric-effort/leakdetector" target="_blank" rel="noopener noreferrer">GitHub</a>
        \u00B7
        <a href="https://github.com/asymmetric-effort/leakdetector/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer">Security</a>
        \u00B7
        <a href="https://github.com/asymmetric-effort/leakdetector/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener noreferrer">Contributing</a>
      </span>
    </div>
  </footer>`;
}

function updateHead(path: string): void {
  const titles: Record<string, string> = Object.create(null);
  titles["/"] = "leakdetector \u2014 Secret Detection for Git Repositories";
  titles["/usage"] = "Usage \u2014 leakdetector";
  titles["/configuration"] = "Configuration \u2014 leakdetector";
  titles["/rules"] = "Detection Rules \u2014 leakdetector";
  titles["/output"] = "Output Formats \u2014 leakdetector";

  document.title = path in titles ? titles[path] : titles["/"];

  let canonical = document.querySelector(
    'link[rel="canonical"]'
  ) as HTMLLinkElement;
  if (!canonical) {
    canonical = document.createElement("link");
    canonical.rel = "canonical";
    document.head.appendChild(canonical);
  }
  canonical.href = `https://leakdetector.asymmetric-effort.com/${path === "/" ? "" : "#" + path}`;
}

function render(): void {
  const path = getPath();
  const root = document.getElementById("root")!;
  const page = path in ROUTES ? ROUTES[path] : ROUTES["/"];

  root.innerHTML = `
    ${renderNav(path)}
    <main class="main">${page()}</main>
    ${renderFooter()}
  `;

  updateHead(path);
}

render();
window.addEventListener("hashchange", render);
