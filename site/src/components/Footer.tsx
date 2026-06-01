import { createElement } from "@asymmetric-effort/specifyjs";

declare const __APP_VERSION__: string;
const VERSION = typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "0.0.0";

export function Footer() {
  return (
    <footer class="footer" role="contentinfo">
      <div class="footer-inner">
        <span>v{VERSION}</span>
        <span>MIT License {"\u00A9"} 2026 Asymmetric Effort, LLC</span>
        <span>
          <a href="https://github.com/asymmetric-effort/leakdetector" target="_blank" rel="noopener noreferrer">GitHub</a>
          {" \u00B7 "}
          <a href="https://github.com/asymmetric-effort/leakdetector/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer">Security</a>
          {" \u00B7 "}
          <a href="https://github.com/asymmetric-effort/leakdetector/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener noreferrer">Contributing</a>
        </span>
      </div>
    </footer>
  );
}
