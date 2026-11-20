import { createElement, Link, useRouter, useState } from "@asymmetric-effort/specifyjs";

const links = [
  { to: "/", label: "Home", exact: true },
  { to: "/usage", label: "Usage", exact: false },
  { to: "/configuration", label: "Configuration", exact: false },
  { to: "/rules", label: "Rules", exact: false },
  { to: "/output", label: "Output", exact: false },
];

export function Nav() {
  const { pathname } = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);

  const toggleMenu = () => setMenuOpen(!menuOpen);
  const closeMenu = () => setMenuOpen(false);

  return (
    <nav class="nav">
      <div class="nav-inner">
        <Link to="/" class="nav-brand" onClick={closeMenu}>
          <img src="/logo.png" alt="leakdetector logo" width="28" height="28" />
          <span class="nav-brand-text">
            <span style={{ color: 'var(--primary)' }}>Leak</span>
            <span style={{ color: 'var(--text)' }}>Detector</span>
          </span>
        </Link>
        <button
          class="nav-toggle"
          onClick={toggleMenu}
          aria-label="Toggle navigation"
          aria-expanded={menuOpen ? "true" : "false"}
        >
          {menuOpen ? "\u2715" : "\u2630"}
        </button>
        <div class={menuOpen ? "nav-links nav-links-open" : "nav-links"}>
          {links.map((link) => {
            const isActive = link.exact
              ? pathname === link.to
              : pathname.startsWith(link.to);
            return (
              <Link
                to={link.to}
                class={isActive ? "active" : ""}
                onClick={closeMenu}
              >
                {link.label}
              </Link>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
