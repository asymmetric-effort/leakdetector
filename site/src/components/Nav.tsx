import { createElement, Link, useRouter } from "@asymmetric-effort/specifyjs";

const links = [
  { to: "/", label: "Home", exact: true },
  { to: "/usage", label: "Usage", exact: false },
  { to: "/configuration", label: "Configuration", exact: false },
  { to: "/rules", label: "Rules", exact: false },
  { to: "/output", label: "Output", exact: false },
];

export function Nav() {
  const { pathname } = useRouter();

  return (
    <nav class="nav">
      <Link to="/" class="nav-brand">
        <img src="/logo.png" alt="leakdetector logo" />
        leakdetector
      </Link>
      <div class="nav-links">
        {links.map((link) => {
          const isActive = link.exact
            ? pathname === link.to
            : pathname.startsWith(link.to);
          return (
            <Link
              to={link.to}
              class={isActive ? "active" : ""}
            >
              {link.label}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
