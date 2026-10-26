import { Link, NavLink, Outlet } from "react-router";
import { api } from "../api/client";
import { useResource } from "../hooks/useResource";
import { SERVICE_STATE_LABELS } from "../lib/labels";
import { Icon, type IconName } from "./Icon";

interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: "/", label: "Tableau de bord", icon: "dashboard", end: true },
  { to: "/scans", label: "Historique", icon: "report", end: true },
  { to: "/compare", label: "Comparer", icon: "compare" },
  { to: "/settings", label: "Réglages", icon: "settings" },
];

function ServicesSummary() {
  const services = useResource(api.services, [], 15_000);
  return (
    <section className="sidebar__services" aria-labelledby="services-title">
      <h2 id="services-title" className="sidebar__heading">
        Services locaux
      </h2>
      {services.error && <p className="sidebar__muted">API injoignable</p>}
      <ul className="service-list">
        {services.data?.map((service) => (
          <li key={service.id} className="service-list__item">
            <span className={`dot dot--${service.state}`} aria-hidden="true" />
            <span className="service-list__name">{service.name}</span>
            <span className="service-list__state">{SERVICE_STATE_LABELS[service.state]}</span>
          </li>
        ))}
      </ul>
      <NavLink to="/settings" className="sidebar__link">
        Gérer les services
      </NavLink>
    </section>
  );
}

function RunningBadge() {
  const scans = useResource(api.listScans, [], 10_000);
  const running = scans.data?.filter((scan) => scan.status === "running").length ?? 0;
  if (!running) return null;
  return (
    <Link to="/scans?status=running" className="nav__item">
      <Icon name="activity" />
      <span className="nav__label">Scans en cours</span>
      <span className="nav__badge">{running}</span>
    </Link>
  );
}

export function Layout() {
  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Aller au contenu
      </a>
      <nav className="sidebar" aria-label="Navigation principale">
        <div className="brand">
          <Icon name="logo" size={28} />
          <div className="brand__text">
            <span className="brand__name">web-check</span>
            <span className="brand__host mono">{window.location.host}</span>
          </div>
        </div>
        <NavLink to="/scans/new" className="btn btn--primary btn--block">
          <Icon name="plus" strokeWidth={2} />
          Nouveau scan
        </NavLink>
        <div className="nav">
          {NAV.slice(0, 1).map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className="nav__item">
              <Icon name={item.icon} />
              <span className="nav__label">{item.label}</span>
            </NavLink>
          ))}
          <RunningBadge />
          {NAV.slice(1).map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className="nav__item">
              <Icon name={item.icon} />
              <span className="nav__label">{item.label}</span>
            </NavLink>
          ))}
        </div>
        <ServicesSummary />
      </nav>
      <main id="main" className="main" tabIndex={-1}>
        <div className="container">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
