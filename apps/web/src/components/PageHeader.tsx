import type { ReactNode } from "react";
import { Link } from "react-router";

interface PageHeaderProps {
  title: ReactNode;
  subtitle?: ReactNode;
  back?: { to: string; label: string };
  actions?: ReactNode;
  mono?: boolean;
}

export function PageHeader({ title, subtitle, back, actions, mono }: PageHeaderProps) {
  return (
    <header className="page-header">
      <div className="page-header__text">
        {back && (
          <Link to={back.to} className="back-link">
            ← {back.label}
          </Link>
        )}
        <h1 className={mono ? "page-title mono" : "page-title"}>{title}</h1>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
      {actions && <div className="page-header__actions">{actions}</div>}
    </header>
  );
}
