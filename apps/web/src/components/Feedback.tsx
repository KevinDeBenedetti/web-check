import type { ReactNode } from "react";
import { Link } from "react-router";
import { Icon } from "./Icon";

export function ErrorNotice({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="notice notice--error" role="alert">
      <Icon name="alert" />
      <span className="notice__text">{error.message}</span>
      {onRetry && (
        <button type="button" className="btn btn--secondary btn--small" onClick={onRetry}>
          Réessayer
        </button>
      )}
    </div>
  );
}

export function Loading({ label = "Chargement…" }: { label?: string }) {
  return (
    <p className="loading" role="status">
      {label}
    </p>
  );
}

interface EmptyStateProps {
  title: string;
  children?: ReactNode;
  action?: { to: string; label: string };
}

export function EmptyState({ title, children, action }: EmptyStateProps) {
  return (
    <div className="empty">
      <p className="empty__title">{title}</p>
      {children && <p className="empty__text">{children}</p>}
      {action && (
        <Link to={action.to} className="btn btn--primary">
          {action.label}
        </Link>
      )}
    </div>
  );
}
