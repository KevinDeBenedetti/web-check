import { EmptyState } from "../components/Feedback";

export function NotFoundPage() {
  return (
    <div className="card">
      <EmptyState title="Page introuvable" action={{ to: "/", label: "Retour au tableau de bord" }} />
    </div>
  );
}
