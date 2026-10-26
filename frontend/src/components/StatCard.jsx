
import { ArrowUpRight } from "lucide-react";

export default function StatCard({
  title,
  value = 0,
  description,
  icon: Icon,
  accent = false,
}) {
  return (
    <>
    <article className="stat-card">
      <div className="stat-card__top">
        <span className="stat-card__title">{title}</span>

        {Icon && (
          <span className={`stat-card__icon ${accent ? "accent" : ""}`}>
            <Icon size={20} strokeWidth={1.8} />
          </span>
        )}
      </div>

      <div className="stat-card__value">{value}</div>

      <div className="stat-card__footer">
        <span>{description}</span>
        <ArrowUpRight size={16} aria-hidden="true" />
      </div>
    </article>
    </>
  );
}
