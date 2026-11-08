export interface IntelligencePillar {
  number: string;
  title: string;
  description: string;
  label: string;
}

export interface MiddleOverviewProps {
  eyebrow?: string;
  title?: string;
  description?: string;
  pillars?: IntelligencePillar[];
}

const defaultPillars: IntelligencePillar[] = [
  {
    number: "01",
    title: "Signal collection",
    description:
      "Bring together signals from web infrastructure, domains, and digital identities to establish a clear picture of risk.",
    label: "Observe",
  },
  {
    number: "02",
    title: "Intelligence analysis",
    description:
      "Correlate indicators and evaluate suspicious patterns with an architecture built to support explainable analysis.",
    label: "Understand",
  },
  {
    number: "03",
    title: "Trust decisions",
    description:
      "Turn intelligence into actionable context so teams can make informed decisions about the assets they rely on.",
    label: "Respond",
  },
];

export default function MiddleOverview({
  eyebrow = "A clearer view of risk",
  title = "Intelligence that connects the whole threat landscape.",
  description = "A modular approach to digital trust helps security teams move from disconnected signals to informed decisions.",
  pillars = defaultPillars,
}: MiddleOverviewProps) {
  return (
    <section className="overview section-shell" id="intelligence" aria-labelledby="overview-title">
      <div className="section-heading">
        <p className="eyebrow"><span className="eyebrow__line" />{eyebrow}</p>
        <div className="section-heading__body">
          <h2 id="overview-title">{title}</h2>
          <p>{description}</p>
        </div>
      </div>

      <div className="overview__grid">
        {pillars.map((pillar) => (
          <article className="pillar-card" key={pillar.number}>
            <div className="pillar-card__top">
              <span className="pillar-card__number">{pillar.number}</span>
              <span className="pillar-card__label">{pillar.label}</span>
            </div>
            <div className="pillar-card__visual" aria-hidden="true">
              <span className="pillar-card__orbit pillar-card__orbit--outer" />
              <span className="pillar-card__orbit pillar-card__orbit--inner" />
              <span className="pillar-card__node" />
            </div>
            <h3>{pillar.title}</h3>
            <p>{pillar.description}</p>
            <span className="pillar-card__rule" />
          </article>
        ))}
      </div>
      <p className="overview__note">
        Architecture and intelligence are configurable to your organization’s
        requirements.
      </p>
    </section>
  );
}
