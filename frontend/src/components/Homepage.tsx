import { useState } from "react";
import BookPanel from "./Bookpanel";
import HeroSection from "./HeroSection";
import type { View } from "../types";

interface HomePageProps {
  onNavigate: (view: View) => void;
}

const stages = [
  {
    index: "01",
    title: "Ingestion",
    texture: "/dark-waves.jpg",
    body: "A submitted URL is normalised and its domain, redirect chain and page content are collected for analysis.",
  },
  {
    index: "02",
    title: "Analysis",
    texture: "/abstract-nodes.jpg",
    body: "Models and rule engines inspect the page for phishing patterns, deceptive ads, credential harvesting forms and weak cryptography.",
  },
  {
    index: "03",
    title: "Scoring",
    texture: "/dark-waves.jpg",
    body: "Signals are combined into a trust verdict with a severity level, so the result is easy to act on.",
  },
  {
    index: "04",
    title: "Logging",
    texture: "/abstract-nodes.jpg",
    body: "Every finding is stored as a threat log entry that analysts can review, edit and extend.",
  },
];

interface InsightCard {
  label: string;
  title: string;
  body: string;
  detail: string;
}

const workflow: InsightCard[] = [
  {
    label: "TARGET / 01",
    title: "Submit a URL or message",
    body: "Choose a web address or paste suspicious message content for analysis.",
    detail: "URLs are validated as HTTP or HTTPS; a missing scheme defaults to HTTPS. Message input is trimmed before submission.",
  },
  {
    label: "EXECUTION / 02",
    title: "Route to the analysis API",
    body: "The console submits the selected target to the public threat analysis service.",
    detail: "URL and message payloads use dedicated analysis endpoints. The console reports the returned analysis or an explicit request error.",
  },
  {
    label: "VERDICT / 03",
    title: "Read the evidence-led report",
    body: "Review the backend classification, risk score, findings and signal-source status.",
    detail: "Findings include severity, evidence and recommendations when returned. INCONCLUSIVE means evidence or integrations may be unavailable—not that the target is safe.",
  },
  {
    label: "INTEGRITY / 04",
    title: "Verify the report record",
    body: "Optionally check a completed report’s verification status using its report ID.",
    detail: "The response identifies verification mode and source, report hash, and whether an on-chain registration exists; registration is never assumed.",
  },
];

const coverage: InsightCard[] = [
  {
    label: "SIGNAL / 01",
    title: "Phishing",
    body: "Look-alike domains and zero-hour phishing pages.",
    detail: "Inspect domain similarity, redirect paths and page-level deception.",
  },
  {
    label: "SIGNAL / 02",
    title: "Credential harvesting",
    body: "Forms and flows built to capture logins and payment details.",
    detail: "Review credential fields and suspicious collection behavior.",
  },
  {
    label: "SIGNAL / 03",
    title: "Deceptive ads",
    body: "Misleading advertising and redirect tricks.",
    detail: "Trace unexpected redirects and inspect misleading ad destinations.",
  },
  {
    label: "SIGNAL / 04",
    title: "Cryptography",
    body: "Weak TLS configurations and certificate problems.",
    detail: "Check transport security indicators and certificate validity.",
  },
];

function NoteStack({ cards }: { cards: InsightCard[] }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [isPeeling, setIsPeeling] = useState(false);
  const activeCard = cards[activeIndex];

  const advance = (event: React.AnimationEvent<HTMLDivElement>) => {
    if (event.animationName !== "note-peel" || !isPeeling) return;
    setActiveIndex((index) => (index + 1) % cards.length);
    setIsPeeling(false);
  };

  return (
    <div
      className={`note-stack${isPeeling ? " is-peeling" : ""}`}
      onAnimationEnd={advance}
    >
      {[2, 1].map((depth) => {
        const card = cards[(activeIndex + depth) % cards.length];
        return (
          <article
            key={`${depth}-${card.label}`}
            aria-hidden="true"
            className={`note-stack__layer note-stack__layer--${depth}`}
          >
            <span className="note-stack__label">{card.label}</span>
            <div>
              <h3>{card.title}</h3>
              <p>{card.body}</p>
            </div>
          </article>
        );
      })}
      <button
        type="button"
        className="note-stack__card"
        aria-label={`Reveal next insight: ${activeCard.title}`}
        disabled={isPeeling}
        onClick={() => setIsPeeling(true)}
      >
        <span className="note-stack__label">{activeCard.label}</span>
        <div>
          <h3>{activeCard.title}</h3>
          <p>{activeCard.body}</p>
          <p className="note-stack__detail">{activeCard.detail}</p>
        </div>
        <span className="note-stack__action">
          Click to peel <span aria-hidden="true">↗</span>
          <span>{String(activeIndex + 1).padStart(2, "0")} / {String(cards.length).padStart(2, "0")}</span>
        </span>
      </button>
    </div>
  );
}

/** Subtle full-bleed texture layer behind a section. */
function Texture({ src, opacity = 0.18 }: { src: string; opacity?: number }) {
  return (
    <div
      aria-hidden
      className="pointer-events-none absolute inset-0 -z-10"
      style={{
        backgroundImage: `url(${src})`,
        backgroundSize: "cover",
        backgroundPosition: "center",
        opacity,
        maskImage: "linear-gradient(to bottom, transparent, #000 20%, #000 80%, transparent)",
        WebkitMaskImage: "linear-gradient(to bottom, transparent, #000 20%, #000 80%, transparent)",
      }}
    />
  );
}

export default function HomePage({ onNavigate: _onNavigate }: HomePageProps) {
  return (
    <>
      <HeroSection />

      {/* Architecture: book panels over a dark-waves texture */}
      <section className="relative isolate border-t border-white/10 bg-black py-24">
        <Texture src="/dark-waves.jpg" opacity={0.28} />
        <div className="mx-auto max-w-7xl px-6">
          <span className="tag-chip">System architecture</span>
          <h2 className="section-title mt-3">How the intelligence engine works</h2>
          <p className="mt-4 max-w-2xl text-slate-sub">
            From a single link to a logged verdict, the engine follows four
            stages. Open each cover to read the detail.
          </p>

          <div className="mt-14 grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
            {stages.map((s) => (
              <BookPanel key={s.index} {...s} />
            ))}
          </div>
        </div>
      </section>

      {/* Workflow and coverage: hairline lists over an abstract-nodes texture */}
      <section className="relative isolate border-t border-white/10 bg-black py-24">
        <Texture src="/abstract-nodes.jpg" opacity={0.22} />
        <div className="mx-auto grid max-w-7xl gap-16 px-6 lg:grid-cols-2">
          <div>
            <span className="tag-chip">Data workflow</span>
            <h2 className="section-title mt-3">From input to insight</h2>
            <div className="mt-10">
              <NoteStack cards={workflow} />
            </div>
          </div>

          <div>
            <span className="tag-chip">What we detect</span>
            <h2 className="section-title mt-3">Threat coverage</h2>
            <div className="mt-10">
              <NoteStack cards={coverage} />
            </div>
          </div>
        </div>
      </section>

    </>
  );
}