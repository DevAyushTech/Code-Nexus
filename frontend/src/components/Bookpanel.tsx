import { useState } from "react";

interface BookPanelProps {
  index: string; // e.g. "01"
  title: string;
  body: string;
  /** Texture image in /public, e.g. "/dark-waves.jpg" */
  texture: string;
}

/**
 * Book-style panel. The cover swings open from the spine on hover or keyboard focus,
 * and toggles on tap for touch screens. The texture sits under a dark overlay,
 * with a charcoal gradient fallback if the image is missing.
 */
export default function BookPanel({ index, title, body, texture }: BookPanelProps) {
  const [open, setOpen] = useState(false);

  return (
    <button
      type="button"
      className="book"
      data-open={open}
      aria-pressed={open}
      onClick={() => setOpen((v) => !v)}
    >
      <span className="book-page">
        <span className="book-page-edge" aria-hidden="true" />
        <span className="tag-chip">{index} / Detail</span>
        <span className="font-display text-3xl font-light uppercase tracking-wide text-white">
          {title}
        </span>
        <span className="text-sm leading-relaxed text-slate-sub">{body}</span>
      </span>

      <span className="book-cover">
        <span
          className="book-cover-face book-cover-front"
          style={{
            backgroundImage: `linear-gradient(rgba(0,0,0,0.55), rgba(0,0,0,0.85)), url(${texture}), linear-gradient(135deg, #1c1c1c, #050505)`,
          }}
        >
          <span className="tag-chip pl-3">{index}</span>
          <span className="pl-3">
            <span className="block font-display text-4xl font-light uppercase leading-none tracking-wide text-white">
              {title}
            </span>
            <span className="mt-4 block font-mono text-[0.62rem] uppercase tracking-[0.25em] text-slate-sub">
              Hover or tap to open
            </span>
          </span>
        </span>
        <span className="book-cover-face book-cover-inside" aria-hidden="true">
          <span className="font-mono text-[0.6rem] uppercase tracking-[0.2em] text-slate-sub">
            Intelligence module / {index}
          </span>
          <span className="font-display text-2xl font-light uppercase tracking-wide text-white/90">
            {title}
          </span>
        </span>
      </span>
    </button>
  );
}