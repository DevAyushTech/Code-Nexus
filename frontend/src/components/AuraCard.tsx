import type { ReactNode } from "react";

interface AuraCardProps {
  title?: string;
  tag?: string;
  children: ReactNode;
}

/** Restrained surface card used for information panels. */
export default function AuraCard({ title, tag, children }: AuraCardProps) {
  return (
    <div className="h-full min-w-0 rounded-box border border-white/10 bg-black/65 transition-colors hover:border-white/25">
      <div className="flex h-full min-w-0 flex-col gap-3 p-6">
        {tag && <span className="tag-chip">{tag}</span>}
        {title && (
          <h3 className="font-display text-2xl font-light uppercase tracking-wide text-white">
            {title}
          </h3>
        )}
        <div className="text-sm leading-relaxed text-slate-sub">{children}</div>
      </div>
    </div>
  );
}