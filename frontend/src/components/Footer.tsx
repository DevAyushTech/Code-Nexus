import type { View } from "../types";

interface FooterProps {
  onNavigate: (view: View) => void;
}

export default function Footer({ onNavigate }: FooterProps) {
  return (
    <footer className="relative isolate overflow-hidden border-t border-white/10 bg-black">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "linear-gradient(180deg, rgb(0 0 0 / 0.78), rgb(0 0 0 / 0.9)), url('/abstract-nodes.jpg')",
          backgroundPosition: "center",
          backgroundSize: "cover",
        }}
      />
      <div className="relative z-10 mx-auto max-w-7xl px-6 py-14">
        <div className="grid gap-10 md:grid-cols-[1.6fr_1fr_1fr]">
          <div>
            <h2 className="font-display text-2xl font-light uppercase tracking-[0.1em] text-white">
              AI-Powered Web Threat &amp; Digital Trust Intelligence
            </h2>
            <p className="mt-3 max-w-md text-sm leading-relaxed text-slate-sub">
              Threat intelligence for phishing, cryptographic weaknesses and
              infrastructure risk.
            </p>
          </div>

          <div>
            <h3 className="tag-chip mb-4">Navigate</h3>
            <ul className="space-y-3 font-mono text-xs uppercase tracking-[0.15em]">
              <li>
                <button
                  onClick={() => onNavigate("home")}
                  className="text-slate-sub transition hover:text-white"
                >
                  Overview
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate("scanner")}
                  className="text-slate-sub transition hover:text-white"
                >
                  Threat Console
                </button>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="tag-chip mb-4">Compliance</h3>
            <ul className="space-y-3 font-mono text-xs uppercase tracking-[0.15em] text-slate-sub">
              <li>SOC 2 TYPE II ALIGNED</li>
              <li>ISO 27001 ALIGNED</li>
            </ul>
          </div>
        </div>

        <div className="mt-12 border-t border-white/10 pt-6 text-xs text-slate-sub/70">
          <p>© {new Date().getFullYear()} All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
}