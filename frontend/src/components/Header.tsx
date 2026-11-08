import type { ReactNode } from "react";
import type { View } from "../types";

interface HeaderProps {
  view: View;
  onNavigate: (view: View) => void;
}

function OverviewIcon() {
  return (
    <svg className="image" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z" />
    </svg>
  );
}

function ConsoleIcon() {
  return (
    <svg className="image" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M4 5h16v14H4zM8 10l2 2-2 2m5 0h3" />
    </svg>
  );
}

export default function Header({ view, onNavigate }: HeaderProps) {
  const link = (target: View, label: string, icon: ReactNode) => (
    <li className="nav-item">
      <button
        onClick={() => onNavigate(target)}
        aria-current={view === target ? "page" : undefined}
        aria-label={label}
        className="nav-item__link"
      >
        {icon}
        <span className="nav-item__tooltip" role="tooltip">
          {label}
        </span>
      </button>
    </li>
  );

  return (
    <>
      <button
        onClick={() => onNavigate("scanner")}
        className="push-button"
        aria-label="Try the prototype"
      >
        <div className="button-outer">
          <div className="button-inner">
            <span>Try Prototype</span>
          </div>
        </div>
      </button>

      <section className="docker" aria-label="Application dock">
        <div className="nav-wrap">
          <nav className="nav-bar" aria-label="Primary navigation">
            <ul className="nav-list">
              {link("home", "Overview", <OverviewIcon />)}
              {link("scanner", "Threat Console", <ConsoleIcon />)}
            </ul>
          </nav>
        </div>
      </section>
    </>
  );
}
