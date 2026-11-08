import { useEffect, useState } from "react";
import Footer from "./components/Footer";
import Header from "./components/Header";
import HomePage from "./components/Homepage";
import ScannerPage from "./components/Scannerpage";
import type { View } from "./types";

const readHash = (): View => (window.location.hash === "#/scanner" ? "scanner" : "home");

export default function App() {
  const [view, setView] = useState<View>(readHash);

  // Lightweight hash routing so the browser back button and deep links work.
  useEffect(() => {
    const onHash = () => setView(readHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const navigate = (next: View) => {
    window.location.hash = next === "scanner" ? "#/scanner" : "#/";
    setView(next);
    window.scrollTo({ top: 0 });
  };

  return (
    <div className="flex min-h-screen flex-col bg-black pb-24">
      <Header view={view} onNavigate={navigate} />
      <div className="flex-1">
        {view === "home" ? <HomePage onNavigate={navigate} /> : <ScannerPage />}
      </div>
      <Footer onNavigate={navigate} />
    </div>
  );
}