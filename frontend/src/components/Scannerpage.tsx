import ThreatScanner from "./ThreatScanner";

export default function ScannerPage() {
  return (
    <main className="relative isolate min-h-[calc(100vh-4rem)] overflow-hidden bg-black py-16">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10"
        style={{
          backgroundImage:
            "linear-gradient(180deg, rgb(0 0 0 / 0.72), rgb(0 0 0 / 0.92)), url('/scanner-demo.jpg')",
          backgroundSize: "cover",
          backgroundPosition: "center",
        }}
      />
      <div className="mx-auto max-w-7xl px-6">
        <span className="tag-chip">Threat Console / Public Analysis API</span>
        <h1 className="section-title mt-3 !text-[clamp(2.75rem,5.5vw,4.5rem)]">
          Threat scanner
        </h1>
        <p className="mt-3 max-w-2xl text-slate-sub">
          Analyze a URL or suspicious message with the public threat analysis
          service. No account is required; results depend on evidence available
          to the backend.
        </p>
        <div className="mt-10">
          <ThreatScanner />
        </div>
      </div>
    </main>
  );
}
