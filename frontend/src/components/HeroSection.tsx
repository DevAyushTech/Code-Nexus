export default function HeroSection() {
  return (
    <section className="relative isolate flex min-h-[min(56rem,calc(100svh-4rem))] w-full items-center overflow-hidden bg-black py-16 md:py-0">
      <img
        src="/download_3.jpg"
        alt="Metallic chrome robot head"
        draggable={false}
        className="pointer-events-none absolute left-1/2 top-1/2 -z-10 h-full max-h-[736px] w-full max-w-[736px] -translate-x-1/2 -translate-y-1/2 select-none object-contain opacity-90"
      />

      <div className="pointer-events-none absolute inset-0 -z-10 bg-[linear-gradient(90deg,#000_0%,rgba(0,0,0,.72)_18%,transparent_43%,transparent_57%,rgba(0,0,0,.72)_82%,#000_100%)]" />
      <div className="pointer-events-none absolute inset-0 -z-10 bg-[linear-gradient(0deg,#000_0%,transparent_18%,transparent_82%,rgba(0,0,0,.25)_100%)]" />

      <div className="mx-auto grid w-full max-w-[1500px] grid-cols-1 items-center gap-12 px-6 md:h-full md:grid-cols-[minmax(0,1fr)_minmax(90px,1.1fr)_minmax(0,1fr)] md:gap-0">
        <div className="flex w-full flex-col items-center rounded-box border border-white/10 bg-black/65 p-5 text-center backdrop-blur-sm md:w-auto md:items-end md:rounded-none md:border-0 md:bg-transparent md:p-0 md:text-right md:backdrop-blur-none md:pr-6">
          <span className="mb-6 font-mono text-[0.65rem] uppercase tracking-[0.2em] text-slate-400">
            THREAT INTELLIGENCE / 01
          </span>
          <h1 className="hero-title max-w-[9ch] text-[clamp(2rem,8vw,3rem)] text-white md:text-[clamp(3rem,6.2vw,5.25rem)]">
            AI-POWERED WEB THREAT
          </h1>
          <p className="hero-sub mt-8 max-w-[28ch] text-slate-300">
            SECURING THE WEB AGAINST THE PHISHING, CRYPTOGRAPHIC
            VULNERABILITIES, AND INFRASTRUCTURE.
          </p>
        </div>

        <div className="hidden md:block" aria-hidden />

        <div className="flex w-full flex-col items-center rounded-box border border-white/10 bg-black/65 p-5 text-center backdrop-blur-sm md:w-auto md:items-start md:rounded-none md:border-0 md:bg-transparent md:p-0 md:text-left md:backdrop-blur-none md:pl-6">
          <span className="mb-6 font-mono text-[0.65rem] uppercase tracking-[0.2em] text-slate-400">
            DIGITAL TRUST / 02
          </span>
          <h2 className="hero-title max-w-[9ch] text-[clamp(2rem,8vw,3rem)] text-white md:text-[clamp(3rem,6.2vw,5.25rem)]">
            DIGITAL TRUST INTELLIGENCE
          </h2>
          <p className="hero-sub mt-8 max-w-[28ch] text-slate-300">
            DEFENDING AGAINST ZERO-HOUR PHISHING, DECEPTIVE ADS, AND CREDENTIAL
            HARVESTING.
          </p>
        </div>
      </div>
    </section>
  );
}