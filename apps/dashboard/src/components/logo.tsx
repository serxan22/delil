/** DƏLİL mark: three linked blocks, the last one sealed, reading as a hash chain. */
export function LogoMark({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <rect x="2" y="2" width="28" height="28" rx="8" fill="#17171a" />
      <rect x="7.5" y="13.5" width="5" height="5" rx="1.25" stroke="#fff" strokeWidth="1.6" />
      <rect x="13.5" y="13.5" width="5" height="5" rx="1.25" stroke="#fff" strokeWidth="1.6" />
      <rect x="19.5" y="13.5" width="5" height="5" rx="1.25" fill="#5eb8a8" stroke="#5eb8a8" strokeWidth="1.6" />
      <path d="M12.5 16h1M18.5 16h1" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="inline-flex items-center gap-2.5">
      <LogoMark />
      <span className="text-[15px] font-semibold tracking-[0.08em]">DƏLİL</span>
    </span>
  );
}
