const paths = {
  overview: "M3 13h8V3H3v10Zm10 8h8V11h-8v10ZM3 21h8v-6H3v6Zm10-18v6h8V3h-8Z",
  events: "M4 6h16M4 12h16M4 18h10",
  streams: "M4 7c4 0 4 4 8 4s4-4 8-4M4 17c4 0 4-4 8-4s4 4 8 4",
  verify: "M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6l-8-3Zm-3.5 9 2.5 2.5 5-5",
  exports: "M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2",
  apiKeys: "M15 7a4 4 0 1 1-3.9 4.9L4 19v-3h2v-2h2l1.1-1.1A4 4 0 0 1 15 7Zm1 3h.01",
  signingKeys: "M7 11V7a5 5 0 0 1 10 0v4M5 11h14v10H5V11Zm7 4v2",
  projects: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.4 7.4 0 0 0-2.1-1.2L14.5 3h-5l-.3 2.6c-.8.3-1.5.7-2.1 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1c.6.5 1.3.9 2.1 1.2l.3 2.6h5l.3-2.6c.8-.3 1.5-.7 2.1-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z",
  check: "m5 12 4 4 10-10",
  x: "M6 6l12 12M18 6 6 18",
  copy: "M9 9h10v10H9V9ZM5 15V5h10",
  arrow: "M5 12h14m-6-6 6 6-6 6",
  logout: "M15 17l5-5-5-5M20 12H9M12 21H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h6",
} as const;

export type IconName = keyof typeof paths;

export function Icon({ name, className = "size-4" }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"
      className={className} aria-hidden="true">
      <path d={paths[name]} />
    </svg>
  );
}
