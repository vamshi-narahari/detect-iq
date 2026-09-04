// DetectIQ logo mark — a waveform crossing a threshold line, the same
// signal/threshold motif used throughout the product. Scales cleanly from
// favicon size up to a hero lockup.
export default function LogoMark({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <line x1="4" y1="11" x2="28" y2="11" stroke="#f2a93b" strokeWidth="1.4" strokeDasharray="2.5 3" opacity="0.85" />
      <path
        d="M4 20 C7 20 8 24 10 24 C12 24 13 8 16 8 C19 8 19 22 22 22 C24 22 25 15 28 15"
        stroke="#4fd1c5"
        strokeWidth="2.3"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      <circle cx="16" cy="11" r="2.1" fill="#f2a93b" />
    </svg>
  );
}
