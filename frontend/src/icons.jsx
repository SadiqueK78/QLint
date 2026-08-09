// Icons shared across more than one file live here, so a glyph used in two
// places stays one component rather than two SVGs that drift apart. Icons used
// by a single file stay next to their caller.

// Points down at rest; the caller rotates it 180deg when its section is open.
export function ChevronIcon({ size = 14 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M6 9 L12 15 L18 9" />
    </svg>
  );
}
