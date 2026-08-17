// Icons shared across more than one file live here, so a glyph used in two
// places stays one component rather than two SVGs that drift apart. Icons used
// by a single file stay next to their caller.

/** The GitHub mark.
 *
 * Moved here from App.jsx once About.jsx needed it too: by the rule at the top
 * of this file, a glyph used in two places is one component rather than two
 * SVGs that drift apart.
 *
 * One filled path, so it takes its colour from `fill` rather than the `stroke`
 * the icons around it use. currentColor throughout, so each caller's own text
 * colour decides it and both themes are handled by the rules already on the
 * control it sits in. `size` is per-placement: the contexts it appears in run
 * from a 12px underlined text link to a 14px button, and one fixed number
 * would be too big in some of them and too small in others.
 */
export function GitHubIcon({ size = 16 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.63 7.63 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}

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
