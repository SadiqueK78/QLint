// Where the QLint backend lives. Shared so App.jsx and the standalone pages
// cannot drift apart, and so pointing the frontend at a deployed backend is a
// config change rather than a code change.
//
// Set VITE_API_URL to override. Vite inlines it at *build* time, not run time,
// so a deployed image has to be rebuilt (or built with the value) to move --
// changing the variable next to an already-built dist/ does nothing. The
// fallback keeps `npm run dev` working with no .env present at all.
const configured = import.meta.env.VITE_API_URL || "http://qlint-production.up.railway.app";

// Every caller writes `${API_BASE}/some/path`, so a trailing slash on the
// configured value would produce "//some/path". Cheaper to strip it here than
// to trust that nobody ever pastes the URL with one.
export const API_BASE = configured.replace(/\/+$/, "");
