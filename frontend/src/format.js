// Formatting shared by the two results views.
//
// These two started in App.jsx and moved here when the website results view
// needed the same score colouring and the same date wording. Importing them
// back out of App.jsx would have made the module graph circular -- App.jsx
// imports the website view -- so they live in a module neither view owns.

export function scoreClass(score) {
  if (score < 40) return "score-critical";
  if (score < 70) return "score-warning";
  return "score-safe";
}

export function formatDateTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const day = date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
  const time = date.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
  });
  return `${day} at ${time}`;
}
