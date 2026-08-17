// Static content page. The team list lives here rather than in a config file
// because nothing else reads it and there is no server to fetch it from.

import { GitHubIcon } from "./icons";

// The project guide, listed above the team and separated from it by a rule.
// Kept as its own value rather than a fourth TEAM entry because the divider
// has to fall in exactly one place, and a flag on a list item to say "draw a
// line after me" is a worse way to spell that than two lists.
const GUIDE = {
  name: "Dr. Uday Wad",
  role: "Project Guide",
  linkedin: "https://www.linkedin.com/in/uday-wad-8740b41a1",
};

const TEAM = [
  {
    name: "Abhushan Bokade",
    role: "Full Stack Developer & Architect",
    github: "https://github.com/Abhushan187",
    linkedin: "https://www.linkedin.com/in/abhushan-bokade/",
  },
  {
    name: "Sadique Khatib",
    role: "AI Engineer",
    github: "https://github.com/SadiqueK78",
    linkedin: "https://www.linkedin.com/in/sadique-khatib-4175342a9/",
  },
  {
    name: "Sharyu Kekane",
    role: "Project Manager",
    github: "https://github.com/SharyuKekane",
    linkedin: "https://www.linkedin.com/in/sharyu-kekane/",
  },
];

// One card, whatever it is a card for, so the guide cannot drift away from the
// team visually the next time either is edited. Each link renders only if the
// entry has it: not everyone listed here has both.
function TeamCard({ member }) {
  return (
    <div className="team-card">
      <div className="team-identity">
        <div className="team-name">{member.name}</div>
        <div className="team-role">{member.role}</div>
      </div>
      <div className="team-links">
        {member.github && (
          <a
            className="team-link team-link-icon"
            href={member.github}
            target="_blank"
            rel="noopener noreferrer"
          >
            {/* 14 against this card's 13px text. The LinkedIn link beside it
                keeps its plain label: this adds the mark that exists, rather
                than inventing a second one for symmetry. */}
            <GitHubIcon size={14} />
            GitHub
          </a>
        )}
        {member.linkedin && (
          <a
            className="team-link"
            href={member.linkedin}
            target="_blank"
            rel="noopener noreferrer"
          >
            LinkedIn
          </a>
        )}
      </div>
    </div>
  );
}

export default function About() {
  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">About Us</h1>
      </div>
      <div className="team-list">
        <TeamCard member={GUIDE} />
        <hr className="team-divider" />
        {TEAM.map((member) => (
          <TeamCard member={member} key={member.name} />
        ))}
      </div>
    </div>
  );
}
