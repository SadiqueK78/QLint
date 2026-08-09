// Static content page. The team list lives here rather than in a config file
// because nothing else reads it and there is no server to fetch it from.

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

export default function About() {
  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">About Us</h1>
      </div>
      <div className="team-list">
        {TEAM.map((member) => (
          <div className="team-card" key={member.name}>
            <div className="team-identity">
              <div className="team-name">{member.name}</div>
              <div className="team-role">{member.role}</div>
            </div>
            <div className="team-links">
              <a
                className="team-link"
                href={member.github}
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub
              </a>
              <a
                className="team-link"
                href={member.linkedin}
                target="_blank"
                rel="noopener noreferrer"
              >
                LinkedIn
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
