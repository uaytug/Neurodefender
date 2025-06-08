import React from 'react';
import './styles/AboutUs.css';

const AboutUs: React.FC = () => {
  const teamMembers = [
    {
      name: "Umut Aytuğ Semerci",
      role: "Founder, Developer & Head of Security",
      bio: "Kadir Has University Computer Science and Engineering student. He is a passionate developer and security researcher.",
      image: "https://avatars.githubusercontent.com/u/54780493?v=4",
      link: "https://github.com/uaytug"
    },
    {
      name: "Göktuğ Ateş",
      role: "Founder & ML Engineer",
      bio: "Kadir Has University Computer Science and Engineering student. He is a passionate developer",
      image: "https://media.licdn.com/dms/image/v2/D4D03AQGfR027bztlbw/profile-displayphoto-shrink_400_400/B4DZYZ1OaDHsAg-/0/1744190105883?e=1753315200&v=beta&t=7CJw8eUNBsvSGjh4WTrrf219EVo0BDDR8jba2CulGbc",
      link: "https://github.com/GoktugAtes04"
    },
    {
      name: "Başar Çelebi",
      role: "Founder, Developer & UI/UX Designer",
      bio: "Kadir Has University Computer Science and Engineering student. He is a passionate Mobile Developer",
      image: "https://avatars.githubusercontent.com/u/75533431?v=4",
      link: "https://github.com/celebibasar"
    },
    {
      name: "Emircan Çapkan",
      role: "Founder & Developer",
      bio: "Kadir Has University Computer Science and Engineering student. He is a passionate C#, .NET Developer",
      image: "https://avatars.githubusercontent.com/u/99869455?v=4",
      link: "https://github.com/emircancapkan"
    }
  ];

  const milestones = [
    { year: "2024 Q4", event: "NeuroDefender founded with a vision for AI-powered security" },
    { year: "2025 Q1", event: "Released first beta version with real-time threat detection" },
    { year: "2025 Q2", event: "Launched advanced ML models for zero-day threat detection" },
    { year: "2025 Q3", event: "First public release of NeuroDefender v1.0 has been made available open source" }
  ];

  return (
    <div className="about-us-container">
      <div className="app-header">
        <div className="app-header-content">
          <h1>About NeuroDefender</h1>
          <p className="header-description">Protecting your digital assets with cutting-edge AI technology</p>
        </div>
      </div>

      {/* Hero Section */}
      <div className="content-card hero-section">
        <div className="hero-content">
          <h2>Our Mission</h2>
          <p className="mission-statement">
            At NeuroDefender, we believe that cybersecurity should be intelligent, proactive, and accessible. 
            Our mission is to revolutionize network security by harnessing the power of artificial intelligence 
            and machine learning to predict, detect, and prevent cyber threats before they cause damage.
          </p>
          <div className="stats-row">
            <div className="stat-item">
              <div className="stat-number">99.9%</div>
              <div className="stat-label">Threat Detection Rate</div>
            </div>
            <div className="stat-item">
              <div className="stat-number">50ms</div>
              <div className="stat-label">Average Response Time</div>
            </div>
            <div className="stat-item">
              <div className="stat-number">24/7</div>
              <div className="stat-label">Monitoring & Support</div>
            </div>
          </div>
        </div>
      </div>

      {/* Core Values */}
      <div className="content-card values-section">
        <h2>Our Core Values</h2>
        <div className="values-grid">
          <div className="value-item">
            <div className="value-icon">🛡️</div>
            <h3>Security First</h3>
            <p>Your security is our top priority. We employ state-of-the-art encryption and follow best practices.</p>
          </div>
          <div className="value-item">
            <div className="value-icon">🚀</div>
            <h3>Innovation</h3>
            <p>Constantly evolving our AI models to stay ahead of emerging threats and vulnerabilities.</p>
          </div>
          <div className="value-item">
            <div className="value-icon">🤝</div>
            <h3>Transparency</h3>
            <p>Clear communication about threats, system status, and our security practices.</p>
          </div>
          <div className="value-item">
            <div className="value-icon">⚡</div>
            <h3>Performance</h3>
            <p>Lightweight, efficient solutions that protect without compromising system performance.</p>
          </div>
        </div>
      </div>

      {/* Our Story */}
      <div className="content-card story-section">
        <h2>Our Story</h2>
        <div className="timeline">
          {milestones.map((milestone, index) => (
            <div key={index} className="timeline-item">
              <div className="timeline-marker"></div>
              <div className="timeline-content">
                <div className="timeline-year">{milestone.year}</div>
                <p>{milestone.event}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Team Section */}
      <div className="content-card team-section">
        <h2>Meet Our Team</h2>
        <p className="section-description">
          Our diverse team of experts brings together decades of experience in cybersecurity, AI, and software development.
        </p>
        <div className="team-grid">
          {teamMembers.map((member, index) => (
            <div key={index} className="team-member">
              <a 
                href={member.link} 
                target="_blank" 
                rel="noopener noreferrer" 
                className="member-avatar-link"
                title={`Visit ${member.name}'s profile`}
              >
                <div className="member-avatar">
                  <img src={member.image} alt={member.name} />
                </div>
              </a>
              <h3>{member.name}</h3>
              <div className="member-role">{member.role}</div>
              <p className="member-bio">{member.bio}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Technology Stack */}
      <div className="content-card tech-section">
        <h2>Our Technology</h2>
        <div className="tech-features">
          <div className="tech-item">
            <h3>Advanced Machine Learning</h3>
            <p>Neural networks trained on millions of threat patterns for superior detection accuracy.</p>
          </div>
          <div className="tech-item">
            <h3>Real-time Analysis</h3>
            <p>Continuous monitoring and instant threat response with minimal latency.</p>
          </div>
          <div className="tech-item">
            <h3>Behavioral Analytics</h3>
            <p>AI-driven analysis of network behavior to identify anomalies and potential threats.</p>
          </div>
          <div className="tech-item">
            <h3>Zero-Day Protection</h3>
            <p>Proactive defense against unknown threats using predictive modeling.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AboutUs; 