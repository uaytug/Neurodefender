import React, { useState, useEffect } from 'react';
import { FAQItem, faqApi } from './services/api';
import './styles/FAQ.css';

// Hardcoded FAQ items as fallback
const hardcodedFAQItems: FAQItem[] = [
  {
    id: '1',
    question: "What is NeuroDefender and how does it work?",
    answer: "NeuroDefender is an advanced AI-powered intrusion detection and prevention system. It uses machine learning algorithms to monitor network traffic in real-time, detecting and preventing potential security threats before they can cause damage. The system analyzes patterns, behaviors, and anomalies to identify both known and zero-day threats.",
    category: "General",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '2',
    question: "Is NeuroDefender compatible with my existing security infrastructure?",
    answer: "Yes, NeuroDefender is designed to seamlessly integrate with your existing security infrastructure. It supports major firewall systems, SIEM solutions, and can work alongside your current antivirus and security tools. Our API allows for custom integrations with enterprise systems.",
    category: "Compatibility",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '3',
    question: "How do I install and set up NeuroDefender?",
    answer: "Installation is straightforward: 1) Download the installer from our website, 2) Run the setup wizard which will guide you through the process, 3) Configure your network settings and detection preferences, 4) Start monitoring. The entire process typically takes less than 30 minutes. Detailed documentation and video tutorials are available in our support center.",
    category: "Installation",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '4',
    question: "What types of threats can NeuroDefender detect?",
    answer: "NeuroDefender can detect a wide range of threats including: malware, ransomware, DDoS attacks, SQL injection attempts, cross-site scripting (XSS), port scanning, brute force attacks, zero-day exploits, insider threats, and unusual network behavior patterns. Our AI models are continuously updated to detect emerging threats.",
    category: "Features",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '5',
    question: "How does the real-time monitoring work?",
    answer: "Our real-time monitoring system continuously analyzes network traffic using deep packet inspection and behavioral analysis. It processes data streams in milliseconds, comparing patterns against our threat database and AI models. When suspicious activity is detected, alerts are generated instantly and automatic prevention measures can be triggered based on your configuration.",
    category: "Features",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '6',
    question: "What is the difference between detection sensitivity levels?",
    answer: "NeuroDefender offers three sensitivity levels: Low (fewer false positives, may miss subtle threats), Medium (balanced approach, recommended for most users), and High (maximum protection, may generate more false positives). You can adjust sensitivity in Settings based on your security requirements and risk tolerance.",
    category: "Configuration",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '7',
    question: "How can I reduce false positive alerts?",
    answer: "To reduce false positives: 1) Whitelist trusted applications and IP addresses, 2) Adjust detection sensitivity to match your environment, 3) Use the machine learning feedback feature to train the system, 4) Configure custom rules for your specific use cases. The system also learns from your responses to alerts over time.",
    category: "Troubleshooting",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '8',
    question: "Is my data secure with NeuroDefender?",
    answer: "Absolutely. We use AES-256 encryption for all data storage and transmission. Your network data is processed locally on your system, and only anonymized threat intelligence is shared with our cloud services (if enabled). We are SOC 2 Type II certified and comply with GDPR, HIPAA, and other major data protection regulations.",
    category: "Security",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '9',
    question: "How often are threat definitions updated?",
    answer: "Threat definitions and AI models are updated continuously. Critical updates are pushed in real-time, while regular updates occur every 4-6 hours. You can configure update preferences in Settings. Our threat intelligence team works 24/7 to ensure protection against the latest threats.",
    category: "Updates",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '10',
    question: "What kind of reports can I generate?",
    answer: "NeuroDefender offers comprehensive reporting including: Executive summaries, detailed threat analysis, compliance reports (PCI-DSS, HIPAA, etc.), network traffic analytics, incident response reports, and custom reports. Reports can be generated in PDF, CSV, JSON, or HTML formats and can be scheduled for automatic generation.",
    category: "Reporting",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '11',
    question: "How do I contact support if I need help?",
    answer: "We offer multiple support channels: 24/7 live chat support, email support at support@neurodefender.com, phone support at 1-800-NEURO-DEFEND, and a comprehensive knowledge base. Premium users also have access to dedicated account managers and priority support.",
    category: "Support",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '12',
    question: "What are the system requirements for NeuroDefender?",
    answer: "Minimum requirements: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 18.04+), 4GB RAM (8GB recommended), 2GHz dual-core processor, 500MB available storage, and active internet connection. For enterprise deployments, we recommend dedicated hardware with higher specifications based on network size.",
    category: "Requirements",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '13',
    question: "Can I use NeuroDefender on multiple devices?",
    answer: "Yes, NeuroDefender supports multi-device deployment. Our licensing model allows you to protect multiple devices based on your subscription plan. Enterprise plans include centralized management console for monitoring and configuring multiple installations from a single dashboard.",
    category: "Licensing",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '14',
    question: "How do I interpret the security score?",
    answer: "The security score (0-100) reflects your overall security posture: 90-100 (Excellent - Well protected), 70-89 (Good - Minor improvements recommended), 50-69 (Fair - Several vulnerabilities need attention), Below 50 (Poor - Immediate action required). The score considers factors like active threats, system configuration, update status, and compliance.",
    category: "Features",
    lastUpdated: new Date().toISOString()
  },
  {
    id: '15',
    question: "What happens when a threat is detected?",
    answer: "When a threat is detected: 1) An alert is generated with threat details, 2) Automatic prevention measures are triggered (if enabled), 3) The incident is logged for analysis, 4) Notifications are sent based on your preferences, 5) Recommended actions are provided. You can configure automatic responses in the Settings menu.",
    category: "Features",
    lastUpdated: new Date().toISOString()
  }
];

const FAQ: React.FC = () => {
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [activeCategory, setActiveCategory] = useState<string>('All');
  const [faqItems, setFaqItems] = useState<FAQItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    const fetchFaqItems = async () => {
      try {
        setLoading(true);
        setError(null);
        const items = await faqApi.getFaqItems();
        // If API returns empty or fails, use hardcoded items
        if (items && items.length > 0) {
          setFaqItems(items);
        } else {
          setFaqItems(hardcodedFAQItems);
        }
        setLoading(false);
      } catch (err) {
        console.error('Failed to fetch FAQ items:', err);
        // Use hardcoded items as fallback
        setFaqItems(hardcodedFAQItems);
        setError(null); // Don't show error since we have fallback data
        setLoading(false);
      }
    };
    fetchFaqItems();
  }, []);
  
  const categories = ['All', ...new Set(faqItems.map(item => item.category))];
  
  const toggleAccordion = (index: number) => {
    setActiveIndex(activeIndex === index ? null : index);
  };
  
  const filteredFAQs = faqItems.filter(item => {
    const matchesSearch = item.question.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         item.answer.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = activeCategory === 'All' || item.category === activeCategory;
    
    return matchesSearch && matchesCategory;
  });
  
  const handleCopyAnswer = (answer: string) => {
    navigator.clipboard.writeText(answer).then(() => {
      // You could show a toast notification here
      console.log('Answer copied to clipboard');
    }).catch(err => {
      console.error('Failed to copy text: ', err);
    });
  };
  
  return (
    <div className="faq-container">
      <div className="app-header">
        <div className="app-header-content">
          <h1>Frequently Asked Questions</h1>
          <p className="header-description">Find answers to common questions about NeuroDefender</p>
        </div>
      </div>
      
      <div className="content-card faq-search-section">
        <div className="search-container">
          <div className="search-input-wrapper">
            <svg xmlns="http://www.w3.org/2000/svg" className="search-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input
              type="text"
              className="search-input"
              placeholder="Search for questions..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            {searchTerm && (
              <button 
                className="clear-search-button"
                onClick={() => setSearchTerm('')}
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            )}
          </div>
        </div>
        
        <div className="category-filter">
          {categories.map((category, index) => (
            <button
              key={index}
              className={`category-button ${activeCategory === category ? 'active' : ''}`}
              onClick={() => setActiveCategory(category)}
            >
              {category}
            </button>
          ))}
        </div>
      </div>
      
      <div className="content-card faq-content">
        {loading ? (
          <div className="loading-spinner">Loading FAQs...</div>
        ) : error ? (
          <div className="error-message">{error}</div>
        ) : filteredFAQs.length > 0 ? (
          <div className="faq-list">
            {filteredFAQs.map((item, index) => (
              <div 
                key={item.id || index}
                className={`faq-item ${activeIndex === index ? 'active' : ''}`}
              >
                <div 
                  className="faq-question"
                  onClick={() => toggleAccordion(index)}
                >
                  <span className="question-text">{item.question}</span>
                  <div className="category-tag">{item.category}</div>
                  <span className="toggle-icon">
                    {activeIndex === index ? (
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                      </svg>
                    ) : (
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                      </svg>
                    )}
                  </span>
                </div>
                <div className={`faq-answer ${activeIndex === index ? 'visible' : ''}`}>
                  <p>{item.answer}</p>
                  <div className="answer-actions">
                    <button className="text-button helpful-button">
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3zM7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"></path>
                      </svg>
                      Helpful
                    </button>
                    <button className="text-button copy-button" onClick={() => handleCopyAnswer(item.answer)}>
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                      Copy
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="no-results">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <h3>No matching questions found</h3>
            <p>Try adjusting your search terms or browse all categories</p>
            <button 
              className="primary-button reset-button"
              onClick={() => {
                setSearchTerm('');
                setActiveCategory('All');
              }}
            >
              Reset Filters
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default FAQ;
