import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import './styles/Navbar.css';
import { alertsApi } from './services/api'; // Import alertsApi

const Navbar: React.FC = () => {
  const [currentTime, setCurrentTime] = useState<string>("");
  const [isMenuOpen, setIsMenuOpen] = useState<boolean>(false);
  const [unreadAlertsCount, setUnreadAlertsCount] = useState<number | null>(null); // State for unread alerts count
  const location = useLocation();
  
  // Handle menu toggle
  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen);
    // Prevent body scroll when menu is open
    document.body.style.overflow = !isMenuOpen ? 'hidden' : 'auto';
  };
  
  // Close menu when clicking outside
  const closeMenu = (e: MouseEvent) => {
    const target = e.target as HTMLElement;
    if (isMenuOpen && !target.closest('.mobile-menu') && !target.closest('.menu-toggle')) {
      setIsMenuOpen(false);
      document.body.style.overflow = 'auto';
    }
  };

  const updateTime = () => {
    const now = new Date();
    const options: Intl.DateTimeFormatOptions = { 
      hour: '2-digit', 
      minute: '2-digit',
      hour12: false
    };
    setCurrentTime(now.toLocaleTimeString('tr-TR', options));
  };

  useEffect(() => {
    updateTime();
    const interval = setInterval(updateTime, 60000); // Update time every minute

    const fetchUnreadAlerts = async () => {
      try {
        const stats = await alertsApi.getAlertStats();
        setUnreadAlertsCount(stats.unreadCount);
      } catch (error) {
        console.error("Failed to fetch unread alerts count:", error);
        setUnreadAlertsCount(null); // Set to null or 0 on error, or handle appropriately
      }
    };

    fetchUnreadAlerts();
    const alertsInterval = setInterval(fetchUnreadAlerts, 60000 * 5); // Refresh every 5 minutes
    
    // Add event listener for closing menu when clicking outside
    document.addEventListener('mousedown', closeMenu);
    
    // Close menu when route changes
    setIsMenuOpen(false);
    document.body.style.overflow = 'auto';
    
    return () => {
      clearInterval(interval);
      clearInterval(alertsInterval); // Clear alerts interval
      document.removeEventListener('mousedown', closeMenu);
    };
  }, [location.pathname]);

  const isActive = (path: string) => {
    return location.pathname === path ? 'active' : '';
  };

  // Navigation links - extracted to reuse in both desktop and mobile menus
  const navLinks = (
    <>
      <Link to="/dashboard" className={`nav-link ${isActive('/dashboard')}`} onClick={() => setIsMenuOpen(false)}>
        <span className="nav-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="3" width="7" height="9"></rect>
            <rect x="14" y="3" width="7" height="5"></rect>
            <rect x="14" y="12" width="7" height="9"></rect>
            <rect x="3" y="16" width="7" height="5"></rect>
          </svg>
        </span>
        Dashboard
      </Link>
      <Link to="/alerts" className={`nav-link ${isActive('/alerts')}`} onClick={() => setIsMenuOpen(false)}>
        <span className="nav-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
          </svg>
        </span>
        Alerts
        {unreadAlertsCount !== null && unreadAlertsCount > 0 && (
          <span className="alert-badge">{unreadAlertsCount > 99 ? '99+' : unreadAlertsCount}</span>
        )}
      </Link>
      <Link to="/reports" className={`nav-link ${isActive('/reports')}`} onClick={() => setIsMenuOpen(false)}>
        <span className="nav-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10 9 9 9 8 9"></polyline>
          </svg>
        </span>
        Reports
      </Link>
      <Link to="/settings" className={`nav-link ${isActive('/settings')}`} onClick={() => setIsMenuOpen(false)}>
        <span className="nav-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </span>
        Settings
      </Link>
      <Link to="/faq" className={`nav-link ${isActive('/faq')}`} onClick={() => setIsMenuOpen(false)}>
        <span className="nav-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </span>
        FAQ
      </Link>
      <Link to="/about" className={`nav-link ${isActive('/about')}`} onClick={() => setIsMenuOpen(false)}>
        <span className="nav-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path>
            <path d="M18 8h-5"></path>
            <path d="M18 12h-5"></path>
          </svg>
        </span>
        About Us
      </Link>
    </>
  );

  // Time display component - reused in both desktop and mobile
  const timeDisplay = (
    <div className="time-display">
      <span className="time-icon">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <polyline points="12 6 12 12 16 14"></polyline>
        </svg>
      </span>
      {currentTime}
    </div>
  );

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <div className="navbar-logo">
          <Link to="/">
            <img src="/neurodefender_logo.png" alt="NeuroDefender Logo" className="logo-img" />
          </Link>
        </div>
        
        {/* Desktop Navigation Links */}
        <div className="navbar-links">
          {navLinks}
        </div>
        
        {/* Desktop Actions */}
        <div className="navbar-actions">
          {timeDisplay}
        </div>
        
        {/* Hamburger Menu Toggle */}
        <div 
          className={`menu-toggle ${isMenuOpen ? 'active' : ''}`}
          onClick={toggleMenu}
        >
          <span></span>
          <span></span>
          <span></span>
        </div>
      </div>
      
      {/* Mobile Menu Overlay */}
      <div className={`mobile-menu-overlay ${isMenuOpen ? 'active' : ''}`}></div>
      
      {/* Mobile Menu */}
      <div className={`mobile-menu ${isMenuOpen ? 'active' : ''}`}>
        <div className="navbar-links">
          {navLinks}
        </div>
        <div className="navbar-actions">
          {timeDisplay}
        </div>
      </div>
    </nav>
  );
};

window.addEventListener('resize', () => {
  if (window.innerWidth > 992) {
    document.querySelector('.menu-toggle')?.classList.remove('active');
    document.querySelector('.mobile-menu')?.classList.remove('active');
    document.querySelector('.mobile-menu-overlay')?.classList.remove('active');
  }
});


export default Navbar;