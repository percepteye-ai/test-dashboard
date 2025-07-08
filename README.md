# SOC Dashboard (Mock)

A comprehensive Security Operations Center (SOC) dashboard featuring real-time monitoring of security alerts, logs, and cases. This dashboard provides cybersecurity professionals with an intuitive interface to track and respond to security incidents.

## Features

### 📊 Overview Dashboard
- **Real-time metrics** displaying critical alerts, active incidents, open cases, and resolved cases
- **Interactive charts** showing alert trends over the last 7 days and threat category distributions
- **Recent activity feed** with real-time updates on security events

### 🚨 Security Alerts
- **Priority-based alerts** (Critical, High, Medium, Low) with color-coded severity levels
- **Advanced alert management** with resolve, snooze, and false positive actions
- **Related data integration** connecting alerts to logs and cases
- **Detailed information** including source, timestamp, IP addresses, user data, and descriptions
- **Filtering and search** capabilities for efficient alert management
- **Real-time updates** with new alerts appearing automatically
- **Automatic snooze expiration** with notifications when alerts become active again

### 📋 Security Logs
- **Comprehensive log viewer** with support for multiple log types (authentication, network, malware, system)
- **Enhanced metadata** including user agents, geolocation, session IDs, and request IDs
- **Related data connections** linking logs to alerts and cases
- **Log level filtering** (Error, Warning, Info, Debug) with appropriate color coding
- **Search functionality** across log messages and sources
- **Timestamp-based sorting** with newest logs displayed first

### 📁 Security Cases
- **Comprehensive case management** with status tracking (Open, Investigating, Resolved, Closed)
- **Evidence tracking** with chain of custody, file hashes, and collection details
- **Timeline management** with detailed event tracking and user actions
- **Stakeholder management** with role assignments and notification tracking
- **SLA and cost tracking** based on priority and status
- **Related data connections** linking cases to alerts and logs
- **Assignment tracking** showing case ownership and responsibilities
- **Priority levels** and detailed case descriptions
- **Status-based filtering** and search capabilities
- **Interactive case actions** including status updates, assignment changes, evidence addition, and case closure

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Styling**: Custom CSS with modern design principles
- **Charts**: Chart.js for interactive data visualization
- **Icons**: Font Awesome for consistent iconography
- **Fonts**: Inter font family for modern typography

## Getting Started

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Internet connection (for CDN resources)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/soc-dashboard.git
   cd soc-dashboard
   ```

2. **Open the dashboard**
   Simply open `index.html` in your web browser or use a local web server:
   ```bash
   # Using Python 3
   python -m http.server 8000
   
   # Using Node.js (if you have live-server installed)
   npx live-server
   ```

3. **Access the dashboard**
   Navigate to `http://localhost:8000` in your browser

## GitHub Pages Deployment

This dashboard is designed to work seamlessly with GitHub Pages:

1. **Enable GitHub Pages**
   - Go to your repository settings
   - Scroll down to "Pages" section
   - Select "Deploy from a branch"
   - Choose "main" branch and "/ (root)" folder
   - Save the settings

2. **Access your live dashboard**
   Your dashboard will be available at: `https://yourusername.github.io/repository-name`

## Data

The dashboard uses **realistic synthetic data** including:

- **25 security alerts** with various threat types and severity levels
- **150 security logs** from different sources and systems
- **35 security cases** with different statuses and assignments
- **Real-time data simulation** with periodic updates

### Sample Data Types

**Alerts:**
- Malware Detection
- Suspicious Login Activity
- DDoS Attacks
- Data Exfiltration
- Privilege Escalation
- Phishing Attempts
- Network Intrusions
- And more...

**Log Sources:**
- Authentication servers
- Firewalls
- Web servers
- Databases
- Mail servers
- DNS servers
- Proxy servers
- VPN gateways

**Case Types:**
- Security Incident Response
- Malware Investigation
- Data Breach Investigation
- Insider Threat Investigation
- Phishing Campaign Analysis
- Network Intrusion Investigation
- Forensic Analysis
- And more...

## Features in Detail

### Navigation
- **Responsive sidebar** with intuitive navigation
- **Active section highlighting** for clear orientation
- **Mobile-friendly design** with collapsible navigation

### Filtering & Search
- **Real-time filtering** by severity, type, and status
- **Search functionality** across all data fields
- **Combined filters** for precise data selection

### Real-time Updates
- **Automatic data refresh** every 30 seconds
- **New alert generation** simulating real security events
- **Live metrics updates** reflecting current security posture
- **Automatic snooze management** with expiration checks and notifications

### Alert Management Features
- **Resolve Alerts**: Mark alerts as resolved with resolution notes and timestamps
- **Snooze Alerts**: Temporarily snooze alerts for 24 hours with reason tracking
- **False Positive Marking**: Mark alerts as false positives with detailed reasoning
- **Related Data Viewing**: See connected logs and cases for comprehensive investigation
- **Action History**: Track all actions taken on alerts with timestamps and user information

### Visual Design
- **Dark theme** optimized for SOC environments
- **Color-coded severity levels** for quick threat assessment
- **Modern UI components** with smooth animations
- **Responsive grid layouts** adapting to different screen sizes

## Customization

### Adding New Alert Types
Edit the `alertTypes` array in `script.js`:
```javascript
const alertTypes = [
    'Your Custom Alert Type',
    // ... existing types
];
```

### Modifying Color Schemes
Update the CSS variables in `styles.css`:
```css
:root {
    --primary-color: #4fc3f7;
    --critical-color: #f44336;
    --warning-color: #ff9800;
    /* ... other colors */
}
```

### Adjusting Update Intervals
Change the refresh interval in `script.js`:
```javascript
// Update every 30 seconds (30000 ms)
setInterval(() => {
    updateData();
    updateMetrics();
    updateLastUpdatedTime();
}, 30000); // Change this value
```

## Browser Support

- ✅ Chrome 60+
- ✅ Firefox 55+
- ✅ Safari 12+
- ✅ Edge 79+

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Note

This dashboard uses **synthetic data only** and is designed for demonstration purposes. Do not use this dashboard with real security data without proper security measures and compliance considerations.

## Support

For support, please open an issue in the GitHub repository or contact the development team.

---

**Built with ❤️ for cybersecurity professionals** 