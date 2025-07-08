// SOC Dashboard JavaScript

// Global Variables
let alerts = [];
let logs = [];
let cases = [];
let threatIntelligence = [];
let assets = [];
let vulnerabilities = [];
let userActivities = [];
let eventTimeline = [];
let networkTraffic = [];
let alertTrendsChart;
let threatCategoriesChart;

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeData();
    initializeNavigation();
    initializeFilters();
    initializeCharts();
    updateMetrics();
    renderOverviewData();
    updateLastUpdatedTime();
    
    // Update data every 30 seconds
    setInterval(() => {
        updateData();
        updateMetrics();
        updateLastUpdatedTime();
    }, 30000);
});

// Generate Synthetic Data
function initializeData() {
    generateAlerts();
    generateLogs();
    generateCases();
    generateThreatIntelligence();
    generateAssets();
    generateVulnerabilities();
    generateUserActivities();
    generateEventTimeline();
    generateNetworkTraffic();
}

function generateAlerts() {
    const alertTypes = [
        'Malware Detection',
        'Suspicious Login Activity',
        'DDoS Attack',
        'Data Exfiltration',
        'Privilege Escalation',
        'Phishing Attempt',
        'Unauthorized Access',
        'Brute Force Attack',
        'SQL Injection',
        'Cross-Site Scripting',
        'Network Intrusion',
        'File Integrity Violation',
        'Anomalous Network Traffic',
        'Insider Threat',
        'Ransomware Activity'
    ];

    const severities = ['critical', 'high', 'medium', 'low'];
    const sources = ['Firewall', 'IDS/IPS', 'Antivirus', 'SIEM', 'Endpoint Security', 'Web Application Firewall', 'Network Monitor', 'Email Security'];
    const ips = ['192.168.1.101', '10.0.0.45', '172.16.0.32', '192.168.2.55', '10.1.1.78', '172.20.0.15', '192.168.3.99', '10.2.2.33'];

    alerts = [];
    for (let i = 0; i < 25; i++) {
        const alertType = alertTypes[Math.floor(Math.random() * alertTypes.length)];
        const severity = severities[Math.floor(Math.random() * severities.length)];
        const source = sources[Math.floor(Math.random() * sources.length)];
        const ip = ips[Math.floor(Math.random() * ips.length)];
        
        alerts.push({
            id: `ALT-${String(i + 1).padStart(4, '0')}`,
            title: alertType,
            severity: severity,
            description: generateAlertDescription(alertType, ip),
            source: source,
            timestamp: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
            ip: ip,
            status: Math.random() > 0.3 ? 'active' : 'resolved'
        });
    }
}

function generateAlertDescription(type, ip) {
    const descriptions = {
        'Malware Detection': `Malicious file detected on endpoint ${ip}. Hash: d41d8cd98f00b204e9800998ecf8427e`,
        'Suspicious Login Activity': `Multiple failed login attempts from ${ip}. Possible credential stuffing attack.`,
        'DDoS Attack': `High volume of requests detected from ${ip}. Rate: 10,000 requests/minute.`,
        'Data Exfiltration': `Unusual data transfer patterns detected from ${ip}. Volume: 2.3GB transferred.`,
        'Privilege Escalation': `Unauthorized privilege elevation detected on ${ip}. User: service_account`,
        'Phishing Attempt': `Suspicious email activity from ${ip}. Potential phishing campaign detected.`,
        'Unauthorized Access': `Access attempt to restricted resource from ${ip}. Resource: /admin/config`,
        'Brute Force Attack': `Repeated authentication failures from ${ip}. Target: SSH service`,
        'SQL Injection': `SQL injection attempt detected from ${ip}. Target: /api/users`,
        'Cross-Site Scripting': `XSS payload detected from ${ip}. Payload: <script>alert('xss')</script>`,
        'Network Intrusion': `Unauthorized network access detected from ${ip}. Port scanning activity.`,
        'File Integrity Violation': `System file modification detected on ${ip}. File: /etc/passwd`,
        'Anomalous Network Traffic': `Unusual network patterns from ${ip}. Protocol: TCP, Port: 4444`,
        'Insider Threat': `Suspicious user activity detected from ${ip}. Off-hours access to sensitive data.`,
        'Ransomware Activity': `Potential ransomware behavior detected on ${ip}. File encryption patterns observed.`
    };
    
    return descriptions[type] || `Security event detected from ${ip}. Requires immediate investigation.`;
}

function generateLogs() {
    const logTypes = ['authentication', 'network', 'malware', 'system'];
    const logLevels = ['error', 'warning', 'info', 'debug'];
    const sources = ['auth-server', 'firewall', 'web-server', 'database', 'mail-server', 'dns-server', 'proxy', 'vpn-gateway'];
    
    logs = [];
    for (let i = 0; i < 150; i++) {
        const logType = logTypes[Math.floor(Math.random() * logTypes.length)];
        const level = logLevels[Math.floor(Math.random() * logLevels.length)];
        const source = sources[Math.floor(Math.random() * sources.length)];
        
        logs.push({
            id: `LOG-${String(i + 1).padStart(6, '0')}`,
            timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
            level: level,
            source: source,
            type: logType,
            message: generateLogMessage(logType, level, source),
            ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
        });
    }
    
    // Sort logs by timestamp (newest first)
    logs.sort((a, b) => b.timestamp - a.timestamp);
}

function generateLogMessage(type, level, source) {
    const messages = {
        authentication: {
            error: `Authentication failed for user admin from ${source}`,
            warning: `Multiple login attempts detected from ${source}`,
            info: `User successfully authenticated from ${source}`,
            debug: `Authentication token validated for ${source}`
        },
        network: {
            error: `Network connection failed to ${source}`,
            warning: `High network latency detected on ${source}`,
            info: `Network connection established to ${source}`,
            debug: `Network packet processed by ${source}`
        },
        malware: {
            error: `Malware signature detected by ${source}`,
            warning: `Suspicious file quarantined by ${source}`,
            info: `Malware database updated on ${source}`,
            debug: `File scan completed by ${source}`
        },
        system: {
            error: `System service failed on ${source}`,
            warning: `High CPU usage detected on ${source}`,
            info: `System backup completed on ${source}`,
            debug: `System health check passed on ${source}`
        }
    };
    
    return messages[type][level] || `${level.toUpperCase()}: Event logged by ${source}`;
}

function generateCases() {
    const caseTypes = [
        'Security Incident Response',
        'Malware Investigation',
        'Data Breach Investigation',
        'Insider Threat Investigation',
        'Phishing Campaign Analysis',
        'Network Intrusion Investigation',
        'Fraud Investigation',
        'Compliance Violation',
        'Vulnerability Assessment',
        'Threat Hunting',
        'Forensic Analysis',
        'Risk Assessment',
        'Security Audit',
        'Incident Containment',
        'Recovery Operations'
    ];
    
    const statuses = ['open', 'investigating', 'resolved', 'closed'];
    const priorities = ['critical', 'high', 'medium', 'low'];
    const assignees = ['John Smith', 'Sarah Johnson', 'Mike Davis', 'Emily Chen', 'David Wilson', 'Lisa Brown', 'Alex Kim', 'Jessica Martinez'];
    
    cases = [];
    for (let i = 0; i < 35; i++) {
        const caseType = caseTypes[Math.floor(Math.random() * caseTypes.length)];
        const status = statuses[Math.floor(Math.random() * statuses.length)];
        const priority = priorities[Math.floor(Math.random() * priorities.length)];
        const assignee = assignees[Math.floor(Math.random() * assignees.length)];
        
        cases.push({
            id: `CASE-${String(i + 1).padStart(4, '0')}`,
            title: caseType,
            description: generateCaseDescription(caseType),
            status: status,
            priority: priority,
            assignee: assignee,
            created: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
            updated: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000)
        });
    }
}

function generateCaseDescription(type) {
    const descriptions = {
        'Security Incident Response': 'Coordinating response to security breach. Multiple systems affected.',
        'Malware Investigation': 'Analyzing malicious software behavior and impact on network infrastructure.',
        'Data Breach Investigation': 'Investigating unauthorized access to customer database containing PII.',
        'Insider Threat Investigation': 'Reviewing suspicious employee activity and data access patterns.',
        'Phishing Campaign Analysis': 'Tracking and analyzing ongoing phishing campaign targeting employees.',
        'Network Intrusion Investigation': 'Investigating unauthorized network access and lateral movement.',
        'Fraud Investigation': 'Investigating suspicious financial transactions and account activities.',
        'Compliance Violation': 'Reviewing potential violation of industry regulations and standards.',
        'Vulnerability Assessment': 'Comprehensive security assessment of critical infrastructure.',
        'Threat Hunting': 'Proactive search for advanced persistent threats in the network.',
        'Forensic Analysis': 'Digital forensic examination of compromised systems and evidence.',
        'Risk Assessment': 'Evaluating security risks and potential impact on business operations.',
        'Security Audit': 'Comprehensive review of security controls and procedures.',
        'Incident Containment': 'Containing and isolating security incident to prevent spread.',
        'Recovery Operations': 'Coordinating system recovery and restoration after security incident.'
    };
    
    return descriptions[type] || 'Security case requiring investigation and resolution.';
}

function generateThreatIntelligence() {
    const threatTypes = ['malware', 'phishing', 'ransomware', 'botnet'];
    const threatNames = [
        'Emotet Botnet Campaign',
        'Ryuk Ransomware Detection',
        'APT29 Cozy Bear Activity',
        'Phishing Campaign - Office 365',
        'Trickbot Banking Trojan',
        'Cobalt Strike Beacons',
        'SolarWinds Supply Chain Attack',
        'DarkHalo APT Group',
        'Maze Ransomware Group',
        'FIN7 Carbanak Activity',
        'Lazarus Group Campaign',
        'BlackCat Ransomware',
        'Conti Ransomware Gang',
        'LockBit Ransomware Family',
        'Qakbot Banking Malware'
    ];
    
    threatIntelligence = [];
    for (let i = 0; i < 20; i++) {
        const threatType = threatTypes[Math.floor(Math.random() * threatTypes.length)];
        const threatName = threatNames[Math.floor(Math.random() * threatNames.length)];
        const severity = ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)];
        
        threatIntelligence.push({
            id: `TI-${String(i + 1).padStart(3, '0')}`,
            name: threatName,
            type: threatType,
            severity: severity,
            description: generateThreatDescription(threatName),
            indicators: Math.floor(Math.random() * 50) + 1,
            firstSeen: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
            lastSeen: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
            confidence: Math.floor(Math.random() * 40) + 60
        });
    }
    
    threatIntelligence.sort((a, b) => b.lastSeen - a.lastSeen);
}

function generateThreatDescription(name) {
    const descriptions = {
        'Emotet Botnet Campaign': 'Widespread email-based malware campaign targeting corporate networks',
        'Ryuk Ransomware Detection': 'Advanced ransomware targeting healthcare and government sectors',
        'APT29 Cozy Bear Activity': 'Nation-state actor conducting espionage operations',
        'Phishing Campaign - Office 365': 'Credential harvesting campaign targeting Office 365 users',
        'Trickbot Banking Trojan': 'Banking malware with credential theft capabilities',
        'Cobalt Strike Beacons': 'Post-exploitation framework used by threat actors',
        'SolarWinds Supply Chain Attack': 'Supply chain compromise affecting multiple organizations',
        'DarkHalo APT Group': 'Advanced persistent threat group targeting critical infrastructure',
        'Maze Ransomware Group': 'Ransomware group known for data exfiltration tactics',
        'FIN7 Carbanak Activity': 'Financially motivated threat group targeting payment systems'
    };
    
    return descriptions[name] || 'Threat intelligence indicator requiring analysis and response.';
}

function generateAssets() {
    const assetTypes = ['Server', 'Workstation', 'Network Device', 'Database', 'Application', 'IoT Device'];
    const assetNames = [
        'DC-SERVER-01', 'WEB-SERVER-02', 'DB-PROD-01', 'MAIL-SERVER-01',
        'WORKSTATION-105', 'WORKSTATION-203', 'WORKSTATION-078', 'WORKSTATION-156',
        'SWITCH-CORE-01', 'ROUTER-EDGE-01', 'FIREWALL-01', 'LOAD-BALANCER-01',
        'CRM-DATABASE', 'ERP-SYSTEM', 'BACKUP-SERVER', 'MONITORING-SERVER',
        'CAMERA-LOBBY-01', 'PRINTER-OFFICE-02', 'HVAC-CONTROLLER', 'DOOR-SYSTEM-01'
    ];
    
    const locations = ['Data Center', 'Office Floor 1', 'Office Floor 2', 'Remote Office', 'Cloud AWS', 'Cloud Azure'];
    const statuses = ['online', 'offline', 'warning'];
    const statusWeights = [0.8, 0.1, 0.1]; // 80% online, 10% offline, 10% warning
    
    assets = [];
    for (let i = 0; i < 25; i++) {
        const assetType = assetTypes[Math.floor(Math.random() * assetTypes.length)];
        const assetName = assetNames[Math.floor(Math.random() * assetNames.length)];
        const location = locations[Math.floor(Math.random() * locations.length)];
        
        // Weighted random status selection
        const rand = Math.random();
        let status = 'online';
        if (rand < statusWeights[1]) status = 'offline';
        else if (rand < statusWeights[1] + statusWeights[2]) status = 'warning';
        
        assets.push({
            id: `AST-${String(i + 1).padStart(3, '0')}`,
            name: assetName,
            type: assetType,
            location: location,
            status: status,
            ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            lastSeen: new Date(Date.now() - Math.random() * 60 * 60 * 1000),
            uptime: Math.floor(Math.random() * 365) + 1,
            riskScore: Math.floor(Math.random() * 100)
        });
    }
}

function generateVulnerabilities() {
    const vulnTypes = [
        'CVE-2023-4911', 'CVE-2023-38831', 'CVE-2023-36884', 'CVE-2023-29336',
        'CVE-2023-24932', 'CVE-2023-23397', 'CVE-2023-21554', 'CVE-2023-20887',
        'CVE-2022-47966', 'CVE-2022-41040', 'CVE-2022-30190', 'CVE-2022-26937',
        'CVE-2022-22947', 'CVE-2021-44228', 'CVE-2021-34527', 'CVE-2021-26855'
    ];
    
    const vulnNames = [
        'Buffer Overflow in GNU C Library',
        'Remote Code Execution in WinRAR',
        'Office and Windows HTML RCE',
        'Win32k Elevation of Privilege',
        'Secure Boot Security Bypass',
        'Outlook Privilege Escalation',
        'Windows CryptoAPI Spoofing',
        'VMware vCenter Server RCE',
        'Zoho ManageEngine RCE',
        'Exchange Server RCE',
        'Microsoft Office RCE',
        'Windows Print Spooler RCE',
        'Spring Cloud Gateway RCE',
        'Apache Log4j RCE',
        'Windows Print Spooler RCE',
        'Exchange Server RCE'
    ];
    
    const severities = ['critical', 'high', 'medium', 'low'];
    const severityWeights = [0.2, 0.3, 0.4, 0.1]; // 20% critical, 30% high, 40% medium, 10% low
    
    vulnerabilities = [];
    for (let i = 0; i < 30; i++) {
        const cve = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
        const vulnName = vulnNames[Math.floor(Math.random() * vulnNames.length)];
        
        // Weighted random severity selection
        const rand = Math.random();
        let severity = 'medium';
        if (rand < severityWeights[0]) severity = 'critical';
        else if (rand < severityWeights[0] + severityWeights[1]) severity = 'high';
        else if (rand < severityWeights[0] + severityWeights[1] + severityWeights[2]) severity = 'medium';
        else severity = 'low';
        
        const cvssScore = severity === 'critical' ? (9.0 + Math.random()).toFixed(1) :
                         severity === 'high' ? (7.0 + Math.random() * 2).toFixed(1) :
                         severity === 'medium' ? (4.0 + Math.random() * 3).toFixed(1) :
                         (0.1 + Math.random() * 3.9).toFixed(1);
        
        vulnerabilities.push({
            id: `VUL-${String(i + 1).padStart(3, '0')}`,
            cve: cve,
            name: vulnName,
            severity: severity,
            cvssScore: parseFloat(cvssScore),
            description: generateVulnDescription(vulnName),
            affectedAssets: Math.floor(Math.random() * 10) + 1,
            discovered: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
            status: Math.random() > 0.3 ? 'open' : 'patched'
        });
    }
    
    vulnerabilities.sort((a, b) => b.cvssScore - a.cvssScore);
}

function generateVulnDescription(name) {
    const descriptions = {
        'Buffer Overflow in GNU C Library': 'Memory corruption vulnerability allowing arbitrary code execution',
        'Remote Code Execution in WinRAR': 'Archive extraction vulnerability enabling remote code execution',
        'Office and Windows HTML RCE': 'HTML processing vulnerability in Microsoft Office applications',
        'Win32k Elevation of Privilege': 'Kernel vulnerability allowing privilege escalation',
        'Secure Boot Security Bypass': 'Boot security mechanism bypass vulnerability',
        'Outlook Privilege Escalation': 'Email client vulnerability enabling privilege escalation',
        'Windows CryptoAPI Spoofing': 'Cryptographic validation bypass vulnerability',
        'VMware vCenter Server RCE': 'Virtualization platform remote code execution vulnerability'
    };
    
    return descriptions[name] || 'Security vulnerability requiring immediate attention and patching.';
}

function generateUserActivities() {
    const users = ['john.smith', 'sarah.johnson', 'mike.davis', 'emily.chen', 'david.wilson', 'lisa.brown', 'alex.kim', 'jessica.martinez'];
    const actions = [
        'Logged in from new location',
        'Failed login attempts detected',
        'Accessed sensitive documents',
        'Changed password',
        'Downloaded large file',
        'Shared file externally',
        'Elevated privileges used',
        'VPN connection established',
        'Database query executed',
        'System configuration changed',
        'Email sent to external domain',
        'File uploaded to cloud storage',
        'Remote desktop session started',
        'Security policy violation',
        'Unusual working hours activity'
    ];
    
    const riskLevels = ['low', 'medium', 'high'];
    const riskWeights = [0.6, 0.3, 0.1]; // 60% low, 30% medium, 10% high
    
    userActivities = [];
    for (let i = 0; i < 40; i++) {
        const user = users[Math.floor(Math.random() * users.length)];
        const action = actions[Math.floor(Math.random() * actions.length)];
        
        // Weighted random risk level selection
        const rand = Math.random();
        let riskLevel = 'low';
        if (rand < riskWeights[2]) riskLevel = 'high';
        else if (rand < riskWeights[2] + riskWeights[1]) riskLevel = 'medium';
        
        userActivities.push({
            id: `UA-${String(i + 1).padStart(3, '0')}`,
            user: user,
            action: action,
            riskLevel: riskLevel,
            location: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
            details: generateUserActivityDetails(action, user)
        });
    }
    
    userActivities.sort((a, b) => b.timestamp - a.timestamp);
}

function generateUserActivityDetails(action, user) {
    const details = {
        'Logged in from new location': `User ${user} logged in from unrecognized IP address`,
        'Failed login attempts detected': `Multiple failed login attempts for user ${user}`,
        'Accessed sensitive documents': `User ${user} accessed classified documents outside normal hours`,
        'Changed password': `User ${user} changed password using self-service portal`,
        'Downloaded large file': `User ${user} downloaded 2.3GB file from file server`,
        'Shared file externally': `User ${user} shared internal document with external email`,
        'Elevated privileges used': `User ${user} used administrative privileges for system access`,
        'VPN connection established': `User ${user} connected via VPN from remote location`
    };
    
    return details[action] || `User ${user} performed ${action.toLowerCase()}`;
}

function generateEventTimeline() {
    const eventTypes = [
        'Security alert triggered',
        'User account locked',
        'System backup completed',
        'Vulnerability scan finished',
        'Firewall rule updated',
        'Certificate expired',
        'Service restart required',
        'Security patch applied',
        'Access denied event',
        'Data backup failed',
        'Network intrusion detected',
        'Malware quarantined',
        'User account created',
        'System maintenance started',
        'Security policy updated'
    ];
    
    const severities = ['critical', 'warning', 'info', 'success'];
    const severityWeights = [0.15, 0.25, 0.45, 0.15]; // 15% critical, 25% warning, 45% info, 15% success
    
    eventTimeline = [];
    for (let i = 0; i < 50; i++) {
        const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
        
        // Weighted random severity selection
        const rand = Math.random();
        let severity = 'info';
        if (rand < severityWeights[0]) severity = 'critical';
        else if (rand < severityWeights[0] + severityWeights[1]) severity = 'warning';
        else if (rand < severityWeights[0] + severityWeights[1] + severityWeights[2]) severity = 'info';
        else severity = 'success';
        
        eventTimeline.push({
            id: `EVT-${String(i + 1).padStart(3, '0')}`,
            event: eventType,
            severity: severity,
            timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
            details: generateEventDetails(eventType),
            source: ['System', 'Security Tool', 'User Action', 'Automated Process'][Math.floor(Math.random() * 4)]
        });
    }
    
    eventTimeline.sort((a, b) => b.timestamp - a.timestamp);
}

function generateEventDetails(eventType) {
    const details = {
        'Security alert triggered': 'High-severity security event detected requiring immediate attention',
        'User account locked': 'Account locked due to multiple failed login attempts',
        'System backup completed': 'Scheduled backup completed successfully with no errors',
        'Vulnerability scan finished': 'Automated vulnerability scan completed, report available',
        'Firewall rule updated': 'Security team updated firewall rules for enhanced protection',
        'Certificate expired': 'SSL certificate expired, renewal required immediately',
        'Service restart required': 'Critical service requires restart for security updates',
        'Security patch applied': 'Security patch successfully applied to production systems',
        'Access denied event': 'Unauthorized access attempt blocked by security controls',
        'Data backup failed': 'Scheduled backup failed, investigation required',
        'Network intrusion detected': 'Suspicious network activity detected and contained',
        'Malware quarantined': 'Malicious software detected and quarantined successfully'
    };
    
    return details[eventType] || `${eventType} occurred in the system`;
}

function generateNetworkTraffic() {
    const sources = [
        '192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103',
        '10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13',
        '172.16.0.20', '172.16.0.21', '172.16.0.22', '172.16.0.23'
    ];
    
    const destinations = [
        '8.8.8.8', '1.1.1.1', '208.67.222.222', '185.228.168.9',
        '157.240.12.35', '52.84.124.75', '104.16.249.249', '151.101.193.140'
    ];
    
    const protocols = ['HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS', 'SMTP', 'POP3', 'IMAP'];
    const volumeLevels = ['normal', 'high', 'critical'];
    const volumeWeights = [0.7, 0.25, 0.05]; // 70% normal, 25% high, 5% critical
    
    networkTraffic = [];
    for (let i = 0; i < 35; i++) {
        const source = sources[Math.floor(Math.random() * sources.length)];
        const destination = destinations[Math.floor(Math.random() * destinations.length)];
        const protocol = protocols[Math.floor(Math.random() * protocols.length)];
        
        // Weighted random volume level selection
        const rand = Math.random();
        let volumeLevel = 'normal';
        if (rand < volumeWeights[2]) volumeLevel = 'critical';
        else if (rand < volumeWeights[2] + volumeWeights[1]) volumeLevel = 'high';
        
        const volume = volumeLevel === 'critical' ? `${(Math.random() * 10 + 10).toFixed(1)}GB` :
                      volumeLevel === 'high' ? `${(Math.random() * 5 + 1).toFixed(1)}GB` :
                      `${(Math.random() * 1000 + 100).toFixed(0)}MB`;
        
        networkTraffic.push({
            id: `NET-${String(i + 1).padStart(3, '0')}`,
            source: source,
            destination: destination,
            protocol: protocol,
            volume: volume,
            volumeLevel: volumeLevel,
            timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
            status: Math.random() > 0.1 ? 'allowed' : 'blocked'
        });
    }
    
    networkTraffic.sort((a, b) => b.timestamp - a.timestamp);
}

// Navigation Functions
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const contentSections = document.querySelectorAll('.content-section');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all links and sections
            navLinks.forEach(l => l.classList.remove('active'));
            contentSections.forEach(s => s.classList.remove('active'));
            
            // Add active class to clicked link
            this.classList.add('active');
            
            // Show corresponding section
            const sectionId = this.getAttribute('data-section');
            document.getElementById(sectionId).classList.add('active');
            
            // Update page title
            updatePageTitle(sectionId);
            
            // Render section data
            renderSectionData(sectionId);
        });
    });
}

function updatePageTitle(section) {
    const titles = {
        overview: 'Security Operations Center',
        alerts: 'Security Alerts',
        logs: 'Security Logs',
        cases: 'Security Cases'
    };
    
    const subtitles = {
        overview: 'Real-time monitoring and incident response',
        alerts: 'Monitor and respond to security threats',
        logs: 'Analyze system and security logs',
        cases: 'Manage security incidents and investigations'
    };
    
    document.getElementById('page-title').textContent = titles[section];
    document.getElementById('page-subtitle').textContent = subtitles[section];
}

// Filter and Search Functions
function initializeFilters() {
    // Alert filters
    document.getElementById('alert-filter').addEventListener('change', filterAlerts);
    document.getElementById('alert-search').addEventListener('input', searchAlerts);
    
    // Log filters
    document.getElementById('log-filter').addEventListener('change', filterLogs);
    document.getElementById('log-search').addEventListener('input', searchLogs);
    
    // Case filters
    document.getElementById('case-filter').addEventListener('change', filterCases);
    document.getElementById('case-search').addEventListener('input', searchCases);
}

function filterAlerts() {
    const filter = document.getElementById('alert-filter').value;
    const search = document.getElementById('alert-search').value.toLowerCase();
    renderAlerts(filter, search);
}

function searchAlerts() {
    const filter = document.getElementById('alert-filter').value;
    const search = document.getElementById('alert-search').value.toLowerCase();
    renderAlerts(filter, search);
}

function filterLogs() {
    const filter = document.getElementById('log-filter').value;
    const search = document.getElementById('log-search').value.toLowerCase();
    renderLogs(filter, search);
}

function searchLogs() {
    const filter = document.getElementById('log-filter').value;
    const search = document.getElementById('log-search').value.toLowerCase();
    renderLogs(filter, search);
}

function filterCases() {
    const filter = document.getElementById('case-filter').value;
    const search = document.getElementById('case-search').value.toLowerCase();
    renderCases(filter, search);
}

function searchCases() {
    const filter = document.getElementById('case-filter').value;
    const search = document.getElementById('case-search').value.toLowerCase();
    renderCases(filter, search);
}

// Render Functions
function renderSectionData(section) {
    switch(section) {
        case 'overview':
            renderOverviewData();
            break;
        case 'alerts':
            renderAlerts();
            break;
        case 'logs':
            renderLogs();
            break;
        case 'cases':
            renderCases();
            break;
    }
}

function renderOverviewData() {
    renderRecentActivity();
    renderScrollableComponents();
    if (alertTrendsChart) updateCharts();
}

function renderAlerts(filter = 'all', search = '') {
    const alertsList = document.getElementById('alerts-list');
    let filteredAlerts = alerts;
    
    // Apply filter
    if (filter !== 'all') {
        filteredAlerts = filteredAlerts.filter(alert => alert.severity === filter);
    }
    
    // Apply search
    if (search) {
        filteredAlerts = filteredAlerts.filter(alert => 
            alert.title.toLowerCase().includes(search) ||
            alert.description.toLowerCase().includes(search) ||
            alert.source.toLowerCase().includes(search)
        );
    }
    
    alertsList.innerHTML = filteredAlerts.map(alert => `
        <div class="alert-item ${alert.severity}">
            <div class="alert-header">
                <h3 class="alert-title">${alert.title}</h3>
                <span class="alert-severity ${alert.severity}">${alert.severity}</span>
            </div>
            <p class="alert-description">${alert.description}</p>
            <div class="alert-meta">
                <span class="alert-source">Source: ${alert.source}</span>
                <span class="alert-time">${formatTime(alert.timestamp)}</span>
            </div>
        </div>
    `).join('');
}

function renderLogs(filter = 'all', search = '') {
    const logsList = document.getElementById('logs-list');
    let filteredLogs = logs;
    
    // Apply filter
    if (filter !== 'all') {
        filteredLogs = filteredLogs.filter(log => log.type === filter);
    }
    
    // Apply search
    if (search) {
        filteredLogs = filteredLogs.filter(log => 
            log.message.toLowerCase().includes(search) ||
            log.source.toLowerCase().includes(search)
        );
    }
    
    logsList.innerHTML = filteredLogs.slice(0, 50).map(log => `
        <div class="log-item">
            <span class="log-timestamp">${formatTimestamp(log.timestamp)}</span>
            <span class="log-level ${log.level}">${log.level}</span>
            <span class="log-source">${log.source}</span>
            <span class="log-message">${log.message}</span>
        </div>
    `).join('');
}

function renderCases(filter = 'all', search = '') {
    const casesList = document.getElementById('cases-list');
    let filteredCases = cases;
    
    // Apply filter
    if (filter !== 'all') {
        filteredCases = filteredCases.filter(case_ => case_.status === filter);
    }
    
    // Apply search
    if (search) {
        filteredCases = filteredCases.filter(case_ => 
            case_.title.toLowerCase().includes(search) ||
            case_.description.toLowerCase().includes(search) ||
            case_.assignee.toLowerCase().includes(search)
        );
    }
    
    casesList.innerHTML = filteredCases.map(case_ => `
        <div class="case-item">
            <div class="case-header">
                <h3 class="case-id">${case_.id}</h3>
                <span class="case-status ${case_.status}">${case_.status}</span>
            </div>
            <h4 class="case-title">${case_.title}</h4>
            <p class="case-description">${case_.description}</p>
            <div class="case-meta">
                <span class="case-assignee">Assigned to: ${case_.assignee}</span>
                <span class="case-date">Updated: ${formatDate(case_.updated)}</span>
            </div>
        </div>
    `).join('');
}

function renderRecentActivity() {
    const activityList = document.getElementById('recent-activity-list');
    const recentActivities = [];
    
    // Get recent alerts
    alerts.filter(alert => alert.timestamp > Date.now() - 24 * 60 * 60 * 1000)
          .slice(0, 3)
          .forEach(alert => {
              recentActivities.push({
                  type: 'alert',
                  title: `New ${alert.severity} alert`,
                  description: alert.title,
                  time: alert.timestamp,
                  icon: 'fas fa-exclamation-triangle',
                  iconColor: alert.severity === 'critical' ? '#f44336' : '#ff9800'
              });
          });
    
    // Get recent cases
    cases.filter(case_ => case_.updated > Date.now() - 24 * 60 * 60 * 1000)
         .slice(0, 3)
         .forEach(case_ => {
             recentActivities.push({
                 type: 'case',
                 title: `Case ${case_.status}`,
                 description: case_.title,
                 time: case_.updated,
                 icon: 'fas fa-folder-open',
                 iconColor: '#4fc3f7'
             });
         });
    
    // Sort by time
    recentActivities.sort((a, b) => b.time - a.time);
    
    activityList.innerHTML = recentActivities.slice(0, 8).map(activity => `
        <div class="activity-item">
            <div class="activity-icon" style="background: ${activity.iconColor}20; color: ${activity.iconColor};">
                <i class="${activity.icon}"></i>
            </div>
            <div class="activity-content">
                <div class="activity-title">${activity.title}</div>
                <div class="activity-description">${activity.description}</div>
            </div>
            <div class="activity-time">${formatTime(activity.time)}</div>
        </div>
    `).join('');
}

function renderScrollableComponents() {
    renderThreatIntelligence();
    renderAssetMonitoring();
    renderVulnerabilities();
    renderUserActivity();
    renderEventTimeline();
    renderNetworkTraffic();
    updateScrollableCardBadges();
}

function renderThreatIntelligence() {
    const threatList = document.getElementById('threat-intelligence-list');
    threatList.innerHTML = threatIntelligence.slice(0, 15).map(threat => `
        <div class="scrollable-item">
            <div class="threat-item">
                <div class="threat-icon ${threat.type}">
                    <i class="fas ${getThreatIcon(threat.type)}"></i>
                </div>
                <div class="item-content">
                    <div class="item-header">
                        <span class="item-title">${threat.name}</span>
                        <span class="item-meta">${formatTime(threat.lastSeen)}</span>
                    </div>
                    <div class="item-description">${threat.description}</div>
                    <div class="item-tags">
                        <span class="item-tag ${threat.severity}">${threat.severity}</span>
                        <span class="item-tag info">${threat.indicators} indicators</span>
                        <span class="item-tag">${threat.confidence}% confidence</span>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function renderAssetMonitoring() {
    const assetList = document.getElementById('asset-monitoring-list');
    assetList.innerHTML = assets.slice(0, 20).map(asset => `
        <div class="scrollable-item">
            <div class="asset-item">
                <div class="asset-status ${asset.status}"></div>
                <div class="asset-info">
                    <div class="asset-name">${asset.name}</div>
                    <div class="asset-details">${asset.type} • ${asset.location} • ${asset.ip}</div>
                </div>
                <div class="item-meta">
                    <div style="text-align: right;">
                        <div>Risk: ${asset.riskScore}</div>
                        <div>${formatTime(asset.lastSeen)}</div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function renderVulnerabilities() {
    const vulnList = document.getElementById('vulnerabilities-list');
    vulnList.innerHTML = vulnerabilities.slice(0, 15).map(vuln => `
        <div class="scrollable-item vuln-item ${vuln.severity}">
            <div class="item-header">
                <span class="item-title">${vuln.name}</span>
                <span class="vuln-score">${vuln.cvssScore}</span>
            </div>
            <div class="item-description">${vuln.description}</div>
            <div class="item-tags">
                <span class="item-tag ${vuln.severity}">${vuln.severity}</span>
                <span class="item-tag info">${vuln.cve}</span>
                <span class="item-tag ${vuln.status === 'open' ? 'warning' : 'success'}">${vuln.status}</span>
                <span class="item-tag">${vuln.affectedAssets} assets</span>
            </div>
        </div>
    `).join('');
}

function renderUserActivity() {
    const userList = document.getElementById('user-activity-list');
    userList.innerHTML = userActivities.slice(0, 25).map(activity => `
        <div class="scrollable-item">
            <div class="user-activity-item">
                <div class="user-avatar">${activity.user.charAt(0).toUpperCase()}</div>
                <div class="user-activity-content">
                    <div class="user-activity-action">${activity.action}</div>
                    <div class="user-activity-details">${activity.details}</div>
                </div>
                <div class="item-meta">
                    <div style="text-align: right;">
                        <div class="item-tag ${activity.riskLevel}">${activity.riskLevel}</div>
                        <div>${formatTime(activity.timestamp)}</div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function renderEventTimeline() {
    const eventList = document.getElementById('event-timeline-list');
    eventList.innerHTML = eventTimeline.slice(0, 30).map(event => `
        <div class="scrollable-item">
            <div class="timeline-item ${event.severity}">
                <div class="timeline-time">${formatTime(event.timestamp)}</div>
                <div class="timeline-event">${event.event}</div>
                <div class="timeline-details">${event.details}</div>
            </div>
        </div>
    `).join('');
}

function renderNetworkTraffic() {
    const trafficList = document.getElementById('network-traffic-list');
    trafficList.innerHTML = networkTraffic.slice(0, 25).map(traffic => `
        <div class="scrollable-item">
            <div class="traffic-item">
                <div class="traffic-info">
                    <div class="traffic-source">${traffic.source} → ${traffic.destination}</div>
                    <div class="traffic-destination">${traffic.protocol} • ${traffic.status}</div>
                </div>
                <div class="traffic-volume ${traffic.volumeLevel}">${traffic.volume}</div>
            </div>
        </div>
    `).join('');
}

function updateScrollableCardBadges() {
    document.getElementById('threat-count').textContent = threatIntelligence.length;
    document.getElementById('asset-count').textContent = assets.length;
    document.getElementById('vuln-count').textContent = vulnerabilities.filter(v => v.severity === 'critical').length;
    document.getElementById('user-activity-count').textContent = userActivities.length;
    document.getElementById('event-count').textContent = eventTimeline.length;
    document.getElementById('traffic-count').textContent = networkTraffic.filter(t => t.volumeLevel === 'high' || t.volumeLevel === 'critical').length;
}

function getThreatIcon(type) {
    const icons = {
        'malware': 'fa-bug',
        'phishing': 'fa-fish',
        'ransomware': 'fa-lock',
        'botnet': 'fa-network-wired'
    };
    return icons[type] || 'fa-exclamation-triangle';
}

// Chart Functions
function initializeCharts() {
    initializeAlertTrendsChart();
    initializeThreatCategoriesChart();
}

function initializeAlertTrendsChart() {
    const ctx = document.getElementById('alertTrendsChart').getContext('2d');
    const last7Days = [];
    const alertCounts = [];
    
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        last7Days.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
        
        const dayStart = new Date(date);
        dayStart.setHours(0, 0, 0, 0);
        const dayEnd = new Date(date);
        dayEnd.setHours(23, 59, 59, 999);
        
        const count = alerts.filter(alert => 
            alert.timestamp >= dayStart && alert.timestamp <= dayEnd
        ).length;
        
        alertCounts.push(count);
    }
    
    alertTrendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: last7Days,
            datasets: [{
                label: 'Alerts',
                data: alertCounts,
                borderColor: '#4fc3f7',
                backgroundColor: 'rgba(79, 195, 247, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#b0b0b0'
                    },
                    grid: {
                        color: '#333'
                    }
                },
                x: {
                    ticks: {
                        color: '#b0b0b0'
                    },
                    grid: {
                        color: '#333'
                    }
                }
            }
        }
    });
}

function initializeThreatCategoriesChart() {
    const ctx = document.getElementById('threatCategoriesChart').getContext('2d');
    const categories = {};
    
    alerts.forEach(alert => {
        const category = alert.title.split(' ')[0];
        categories[category] = (categories[category] || 0) + 1;
    });
    
    const sortedCategories = Object.entries(categories)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 6);
    
    threatCategoriesChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: sortedCategories.map(([category]) => category),
            datasets: [{
                data: sortedCategories.map(([, count]) => count),
                backgroundColor: [
                    '#f44336',
                    '#ff9800',
                    '#ffeb3b',
                    '#4caf50',
                    '#2196f3',
                    '#9c27b0'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#b0b0b0',
                        padding: 20
                    }
                }
            }
        }
    });
}

function updateCharts() {
    // Update alert trends chart with latest data
    const last7Days = [];
    const alertCounts = [];
    
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        last7Days.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
        
        const dayStart = new Date(date);
        dayStart.setHours(0, 0, 0, 0);
        const dayEnd = new Date(date);
        dayEnd.setHours(23, 59, 59, 999);
        
        const count = alerts.filter(alert => 
            alert.timestamp >= dayStart && alert.timestamp <= dayEnd
        ).length;
        
        alertCounts.push(count);
    }
    
    alertTrendsChart.data.labels = last7Days;
    alertTrendsChart.data.datasets[0].data = alertCounts;
    alertTrendsChart.update();
    
    // Update threat categories chart
    const categories = {};
    alerts.forEach(alert => {
        const category = alert.title.split(' ')[0];
        categories[category] = (categories[category] || 0) + 1;
    });
    
    const sortedCategories = Object.entries(categories)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 6);
    
    threatCategoriesChart.data.labels = sortedCategories.map(([category]) => category);
    threatCategoriesChart.data.datasets[0].data = sortedCategories.map(([, count]) => count);
    threatCategoriesChart.update();
}

// Metrics Functions
function updateMetrics() {
    const criticalAlerts = alerts.filter(alert => alert.severity === 'critical').length;
    const activeIncidents = alerts.filter(alert => alert.status === 'active').length;
    const openCases = cases.filter(case_ => case_.status === 'open').length;
    const resolvedToday = cases.filter(case_ => {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        return case_.status === 'resolved' && case_.updated >= today;
    }).length;
    
    document.getElementById('critical-alerts').textContent = criticalAlerts;
    document.getElementById('active-incidents').textContent = activeIncidents;
    document.getElementById('open-cases').textContent = openCases;
    document.getElementById('resolved-today').textContent = resolvedToday;
}

// Data Update Functions
function updateData() {
    // Simulate new alerts
    if (Math.random() > 0.7) {
        const newAlert = generateNewAlert();
        alerts.unshift(newAlert);
        if (alerts.length > 50) alerts.pop();
    }
    
    // Simulate new logs
    if (Math.random() > 0.5) {
        const newLog = generateNewLog();
        logs.unshift(newLog);
        if (logs.length > 200) logs.pop();
    }
    
    // Update current section display
    const activeSection = document.querySelector('.content-section.active');
    if (activeSection) {
        renderSectionData(activeSection.id);
    }
}

function generateNewAlert() {
    const alertTypes = ['Malware Detection', 'Suspicious Login Activity', 'DDoS Attack', 'Phishing Attempt'];
    const severities = ['critical', 'high', 'medium', 'low'];
    const sources = ['Firewall', 'IDS/IPS', 'Antivirus', 'SIEM'];
    const ips = ['192.168.1.101', '10.0.0.45', '172.16.0.32'];
    
    const alertType = alertTypes[Math.floor(Math.random() * alertTypes.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const source = sources[Math.floor(Math.random() * sources.length)];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    
    return {
        id: `ALT-${String(Date.now()).slice(-4)}`,
        title: alertType,
        severity: severity,
        description: generateAlertDescription(alertType, ip),
        source: source,
        timestamp: new Date(),
        ip: ip,
        status: 'active'
    };
}

function generateNewLog() {
    const logTypes = ['authentication', 'network', 'malware', 'system'];
    const logLevels = ['error', 'warning', 'info', 'debug'];
    const sources = ['auth-server', 'firewall', 'web-server', 'database'];
    
    const logType = logTypes[Math.floor(Math.random() * logTypes.length)];
    const level = logLevels[Math.floor(Math.random() * logLevels.length)];
    const source = sources[Math.floor(Math.random() * sources.length)];
    
    return {
        id: `LOG-${String(Date.now()).slice(-6)}`,
        timestamp: new Date(),
        level: level,
        source: source,
        type: logType,
        message: generateLogMessage(logType, level, source),
        ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
    };
}

// Utility Functions
function formatTime(date) {
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
}

function formatTimestamp(date) {
    return date.toLocaleString('en-US', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function formatDate(date) {
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function updateLastUpdatedTime() {
    const now = new Date();
    document.getElementById('last-updated-time').textContent = 
        now.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
} 