// SOC Dashboard JavaScript

// Global Variables
let alerts = [];
let logs = [];
let cases = [];
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