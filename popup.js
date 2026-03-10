// 1. The Comprehensive Risk Matrix
const RISK_WEIGHTS = {
    permissions: {
        // Legacy / Out-of-Band (CRITICAL)
        "socket": { 
            score: 50, 
            reason: "Threat: C2 Channel. Allows raw TCP/UDP traffic to bypass browser security filters and establish direct contact with attacker servers." 
        },
        "fileSystem.write": { 
            score: 50, 
            reason: "Threat: Ransomware/Malware Drop. Allows writing malicious binaries directly to the local OS, bypassing the browser sandbox." 
        },
        "fileSystem": { 
            score: 40, 
            reason: "Threat: Data Exfiltration. Allows reading sensitive local files (like SSH keys or config files) from the user's hard drive." 
        },
        
        // Identity & Hijack (HIGH)
        "identity": { 
            score: 30, 
            reason: "Threat: Account Takeover. Allows silent extraction of OAuth tokens to access the user's primary Google/Microsoft accounts." 
        },
        "identity.email": { 
            score: 30, 
            reason: "Threat: Targeted Phishing. Scrapes the user's email address to facilitate highly credible social engineering attacks." 
        },
        "cookies": { 
            score: 30, 
            reason: "Threat: Session Hijacking. Allows stealing active session tokens to bypass Multi-Factor Authentication (MFA) on corporate SaaS platforms." 
        },
        "nativeMessaging": { 
            score: 40, 
            reason: "Threat: Remote Code Execution (RCE). Allows the extension to communicate with and execute local OS applications." 
        },
        
        // Network & DOM (HIGH/MEDIUM)
        "webRequest": { 
            score: 30, 
            reason: "Threat: Man-in-the-Middle (MitM). Allows interception and modification of data while it is in transit to/from a website." 
        },
        "webRequestBlocking": { 
            score: 35, 
            reason: "Threat: Traffic Hijacking. Allows the extension to block security updates or redirect the user to phishing mirrors." 
        },
        "declarativeNetRequest": { 
            score: 25, 
            reason: "Threat: Silent Header Injection. Allows modifying HTTP headers (like Authorization) without triggering traditional browser warnings." 
        },
        "scripting": { 
            score: 25, 
            reason: "Threat: Prompt Poaching. Allows injecting JavaScript into pages like ChatGPT to scrape prompts and responses in plain text." 
        },
        
        // Reconnaissance & Environment (MEDIUM)
        "tabs": { 
            score: 10, 
            reason: "Threat: Targeted Reconnaissance. Monitors active URLs to identify when a user visits high-value internal portals or bank sites." 
        },
        "clipboardRead": { 
            score: 20, 
            reason: "Threat: Sensitive Data Theft. Scrapes data the user has copied (passwords, PII, or code) before it is even pasted." 
        },
        "desktopCapture": { 
            score: 30, 
            reason: "Threat: Visual Surveillance. Allows taking silent screenshots or video of the user's active browser window." 
        }
    },
    host_permissions: {
        "<all_urls>": { score: 50, reason: "Threat: Universal Scoping. Grants the extension permission to read/write data on every website the user visits." },
        "*://*/*": { score: 50, reason: "Threat: Universal Scoping. Grants the extension permission to read/write data on every website the user visits." }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    chrome.management.getAll(async (extensionList) => {
        const scanPromises = extensionList.map(async (ext) => {
            // Skip themes and the scanner itself
            if (ext.type === "theme" || ext.id === chrome.runtime.id) return null;

            let extRisk = {
                name: ext.name, 
                id: ext.id, 
                version: ext.version, 
                manifestVersion: ext.manifestVersion,
                totalScore: 0, 
                flags: [], 
                alerts: [],
                // Temporary tracking object for heuristics analysis
                meta: { highRiskCount: 0, hasBroadHost: false, hasDOMInjection: false }
            };

            // LEVEL 1: Standard API Scan (Always succeeds)
            performLevel1Scan(ext, extRisk);

            // LEVEL 2: Deep Scan (May be blocked by Browser Sandbox)
            try {
                // Short timeout to prevent hanging on blocked requests
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 1000);

                const response = await fetch(`chrome-extension://${ext.id}/manifest.json`, {
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);

                if (response.ok) {
                    const rawManifest = await response.json();
                    performLevel2Analysis(rawManifest, extRisk);
                    extRisk.flags.push("[Deep Scan] Successfully analyzed raw manifest metadata.");
                } else {
                    extRisk.flags.push("[Sandbox Control] Access to raw manifest denied by target extension.");
                }
            } catch (error) {
                // Silently swallow sandbox blocks or network aborts
                extRisk.flags.push("[Sandbox Control] Private manifest; deep scan restricted by Chrome.");
            }

            // Synthesize findings
            calculateHeuristics(extRisk);
            finalizeRiskCategory(extRisk);

            return extRisk;
        });

        // Wait for all async deep scans to complete
        const rawResults = await Promise.all(scanPromises);
        const report = rawResults.filter(r => r !== null).sort((a, b) => b.totalScore - a.totalScore);
        
        document.getElementById('loading').style.display = 'none';
        renderReport(report);
    });
});

// --- HELPER FUNCTIONS ---

function performLevel1Scan(ext, extRisk) {
    if (ext.manifestVersion === 2) {
        extRisk.totalScore += 20;
        extRisk.flags.push("[Legacy] Manifest V2 lacks modern security boundaries.");
    }
    
    if (ext.permissions) {
        ext.permissions.forEach(perm => {
            let permData = RISK_WEIGHTS.permissions[perm];
            if (permData) {
                extRisk.totalScore += permData.score;
                extRisk.flags.push(`[${perm}] ${permData.reason}`);
                
                if (permData.score >= 30) extRisk.meta.highRiskCount++;
                if (perm === "scripting" || perm === "activeTab") extRisk.meta.hasDOMInjection = true;
            }
        });
    }

    if (ext.hostPermissions) {
        ext.hostPermissions.forEach(host => {
            let hostData = RISK_WEIGHTS.host_permissions[host];
            if (hostData) {
                extRisk.totalScore += hostData.score;
                extRisk.flags.push(`[${host}] ${hostData.reason}`);
                extRisk.meta.hasBroadHost = true;
                extRisk.meta.highRiskCount++;
            } else if (host.includes("*")) {
                extRisk.totalScore += 10;
                extRisk.flags.push(`[${host}] Broad wildcard host scope.`);
            }
        });
    }
}

function performLevel2Analysis(rawManifest, extRisk) {
    // 1. Cross-Extension Exploitation Check
    if (rawManifest.externally_connectable && rawManifest.externally_connectable.ids) {
        if (rawManifest.externally_connectable.ids.includes("*")) {
            extRisk.alerts.push("🚨 CROSS-EXTENSION HIJACK RISK: Allows universal external connections (externally_connectable: *).");
            extRisk.totalScore += 40;
        }
    }

    // 2. Weak CSP Check
    if (rawManifest.content_security_policy) {
        const cspString = typeof rawManifest.content_security_policy === 'string' 
            ? rawManifest.content_security_policy 
            : JSON.stringify(rawManifest.content_security_policy);
            
        if (cspString.includes("'unsafe-eval'") || cspString.includes("'unsafe-inline'")) {
            extRisk.flags.push("[Weak CSP] Allows potentially unsafe dynamic code execution.");
            extRisk.totalScore += 20;
        }
    }

    // 3. Web Accessible Resources Overexposure Check
    if (rawManifest.web_accessible_resources) {
        let isOverexposed = false;
        rawManifest.web_accessible_resources.forEach(war => {
            if (war.matches && (war.matches.includes("<all_urls>") || war.matches.includes("*://*/*"))) {
                isOverexposed = true;
            }
        });
        if (isOverexposed) {
            extRisk.flags.push("[WAR Overexposure] Resources broadly exposed to all websites (Clickjacking risk).");
            extRisk.totalScore += 10;
        }
    }
}

function calculateHeuristics(extRisk) {
    // Alert for Prompt Poaching (Host + Scripting)
    if (extRisk.meta.hasBroadHost && extRisk.meta.hasDOMInjection) {
        extRisk.alerts.push("🚨 THREAT: PROMPT POACHER. This extension can read every interaction on GenAI platforms (ChatGPT/Claude) due to universal host access and script injection.");
        extRisk.totalScore += 50; 
    }
    
    // Alert for Supply Chain attractiveness (High privilege density)
    if (extRisk.meta.highRiskCount >= 3) {
        extRisk.alerts.push(`🚨 GOVERNANCE ALERT: OVER-PRIVILEGED. This extension holds ${extRisk.meta.highRiskCount} critical system-level permissions. If this extension's developer account is compromised, it becomes a pre-authenticated backdoor into your environment.`);
        extRisk.totalScore += (extRisk.meta.highRiskCount * 15); 
    }
    
    delete extRisk.meta;
}

function finalizeRiskCategory(extRisk) {
    if (extRisk.totalScore >= 100) extRisk.category = "CRITICAL";
    else if (extRisk.totalScore >= 60) extRisk.category = "HIGH";
    else if (extRisk.totalScore >= 30) extRisk.category = "MEDIUM";
    else extRisk.category = "LOW";
}

function renderReport(report) {
    const container = document.getElementById('results');
    container.textContent = ''; // Secure DOM clearing

    report.forEach(ext => {
        const extWrapper = document.createElement('div');
        extWrapper.className = 'extension-card';

        // Header
        const header = document.createElement('div');
        header.className = 'ext-header';
        
        let colorClass = 'badge-low';
        if (ext.category === "CRITICAL") colorClass = 'badge-critical';
        else if (ext.category === "HIGH") colorClass = 'badge-high';
        else if (ext.category === "MEDIUM") colorClass = 'badge-medium';
        
        header.classList.add(colorClass);
        header.textContent = `${ext.name} (v${ext.version}) — ${ext.category} [Score: ${ext.totalScore}]`;
        extWrapper.appendChild(header);

        // Alerts (High Severity)
        ext.alerts.forEach(alertText => {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert-box';
            alertDiv.textContent = alertText; 
            extWrapper.appendChild(alertDiv);
        });

        // Flags (Standard Audit Items)
        const ul = document.createElement('ul');
        ext.flags.forEach(flagText => {
            const li = document.createElement('li');
            li.textContent = flagText; 
            ul.appendChild(li);
        });
        extWrapper.appendChild(ul);

        container.appendChild(extWrapper);
    });
}