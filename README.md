# SCOPE
**S.C.O.P.E.**- Browser Extension Risk &amp; Governance Auditor. A security-first diagnostic tool designed to bridge the visibility gap in browser extension governance. It audits the local extension for high-risk permissions, legacy Manifest V2 vulnerabilities, and "Toxic Permission Combinations" that enable GenAI prompt poaching and SaaS identity theft.

S.C.O.P.E - Supply-Chain Oversight & Permission Evaluator

**Core Research Features:**

**1. Heuristic Threat Detection:** Automatically flags "Prompt Poacher" profiles (Universal Host Access + Script Injection).

**2. Permission Density Scoring:** Calculates an empirical risk score based on a weighted matrix of 20+ critical permissions (Sockets, FileSystem, Identity, etc.).

**3. Deep Manifest Analysis:** Asynchronously attempts to bypass the browser sandbox to inspect raw manifest.json files for hidden risks like externally_connectable: *.

**4. Hardened Architecture:** Engineered with XSS-resistant rendering (textContent) and a strict Content Security Policy (CSP) to prevent cross-extension exploitation.

**How to Install (For Researchers):**

Clone this repository.

Open Chrome and navigate to chrome://extensions.

Enable Developer Mode (top right toggle).

Click Load unpacked and select the repository folder.

Click the S.C.O.P.E. icon to generate your fleet's risk report.

**Technical Risk Mapping:**
| Permission | Threat Profile |
| :--- | :--- |
| socket | C2 Channel / Firewall Bypass |
| cookies | Session Hijacking / MFA Bypass |
| scripting | DOM Injection / Prompt Poaching |
| fileSystem | Local Data Exfiltration |
