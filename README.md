# SCOPE
**S.C.O.P.E.**- Browser Extension Risk &amp; Governance Auditor. A security-first diagnostic tool designed to bridge the visibility gap in browser extension governance. It audits the local extension for high-risk permissions, legacy Manifest V2 vulnerabilities, and "Toxic Permission Combinations" that enable GenAI prompt poaching and SaaS identity theft.

S.C.O.P.E - Supply-Chain Oversight & Permission Evaluator

**Core Research Features:**

**1. Heuristic Threat Detection:** Automatically flags "Prompt Poacher" profiles (Universal Host Access + Script Injection).

**2. Permission Density Scoring:** Calculates an empirical risk score based on a weighted matrix of 20+ critical permissions (Sockets, FileSystem, Identity, etc.).

**3. Deep Manifest Analysis:** Asynchronously attempts to bypass the browser sandbox to inspect raw manifest.json files for hidden risks like externally_connectable: *.

**4. Hardened Architecture:** Engineered with XSS-resistant rendering (textContent) and a strict Content Security Policy (CSP) to prevent cross-extension exploitation.

**How to Install (For Researchers):**

1. Clone this repository.

2. Open Chrome and navigate to chrome://extensions.

3. Enable Developer Mode (top right toggle).

4. Click Load unpacked and select the repository folder.

5. Click the S.C.O.P.E. icon to generate your fleet's risk report.

**Technical Risk Mapping:**
| Permission | Threat Profile |
| :--- | :--- |
| socket | C2 Channel / Firewall Bypass |
| cookies | Session Hijacking / MFA Bypass |
| scripting | DOM Injection / Prompt Poaching |
| fileSystem | Local Data Exfiltration |

**Disclaimer**
S.C.O.P.E. (Supply-Chain Oversight & Permission Evaluator) is a Proof-of-Concept (PoC) diagnostic tool intended for security research, auditing, and educational purposes only.

Risk Assessment, Not Guarantee: This tool identifies potential risks based on declared permissions and heuristic patterns. A "Critical" score does not prove that an extension is malicious. Malicious intent can exist in extensions with minimal permissions through obfuscation or future updates.

No Remediation: S.C.O.P.E. is a passive scanner. It does not disable, remove, or modify other extensions. Any administrative actions taken based on the output of this tool (such as uninstalling corporate software) are at the sole discretion and risk of the user/organization.

"As-Is" Software: This software is provided "as is," without warranty of any kind, express or implied. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability arising from the use of this tool.

Experimental Fetching: The "Deep Scan" feature attempts to fetch local manifest files. While engineered with safe error-handling, this behavior may trigger browser-level security warnings in the developer console. This is expected behavior and does not impact browser stability.
