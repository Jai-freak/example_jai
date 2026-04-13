import { useState, useRef, useEffect } from "react"; const VULNERABILITY_DB = [ { id: "CVE-2024-1001", name: "SQL Injection Vector", severity: "critical", category: "Injection", line: "Line 42-48", description: "User input is concatenated directly into
SQL queries without parameterization, allowing attackers to execute arbitrary SQL commands.", impact: "Full database compromise, data exfiltration, authentication bypass, and potential remote code execution.", remediation: [ "Use parameterized queries
or prepared statements for all database interactions", "Implement input validation and sanitization using allowlists", "Apply the principle of least privilege for database accounts", "Deploy a Web Application Firewall (WAF) as an additional layer", "Conduct
regular code reviews focusing on data access layers" ], cwe: "CWE-89", owasp: "A03:2021 – Injection", cvss: 9.8 }, { id: "CVE-2024-1002", name: "Cross-Site Scripting (XSS)", severity: "high", category: "XSS", line: "Line 115-120", description: "Reflected
XSS vulnerability detected where user-controlled data is rendered in HTML without proper encoding or escaping.", impact: "Session hijacking, credential theft, defacement, phishing attacks, and malware distribution.", remediation: [ "Encode all user-supplied
data before rendering in HTML context", "Implement Content Security Policy (CSP) headers", "Use frameworks that auto-escape output (React, Angular)", "Sanitize HTML input with libraries like DOMPurify", "Set HttpOnly and Secure flags on session cookies"
], cwe: "CWE-79", owasp: "A03:2021 – Injection", cvss: 7.5 }, { id: "CVE-2024-1003", name: "Hardcoded API Credentials", severity: "critical", category: "Secrets", line: "Line 8-12", description: "API keys and authentication tokens are embedded directly
in the source code, exposing them to anyone with access to the codebase.", impact: "Unauthorized API access, data breaches, service abuse, financial loss, and lateral movement in cloud environments.", remediation: [ "Move all secrets to environment variables
or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)", "Rotate all exposed credentials immediately", "Add secret scanning to CI/CD pipeline (e.g., git-secrets, truffleHog)", "Implement .gitignore rules for configuration files", "Use short-lived
tokens and automatic rotation policies" ], cwe: "CWE-798", owasp: "A07:2021 – Identification and Authentication Failures", cvss: 9.1 }, { id: "CVE-2024-1004", name: "Insecure Deserialization", severity: "high", category: "Deserialization", line: "Line
203-210", description: "Untrusted data is deserialized without validation, allowing attackers to inject malicious objects that execute during the deserialization process.", impact: "Remote code execution, denial of service, privilege escalation, and application
logic bypass.", remediation: [ "Never deserialize data from untrusted sources", "Use safe serialization formats like JSON instead of native serialization", "Implement integrity checks (e.g., digital signatures) on serialized data", "Apply strict type
constraints during deserialization", "Monitor deserialization operations and log anomalies" ], cwe: "CWE-502", owasp: "A08:2021 – Software and Data Integrity Failures", cvss: 8.1 }, { id: "CVE-2024-1005", name: "Path Traversal", severity: "medium", category:
"File Access", line: "Line 78-85", description: "File path input is not properly sanitized, enabling attackers to use sequences like '../' to access files outside the intended directory.", impact: "Unauthorized file access, configuration file exposure,
source code leakage, and potential system compromise.", remediation: [ "Validate and canonicalize all file paths before use", "Use a whitelist of allowed file paths or directories", "Implement chroot jails or sandboxing for file operations", "Remove or
encode '../' and other traversal sequences", "Set restrictive file system permissions" ], cwe: "CWE-22", owasp: "A01:2021 – Broken Access Control", cvss: 6.5 }, { id: "CVE-2024-1006", name: "Weak Cryptographic Hash", severity: "medium", category: "Cryptography",
line: "Line 155-158", description: "MD5 or SHA-1 hash functions are used for password hashing or data integrity, which are vulnerable to collision and preimage attacks.", impact: "Password cracking, authentication bypass, data tampering, and integrity
verification failures.", remediation: [ "Replace MD5/SHA-1 with bcrypt, scrypt, or Argon2 for passwords", "Use SHA-256 or SHA-3 for data integrity checks", "Implement proper salting for all password hashes", "Configure appropriate work factors for adaptive
hash functions", "Plan for cryptographic agility to swap algorithms in the future" ], cwe: "CWE-328", owasp: "A02:2021 – Cryptographic Failures", cvss: 5.9 }, { id: "CVE-2024-1007", name: "Missing Rate Limiting", severity: "low", category: "DoS", line:
"Line 30-35", description: "API endpoints lack rate limiting controls, making them susceptible to brute-force attacks and denial-of-service.", impact: "Brute-force credential attacks, resource exhaustion, API abuse, and degraded service availability.",
remediation: [ "Implement rate limiting on all authentication endpoints", "Use token bucket or sliding window algorithms", "Add CAPTCHA after repeated failed attempts", "Deploy API gateway with built-in rate limiting", "Set up alerts for abnormal request
patterns" ], cwe: "CWE-770", owasp: "A04:2021 – Insecure Design", cvss: 3.7 }, { id: "CVE-2024-1008", name: "Verbose Error Messages", severity: "low", category: "Information Disclosure", line: "Line 92-99", description: "Detailed error messages including
stack traces and internal paths are exposed to end users in production.", impact: "Information leakage revealing internal architecture, technology stack, file paths, and potential attack vectors.", remediation: [ "Implement generic user-facing error messages
in production", "Log detailed errors server-side only with structured logging", "Configure framework-level error handling to suppress stack traces", "Use unique error IDs that map to detailed internal logs", "Regularly audit error responses for information
leakage" ], cwe: "CWE-209", owasp: "A05:2021 – Security Misconfiguration", cvss: 3.1 } ]; const getSeverityColor = (s) => ({ critical: "#ff1744", high: "#ff6d00", medium: "#ffc400", low: "#00e5ff" }[s] || "#888"); const getSeverityBg = (s) => ({ critical:
"rgba(255,23,68,0.12)", high: "rgba(255,109,0,0.12)", medium: "rgba(255,196,0,0.12)", low: "rgba(0,229,255,0.12)" }[s] || "rgba(136,136,136,0.12)"); const ShieldIcon = () => (
<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" strokeWidth="1.5">
    <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
    <path d="M9 12l2 2 4-4" stroke="#00e5ff" strokeWidth="2"/>
  </svg> ); const BugIcon = () => (
<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path d="M8 2l1.88 1.88M14.12 3.88L16 2M9 7.13v-1a3.003 3.003 0 116 0v1"/>
    <path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 014-4h4a4 4 0 014 4v3c0 3.3-2.7 6-6 6z"/>
    <path d="M12 20v-9M6.53 9C4.6 8.8 3 7.1 3 5M17.47 9c1.93-.2 3.53-1.9 3.53-4M12 11h6M12 11H6M12 15h6M12 15H6"/>
  </svg> ); const FileIcon = ({ ext }) => (
<div style={{ width: 42, height: 52, background: "linear-gradient(135deg, #1a2744 60%, #0d1b2a)", border: "1px solid #1e3a5f", borderRadius: 6, display: "flex", alignItems: "flex-end", justifyContent: "center", paddingBottom: 6, fontSize: 10, fontWeight:
    700, color: "#00e5ff", letterSpacing: 1, position: "relative", overflow: "hidden" }}>
    <div style={{ position: "absolute", top: 0, right: 0, width: 14, height: 14, background: "#0d1b2a", borderBottomLeft: "1px solid #1e3a5f", clipPath: "polygon(100% 0, 0 100%, 100% 100%)" }}/> {ext}
</div>
); function ScanAnimation({ progress, phase }) { return (
<div style={{ padding: "40px 0", textAlign: "center" }}>
    <div style={{ position: "relative", width: 180, height: 180, margin: "0 auto 30px" }}>
        <svg width="180" height="180" viewBox="0 0 180 180" style={{ transform: "rotate(-90deg)" }}>
          <circle cx="90" cy="90" r="78" fill="none" stroke="#0a1628" strokeWidth="6"/>
          <circle cx="90" cy="90" r="78" fill="none" stroke="#00e5ff" strokeWidth="6"
            strokeDasharray={`${progress * 4.9} 490`}
            strokeLinecap="round"
            style={{ transition: "stroke-dasharray 0.3s ease", filter: "drop-shadow(0 0 8px rgba(0,229,255,0.5))" }}
          />
        </svg>
        <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", fontSize: 36, fontWeight: 800, color: "#00e5ff", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
            {progress}%
        </div>
    </div>
    <div style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: 13, color: "#4a9eff", letterSpacing: 1, animation: "pulse 1.5s ease-in-out infinite" }}>
        {phase}
    </div>
    <style>
        {
            `@keyframes pulse {
                0%,
                100% {
                    opacity: 0.5;
                }
                50% {
                    opacity: 1;
                }
            }
            `
        }
    </style>
</div>
); } function VulnCard({ vuln, onClick, selected }) { const sColor = getSeverityColor(vuln.severity); return (
<div onClick={onClick} style={{ background: selected ? "rgba(0,229,255,0.06)" : "rgba(10,22,40,0.7)", border: `1px solid ${selected ? "#00e5ff" : "#1e3a5f"}`, borderLeft: `3px solid ${sColor}`, borderRadius: 10, padding: "16px 18px", cursor: "pointer",
    transition: "all 0.2s ease", marginBottom: 10, boxShadow: selected ? `0 0 20px rgba(0,229,255,0.1)` : "none" }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <span style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 2, color: sColor, background: getSeverityBg(vuln.severity), padding: "3px 10px", borderRadius: 20 }}>
          {vuln.severity}
        </span>
        <span style={{ fontSize: 11, color: "#4a6a8a", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
          CVSS {vuln.cvss}
        </span>
    </div>
    <div style={{ fontSize: 14, fontWeight: 600, color: "#e0eaff", marginBottom: 4 }}>{vuln.name}</div>
    <div style={{ fontSize: 11, color: "#4a6a8a", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
        {vuln.id} · {vuln.line}
    </div>
</div>
); } function DetailPanel({ vuln }) { if (!vuln) return (
<div style={{ height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "#2a4a6a", padding: 40, textAlign: "center" }}>
    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#1e3a5f" strokeWidth="1">
        <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
      </svg>
    <div style={{ marginTop: 20, fontSize: 14, fontWeight: 500 }}>Select a vulnerability to view details</div>
</div>
); const sColor = getSeverityColor(vuln.severity); return (
<div style={{ padding: "24px 28px", overflowY: "auto", height: "100%" }}>
    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
        <div style={{ width: 40, height: 40, borderRadius: 10, background: getSeverityBg(vuln.severity), display: "flex", alignItems: "center", justifyContent: "center", border: `1px solid ${sColor}33` }}>
            <BugIcon />
        </div>
        <div>
            <div style={{ fontSize: 18, fontWeight: 700, color: "#e0eaff" }}>{vuln.name}</div>
            <div style={{ fontSize: 11, color: "#4a6a8a", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
                {vuln.id}
            </div>
        </div>
    </div>

    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 24 }}>
        {[ { label: "Severity", value: vuln.severity.toUpperCase(), color: sColor }, { label: "CVSS Score", value: vuln.cvss, color: sColor }, { label: "Category", value: vuln.category, color: "#4a9eff" } ].map((m, i) => (
        <div key={i} style={{ background: "rgba(10,22,40,0.8)", border: "1px solid #1e3a5f", borderRadius: 8, padding: "12px 14px", textAlign: "center" }}>
            <div style={{ fontSize: 10, color: "#4a6a8a", textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>
                {m.label}
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, color: m.color }}>{m.value}</div>
        </div>
        ))}
    </div>

    <Section title="Location" color="#4a9eff">
        <code style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: 12, color: "#00e5ff", background: "rgba(0,229,255,0.08)", padding: "6px 12px", borderRadius: 6, display: "inline-block" }}>
          {vuln.line}
        </code>
    </Section>

    <Section title="Description" color="#4a9eff">
        <p style={{ fontSize: 13, color: "#8aa4c0", lineHeight: 1.7, margin: 0 }}>{vuln.description}</p>
    </Section>

    <Section title="Impact" color="#ff6d00">
        <p style={{ fontSize: 13, color: "#8aa4c0", lineHeight: 1.7, margin: 0 }}>{vuln.impact}</p>
    </Section>

    <Section title="Remediation Steps" color="#00e676">
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {vuln.remediation.map((step, i) => (
            <div key={i} style={{ display: "flex", gap: 12, alignItems: "flex-start", background: "rgba(0,230,118,0.04)", border: "1px solid rgba(0,230,118,0.1)", borderRadius: 8, padding: "10px 14px" }}>
                <span style={{ minWidth: 22, height: 22, borderRadius: "50%", background: "rgba(0,230,118,0.15)", color: "#00e676", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", marginTop: 1 }}>
                {i + 1}
              </span>
                <span style={{ fontSize: 12.5, color: "#8aa4c0", lineHeight: 1.6 }}>{step}</span>
            </div>
            ))}
        </div>
    </Section>

    <Section title="References" color="#4a9eff">
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {[vuln.cwe, vuln.owasp].map((ref, i) => (
            <span key={i} style={{ fontSize: 11, color: "#4a9eff", background: "rgba(74,158,255,0.08)", border: "1px solid rgba(74,158,255,0.2)", padding: "5px 12px", borderRadius: 20, fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
              {ref}
            </span> ))}
        </div>
    </Section>
</div>
); } function Section({ title, color, children }) { return (
<div style={{ marginBottom: 22 }}>
    <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 2, color, marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ width: 16, height: 1, background: color, display: "inline-block" }}/> {title}
    </div>
    {children}
</div>
); } export default function CyberScanner() { const [state, setState] = useState("idle"); // idle, scanning, done const [file, setFile] = useState(null); const [progress, setProgress] = useState(0); const [phase, setPhase] = useState(""); const [vulns,
setVulns] = useState([]); const [selected, setSelected] = useState(null); const [filter, setFilter] = useState("all"); const fileRef = useRef(); const dragRef = useRef(false); const [dragOver, setDragOver] = useState(false); const handleFile = (f) =>
{ if (!f) return; setFile(f); setState("scanning"); setProgress(0); setSelected(null); setVulns([]); const phases = [ "Initializing scan engine...", "Parsing file structure...", "Analyzing code patterns...", "Checking dependency tree...", "Running static
analysis...", "Detecting injection vectors...", "Scanning for hardcoded secrets...", "Evaluating crypto implementations...", "Checking access controls...", "Generating vulnerability report..." ]; let p = 0; const interval = setInterval(() => { p += Math.floor(Math.random()
* 4) + 1; if (p > 100) p = 100; setProgress(p); setPhase(phases[Math.min(Math.floor(p / 10), phases.length - 1)]); if (p >= 100) { clearInterval(interval); setTimeout(() => { const ext = f.name.split('.').pop().toLowerCase(); let count; if (['js','jsx','ts','tsx','py','java','c','cpp','rb','php','go','rs'].includes(ext))
{ count = 4 + Math.floor(Math.random() * 5); } else if (['json','xml','yaml','yml','env','cfg','ini','conf'].includes(ext)) { count = 2 + Math.floor(Math.random() * 3); } else { count = 1 + Math.floor(Math.random() * 3); } const shuffled = [...VULNERABILITY_DB].sort(()
=> Math.random() - 0.5); setVulns(shuffled.slice(0, Math.min(count, shuffled.length))); setState("done"); }, 600); } }, 120); }; const handleDrop = (e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f);
}; const counts = { all: vulns.length, critical: vulns.filter(v => v.severity === "critical").length, high: vulns.filter(v => v.severity === "high").length, medium: vulns.filter(v => v.severity === "medium").length, low: vulns.filter(v => v.severity ===
"low").length }; const filtered = filter === "all" ? vulns : vulns.filter(v => v.severity === filter); const riskScore = vulns.length === 0 ? 100 : Math.max(0, 100 - vulns.reduce((a, v) => a + v.cvss * 3, 0)); const font = `'JetBrains Mono', 'Fira Code',
'Source Code Pro', monospace`; return (
<div style={{ minHeight: "100vh", background: "#060d18", fontFamily: "'Segoe UI', 'SF Pro Display', -apple-system, sans-serif", color: "#e0eaff", position: "relative", overflow: "hidden" }}>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet" /> {/* Background grid */}
    <div style={{ position: "fixed", inset: 0, opacity: 0.03, backgroundImage: `linear-gradient(#00e5ff 1px, transparent 1px), linear-gradient(90deg, #00e5ff 1px, transparent 1px)`, backgroundSize: "40px 40px", pointerEvents: "none" }}/> {/* Header */}
    <header style={{ padding: "16px 28px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid #0e1f38", background: "rgba(6,13,24,0.9)", backdropFilter: "blur(20px)", position: "sticky", top: 0, zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <ShieldIcon />
            <div>
                <div style={{ fontSize: 17, fontWeight: 700, letterSpacing: 1, fontFamily: "'Space Grotesk', sans-serif", color: "#e0eaff" }}>
                    SENTINEL
                </div>
                <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 3, fontWeight: 500 }}>
                    VULNERABILITY SCANNER
                </div>
            </div>
        </div>
        {state === "done" && (
        <button onClick={()=> { setState("idle"); setFile(null); setVulns([]); setSelected(null); }}
            style={{
              background: "rgba(0,229,255,0.08)", border: "1px solid #1e3a5f",
              color: "#00e5ff", padding: "8px 20px", borderRadius: 8,
              fontSize: 12, fontWeight: 600, cursor: "pointer", letterSpacing: 1,
              fontFamily: font, transition: "all 0.2s"
            }}
          >
            NEW SCAN
          </button> )}
    </header>

    {/* Upload State */} {state === "idle" && (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "calc(100vh - 70px)", padding: 40 }}>
        <div onDragOver={(e)=> { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)} onDrop={handleDrop} onClick={() => fileRef.current?.click()} style={{ width: "100%", maxWidth: 560, padding: "60px 40px", border: `2px dashed ${dragOver ? "#00e5ff"
            : "#1e3a5f"}`, borderRadius: 16, textAlign: "center", cursor: "pointer", background: dragOver ? "rgba(0,229,255,0.04)" : "rgba(10,22,40,0.4)", transition: "all 0.3s ease" }} >
            <input ref={fileRef} type="file" style={{ display: "none" }} onChange={(e)=> handleFile(e.target.files[0])} />

            <div style={{ width: 80, height: 80, margin: "0 auto 24px", borderRadius: "50%", background: "rgba(0,229,255,0.06)", border: "1px solid #1e3a5f", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" strokeWidth="1.5">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/>
                <line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
            </div>
            <div style={{ fontSize: 18, fontWeight: 600, color: "#e0eaff", marginBottom: 8 }}>
                Drop your file here to scan
            </div>
            <div style={{ fontSize: 13, color: "#4a6a8a", marginBottom: 24 }}>
                or click to browse — supports source code, configs, binaries & more
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
                {[".js", ".py", ".java", ".json", ".xml", ".env", ".php", ".go"].map(ext => (
                <span key={ext} style={{ fontSize: 11, color: "#2a5a8a", background: "rgba(10,22,40,0.8)", border: "1px solid #0e1f38", padding: "3px 10px", borderRadius: 12, fontFamily: font }}>
                  {ext}
                </span> ))}
            </div>
        </div>
    </div>
    )} {/* Scanning State */} {state === "scanning" && (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "calc(100vh - 70px)", padding: 40 }}>
        <div style={{ width: "100%", maxWidth: 480, background: "rgba(10,22,40,0.5)", border: "1px solid #1e3a5f", borderRadius: 16, padding: 40, textAlign: "center" }}>
            <div style={{ fontFamily: font, fontSize: 12, color: "#2a5a8a", marginBottom: 16, letterSpacing: 1 }}>
                SCANNING: {file?.name}
            </div>
            <ScanAnimation progress={progress} phase={phase} />
        </div>
    </div>
    )} {/* Results Dashboard */} {state === "done" && (
    <div style={{ padding: "24px 28px" }}>
        {/* Stats Row */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 14, marginBottom: 24 }}>
            <StatCard label="File Scanned" value={file?.name} sub={`${(file?.size / 1024).toFixed(1)} KB`} color="#4a9eff" />
            <StatCard label="Risk Score" value={`${Math.round(riskScore)}/100`} sub={riskScore> 70 ? "Low Risk" : riskScore > 40 ? "Medium Risk" : "High Risk"} color={riskScore > 70 ? "#00e676" : riskScore > 40 ? "#ffc400" : "#ff1744"}/>
                <StatCard label="Vulnerabilities" value={vulns.length} sub="Total Found" color="#ff6d00" />
                <StatCard label="Critical" value={counts.critical} sub="Immediate Action" color="#ff1744" />
        </div>

        {/* Filter Tabs */}
        <div style={{ display: "flex", gap: 6, marginBottom: 20, flexWrap: "wrap" }}>
            {["all", "critical", "high", "medium", "low"].map(f => (
            <button key={f} onClick={()=> setFilter(f)}
                style={{
                  background: filter === f ? "rgba(0,229,255,0.1)" : "transparent",
                  border: `1px solid ${filter === f ? "#00e5ff" : "#1e3a5f"}`,
                  color: filter === f ? "#00e5ff" : "#4a6a8a",
                  padding: "6px 16px", borderRadius: 20, fontSize: 11,
                  fontWeight: 600, cursor: "pointer", textTransform: "uppercase",
                  letterSpacing: 1, transition: "all 0.2s",
                  fontFamily: font
                }}
              >
                {f} {counts[f] > 0 ? `(${counts[f]})` : ""}
              </button> ))}
        </div>

        {/* Main Content */}
        <div style={{ display: "grid", gridTemplateColumns: window.innerWidth> 800 ? "380px 1fr" : "1fr", gap: 20, minHeight: 500 }}> {/* Vulnerability List */}
            <div style={{ overflowY: "auto", maxHeight: "calc(100vh - 300px)", paddingRight: 6 }}>
                {filtered.length === 0 ? (
                <div style={{ textAlign: "center", padding: 40, color: "#2a5a8a" }}>
                    No vulnerabilities in this category
                </div>
                ) : ( filtered.map(v => (
                <VulnCard key={v.id} vuln={v} selected={selected?.id===v .id} onClick={()=> setSelected(v)} /> )) )}
            </div>

            {/* Detail Panel */}
            <div style={{ background: "rgba(10,22,40,0.4)", border: "1px solid #1e3a5f", borderRadius: 12, overflow: "hidden", maxHeight: "calc(100vh - 300px)", overflowY: "auto" }}>
                <DetailPanel vuln={selected} />
            </div>
        </div>
    </div>
    )}
</div>
); } function StatCard({ label, value, sub, color }) { return (
<div style={{ background: "rgba(10,22,40,0.5)", border: "1px solid #1e3a5f", borderRadius: 12, padding: "16px 18px" }}>
    <div style={{ fontSize: 10, color: "#4a6a8a", textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 8 }}>
        {label}
    </div>
    <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: "'JetBrains Mono', 'Fira Code', monospace", marginBottom: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {value}
    </div>
    <div style={{ fontSize: 11, color: "#2a5a8a" }}>{sub}</div>
</div>
); }