import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const SECTIONS = [
  {
    icon: '🧬',
    title: 'AI Architecture',
    path: 'how the AI works',
    summary: 'The nine AI/ML modules that power detection, prediction, and prioritization — what each one does and how it works.',
    details: [
      { heading: 'Anomaly Detection — Isolation Forest',
        body: 'A scikit-learn IsolationForest (100 trees) inside a StandardScaler pipeline. It learns 14 features of your system every 5 seconds — CPU/RAM/disk, four network rates, CPU temperature, login activity, connection count, processes, and time-of-day/day-of-week. After ~30 minutes (500 samples) it auto-trains and persists the model to disk. From then on, every new metric snapshot is scored 0–1 for how much it deviates from your normal. Catches genuinely novel deviations no signature would flag. A rule-based fallback (CPU > 90, RAM > 92, etc.) covers the warm-up period.' },
      { heading: 'Intrusion Detection — Hybrid Signature + Behavioral',
        body: '11 compiled regex rules tagged with MITRE ATT&CK techniques cover SSH brute force, root SSH attempts, sudo escalation, SQLi, XSS, path traversal/LFI, command injection, crypto miners, reverse shells, and wget|bash one-liners. Each rule has a sliding-window threshold (e.g. 5 failed SSH passwords in 60s) so a single mistype doesn’t fire an alert but real brute-force does. A separate stateful port-scan detector counts unique destination ports per source IP in a 60s window and alerts at 15+. Whitelists 127.0.0.1 and ::1 so local processes are never flagged.' },
      { heading: 'Log Intelligence — Keyword Scoring + Cross-Source Correlation',
        body: 'Every log line is scored against a curated keyword dictionary across four severity tiers (critical/high/medium/low). Source format (auth/syslog/kern/nginx/apache/fail2ban) is auto-detected from the filename. A correlation engine runs every 60 seconds and surfaces three multi-event patterns: "Sustained attack" (one IP generating ≥3 high-sev events), "Credential stuffing" (one IP attempting ≥3 distinct users with ≥5 failures), and "Account targeted" (one user failing from ≥3 different IPs). Each insight comes with concrete remediation commands — copy-paste iptables rules, passwd -l calls, etc.' },
      { heading: 'Threat Predictor — Holt-Winters + Seasonal Decomposition',
        body: 'Three lightweight time-series models combined: Holt’s Double Exponential Smoothing (α=0.25, β=0.1) captures the trend and projects 24 hours ahead; a 24-hour seasonal decomposition divides each hour’s historical average by the global mean to learn daily attack rhythms; a momentum signal compares the last 6 hours to the prior 6 hours for short-term escalation. Output is hour-by-hour predictions with confidence (decays from 1.0 at h+1 to 0.4 at h+24), an overall risk label, peak hour, and prose recommendations. Runs in microseconds.' },
      { heading: 'File Integrity Monitor — SHA-256 + ML Triage',
        body: 'SHA-256 hashes every file under critical paths (auth files, SSH config, sudoers, PAM, crontabs, systemd, /usr/bin, /usr/sbin) up to depth 3. Diff scan every 5 minutes. A 10-feature heuristic classifier scores each change for suspicion (is_critical_auth, is_suid, odd_hour, rapid_change, size_spike, permission_loosen, root_owned_change, deleted_critical, new_executable). After 200 events accumulate, an Isolation Forest trains on the feature vectors and is blended 60/40 with the heuristic — so the system gradually learns what change patterns are normal in your environment. Benign-classified changes silently update the baseline so apt upgrades don’t generate noise.' },
      { heading: 'Vulnerability Scanner — CVE Match + AI Prioritization',
        body: 'Enumerates installed packages via dpkg/rpm/apk and matches against an offline CVE database (20 embedded high-impact CVEs always available; optional NVD cache extends coverage). The AI prioritizer adjusts raw CVSS scores based on context: +1.5 if the package is actively listening on a port, +0.5 each for low complexity / no auth required, +0.3 for SBC-amplified packages, +0.5 for kernel/glibc local privilege escalation, −0.5 for required user interaction. The result is a 0–10 priority score with plain-English rationale and a copy-paste fix command.' },
      { heading: 'Hardening Advisor — Rule-Based Audit',
        body: 'Deliberately rule-based — hardening best practices are stable, ML adds nothing. 34 checks across 8 domains: SSH config (8), firewall (2), kernel sysctl (8), SUID binaries vs known-safe list, sudo NOPASSWD/ALL=(ALL) ALL grants, users (UID 0 dups, empty passwords, system shells), risky services (telnet/rsh/rlogin/tftp/finger/talk + open-port count), file permissions (shadow, passwd, sudoers, sshd_config, crontab). Proportional scoring → 0–100 → A+/A/B/C/D/F grade. The summary generator ranks failures by severity and impact and produces prioritized recommendations.' },
      { heading: 'Honeypot — Decoy Services + Payload Clustering',
        body: 'Asyncio TCP listeners on 10 attacker-magnet ports (fake SSH on 2222, fake HTTP on 8080, fake Telnet, fake RDP, fake MySQL, fake Redis, fake VNC, fake FTP). Each sends a service-realistic banner and reads up to 2 KB. A payload classifier categorizes probes into credential_brute_force / exploit_attempt / recon / port_scan with service-specific multipliers (SSH brute-force scoring is 1.5× on the SSH honeypot). A fingerprint clusterer groups probes by label + port overlap + recency + same /24 subnet so distributed attacks merge into one alert. High-confidence probes auto-feed the IDS for blocking.' },
      { heading: 'Federated Learning — Privacy-First Model Improvement',
        body: 'Opt-in. Only model weight tensors are transmitted — never raw logs, IPs, usernames, or hostnames. Weights are clipped to L2 norm ≤ 1.0 then perturbed with Gaussian noise (σ = 0.1) before upload, providing strict (ε, δ)-differential privacy guarantees (per-upload ε ≈ 0.0005). A central aggregator runs FedAvg over all opt-in clients; downloads are blended 30% community / 70% local so your detector improves without losing environment-specific learning. Anonymous random node ID, never linked to any system identifier. Uploads every 24h, downloads every 12h.' },
    ],
  },
  {
    icon: '⊞',
    title: 'Overview',
    path: '/',
    summary: 'Your security command centre — shows everything at a glance.',
    details: [
      { heading: 'Live metrics', body: 'CPU, RAM, disk usage and temperature are shown in real time via WebSocket. Values turn red when they breach safe thresholds (CPU > 80 %, RAM > 85 %, temp > 75 °C).' },
      { heading: 'AI Engine Status', body: 'Nine AI modules are shown with green/yellow/grey indicators: Anomaly Detector (Isolation Forest), IDS Engine (signature + behavioral), Log Intelligence (correlation), Threat Predictor (Holt-Winters), File Integrity Monitor, Vulnerability Scanner, Hardening Advisor, Honeypot, and Federated Learning. Yellow means the module is warming up (e.g. anomaly detector still collecting baseline samples); grey means no data yet.' },
      { heading: 'Threat Score Chart', body: 'An area chart of the rolling threat score over time. Spikes indicate periods of elevated attack activity detected by the IDS or anomaly engine.' },
      { heading: 'CPU / Network Charts', body: 'Scrolling 20-point history of CPU % and network throughput (recv/sent). Useful for spotting sustained load caused by attacks or cryptominers.' },
      { heading: 'Recent Alerts & Processes', body: 'The last five security alerts and the top CPU-consuming processes, so you can correlate suspicious processes with alerts without leaving the page.' },
    ],
  },
  {
    icon: '🔔',
    title: 'Alerts',
    path: '/alerts',
    summary: 'Every threat event generated by the AI engines, in one list.',
    details: [
      { heading: 'Severity filter', body: 'Use the pill buttons to filter by Critical, High, Medium, Low, or Info. The badge on each pill shows how many unresolved alerts exist at that level.' },
      { heading: 'Threat Score Ring', body: 'The ring on the left of each alert shows a 0–10 threat score: red (≥ 8), yellow (≥ 6), green (< 6). This is calculated by the IDS engine from attack signatures and behavioural patterns.' },
      { heading: 'ACK / CLOSE', body: 'Acknowledge an alert to mark it as seen without closing it. Close (resolve) an alert once you have investigated and handled it. Resolved alerts are hidden by default — enable "Show resolved" to see them.' },
      { heading: 'Source IP & geo', body: 'If the IDS identified a source IP, it is shown alongside the country code so you can quickly judge whether traffic is expected.' },
    ],
  },
  {
    icon: '🧠',
    title: 'AI Insights',
    path: '/ai',
    summary: 'Predictive threat forecasting and log correlation from the ML models.',
    details: [
      { heading: 'Forecast tab', body: 'The AI Threat Predictor analyses historical attack patterns to predict the threat level for each of the next 24 hours. The area chart shows the predicted score (0–100 %). Overall risk and peak hour are highlighted above the chart.' },
      { heading: 'Recommendations', body: 'The predictor generates plain-English recommendations based on its forecast, such as "Consider tightening SSH rate limits during the 02:00–04:00 window".' },
      { heading: 'Log Insights tab', body: 'The Log Intelligence engine correlates raw system logs to surface multi-event patterns, for example: "50 failed SSH logins from 3 IPs in 10 minutes". Each insight shows affected IPs and a severity rating.' },
      { heading: 'IDS Alerts tab', body: 'Raw IDS detections with MITRE ATT&CK technique tags and exact threat scores. Use this for deep investigation when you want more technical detail than the Alerts panel shows.' },
    ],
  },
  {
    icon: '🌐',
    title: 'Network',
    path: '/network',
    summary: 'Live connection table, bandwidth stats, and suspicious connection alerts.',
    details: [
      { heading: 'Stat cards', body: 'Total, Established, Listening, and Suspicious connection counts refresh every 8 seconds. A red Suspicious count means at least one connection matches a known bad pattern (port scanning, unusual destination, etc.).' },
      { heading: 'Bandwidth', body: 'Inbound and outbound data rates sourced from the live WebSocket stream. High outbound from a process you don\'t recognise may indicate data exfiltration.' },
      { heading: 'Suspicious connections panel', body: 'When suspicious connections are detected, they surface above the table in a red panel so they are impossible to miss. Shows remote IP, destination port, protocol, and status.' },
      { heading: 'Connection table', body: 'Up to 30 active connections with local address, remote address, status, protocol, and service label. Suspicious rows are highlighted in red.' },
    ],
  },
  {
    icon: '📄',
    title: 'File Integrity',
    path: '/fim',
    summary: 'AI-powered monitoring of critical system files for unauthorised changes.',
    details: [
      { heading: 'How it works', body: 'The FIM engine builds SHA-256 baseline hashes of critical files (e.g. /etc/passwd, /etc/ssh/sshd_config, web server configs). It compares live hashes against the baseline every few minutes.' },
      { heading: 'Severity', body: 'Changes are scored by the AI: system binary modifications are Critical, config changes are High, log rotation is Info. This avoids alert fatigue from expected changes.' },
      { heading: 'Rebuild Baseline', body: 'Click "Rebuild Baseline" after you intentionally change a monitored file (e.g. after a legitimate config edit) to update the reference hashes and clear the alert.' },
      { heading: 'Events list', body: 'Each event shows the file path, change type (modified / added / deleted), old and new hash, and the AI severity assessment.' },
    ],
  },
  {
    icon: '🐞',
    title: 'Vulnerabilities',
    path: '/vulns',
    summary: 'CVE scanning of installed packages with AI-powered risk prioritisation.',
    details: [
      { heading: 'CVE scan', body: 'The scanner reads installed package versions and matches them against the NVD / OSV databases. It identifies packages with known vulnerabilities and fetches CVSS scores.' },
      { heading: 'AI prioritisation', body: 'A raw CVSS score does not account for whether the vulnerable service is exposed, whether exploits are public, or how critical the package is to your deployment. The AI layer re-ranks findings for your specific context.' },
      { heading: 'Fix commands', body: 'Each vulnerability includes the recommended remediation command (e.g. apt upgrade <package>=<version>). You can copy these directly to your terminal.' },
      { heading: 'Scan now', body: 'Scans run automatically on startup and periodically. Use "Scan Now" to trigger an immediate re-scan after applying patches to verify they resolved the findings.' },
    ],
  },
  {
    icon: '🛡',
    title: 'Hardening',
    path: '/hardening',
    summary: 'CIS-inspired configuration audit across SSH, firewall, kernel, SUID, sudo, services, and more.',
    details: [
      { heading: 'Hardening Score', body: 'Scored 0–100 proportionally: each failed check deducts a weighted share of the total possible points. A score of 100 means every check passed. Grade A+ = 95–100, A = 85–94, B = 70–84, C = 55–69, D = 40–54, F < 40.' },
      { heading: 'AI Assessment', body: 'The AI generates a plain-English summary of your security posture and a ranked list of the most impactful recommendations to action first.' },
      { heading: 'Category tabs', body: 'Filter findings by category: SSH configuration, Firewall rules, Kernel parameters, SUID binaries, sudo policy, User accounts, Running services, File permissions.' },
      { heading: 'Auto Fix', body: 'Checks marked with ⚡ Auto Fix have a safe, reversible remediation command. Clicking Auto Fix runs the command directly on the system (the service runs as root, so no sudo prompt). Always review the shown command before applying.' },
      { heading: 'Show passed', body: 'By default, only failed checks are shown to reduce noise. Enable "Show passed" to see the full audit log including everything that is correctly configured.' },
    ],
  },
  {
    icon: '🍯',
    title: 'Honeypot',
    path: '/honeypot',
    summary: 'Decoy services that lure and fingerprint attackers probing your system.',
    details: [
      { heading: 'How it works', body: 'The honeypot runs lightweight fake services (SSH, HTTP, Telnet, RDP, MSSQL, MySQL, Redis, VNC, FTP) on attacker-magnet ports. Each sends a realistic banner and reads up to 2 KB of payload before closing. Any connection to these ports is inherently suspicious — no legitimate user should be contacting them. Probes from RFC1918 / loopback addresses are filtered out so internal scans don’t generate noise.' },
      { heading: 'Payload classification', body: 'Each probe is classified into one of four categories — credential_brute_force, exploit_attempt, recon, or port_scan — using a curated pattern dictionary with service-specific multipliers (SSH brute-force scores 1.5× on the SSH honeypot, SQLi scores 1.3× on MySQL/MSSQL).' },
      { heading: 'Fingerprint clustering', body: 'A lightweight clusterer groups probes by label + port overlap + recency + same /24 subnet, up to 20 active clusters. The dashboard shows "27 probes from the same /24 trying credential brute force" instead of 27 separate alerts.' },
      { heading: 'Auto-feed to IDS', body: 'Probes scoring ≥ 0.7 with exploit_attempt or credential_brute_force labels are forwarded to the IDS for blocking. Full payload previews are kept so you can review exactly what an attacker sent.' },
    ],
  },
  {
    icon: '⊗',
    title: 'Blocked IPs',
    path: '/blocked',
    summary: 'Manage the firewall IP blocklist — view, add, and remove blocked addresses.',
    details: [
      { heading: 'Automatic blocks', body: 'IPs can be added automatically by the IDS or Honeypot when they exceed a threat threshold. Auto-blocked IPs are tagged "Auto" in the source column.' },
      { heading: 'Manual block', body: 'Enter any IPv4 address and an optional reason to add it to the firewall immediately. Useful for blocking IPs identified through external threat intelligence.' },
      { heading: 'Unblock', body: 'Click Unblock on any row to remove the IP from the firewall. The change takes effect immediately. Use this if a legitimate IP was blocked by mistake.' },
      { heading: 'Under the hood', body: 'Blocks are applied via iptables (or nftables depending on your OS). The dashboard manages the rules — you do not need to touch the command line.' },
    ],
  },
  {
    icon: '⚙',
    title: 'Settings',
    path: '/settings',
    summary: 'Account security and AI privacy configuration.',
    details: [
      { heading: 'Security tab — Two-Factor Authentication', body: 'Enable TOTP 2FA for your account. Scan the QR code with any authenticator app (Google Authenticator, Authy, 1Password, etc.). Once enabled, every login requires a 6-digit code in addition to your password. Disable requires entering a current 2FA code, so a stolen session cannot turn it off.' },
      { heading: 'Security tab — Password change', body: 'Change your dashboard password. Requires entering your current password. Minimum 8 characters. Choose a strong password — the dashboard has full control over your system\'s security configuration.' },
      { heading: 'Account tab', body: 'Read-only view of your account: username, email, admin role, account creation date, last login, and current 2FA status.' },
      { heading: 'AI & Privacy tab — Federated Learning', body: 'Opt-in only. When enabled, your device uploads its anomaly model weight tensors (with Gaussian differential privacy noise applied — ε ≈ 0.0005 per upload) every 24 hours and downloads the aggregated community weights every 12 hours. Downloads are blended 30% community / 70% local so your detector improves without losing environment-specific learning. Only model weights are transmitted — never logs, IPs, usernames, or hostnames. An anonymous random node ID is generated locally and never linked to any system identifier. Toggle off at any time.' },
      { heading: 'AI & Privacy tab — Privacy budget display', body: 'Shows total uploads, total downloads, last sync timestamps, your anonymous node ID prefix, and the cumulative differential-privacy ε spent so far. Useful for verifying your privacy guarantees.' },
      { heading: 'Where do I tune AI thresholds?', body: 'Threshold tuning (anomaly sensitivity, IDS alert threshold, contamination factor, etc.) lives in /etc/ai-sbc-security/config.yaml on the device — see the Configuration section of the GitHub README. Restart the service after editing: sudo systemctl restart ai-sbc-security.' },
    ],
  },
]

export default function Help() {
  const [openIdx, setOpenIdx] = useState(null)

  return (
    <div style={{ padding: 24 }}>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Help &amp; Documentation</h2>
        <p style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
          Learn what each section of the dashboard does and how to use it effectively.
        </p>
      </div>

      {/* Quick nav chips */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 24 }}>
        {SECTIONS.map((s, i) => (
          <button key={i}
            onClick={() => setOpenIdx(openIdx === i ? null : i)}
            style={{
              padding: '5px 12px', borderRadius: 99, fontSize: 12, fontWeight: 600,
              cursor: 'pointer', border: '1px solid var(--border-md)',
              background: openIdx === i ? 'var(--accent)' : 'var(--bg-surface)',
              color: openIdx === i ? '#fff' : 'var(--text-2)',
              transition: 'all 0.15s',
            }}>
            {s.icon} {s.title}
          </button>
        ))}
      </div>

      {/* Section cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {SECTIONS.map((section, i) => (
          <motion.div key={i} className="card"
            style={{ overflow: 'hidden' }}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.03 }}>

            {/* Section header / toggle */}
            <div
              onClick={() => setOpenIdx(openIdx === i ? null : i)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '14px 18px', cursor: 'pointer',
                borderBottom: openIdx === i ? '1px solid var(--border)' : 'none',
              }}>
              <span style={{ fontSize: 20, flexShrink: 0 }}>{section.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)' }}>
                  {section.title}
                  <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-3)', fontFamily: 'var(--font-mono)', marginLeft: 8 }}>
                    {section.path}
                  </span>
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 2 }}>
                  {section.summary}
                </div>
              </div>
              <span style={{ fontSize: 13, color: 'var(--text-3)', flexShrink: 0 }}>
                {openIdx === i ? '▲' : '▼'}
              </span>
            </div>

            {/* Details */}
            <AnimatePresence>
              {openIdx === i && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.22 }}
                  style={{ overflow: 'hidden' }}>
                  <div style={{ padding: '16px 18px 18px', display: 'flex', flexDirection: 'column', gap: 14 }}>
                    {section.details.map((d, j) => (
                      <div key={j}>
                        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                          {d.heading}
                        </div>
                        <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.65, margin: 0 }}>
                          {d.body}
                        </p>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

          </motion.div>
        ))}
      </div>

      {/* Footer */}
      <div style={{ marginTop: 24, padding: '16px 18px', borderRadius: 10, background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <p style={{ fontSize: 13, color: 'var(--text-3)', margin: 0, lineHeight: 1.6 }}>
          Need more help? Check the{' '}
          <a href="https://github.com/fahimrahmanbooom/ai-sbc-security" target="_blank" rel="noopener noreferrer"
            style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>
            GitHub repository
          </a>{' '}
          for full documentation, issue tracking, and community discussions. Found a bug? Open an issue — contributions are very welcome.
        </p>
      </div>
    </div>
  )
}
