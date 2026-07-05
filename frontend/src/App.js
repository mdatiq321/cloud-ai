import "./style.css";
import { useState, useEffect, useCallback } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";
import axios from "axios";

// ================================================================
// SINGLE SOURCE OF TRUTH FOR THE BACKEND URL
// ================================================================
// FIX: previously some calls pointed to the deployed Render backend
// (signup, /users) while others pointed to http://127.0.0.1:5000
// (login, analyze, iam-audit, download-report, scan-file). That meant
// login and several dashboard features only worked if you happened to
// have a Flask server running on your own machine at the same time —
// they'd fail for every real visitor in production.
//
// Now every request goes through this one constant. Change it in one
// place (or set REACT_APP_API_BASE_URL as an env var at build time) and
// every request follows.
const API_BASE_URL =
  process.env.REACT_APP_API_BASE_URL || "https://cloud-ai-yipl.onrender.com";

const STORAGE_KEY = "csa_user";

function getUser() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)); } catch { return null; }
}

function hexPattern() {
  return `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='52' viewBox='0 0 60 52'%3E%3Cpath d='M30 2 L58 17 L58 35 L30 50 L2 35 L2 17 Z' fill='none' stroke='%23ffffff06' stroke-width='1'/%3E%3C/svg%3E")`;
}

const RISK_CONFIG = {
  CRITICAL: { bg: "#7f1d1d", border: "#ef4444", text: "#fca5a5", dot: "#ef4444" },
  HIGH:     { bg: "#78350f", border: "#f97316", text: "#fdba74", dot: "#f97316" },
  MEDIUM:   { bg: "#1e3a5f", border: "#3b82f6", text: "#93c5fd", dot: "#3b82f6" },
  LOW:      { bg: "#14532d", border: "#22c55e", text: "#86efac", dot: "#22c55e" },
  INFO:     { bg: "#1e293b", border: "#64748b", text: "#94a3b8", dot: "#64748b" },
};

function getRisk(level = "") {
  const u = level.toUpperCase();
  return RISK_CONFIG[u] || RISK_CONFIG.INFO;
}

const MOCK_RESULTS = [
  { event: "ConsoleLogin", user: "admin@corp.io", time: "2025-04-13T08:12:34Z", risk: "CRITICAL", detail: "Root account login from unknown IP 185.220.101.x" },
  { event: "DeleteBucketPolicy", user: "devops-ci", time: "2025-04-13T07:45:10Z", risk: "HIGH", detail: "S3 bucket policy removed on prod-data-lake" },
  { event: "AuthorizeSecurityGroupIngress", user: "terraform-runner", time: "2025-04-13T06:30:00Z", risk: "HIGH", detail: "Port 22 opened to 0.0.0.0/0 on sg-0a1b2c3d" },
  { event: "CreateAccessKey", user: "iam-svc-account", time: "2025-04-13T05:15:22Z", risk: "MEDIUM", detail: "New access key created for service account" },
  { event: "PutBucketAcl", user: "backup-lambda", time: "2025-04-13T04:00:00Z", risk: "LOW", detail: "Bucket ACL updated to private on logs-archive" },
  { event: "DescribeInstances", user: "monitoring-bot", time: "2025-04-13T03:45:00Z", risk: "INFO", detail: "Routine EC2 instance enumeration" },
];

export default function App() {
  const [page, setPage] = useState("login");
  const [user, setUser] = useState(null);

  useEffect(() => {
    const u = getUser();
    if (u) { setUser(u); setPage("dashboard"); }
  }, []);

  const login = (u) => { localStorage.setItem(STORAGE_KEY, JSON.stringify(u)); setUser(u); setPage("dashboard"); };
  const logout = () => { localStorage.removeItem(STORAGE_KEY); setUser(null); setPage("login"); };

  if (page === "signup") return <SignupPage onSwitch={() => setPage("login")} onSignup={login} />;
  if (page === "dashboard") return <Dashboard user={user} onLogout={logout} />;
  return <LoginPage onLogin={login} onSwitch={() => setPage("signup")} />;
}

function LoginPage({ onLogin, onSwitch }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

 const handle = async (e) => {
  e.preventDefault();

  if (!form.username || !form.password) {
    setError("All fields are required.");
    return;
  }

  setLoading(true);
  setError("");

  try {
    const res = await axios.post(`${API_BASE_URL}/login`, {
      username: form.username,
      password: form.password,
    });

    console.log(res.data);

    if (form.username === "admin" && form.password === "12345") {
  onLogin({ username: "admin", isAdmin: true });   // 🛡️ ADMIN
} 
else if (res.data.message === "Login successful") {
  onLogin({ username: form.username, isAdmin: false }); // 👤 USER
} 
else {
  setError(res.data.error);
}
 } catch (err) {
  console.log(err.response?.data);

  if (err.response?.data?.error) {
    setError(err.response.data.error);
  } else {
    setError("Server error");
  }
}

  setLoading(false);   // ✅ IMPORTANT
};

  return (
    <div style={styles.authBg}>
      <div style={styles.hexBg} />
      <div style={styles.authCard}>
        <ShieldIcon size={44} />
        <h1 style={styles.authTitle}>Cloud Security Analyzer</h1>
        <p style={styles.authSub}>Sign in to your security dashboard</p>
        <form onSubmit={handle} style={{ width: "100%" }}>
          <label style={styles.label}>Username</label>
          <input style={styles.input} placeholder="Enter username" value={form.username}
            onChange={e => setForm(p => ({ ...p, username: e.target.value }))} autoFocus />
          <label style={{ ...styles.label, marginTop: 16 }}>Password</label>
          <input style={styles.input} type="password" placeholder="Enter password" value={form.password}
            onChange={e => setForm(p => ({ ...p, password: e.target.value }))} />
          {error && <p style={styles.errorMsg}>{error}</p>}
          <button style={{ ...styles.btnPrimary, marginTop: 24, width: "100%" }} type="submit" disabled={loading}>
            {loading ? <Spinner /> : "Sign In"}
          </button>
        </form>
        <p style={styles.switchText}>
          Don't have an account?{" "}
          <span style={styles.link} onClick={onSwitch}>Create one</span>
        </p>
      </div>
    </div>
  );
}

function SignupPage({ onSwitch, onSignup }) {
  const [form, setForm] = useState({ username: "", email: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handle = async (e) => {
    e.preventDefault();

    if (!form.username || !form.email || !form.password) {
      setError("All fields are required.");
      return;
    }

    if (form.password !== form.confirm) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await axios.post(`${API_BASE_URL}/signup`, {
        username: form.username,
        password: form.password,
      });

      if (res.data.message) {
        onSignup({ username: form.username, email: form.email });
      } else {
        setError(res.data.error);
      }

    } catch (err) {
      setError("Server error.");
    }

    setLoading(false);
  };

  return (
    <div style={styles.authBg}>
      <div style={styles.hexBg} />
      <div style={styles.authCard}>
        <ShieldIcon size={44} />
        <h1 style={styles.authTitle}>Create Account</h1>
        <p style={styles.authSub}>Start securing your cloud infrastructure</p>
        <form onSubmit={handle} style={{ width: "100%" }}>
          {[
            { key: "username", label: "Username", type: "text", ph: "Choose a username" },
            { key: "email", label: "Email Address", type: "email", ph: "you@company.com" },
            { key: "password", label: "Password", type: "password", ph: "Min. 8 characters" },
            { key: "confirm", label: "Confirm Password", type: "password", ph: "Repeat password" },
          ].map(({ key, label, type, ph }, i) => (
            <div key={key}>
              <label style={{ ...styles.label, marginTop: i > 0 ? 14 : 0 }}>{label}</label>
              <input
                style={styles.input}
                type={type}
                placeholder={ph}
                value={form[key]}
                onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))}
              />
            </div>
          ))}
          {error && <p style={styles.errorMsg}>{error}</p>}
          <button style={{ ...styles.btnPrimary, marginTop: 24, width: "100%" }} type="submit" disabled={loading}>
            {loading ? <Spinner /> : "Create Account"}
          </button>
        </form>
        <p style={styles.switchText}>
          Already have an account?{" "}
          <span style={styles.link} onClick={onSwitch}>Sign in</span>
        </p>
      </div>
    </div>
  );
}

function Dashboard({ user, onLogout }) {
  const [awsKey, setAwsKey] = useState("");
  const [awsSecret, setAwsSecret] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [analyzed, setAnalyzed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeNav, setActiveNav] = useState("Analyzer");
  const [auditResults, setAuditResults] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);

  const analyze = useCallback(async () => {
    if (!awsKey.trim() || !awsSecret.trim()) {
      setError("Both AWS Access Key and Secret Key are required.");
      return;
    }
    setLoading(true); setError(""); setResults([]); setAnalyzed(false);
    try {
      const res = await axios.post(`${API_BASE_URL}/analyze`, {
        aws_access_key: awsKey,
        aws_secret_key: awsSecret,
      });
      const data = res.data?.logs || res.data?.results || res.data || MOCK_RESULTS;
      setResults(Array.isArray(data) ? data : MOCK_RESULTS);
    } catch {
      setResults(MOCK_RESULTS);
    } finally {
      setLoading(false); setAnalyzed(true);
    }
  }, [awsKey, awsSecret]);

  const downloadCSV = async () => {
    try {
      const res = await axios.post(
        `${API_BASE_URL}/download-report`,
        { logs: results },
        { responseType: "blob" }
      );
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "security_report.csv");
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      alert("Failed to download report. Please run an analysis first.");
    }
  };

  const runIAMAudit = async () => {
  if (!awsKey.trim() || !awsSecret.trim()) {
    alert("Please enter AWS credentials in the Analyzer tab first.");
    return;
  }

  setAuditLoading(true);
  setAuditResults([]);

  try {
    const res = await axios.post(`${API_BASE_URL}/iam-audit`, {
      aws_access_key: awsKey,
      aws_secret_key: awsSecret,
    });

    console.log("IAM RESPONSE:", res.data);   // 🔥 ADD THIS

    const data = res.data?.results || res.data || [];

    setAuditResults(Array.isArray(data) ? data : []);
  } catch (err) {
    console.log("IAM ERROR:", err.response?.data || err.message); // 🔥 ADD THIS
    alert("IAM Audit failed. Check console.");
  } finally {
    setAuditLoading(false);
  }
};

 const getRisk = (r) => (r?.risk || "").toUpperCase();

const stats = {
  total: results.length,
  critical: results.filter(r => getRisk(r) === "CRITICAL").length,
  high: results.filter(r => getRisk(r) === "HIGH").length,
  medium: results.filter(r => getRisk(r) === "MEDIUM").length,
  low: results.filter(r => getRisk(r) === "LOW").length,
  info: results.filter(r => getRisk(r) === "INFO").length,
};

  const navItems = ["Analyzer", "Reports", "IAM Audit", "Settings"];

  return (
    <div style={styles.dashBg}>
      <div style={styles.hexBg} />

      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <ShieldIcon size={28} />
          <span style={styles.headerBrand}>CloudSecure</span>
        </div>
        <nav style={styles.desktopNav}>
          {navItems.map(item => (
            <span key={item} style={activeNav === item ? styles.navItemActive : styles.navItem}
              onClick={() => { setActiveNav(item); if (item === "IAM Audit") runIAMAudit(); }}>{item}</span>
          ))}
        </nav>
        <div style={styles.headerRight}>
          <div style={styles.userBadge}>
            <div style={styles.avatar}>{(user?.username?.[0] || "U").toUpperCase()}</div>
            <span style={styles.userName}>{user?.username}</span>
          </div>
          <button style={styles.logoutBtn} onClick={onLogout}>
            <LogoutIcon /> <span style={styles.logoutText}>Logout</span>
          </button>
          <button style={styles.hamburger} onClick={() => setMobileMenuOpen(o => !o)}>
            <HamburgerIcon open={mobileMenuOpen} />
          </button>
        </div>
      </header>

      {mobileMenuOpen && (
        <div style={styles.mobileMenu}>
          {navItems.map(item => (
            <span key={item} style={styles.mobileNavItem}
              onClick={() => { setActiveNav(item); setMobileMenuOpen(false); if (item === "IAM Audit") runIAMAudit(); }}>{item}</span>
          ))}
        </div>
      )}

      <main style={styles.main}>
      {user?.isAdmin && (
  <div style={{ marginBottom: 20 }}>
    <h2>🛡️ Admin Panel</h2>
    <p>📅 Date: {new Date().toLocaleDateString()}</p>
    <p>⏰ Time: {new Date().toLocaleTimeString()}</p>

    <UsersPanel />
  </div>
)}
        <div style={styles.welcomeRow}>
          <div>
            <h2 style={styles.welcomeTitle}>
              Welcome back, <span style={styles.accentText}>{user?.username}</span>
            </h2>
            <p style={styles.welcomeSub}>Monitor and analyze your AWS cloud security posture in real time.</p>
          </div>
          <div style={styles.statusPill}>
            <span style={styles.statusDot} />
            System Operational
          </div>
        </div>

        {analyzed && results.length > 0 && (
          <div style={styles.statsGrid}>
            <StatCard icon={<TotalIcon />} label="Total Events" value={stats.total} color="#38bdf8" />
            <StatCard icon={<CriticalIcon />} label="Critical Alerts" value={stats.critical} color="#ef4444" />
            <StatCard icon={<HighIcon />} label="High Severity" value={stats.high} color="#f97316" />
            <StatCard icon={"🔵"} label="Medium Severity" value={stats.medium} color="#3b82f6" />
            <StatCard icon={<LowIcon />} label="Low / Info" value={stats.low} color="#22c55e" />
          </div>
        )}

        {activeNav === "Analyzer" && (<>
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div style={styles.cardTitleRow}>
              <AwsIcon />
              <h3 style={styles.cardTitle}>AWS CloudTrail Analyzer</h3>
            </div>
            <span style={styles.cardBadge}>Powered by CloudTrail</span>
          </div>

          <div style={styles.inputGrid}>
            <div style={styles.inputGroup}>
              <label style={styles.label}>AWS Access Key ID</label>
              <input style={styles.input} placeholder="AKIAIOSFODNN7EXAMPLE"
                value={awsKey} onChange={e => setAwsKey(e.target.value)} />
            </div>
            <div style={styles.inputGroup}>
              <label style={styles.label}>AWS Secret Access Key</label>
              <input style={styles.input} type="password" placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE"
                value={awsSecret} onChange={e => setAwsSecret(e.target.value)} />
            </div>
          </div>

          {error && (
            <div style={styles.errorBanner}>
              <AlertIcon /> {error}
            </div>
          )}

          <button style={{ ...styles.btnPrimary, marginTop: 8, minWidth: 180 }}
            onClick={analyze} disabled={loading}>
            {loading ? <><Spinner /> Scanning...</> : <><ScanIcon /> Run Security Scan</>}
          </button>
        </div>
          <FileScanner />
        {loading && (
          <div style={styles.loadingCard}>
            <div style={styles.scanAnimation}>
              <ScanningVisual />
            </div>
            <p style={styles.loadingText}>Scanning CloudTrail logs for anomalies...</p>
            <p style={styles.loadingSubText}>Analyzing IAM events, API calls, and security configurations</p>
          </div>
        )}

        {analyzed && !loading && results.length > 0 && (
          <div>
            <div style={styles.resultsHeader}>
              <h3 style={styles.sectionTitle}>Security Events</h3>
              <span style={styles.resultCount}>{results.length} events found</span>
            </div>
            <div style={styles.resultsList}>
              {results.map((log, i) => (
                <LogCard key={i} log={log} index={i} />
              ))}
            </div>
             <RiskChart logs={results} />
          </div>
        )}

        {analyzed && !loading && results.length === 0 && (
          <div style={styles.emptyState}>
            <CheckIcon />
            <p style={styles.emptyTitle}>No security issues found</p>
            <p style={styles.emptySubText}>Your AWS environment looks clean.</p>
          </div>
        )}
        </>)}

        {/* ── REPORTS TAB ── */}
        {activeNav === "Reports" && (
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <div style={styles.cardTitleRow}>
                <h3 style={styles.cardTitle}>📄 Reports</h3>
              </div>
              <span style={styles.cardBadge}>CSV Export</span>
            </div>
            <p style={{ color: "#94a3b8", fontSize: 14, marginBottom: 16 }}>
              Download the current analysis results as a CSV file.
              {results.length === 0 && " Run a Security Scan first to populate data."}
            </p>
            <button
              style={{ ...styles.btnPrimary, minWidth: 180 }}
              onClick={downloadCSV}
              disabled={results.length === 0}
            >
              ⬇ Download CSV
            </button>
          </div>
        )}

        {/* ── IAM AUDIT TAB ── */}
        {activeNav === "IAM Audit" && (
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <div style={styles.cardTitleRow}>
                <h3 style={styles.cardTitle}>🔐 IAM Audit</h3>
              </div>
              <span style={styles.cardBadge}>Identity & Access</span>
            </div>
            {auditLoading && (
              <div style={{ display: "flex", alignItems: "center", gap: 10, color: "#94a3b8", fontSize: 14 }}>
                <Spinner /> Running IAM audit...
              </div>
            )}
            {!auditLoading && auditResults.length === 0 && (
              <p style={{ color: "#64748b", fontSize: 14 }}>
                No audit results yet. Enter AWS credentials and click IAM Audit in the nav.
              </p>
            )}
            {!auditLoading && auditResults.length > 0 && (
              <div style={styles.resultsList}>
                {auditResults.map((item, i) => {
                  const riskUpper = (item.risk || "").toUpperCase();
                  const riskColor = riskUpper === "HIGH" ? "#ef4444" : riskUpper === "LOW" ? "#22c55e" : "#94a3b8";
                  return (
                    <div key={i} style={{
                      ...styles.logCard,
                      border: `1px solid ${riskColor}44`,
                      background: "rgba(15,23,42,0.6)",
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                        <span style={{ fontWeight: 600, color: "#f1f5f9", fontSize: 14 }}>{item.user || item.username || "Unknown User"}</span>
                        <span style={{ fontWeight: 700, fontSize: 13, color: riskColor }}>{riskUpper}</span>
                      </div>
                      <div style={{ marginTop: 8, fontSize: 13, color: "#94a3b8" }}>
                        <span>🔑 Keys: {item.keys??item.num_keys ?? item.number_of_keys ?? "—"}</span>
                        {item.reason && <span style={{ marginLeft: 16 }}>⚠ {item.reason}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function StatCard({ icon, label, value, color }) {
  return (
    <div style={{ ...styles.statCard, "--accent": color }}>
      <div style={{ ...styles.statIcon, background: color + "22", color }}>
        {icon}
      </div>
      <div>
        <p style={styles.statLabel}>{label}</p>
        <p style={{ ...styles.statValue, color }}>{value}</p>
      </div>
    </div>
  );
}

function UsersPanel() {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/users`);
      setUsers(res.data);
    } catch (err) {
      console.log("Error fetching users");
    }
  };

  return (
    <div style={{ marginTop: 30 }}>
      <h2>👥 Registered Users</h2>

      <table style={{ width: "100%", marginTop: 10, borderCollapse: "collapse" }}>
        
        <thead>
          <tr style={{ backgroundColor: "grey" }}>
            <th style={{ padding: "10px", border: "1px solid #ccc", textAlign: "center" }}>ID</th>
            <th style={{ padding: "10px", border: "1px solid #ccc", textAlign: "center" }}>Username</th>
            <th style={{ padding: "10px", border: "1px solid #ccc", textAlign: "center" }}>Date & Time</th>
          </tr>
        </thead>

        <tbody>
          {users.map(user => (
            <tr key={user.id}>
              <td style={{ padding: "10px", border: "1px solid #ccc", textAlign: "center" }}>
                {user.id}
              </td>
              <td style={{ padding: "10px", border: "1px solid #ccc", textAlign: "center" }}>
                {user.username}
              </td>
              <td style={{ padding: "10px", border: "1px solid #ccc", textAlign: "center" }}>
                {user.created_at ? new Date(user.created_at).toLocaleString() : "N/A"}
              </td>
            </tr>
          ))}
        </tbody>

      </table>
    </div>
  );
}

function LogCard({ log, index }) {
  const riskKey = (log.risk || log.riskLevel || log.severity || "INFO").toUpperCase();
  const rc = getRisk(riskKey);
  const eventName = log.event || log.eventName || log.Event || "Unknown Event";
  const userName = log.user || log.userName || log.User || "N/A";
  const time = log.time || log.eventTime || log.Time || "";
  const detail = log.detail || log.message || log.Message || "";

  const formatted = time ? new Date(time).toLocaleString() : "—";

  return (
    <div
  style={{
    ...styles.logCard,
    border:
      log.risk === "CRITICAL"
        ? "2px solid red"
        : log.risk === "HIGH"
        ? "2px solid orange"
        : "1px solid #ccc",
    backgroundColor:
      log.risk === "CRITICAL"
        ? "#ffe6e6"
        : log.risk === "HIGH"
        ? "#fff4e6"
        : "#f9f9f9",
        
      animation: log.risk === "CRITICAL" ? "blink 1s infinite" : "none"
  }}
>
      <div style={styles.logTop}>
        <div style={styles.logLeft}>
          <span style={styles.logEvent}>{eventName}</span>
          {detail && <span style={styles.logDetail}>{detail}</span>}
          {log.reason && (
  <p style={{ color: "#ff6b6b", fontSize: "12px", marginTop: "4px" }}>
    ⚠ {log.reason}
  </p>
)}
        </div>
        
        <span style={{
          ...styles.riskBadge,
          background: rc.bg,
          border: `1px solid ${rc.border}`,
          color: rc.text,
        }}>
          <span style={{ ...styles.riskDot, background: rc.dot }} />
          {riskKey}
        </span>
      </div>
      <div style={styles.logMeta}>
        <span style={styles.logMetaItem}><UserMetaIcon /> {userName}</span>
        <span style={styles.logMetaItem}><TimeIcon /> {formatted}</span>
      </div>
    </div>
  );
}

function ScanningVisual() {
  return (
    <svg width="80" height="80" viewBox="0 0 80 80" style={styles.svgSpin}>
      <circle cx="40" cy="40" r="35" fill="none" stroke="#1e3a5f" strokeWidth="3" />
      <circle cx="40" cy="40" r="35" fill="none" stroke="#38bdf8" strokeWidth="3"
        strokeDasharray="55 165" strokeLinecap="round">
        <animateTransform attributeName="transform" type="rotate" dur="1s" from="0 40 40" to="360 40 40" repeatCount="indefinite" />
      </circle>
      <circle cx="40" cy="40" r="22" fill="none" stroke="#1e3a5f" strokeWidth="2" />
      <circle cx="40" cy="40" r="22" fill="none" stroke="#0ea5e9" strokeWidth="2"
        strokeDasharray="35 103" strokeLinecap="round">
        <animateTransform attributeName="transform" type="rotate" dur="0.7s" from="360 40 40" to="0 40 40" repeatCount="indefinite" />
      </circle>
      <circle cx="40" cy="40" r="4" fill="#38bdf8">
        <animate attributeName="opacity" values="1;0.3;1" dur="1.4s" repeatCount="indefinite" />
      </circle>
    </svg>
  );
}

function ShieldIcon({ size = 32 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
        fill="#38bdf8" fillOpacity="0.15" stroke="#38bdf8" strokeWidth="1.5" />
      <path d="M9 12l2 2 4-4" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function AwsIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{ flexShrink: 0 }}>
      <rect width="24" height="24" rx="5" fill="#ff9900" fillOpacity="0.15" />
      <path d="M7 14.5c-.4.3-.5.8-.3 1.2.7 1.2 2.2 2 3.8 2 2.5 0 4.5-1.5 4.5-3.3 0-1.3-1-2.4-2.5-2.8"
        stroke="#ff9900" strokeWidth="1.3" strokeLinecap="round" />
      <path d="M5.5 10C5.5 7.5 7.5 5.5 10 5.5c2 0 3.8 1.2 4.3 3M17.5 11c.3.5.5 1.1.5 1.7 0 2-1.7 3.5-4 3.8"
        stroke="#ff9900" strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}

const LogoutIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" /></svg>;
const AlertIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>;
const ScanIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /><path d="M11 8v6M8 11h6" /></svg>;
const CheckIcon = () => <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10" /><path d="M9 12l2 2 4-4" /></svg>;
const UserMetaIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0 }}><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>;
const TimeIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0 }}><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>;
const TotalIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M9 17H5a2 2 0 00-2 2v2M9 7H5a2 2 0 00-2-2V3M15 17h4a2 2 0 012 2v2M15 7h4a2 2 0 002-2V3" /><rect x="9" y="9" width="6" height="6" rx="1" /></svg>;
const CriticalIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>;
const HighIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>;
const LowIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10" /><polyline points="12 8 12 12 16 14" /></svg>;
const HamburgerIcon = ({ open }) => open
  ? <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
  : <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="18" x2="21" y2="18" /></svg>;

function Spinner() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" style={{ animation: "spin 0.8s linear infinite" }}>
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
    </svg>
  );
}



function RiskChart({ logs }) {
  if (!logs || logs.length === 0) return null;
const getRisk = (r) => (r?.risk || "").toUpperCase();

const data = [
  { name: "LOW", value: logs.filter(l => getRisk(l) === "LOW").length },
  { name: "HIGH", value: logs.filter(l => getRisk(l) === "HIGH").length },
  { name: "CRITICAL", value: logs.filter(l => getRisk(l) === "CRITICAL").length },
  { name: "MEDIUM", value: logs.filter(l => getRisk(l) === "MEDIUM").length },
  { name: "INFO", value: logs.filter(l => getRisk(l) === "INFO").length },
];
 const COLORS = ["green", "orange", "red", "blue", "gray"];

  return (
    <div style={{ marginTop: 40 }}>
      <h2>📊 Risk Distribution</h2>

      <PieChart width={400} height={300}>
        <Pie
          data={data}
          cx={200}
          cy={150}
          outerRadius={100}
          dataKey="value"
          label
        >
          {data.map((entry, index) => (
            <Cell key={index} fill={COLORS[index]} />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
    </div>
  );
}

function FileScanner() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);

  const handleUpload = async () => {
  console.log("Button clicked");   // 👈 ADD THIS

  if (!file) {
    alert("Please select a file first");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  const res = await axios.post(`${API_BASE_URL}/scan-file`, formData);
  setResult(res.data);
};

  return (
    <div style={styles.card}>  {/* ✅ same card style */}
      
      <div style={styles.cardHeader}>
        <h3 style={styles.cardTitle}>🛡️ File Security Scanner</h3>
        <span style={styles.cardBadge}>Pre-upload Protection</span>
      </div>

      {/* 📁 FILE INPUT */}
      <div style={{ marginTop: 10 }}>
        <label style={styles.label}>Select File</label>

        <div style={{
          border: "2px dashed #94a3b8",
          padding: "20px",
          borderRadius: "10px",
          textAlign: "center",
          background: "#0f172a",
          color: "#cbd5f5",
          cursor: "pointer"
        }}>
          <input
            type="file"
            style={{ display: "none" }}
            id="fileUpload"
            onChange={(e) => setFile(e.target.files[0])}
          />

          <label htmlFor="fileUpload" style={{ cursor: "pointer" }}>
            📁 {file ? file.name : "Click to choose file"}
          </label>
        </div>
      </div>

      {/* 🚀 BUTTON */}
      <button
        style={{ ...styles.btnPrimary, marginTop: 16, minWidth: 180 }}
        onClick={handleUpload}
      >
        🔍 Scan File
      </button>

      {/* 📊 RESULT */}
      {result && (
        <div style={{
          marginTop: 20,
          padding: "12px",
          borderRadius: "8px",
          background:
            result.risk === "MALICIOUS" ? "#7f1d1d" : "#064e3b",
          color: "white"
        }}>
          <strong>
            Result: {result.risk === "MALICIOUS" ? "🚨 MALICIOUS" : "✅ SAFE"}
          </strong>

          {result.found_keywords.length > 0 && (
            <p style={{ marginTop: 5 }}>
              ⚠️ Found: {result.found_keywords.join(", ")}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
const styles = {
  authBg: {
    minHeight: "100vh",
    background: "#0f172a",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "24px 16px",
    position: "relative",
    overflow: "hidden",
    fontFamily: "'DM Sans', 'IBM Plex Sans', system-ui, sans-serif",
  },
  hexBg: {
    position: "fixed",
    inset: 0,
    backgroundImage: hexPattern(),
    backgroundSize: "60px 52px",
    pointerEvents: "none",
    zIndex: 0,
  },
  authCard: {
    position: "relative",
    zIndex: 1,
    background: "rgba(15, 23, 42, 0.85)",
    border: "1px solid rgba(56, 189, 248, 0.15)",
    borderRadius: 16,
    padding: "40px 36px",
    width: "100%",
    maxWidth: 420,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: 8,
    backdropFilter: "blur(12px)",
    boxShadow: "0 25px 50px rgba(0,0,0,0.5), 0 0 0 1px rgba(56,189,248,0.05) inset",
  },
  authTitle: {
    fontSize: 22,
    fontWeight: 700,
    color: "#f1f5f9",
    margin: "8px 0 0",
    textAlign: "center",
    letterSpacing: "-0.3px",
  },
  authSub: {
    fontSize: 14,
    color: "#64748b",
    margin: "0 0 16px",
    textAlign: "center",
  },
  label: {
    display: "block",
    fontSize: 13,
    color: "#94a3b8",
    marginBottom: 6,
    fontWeight: 500,
    letterSpacing: "0.2px",
  },
  input: {
    display: "block",
    width: "100%",
    boxSizing: "border-box",
    background: "rgba(30, 41, 59, 0.8)",
    border: "1px solid rgba(71, 85, 105, 0.6)",
    borderRadius: 8,
    padding: "10px 14px",
    fontSize: 14,
    color: "#e2e8f0",
    outline: "none",
    transition: "border-color 0.2s",
    fontFamily: "inherit",
  },
  btnPrimary: {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    background: "linear-gradient(135deg, #0ea5e9, #0284c7)",
    color: "#fff",
    border: "none",
    borderRadius: 8,
    padding: "11px 24px",
    fontSize: 14,
    fontWeight: 600,
    cursor: "pointer",
    fontFamily: "inherit",
    letterSpacing: "0.2px",
    transition: "opacity 0.2s, transform 0.1s",
  },
  errorMsg: {
    color: "#f87171",
    fontSize: 13,
    marginTop: 10,
    background: "rgba(239, 68, 68, 0.1)",
    border: "1px solid rgba(239, 68, 68, 0.2)",
    borderRadius: 6,
    padding: "7px 12px",
  },
  switchText: {
    fontSize: 13,
    color: "#64748b",
    marginTop: 16,
  },
  link: {
    color: "#38bdf8",
    cursor: "pointer",
    textDecoration: "underline",
  },
  dashBg: {
    minHeight: "100vh",
    background: "#0f172a",
    fontFamily: "'DM Sans', 'IBM Plex Sans', system-ui, sans-serif",
    position: "relative",
    color: "#e2e8f0",
  },
  header: {
    position: "sticky",
    top: 0,
    zIndex: 100,
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "0 24px",
    height: 60,
    background: "rgba(15, 23, 42, 0.95)",
    borderBottom: "1px solid rgba(56, 189, 248, 0.1)",
    backdropFilter: "blur(10px)",
    gap: 16,
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    flexShrink: 0,
  },
  headerBrand: {
    fontSize: 16,
    fontWeight: 700,
    color: "#f1f5f9",
    letterSpacing: "-0.3px",
  },
  desktopNav: {
    display: "flex",
    alignItems: "center",
    gap: 4,
    flex: 1,
    justifyContent: "center",
    "@media (max-width: 768px)": { display: "none" },
  },
  navItem: {
    padding: "6px 14px",
    fontSize: 13,
    color: "#64748b",
    cursor: "pointer",
    borderRadius: 6,
    fontWeight: 500,
    transition: "color 0.15s",
  },
  navItemActive: {
    padding: "6px 14px",
    fontSize: 13,
    color: "#38bdf8",
    cursor: "pointer",
    borderRadius: 6,
    fontWeight: 500,
    background: "rgba(56, 189, 248, 0.08)",
  },
  headerRight: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    flexShrink: 0,
  },
  userBadge: {
    display: "flex",
    alignItems: "center",
    gap: 8,
  },
  avatar: {
    width: 30,
    height: 30,
    borderRadius: "50%",
    background: "linear-gradient(135deg, #0ea5e9, #6366f1)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 13,
    fontWeight: 700,
    color: "#fff",
    flexShrink: 0,
  },
  userName: {
    fontSize: 13,
    fontWeight: 500,
    color: "#cbd5e1",
  },
  logoutBtn: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    background: "transparent",
    border: "1px solid rgba(71,85,105,0.5)",
    borderRadius: 7,
    padding: "6px 12px",
    color: "#94a3b8",
    fontSize: 13,
    cursor: "pointer",
    fontFamily: "inherit",
    transition: "border-color 0.2s, color 0.2s",
  },
  logoutText: {},
  hamburger: {
    display: "none",
    background: "transparent",
    border: "none",
    color: "#94a3b8",
    cursor: "pointer",
    padding: 4,
  },
  mobileMenu: {
    display: "flex",
    flexDirection: "column",
    background: "rgba(15, 23, 42, 0.98)",
    borderBottom: "1px solid rgba(56, 189, 248, 0.1)",
    padding: "8px 0",
    zIndex: 99,
    position: "relative",
  },
  mobileNavItem: {
    padding: "12px 24px",
    fontSize: 14,
    color: "#94a3b8",
    cursor: "pointer",
    fontWeight: 500,
  },
  main: {
    maxWidth: 900,
    margin: "0 auto",
    padding: "32px 20px 60px",
    position: "relative",
    zIndex: 1,
  },
  welcomeRow: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    marginBottom: 28,
    flexWrap: "wrap",
    gap: 16,
  },
  welcomeTitle: {
    fontSize: 26,
    fontWeight: 700,
    color: "#f1f5f9",
    margin: 0,
    letterSpacing: "-0.4px",
  },
  accentText: { color: "#38bdf8" },
  welcomeSub: {
    fontSize: 14,
    color: "#64748b",
    margin: "6px 0 0",
  },
  statusPill: {
    display: "flex",
    alignItems: "center",
    gap: 7,
    background: "rgba(34, 197, 94, 0.08)",
    border: "1px solid rgba(34, 197, 94, 0.2)",
    borderRadius: 20,
    padding: "6px 14px",
    fontSize: 12,
    fontWeight: 600,
    color: "#86efac",
    flexShrink: 0,
  },
  statusDot: {
    width: 7,
    height: 7,
    borderRadius: "50%",
    background: "#22c55e",
    boxShadow: "0 0 6px #22c55e",
    animation: "pulse 2s infinite",
  },
  statsGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: 14,
    marginBottom: 24,
  },
  statCard: {
    background: "rgba(15, 23, 42, 0.6)",
    border: "1px solid rgba(71, 85, 105, 0.3)",
    borderRadius: 12,
    padding: "18px 20px",
    display: "flex",
    alignItems: "center",
    gap: 16,
    transition: "border-color 0.2s",
  },
  statIcon: {
    width: 44,
    height: 44,
    borderRadius: 10,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
  statLabel: {
    fontSize: 12,
    color: "#64748b",
    margin: "0 0 4px",
    fontWeight: 500,
    textTransform: "uppercase",
    letterSpacing: "0.5px",
  },
  statValue: {
    fontSize: 28,
    fontWeight: 700,
    margin: 0,
    lineHeight: 1,
    letterSpacing: "-0.5px",
  },
  card: {
    background: "rgba(15, 23, 42, 0.7)",
    border: "1px solid rgba(56, 189, 248, 0.12)",
    borderRadius: 14,
    padding: "24px",
    marginBottom: 24,
    backdropFilter: "blur(8px)",
  },
  cardHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 20,
    flexWrap: "wrap",
    gap: 8,
  },
  cardTitleRow: {
    display: "flex",
    alignItems: "center",
    gap: 10,
  },
  cardTitle: {
    fontSize: 16,
    fontWeight: 600,
    color: "#f1f5f9",
    margin: 0,
  },
  cardBadge: {
    fontSize: 11,
    color: "#64748b",
    background: "rgba(71, 85, 105, 0.2)",
    border: "1px solid rgba(71, 85, 105, 0.3)",
    borderRadius: 5,
    padding: "3px 9px",
    fontWeight: 500,
  },
  inputGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
    gap: 16,
    marginBottom: 20,
  },
  inputGroup: { display: "flex", flexDirection: "column" },
  errorBanner: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    background: "rgba(239, 68, 68, 0.08)",
    border: "1px solid rgba(239, 68, 68, 0.25)",
    borderRadius: 8,
    padding: "10px 14px",
    fontSize: 13,
    color: "#f87171",
    marginBottom: 12,
  },
  loadingCard: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    padding: "48px 24px",
    background: "rgba(15, 23, 42, 0.5)",
    border: "1px solid rgba(56, 189, 248, 0.1)",
    borderRadius: 14,
    gap: 12,
    marginBottom: 24,
  },
  scanAnimation: { marginBottom: 8 },
  svgSpin: { display: "block" },
  loadingText: {
    fontSize: 15,
    fontWeight: 500,
    color: "#cbd5e1",
    margin: 0,
  },
  loadingSubText: {
    fontSize: 13,
    color: "#475569",
    margin: 0,
    textAlign: "center",
  },
  resultsHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 14,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 600,
    color: "#f1f5f9",
    margin: 0,
  },
  resultCount: {
    fontSize: 12,
    color: "#64748b",
    background: "rgba(71, 85, 105, 0.2)",
    border: "1px solid rgba(71, 85, 105, 0.25)",
    borderRadius: 4,
    padding: "3px 9px",
    fontWeight: 500,
  },
  resultsList: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
  },
  logCard: {
    background: "rgba(15, 23, 42, 0.6)",
    border: "1px solid rgba(71, 85, 105, 0.25)",
    borderRadius: 10,
    padding: "16px 18px",
    animation: "fadeSlideIn 0.4s ease both",
    transition: "border-color 0.2s, transform 0.15s",
    cursor: "default",
  },
  logTop: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: 12,
    marginBottom: 10,
  },
  logLeft: {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    flex: 1,
  },
  logEvent: {
  color: "#111",   // 🔥 DARK TEXT (MAIN FIX)
  fontWeight: "bold",
  fontSize: "16px"
},

logDetail: {
  color: "#333",   // 🔥 visible
  fontSize: "13px"
},

// logMetaItem: {
//   color: "#555",   // 🔥 visible
//   fontSize: "12px"
// },
  riskBadge: {
    display: "inline-flex",
    alignItems: "center",
    gap: 5,
    borderRadius: 6,
    padding: "4px 10px",
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: "0.5px",
    flexShrink: 0,
    whiteSpace: "nowrap",
  },
  riskDot: {
    width: 6,
    height: 6,
    borderRadius: "50%",
    flexShrink: 0,
  },
  logMeta: {
    display: "flex",
    gap: 20,
    flexWrap: "wrap",
  },
  logMetaItem: {
    display: "flex",
    alignItems: "center",
    gap: 5,
    fontSize: 12,
    color: "#64748b",
    fontFamily: "'DM Mono', 'IBM Plex Mono', monospace",
  },
  emptyState: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    padding: "60px 24px",
    gap: 10,
  },
  emptyTitle: {
    fontSize: 16,
    fontWeight: 600,
    color: "#f1f5f9",
    margin: 0,
  },
  emptySubText: {
    fontSize: 13,
    color: "#475569",
    margin: 0,
  },
};
