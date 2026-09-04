import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import LogoMark from "./LogoMark";

export default function LoginModal() {
  const { signIn, signUp } = useAuth();
  const [mode, setMode] = useState("signin"); // 'signin' | 'signup'
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const demoEmail = import.meta.env.VITE_DEMO_EMAIL;
  const demoPassword = import.meta.env.VITE_DEMO_PASSWORD;
  const demoAvailable = Boolean(demoEmail && demoPassword);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    const action = mode === "signin" ? signIn : signUp;
    const { error } = await action(email, password);
    setBusy(false);
    if (error) setError(error.message);
  }

  async function tryDemo() {
    setError("");
    setBusy(true);
    const { error } = await signIn(demoEmail, demoPassword);
    setBusy(false);
    if (error) setError("Demo login isn't set up on this instance yet.");
  }

  return (
    <div style={styles.overlay}>
      <form style={styles.card} onSubmit={handleSubmit}>
        <div style={styles.brandRow}>
          <div style={styles.brandMark}><LogoMark size={18} /></div>
          <h1 style={styles.title}>DetectIQ</h1>
        </div>
        <p style={styles.sub}>
          {mode === "signin" ? "Sign in to your workspace" : "Create a demo account"}
        </p>

        <input
          className="input"
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          style={{ marginBottom: 10 }}
        />
        <input
          className="input"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          style={{ marginBottom: 14 }}
        />

        {error && <div style={styles.error}>{error}</div>}

        <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "Working..." : mode === "signin" ? "Sign in" : "Create account"}
        </button>

        {demoAvailable && (
          <button type="button" className="btn" onClick={tryDemo} disabled={busy} style={{ width: "100%", marginTop: 8 }}>
            Try the demo — no signup
          </button>
        )}

        <button
          type="button"
          onClick={() => setMode(mode === "signin" ? "signup" : "signin")}
          style={styles.switchLink}
        >
          {mode === "signin" ? "Need an account? Sign up" : "Have an account? Sign in"}
        </button>
      </form>
    </div>
  );
}

const styles = {
  overlay: {
    position: "fixed",
    inset: 0,
    background: "var(--bg)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  card: {
    width: 320,
    padding: 28,
    borderRadius: "var(--radius)",
    border: "1px solid var(--border)",
    background: "var(--panel)",
  },
  title: { fontFamily: "var(--mono)", fontSize: 20, margin: 0, fontWeight: 600 },
  brandRow: { display: "flex", alignItems: "center", gap: 10, marginBottom: 4 },
  brandMark: {
    width: 30, height: 30, borderRadius: 7, background: "var(--panel-2)",
    border: "1px solid var(--border-strong)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
  },
  sub: { color: "var(--text-muted)", fontSize: 13, margin: "0 0 18px 0" },
  error: { color: "var(--red)", fontSize: 12.5, marginBottom: 12 },
  switchLink: {
    background: "none",
    border: "none",
    color: "var(--cyan)",
    fontSize: 12.5,
    marginTop: 12,
    cursor: "pointer",
    width: "100%",
  },
};
