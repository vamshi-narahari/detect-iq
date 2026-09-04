import { useState, useRef, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Hammer,
  Compass,
  Layers,
  Library,
  Search,
  Inbox,
  Filter,
  FileEdit,
  Terminal,
  Settings,
  Bell,
  ChevronDown,
  Target,
  Repeat,
  Server,
  Crosshair,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { supabase } from "../lib/supabase";
import LogoMark from "../components/LogoMark";

const NAV_GROUPS = [
  {
    label: "AGENTS",
    items: [
      { to: "/blindspot", label: "Blindspot", icon: Crosshair },
    ],
  },
  {
    label: "BUILD",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
      { to: "/builder", label: "Builder", icon: Hammer },
      { to: "/leads", label: "Leads", icon: Compass },
      { to: "/packs", label: "Packs", icon: Layers },
      { to: "/coverage", label: "Coverage", icon: Target },
      { to: "/library", label: "Library", icon: Library },
    ],
  },
  {
    label: "OPERATE",
    items: [
      { to: "/search", label: "Search", icon: Search },
      { to: "/intake", label: "Intake", icon: Inbox },
      { to: "/allowlists", label: "Allowlists", icon: Filter },
      { to: "/editor", label: "Editor", icon: FileEdit },
      { to: "/translator", label: "Translator", icon: Repeat },
    ],
  },
  {
    label: "SYSTEM",
    items: [
      { to: "/macros", label: "Macros", icon: Terminal },
      { to: "/assets", label: "Assets", icon: Server },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

const TIMEZONES = ["UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "Europe/London", "Europe/Berlin", "Asia/Kolkata", "Asia/Singapore", "Australia/Sydney"];

function initials(email) {
  if (!email) return "?";
  return email.split("@")[0].slice(0, 2).toUpperCase();
}

export default function Shell({ children }) {
  const location = useLocation();
  const { user, profile, signOut, refreshProfile } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    function onClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) setMenuOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  async function updateTimezone(tz) {
    await supabase.from("profiles").update({ timezone: tz, updated_at: new Date().toISOString() }).eq("id", user.id);
    refreshProfile();
  }

  const current = NAV_GROUPS.flatMap((g) => g.items).find((n) =>
    n.end ? location.pathname === n.to : location.pathname.startsWith(n.to)
  );

  return (
    <div style={styles.shell}>
      <nav style={styles.sidebar} aria-label="Primary">
        <div style={styles.brand}>
          <div style={styles.mark} aria-hidden="true"><LogoMark size={16} /></div>
          <span style={styles.brandName}>DetectIQ</span>
        </div>

        {NAV_GROUPS.map((group) => (
          <div key={group.label} style={styles.group}>
            <div style={styles.groupLabel}>{group.label}</div>
            {group.items.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                style={({ isActive }) => ({ ...styles.navItem, ...(isActive ? styles.navItemActive : {}) })}
              >
                <Icon size={16} />
                <span>{label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div style={styles.main}>
        <header style={styles.topbar}>
          <span style={styles.crumb}>detectiq / {current?.label || ""}</span>
          <div style={styles.right}>
            <div style={styles.iconBtn} role="button" tabIndex={0} aria-label="Notifications">
              <Bell size={16} />
            </div>

            <div style={{ position: "relative" }} ref={menuRef}>
              <div style={styles.user} role="button" tabIndex={0} onClick={() => setMenuOpen(!menuOpen)}>
                {profile?.avatar_url ? (
                  <img src={profile.avatar_url} alt="" style={styles.avatarImg} />
                ) : (
                  <div style={styles.avatar}>{initials(user?.email)}</div>
                )}
                <ChevronDown size={14} />
              </div>

              {menuOpen && (
                <div style={styles.menu}>
                  <div style={styles.menuEmail}>{user?.email}</div>

                  <div style={styles.menuSection}>
                    <label style={styles.menuLabel}>Time zone</label>
                    <select className="input" value={profile?.timezone || "UTC"} onChange={(e) => updateTimezone(e.target.value)}>
                      {TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
                    </select>
                  </div>

                  <div style={styles.menuDivider} />

                  <a href="https://github.com/vamshi-narahari/detect-iq#readme" target="_blank" rel="noreferrer" style={styles.menuLink}>Documentation</a>
                  <a href="https://github.com/vamshi-narahari/detect-iq" target="_blank" rel="noreferrer" style={styles.menuLink}>Learn more</a>

                  <div style={styles.menuDivider} />

                  <button style={styles.menuSignOut} onClick={signOut}>Sign out</button>
                </div>
              )}
            </div>
          </div>
        </header>
        <main style={styles.content}>{children}</main>
      </div>
    </div>
  );
}

const styles = {
  shell: { display: "flex", minHeight: "100vh" },
  sidebar: {
    width: 220, background: "var(--panel)", borderRight: "1px solid var(--border)",
    display: "flex", flexDirection: "column", padding: "16px 12px", flexShrink: 0, overflowY: "auto",
  },
  brand: { display: "flex", alignItems: "center", gap: 8, padding: "0 4px", marginBottom: 20 },
  mark: {
    width: 26, height: 26, borderRadius: 6, background: "var(--panel-2)",
    border: "1px solid var(--border-strong)", display: "flex", alignItems: "center",
    justifyContent: "center", color: "var(--cyan)", flexShrink: 0,
  },
  brandName: { fontFamily: "var(--mono)", fontSize: 14, fontWeight: 600 },
  group: { marginBottom: 18 },
  groupLabel: {
    fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.08em", color: "var(--text-muted)",
    padding: "0 8px", marginBottom: 6, textTransform: "uppercase",
  },
  navItem: {
    display: "flex", alignItems: "center", gap: 10, padding: "8px 8px", borderRadius: "var(--radius-sm)",
    color: "var(--text-muted)", textDecoration: "none", fontSize: 13.5, marginBottom: 2,
  },
  navItemActive: { color: "var(--cyan)", background: "var(--panel-2)" },
  main: { flex: 1, display: "flex", flexDirection: "column", minWidth: 0 },
  topbar: {
    height: 52, borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center",
    padding: "0 20px", flexShrink: 0,
  },
  crumb: { fontFamily: "var(--mono)", fontSize: 12.5, color: "var(--text-muted)" },
  right: { marginLeft: "auto", display: "flex", alignItems: "center", gap: 14 },
  iconBtn: {
    width: 30, height: 30, display: "flex", alignItems: "center", justifyContent: "center",
    color: "var(--text-muted)", borderRadius: "var(--radius-sm)", cursor: "pointer",
  },
  user: {
    display: "flex", alignItems: "center", gap: 6, padding: "4px 8px 4px 4px",
    borderRadius: "var(--radius-sm)", cursor: "pointer", border: "1px solid var(--border)",
  },
  avatar: {
    width: 26, height: 26, borderRadius: "50%", background: "linear-gradient(135deg, var(--cyan), var(--amber))",
    display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10.5, fontWeight: 700,
    color: "#06141a", fontFamily: "var(--mono)", flexShrink: 0,
  },
  avatarImg: { width: 26, height: 26, borderRadius: "50%", objectFit: "cover", flexShrink: 0 },
  menu: {
    position: "absolute", top: "calc(100% + 8px)", right: 0, width: 260, background: "var(--panel)",
    border: "1px solid var(--border-strong)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-2)",
    padding: 14, zIndex: 40,
  },
  menuEmail: { fontFamily: "var(--mono)", fontSize: 12.5, color: "var(--text)", marginBottom: 12, wordBreak: "break-all" },
  menuSection: { display: "grid", gap: 6, marginBottom: 4 },
  menuLabel: { fontSize: 11, color: "var(--text-muted)" },
  menuDivider: { height: 1, background: "var(--border)", margin: "12px 0" },
  menuLink: { display: "block", fontSize: 13, color: "var(--text)", textDecoration: "none", padding: "6px 0" },
  menuSignOut: { background: "none", border: "none", color: "var(--red)", fontSize: 13, cursor: "pointer", padding: "6px 0", textAlign: "left", width: "100%" },
  content: { padding: 24, overflowY: "auto", flex: 1 },
};
