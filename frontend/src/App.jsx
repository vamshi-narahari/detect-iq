import { Routes, Route } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import RequireAuth from "./components/RequireAuth";
import Shell from "./components/Shell";
import Overview from "./pages/Overview";
import Blindspot from "./pages/Blindspot";
import Builder from "./pages/Builder";
import Leads from "./pages/Leads";
import Packs from "./pages/Packs";
import Coverage from "./pages/Coverage";
import DetectionLibrary from "./pages/DetectionLibrary";
import SearchPage from "./pages/Search";
import Intake from "./pages/Intake";
import Allowlists from "./pages/Allowlists";
import Editor from "./pages/Editor";
import Translator from "./pages/Translator";
import Macros from "./pages/Macros";
import Assets from "./pages/Assets";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <AuthProvider>
      <RequireAuth>
        <Shell>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/blindspot" element={<Blindspot />} />
            <Route path="/builder" element={<Builder />} />
            <Route path="/leads" element={<Leads />} />
            <Route path="/packs" element={<Packs />} />
            <Route path="/coverage" element={<Coverage />} />
            <Route path="/library" element={<DetectionLibrary />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/intake" element={<Intake />} />
            <Route path="/allowlists" element={<Allowlists />} />
            <Route path="/editor" element={<Editor />} />
            <Route path="/translator" element={<Translator />} />
            <Route path="/macros" element={<Macros />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </Shell>
      </RequireAuth>
    </AuthProvider>
  );
}
