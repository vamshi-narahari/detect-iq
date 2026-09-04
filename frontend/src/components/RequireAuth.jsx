import { useAuth } from "../context/AuthContext";
import LoginModal from "./LoginModal";

export default function RequireAuth({ children }) {
  const { user, loading } = useAuth();

  if (loading) return null;
  if (!user) return <LoginModal />;
  return children;
}
