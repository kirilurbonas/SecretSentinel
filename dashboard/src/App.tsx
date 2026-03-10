import { Routes, Route, Navigate, Link } from "react-router-dom";
import { useAuth } from "./auth";
import Login from "./pages/Login";
import Secrets from "./pages/Secrets";

function Layout({ children }: { children: React.ReactNode }) {
  const { token, logout } = useAuth();
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <Link to="/secrets" className="text-xl font-semibold text-slate-100">
          SecretSentinel
        </Link>
        {token && (
          <button
            type="button"
            onClick={logout}
            className="text-sm text-slate-400 hover:text-slate-200"
          >
            Sign out
          </button>
        )}
      </header>
      <main className="flex-1 p-6">{children}</main>
    </div>
  );
}

export default function App() {
  const { token } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/secrets"
        element={
          token ? (
            <Layout>
              <Secrets />
            </Layout>
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route path="/" element={<Navigate to={token ? "/secrets" : "/login"} replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
