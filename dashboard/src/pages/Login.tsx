import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth";

export default function Login() {
  const [token, setToken] = useState("");
  const { login } = useAuth();
  const navigate = useNavigate();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (token.trim()) {
      login(token.trim());
      navigate("/secrets", { replace: true });
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-full max-w-sm rounded-lg border border-slate-800 bg-slate-900/50 p-8 shadow-xl">
        <h1 className="text-2xl font-semibold text-slate-100 mb-2">SecretSentinel</h1>
        <p className="text-slate-400 text-sm mb-6">Sign in with your API token (dev: any non-empty value)</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            placeholder="Token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            className="w-full rounded-md border border-slate-700 bg-slate-900 px-4 py-2 text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
          <button
            type="submit"
            className="w-full rounded-md bg-sky-600 px-4 py-2 font-medium text-white hover:bg-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:ring-offset-2 focus:ring-offset-slate-950"
          >
            Sign in
          </button>
        </form>
      </div>
    </div>
  );
}
