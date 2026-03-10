import { useState, useEffect } from "react";
import { listSecretKeys, setSecret, rotateSecret } from "../api";

const ENVS = ["dev", "staging", "prod"];

export default function Secrets() {
  const [env, setEnv] = useState("dev");
  const [keys, setKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addKey, setAddKey] = useState("");
  const [addValue, setAddValue] = useState("");
  const [rotating, setRotating] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    listSecretKeys(env)
      .then(setKeys)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [env]);

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!addKey.trim() || !addValue.trim()) return;
    setError(null);
    try {
      await setSecret(env, addKey.trim(), addValue.trim());
      setKeys((k) => [...k, addKey.trim()].sort());
      setAddKey("");
      setAddValue("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleRotate(key: string) {
    setRotating(key);
    setError(null);
    try {
      await rotateSecret(env, key);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRotating(null);
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-slate-100">Secrets</h1>

      <div className="flex gap-2">
        {ENVS.map((e) => (
          <button
            key={e}
            type="button"
            onClick={() => setEnv(e)}
            className={`rounded-md px-4 py-2 text-sm font-medium ${
              env === e
                ? "bg-sky-600 text-white"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {e}
          </button>
        ))}
      </div>

      {error && (
        <div className="rounded-md bg-red-900/30 border border-red-800 px-4 py-2 text-red-200 text-sm">
          {error}
        </div>
      )}

      <section className="rounded-lg border border-slate-800 bg-slate-900/50 p-6">
        <h2 className="text-lg font-medium text-slate-200 mb-4">Add secret</h2>
        <form onSubmit={handleAdd} className="flex flex-wrap gap-3">
          <input
            type="text"
            placeholder="Key (e.g. DATABASE_URL)"
            value={addKey}
            onChange={(e) => setAddKey(e.target.value)}
            className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100 placeholder-slate-500 w-48"
          />
          <input
            type="password"
            placeholder="Value"
            value={addValue}
            onChange={(e) => setAddValue(e.target.value)}
            className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100 placeholder-slate-500 w-48"
          />
          <button
            type="submit"
            className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500"
          >
            Add
          </button>
        </form>
      </section>

      <section className="rounded-lg border border-slate-800 bg-slate-900/50 p-6">
        <h2 className="text-lg font-medium text-slate-200 mb-4">Secret keys ({env})</h2>
        {loading ? (
          <p className="text-slate-400">Loading…</p>
        ) : keys.length === 0 ? (
          <p className="text-slate-500">No secrets for this environment.</p>
        ) : (
          <ul className="space-y-2">
            {keys.map((key) => (
              <li
                key={key}
                className="flex items-center justify-between rounded-md bg-slate-800/50 px-4 py-2"
              >
                <span className="font-mono text-slate-200">{key}</span>
                <button
                  type="button"
                  onClick={() => handleRotate(key)}
                  disabled={rotating === key}
                  className="rounded px-3 py-1 text-sm text-sky-400 hover:bg-sky-500/20 disabled:opacity-50"
                >
                  {rotating === key ? "Rotating…" : "Rotate"}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
