import { type FormEvent, useState } from "react";

import { describe, session } from "./api.ts";

export function AuthForm() {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await (mode === "login" ? session.logIn(email, password) : session.signUp(email, password));
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card auth" onSubmit={submit}>
      <h1>Notebook</h1>
      <label>
        Email
        <input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      <label>
        Password
        <input
          type="password"
          autoComplete={mode === "login" ? "current-password" : "new-password"}
          required
          minLength={mode === "signup" ? 12 : undefined}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      {mode === "signup" && <p className="hint">At least 12 characters.</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy}>
        {mode === "login" ? "Log in" : "Create account"}
      </button>
      <button type="button" className="link" onClick={() => setMode(mode === "login" ? "signup" : "login")}>
        {mode === "login" ? "New here? Create an account" : "Have an account? Log in"}
      </button>
    </form>
  );
}
