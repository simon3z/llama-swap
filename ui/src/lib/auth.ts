import { writable } from "svelte/store";
import { apiUrl } from "./apiPath";

/**
 * UI authentication against a server with apiKeys configured.
 *
 * The SPA document itself loads without a key; when the server requires a
 * key the app shows the login page instead of the dashboard. A valid key is
 * stored server-side in an httpOnly session cookie, so every later request -
 * fetches and EventSources alike, which all carry cookies - authenticates
 * without any per-call wiring.
 */

export type AuthState = "checking" | "login" | "authed";

/** True once a 401 has been observed: the server has apiKeys configured and
 * the browser does not yet hold a valid login cookie. */
export const authRequired = writable(false);
export const authState = writable<AuthState>("checking");

/** Ask the server whether a key is required and the presented one is valid. */
export async function checkAuth(): Promise<void> {
  try {
    const res = await fetch(apiUrl("/api/auth-check"));
    const body = (await res.json()) as { required: boolean; authenticated: boolean };
    authRequired.set(body.required);
    authState.set(body.authenticated ? "authed" : "login");
  } catch {
    // Server unreachable: show the login page; logging in will retry.
    authState.set("login");
  }
}

/**
 * Submit an API key. Returns true when the server accepted it and stored it
 * in the session cookie.
 */
export async function login(apiKey: string): Promise<boolean> {
  try {
    const res = await fetch(apiUrl("/api/login"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: apiKey }),
    });
    if (res.ok) {
      authRequired.set(true);
      authState.set("authed");
      return true;
    }
  } catch {
    // fall through to the error path
  }
  return false;
}

/** Clear the session cookie and go back to the login page. */
export async function logout(): Promise<void> {
  try {
    await fetch(apiUrl("/api/logout"), { method: "POST" });
  } finally {
    authState.set("login");
  }
}
