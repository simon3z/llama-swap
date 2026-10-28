import { describe, it, expect, beforeEach, vi } from "vitest";
import type { Writable } from "svelte/store";
import { authState, authRequired, checkAuth, login, logout } from "./auth";

/** Read the current value of a classic svelte store. */
function value<T>(store: Writable<T>): T {
  let out: T | undefined;
  const unsubscribe = store.subscribe((v) => (out = v));
  unsubscribe();
  return out as T;
}

function stubFetch(status: number, body: object = {}): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })),
  );
}

describe("auth", () => {
  beforeEach(() => {
    authState.set("checking");
    authRequired.set(false);
    vi.unstubAllGlobals();
  });

  it("auth-check 200 with no keys configured skips the login page", async () => {
    stubFetch(200, { required: false, authenticated: true });
    await checkAuth();
    expect(value(authState)).toBe("authed");
    expect(value(authRequired)).toBe(false);
  });

  it("auth-check 200 with a valid cookie reports a key is required", async () => {
    stubFetch(200, { required: true, authenticated: true });
    await checkAuth();
    expect(value(authState)).toBe("authed");
    expect(value(authRequired)).toBe(true);
  });

  it("auth-check 401 shows the login page", async () => {
    stubFetch(401, { required: true, authenticated: false });
    await checkAuth();
    expect(value(authState)).toBe("login");
    expect(value(authRequired)).toBe(true);
  });

  it("a network error falls back to the login page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("down");
      }),
    );
    await checkAuth();
    expect(value(authState)).toBe("login");
  });

  it("login with an accepted key becomes authed", async () => {
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body))).toEqual({ api_key: "secret" });
      return new Response("ok", { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);
    expect(await login("secret")).toBe(true);
    expect(value(authState)).toBe("authed");
  });

  it("login with a rejected key stays on the login page", async () => {
    stubFetch(401);
    authState.set("login");
    expect(await login("wrong")).toBe(false);
    expect(value(authState)).toBe("login");
  });

  it("logout returns to the login page", async () => {
    stubFetch(200, { required: true, authenticated: true });
    authState.set("authed");
    await logout();
    expect(value(authState)).toBe("login");
  });
});
