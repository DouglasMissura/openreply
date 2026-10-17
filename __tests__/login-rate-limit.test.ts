/**
 * Magic link rate limit, exercised through the real Auth.js signIn callback.
 * The Redis counter is replaced by an in-memory one.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { counts, reserveDMSlot } = vi.hoisted(() => {
  const counts = new Map<string, number>();
  const reserveDMSlot = vi.fn(async (key: string) => {
    const currentCount = (counts.get(key) ?? 0) + 1;
    counts.set(key, currentCount);
    return { currentCount };
  });
  return { counts, reserveDMSlot };
});

vi.mock("@/lib/utils/rate-limiter", () => ({ reserveDMSlot }));
vi.mock("@/lib/db/client", () => ({ prisma: {} }));
vi.mock("@/lib/workspace", () => ({}));
vi.mock("next-auth", () => ({ default: () => ({}) }));

import { authConfig } from "../lib/auth";
import {
  LOGIN_REQUESTS_PER_ADDRESS,
  LOGIN_REQUESTS_TOTAL,
} from "../lib/login-rate-limit";

type SignInParams = Parameters<typeof authConfig.callbacks.signIn>[0];

// Request phase (sends an email) when verificationRequest is true, link click otherwise.
function signIn(email: string, verificationRequest: boolean) {
  return authConfig.callbacks.signIn({
    user: { id: "u1", email },
    account: null,
    ...(verificationRequest ? { email: { verificationRequest: true } } : {}),
  } as SignInParams);
}

beforeEach(() => {
  counts.clear();
  reserveDMSlot.mockClear();
  vi.stubEnv("ALLOWED_EMAILS", "owner@example.com");
});

describe("magic link rate limit", () => {
  it("refuses a request once the address passed its limit", async () => {
    for (let i = 0; i < LOGIN_REQUESTS_PER_ADDRESS; i++) {
      expect(await signIn("owner@example.com", true)).toBe(true);
    }
    expect(await signIn("owner@example.com", true)).toBe(false);
  });

  it("never counts the link click", async () => {
    for (let i = 0; i < 10; i++) {
      expect(await signIn("owner@example.com", false)).toBe(true);
    }
    expect(reserveDMSlot).not.toHaveBeenCalled();

    for (let i = 0; i < LOGIN_REQUESTS_PER_ADDRESS; i++) {
      await signIn("owner@example.com", true);
    }
    // Over the request limit, the link already sent still signs in.
    expect(await signIn("owner@example.com", false)).toBe(true);
  });

  it("caps requests across all addresses", async () => {
    const addresses = Array.from({ length: 10 }, (_, i) => `u${i}@example.com`);
    vi.stubEnv("ALLOWED_EMAILS", addresses.join(","));
    const results: boolean[] = [];
    for (const address of addresses) {
      for (let i = 0; i < 3; i++) {
        results.push((await signIn(address, true)) as boolean);
      }
    }
    expect(results.filter(Boolean)).toHaveLength(LOGIN_REQUESTS_TOTAL);
  });

  it("refuses the request when the counter is unavailable", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    reserveDMSlot.mockRejectedValueOnce(new Error("redis down"));
    expect(await signIn("owner@example.com", true)).toBe(false);
  });

  it("does not count addresses outside the allowlist", async () => {
    expect(await signIn("stranger@example.com", true)).toBe(false);
    expect(reserveDMSlot).not.toHaveBeenCalled();
  });
});
