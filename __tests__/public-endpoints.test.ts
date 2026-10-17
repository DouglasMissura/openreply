/**
 * Public endpoints must not leak internals: health hides worker host, pid and
 * error messages; an unsigned webhook is refused without logging its body.
 */

import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/db/client", () => ({
  prisma: {
    $queryRaw: vi.fn(async () => {
      throw new Error("connect ECONNREFUSED db.internal:5432");
    }),
  },
}));
vi.mock("@/lib/queue/client", () => ({
  getRedisConnection: () => ({ ping: async () => "PONG" }),
  getDMQueue: () => ({ getJobCounts: async () => ({ waiting: 0, active: 0 }) }),
}));
vi.mock("@/lib/ops/worker-health", () => ({
  getWorkerHealth: async () => ({
    healthy: true,
    ageMs: 1000,
    heartbeat: { status: "running", worker: "dm", pid: 4242, hostname: "box-7" },
  }),
}));
vi.mock("@/lib/queue/process-webhook", () => ({ processInstagramWebhook: vi.fn() }));

import { GET as health } from "../app/api/health/route";
import { POST as webhook } from "../app/api/webhook/route";

describe("public endpoints", () => {
  it("health keeps each status but drops host, pid and error text", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await health();
    const text = await res.clone().text();
    const body = await res.json();

    expect(res.status).toBe(503);
    expect(body.checks.database).toEqual({ status: "error", detail: "Database check failed" });
    expect(body.checks.redis.status).toBe("ok");
    expect(body.checks.worker).toEqual({ healthy: true, ageMs: 1000 });
    for (const leak of ["4242", "box-7", "hostname", "pid", "ECONNREFUSED"]) {
      expect(text).not.toContain(leak);
    }
  });

  it("webhook with a bad signature answers 401 and never logs the body", async () => {
    vi.stubEnv("FACEBOOK_APP_SECRET", "test_app_secret");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const res = await webhook(
      new Request("http://localhost/api/webhook", {
        method: "POST",
        headers: { "x-hub-signature-256": "sha256=bad" },
        body: "secret-body-content",
      }) as never
    );

    expect(res.status).toBe(401);
    expect(JSON.stringify(warn.mock.calls)).not.toContain("secret-body-content");
  });
});
