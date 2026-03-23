import { describe, it, expect, beforeAll } from "vitest";
import { createHmac } from "crypto";
import express from "express";
import request from "supertest";

// Set JWT_SECRET before importing the module under test so the fail-fast check passes.
const TEST_SECRET = "test-secret-for-unit-tests";
process.env.JWT_SECRET = TEST_SECRET;

// Dynamic import after env is set.
const { authMiddleware } = await import("./middleware.js");

function makeJwt(payload: Record<string, unknown>, secret = TEST_SECRET): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(authMiddleware);
  app.get("/me", (req, res) => {
    res.json({ userId: (req as express.Request & { userId?: string }).userId ?? null });
  });
  return app;
}

describe("authMiddleware", () => {
  let app: express.Express;

  beforeAll(() => {
    app = buildApp();
  });

  it("passes request with no token (userId is null)", async () => {
    const res = await request(app).get("/me");
    expect(res.status).toBe(200);
    expect(res.body.userId).toBeNull();
  });

  it("accepts a valid HMAC-SHA256 JWT and extracts sub", async () => {
    const token = makeJwt({ sub: "user-123" });
    const res = await request(app).get("/me").set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe("user-123");
  });

  it("rejects a JWT signed with a wrong secret", async () => {
    const token = makeJwt({ sub: "attacker" }, "wrong-secret");
    const res = await request(app).get("/me").set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid token");
  });

  it("rejects a forged JWT (tampered payload, original signature)", async () => {
    const real = makeJwt({ sub: "user-123" });
    const [header, , sig] = real.split(".");
    const fakePayload = Buffer.from(JSON.stringify({ sub: "admin" })).toString("base64url");
    const forged = `${header}.${fakePayload}.${sig}`;
    const res = await request(app).get("/me").set("Authorization", `Bearer ${forged}`);
    expect(res.status).toBe(401);
  });

  it("accepts opaque non-JWT bearer token without rejecting", async () => {
    const res = await request(app).get("/me").set("Authorization", "Bearer opaque-token-no-dots");
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe("bearer");
  });
});
