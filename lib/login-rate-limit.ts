import { createHash } from "crypto";
import { reserveDMSlot } from "@/lib/utils/rate-limiter";

/**
 * Caps magic link requests before any email is sent, per address and in total.
 *
 * Reuses the Redis counter of the private-reply limiter: reserveDMSlot
 * increments a key that expires one hour after its first hit and returns the
 * running count, so a count above the cap means the request is refused.
 * ponytail: the window is the limiter's fixed hour; a shorter window needs a
 * window parameter in lib/utils/rate-limiter.ts.
 */
export const LOGIN_REQUESTS_PER_ADDRESS = 5;
export const LOGIN_REQUESTS_TOTAL = 20;
const COUNTER_TIMEOUT_MS = 3000;

export async function allowMagicLinkRequest(email: string): Promise<boolean> {
  // The address is hashed so the Redis key never holds it in clear text.
  const addressKey = `login:${createHash("sha256")
    .update(email.toLowerCase())
    .digest("hex")}`;

  try {
    // The limiter's Redis client queues commands while disconnected, so an
    // unreachable Redis would otherwise hang the login request.
    const [address, total] = await Promise.race([
      Promise.all([reserveDMSlot(addressKey), reserveDMSlot("login:all")]),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), COUNTER_TIMEOUT_MS)
      ),
    ]);
    const allowed =
      address.currentCount <= LOGIN_REQUESTS_PER_ADDRESS &&
      total.currentCount <= LOGIN_REQUESTS_TOTAL;
    if (!allowed) console.warn("Magic link request refused: rate limit");
    return allowed;
  } catch (error) {
    // Fail closed: without a working counter no email goes out.
    console.error("Magic link rate limit unavailable", error);
    return false;
  }
}
