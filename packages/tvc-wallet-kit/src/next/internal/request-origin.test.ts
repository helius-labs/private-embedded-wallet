import { describe, expect, it } from "vitest";
import { sameRequestOrigin } from "./request-origin";

describe("sameRequestOrigin", () => {
  it("accepts the public origin behind a TLS-terminating proxy", () => {
    const request = new Request("http://internal:3001/api/tvc/v1/ping", {
      method: "POST",
      headers: {
        host: "wallet.example.com",
        origin: "https://wallet.example.com",
      },
    });
    expect(sameRequestOrigin(request)).toBe("https://wallet.example.com");
  });

  it("rejects a different browser origin", () => {
    const request = new Request("http://internal:3001/api/tvc/v1/ping", {
      method: "POST",
      headers: {
        host: "wallet.example.com",
        origin: "https://evil.example",
      },
    });
    expect(() => sameRequestOrigin(request)).toThrow(
      "CrossOriginRequestDenied",
    );
  });
});
