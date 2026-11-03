import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { HeliusPrivateWalletSlot, type HeliusPrivateWallet } from "helius-wallet-kit/core";
import { useHeliusPrivateWallet } from "./useHeliusPrivateWallet";

const rendered: HeliusPrivateWallet[] = [];

function PrivateProbe() {
  rendered.push(useHeliusPrivateWallet());
  return null;
}

const enabled: HeliusPrivateWallet = {
  status: "idle",
  session: null,
  error: null,
  connect: () => Promise.reject(new Error("not in this test")),
  disconnect: () => {},
};

describe("useHeliusPrivateWallet", () => {
  it("is the one object the provider holds in wallet-kit's slot", () => {
    rendered.length = 0;
    renderToStaticMarkup(
      <HeliusPrivateWalletSlot.Provider value={enabled}>
        <PrivateProbe />
        <PrivateProbe />
      </HeliusPrivateWalletSlot.Provider>,
    );
    expect(rendered).toEqual([enabled, enabled]);
    expect(rendered[0]).toBe(enabled);
  });

  it("names the missing provider", () => {
    expect(() => renderToStaticMarkup(<PrivateProbe />)).toThrow("HeliusPrivateWalletProviderRequired");
  });
});
