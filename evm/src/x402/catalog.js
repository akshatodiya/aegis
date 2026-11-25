// the service catalog: the x402 half of the reputation lane.
//
// before the agent pays a 402 challenge, Aegis asks two questions the signer
// alone can't answer, because they need off-wire context: is this payTo a
// service the agent actually meant to buy from, and is the amount it's demanding
// the price that service actually posts? A payTo that isn't listed is unknown;
// an amount over the posted price is a bait-and-switch (or a decimal-inflation
// attack - the classic "0.01 becomes 10,000" when someone confuses 6 and 18
// decimals). This stands in for a live Circle Agent Marketplace lookup; the
// interface is the same, only the source of truth changes.
//
// prices are in USDC BASE UNITS (6 decimals), the same units PaymentRequirements
// use, so the comparison never crosses a decimal boundary.

export function createCatalog(entries = []) {
  // key by lowercased address so lookups are case-insensitive
  const byAddress = new Map();
  for (const e of entries) {
    if (!e?.payTo) continue;
    byAddress.set(e.payTo.toLowerCase(), {
      name: e.name ?? 'unnamed service',
      maxPrice: BigInt(e.maxPrice), // base units, the most this service may charge
    });
  }

  return {
    // the listed service for this payTo, or null if we've never heard of it.
    lookup(payTo) {
      return byAddress.get(String(payTo).toLowerCase()) ?? null;
    },
    // convenience for the demo/tests
    list() {
      return [...byAddress.entries()].map(([payTo, v]) => ({ payTo, ...v }));
    },
  };
}
