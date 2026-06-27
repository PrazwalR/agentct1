import type { Policy } from "../types.js";

interface BigIntTag {
  __bigint: string;
}

function isBigIntTag(v: unknown): v is BigIntTag {
  return typeof v === "object" && v !== null && "__bigint" in v;
}

/** Serialize a Policy to JSON, encoding bigint rule amounts losslessly. */
export function policyToJSON(policy: Policy): string {
  return JSON.stringify(
    policy,
    (_key, value) => (typeof value === "bigint" ? { __bigint: value.toString() } : value),
    2,
  );
}

/** Parse a Policy from JSON produced by policyToJSON. */
export function policyFromJSON(json: string): Policy {
  return JSON.parse(json, (_key, value) =>
    isBigIntTag(value) ? BigInt(value.__bigint) : value,
  ) as Policy;
}
