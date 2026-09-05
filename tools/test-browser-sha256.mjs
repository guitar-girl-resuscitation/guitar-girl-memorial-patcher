// Known-vector test for the exact in-browser implementation embedded in index.html.
// This file contains no copy of the implementation, so the test cannot drift.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8");
const classStart = html.indexOf("class SHA256{");
const hashStart = html.indexOf("async function hashFile", classStart);
if (classStart < 0 || hashStart < 0) throw new Error("embedded SHA256 implementation not found");
const source = html.slice(classStart, hashStart);
const SHA256 = Function(`${source}; return SHA256`)();

for (const bytes of [
  new Uint8Array(),
  new TextEncoder().encode("abc"),
  new Uint8Array(1_000_000).fill(0x61),
]) {
  const expected = createHash("sha256").update(bytes).digest("hex").toUpperCase();
  const incremental = new SHA256();
  for (let offset = 0; offset < bytes.length; offset += 7919) {
    incremental.update(bytes.subarray(offset, offset + 7919));
  }
  const actual = incremental.hex();
  if (actual !== expected) throw new Error(`SHA-256 mismatch: ${actual} != ${expected}`);
}
console.log("browser SHA-256 known vectors: OK");
