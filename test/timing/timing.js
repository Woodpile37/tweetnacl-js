// Measures timing variations and displays them
const nacl =
  typeof window !== "undefined"
    ? window.nacl
    : require("../../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const test = require("tape");

const hex = function (x) {
  return Buffer.from(x).toString("hex");
};

test("nacl.scalarMult timings", function (t) {
  function measure(x, prev) {
    let avgdiff = 0;
    for (let k = 0; k < 10; k++) {
      const t0 = Date.now();
      for (let j = 0; j < 100; j++) {
        z = nacl.scalarMult.base(x);
        nacl.scalarMult(x, prev);
      }
      const t1 = Date.now();
      avgdiff += t1 - t0;
    }
    avgdiff /= 10;
    return avgdiff;
  }

  const diffs = [];
  let z;
  let prev = nacl.scalarMult.base(nacl.randomBytes(32));
  for (let i = 0; i < 10; i++) {
    const x = nacl.randomBytes(32);
    if (i % 2 === 0) {
      for (var k = 0; k < 16; k++) x[k] = 0;
    } else if (i % 2 === 3) {
      for (var k = 16; k < 32; k++) x[k] = 0;
    }
    const diff = measure(x, prev);

    prev = z;
    diffs.push({
      diff,
      x,
      prev,
    });
  }
  diffs.sort(function (a, b) {
    return a.diff - b.diff;
  });
  const lo = diffs[0];
  const hi = diffs[diffs.length - 1];

  /* Retest low and high */

  const rlo = measure(lo.x, lo.prev);
  const rhi = measure(hi.x, hi.prev);

  t.end();
});
