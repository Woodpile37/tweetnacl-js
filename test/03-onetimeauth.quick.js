const nacl =
  typeof window !== "undefined"
    ? window.nacl
    : require("../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const test = require("tape");

const specVectors = require("./data/onetimeauth.spec");

const enc = nacl.util.encodeBase64;

test("nacl.lowlevel.crypto_onetimeauth specified vectors", function (t) {
  const out = new Uint8Array(16);
  specVectors.forEach(function (v) {
    nacl.lowlevel.crypto_onetimeauth(out, 0, v.m, 0, v.m.length, v.k);
    t.equal(enc(out), enc(v.out));
  });
  t.end();
});
