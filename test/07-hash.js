const nacl =
  typeof window !== "undefined"
    ? window.nacl
    : require("../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const test = require("tape");

const randomVectors = require("./data/hash.random");

const enc = nacl.util.encodeBase64;
const dec = nacl.util.decodeBase64;

test("nacl.hash random test vectors", function (t) {
  randomVectors.forEach(function (vec) {
    const msg = dec(vec[0]);
    const goodHash = dec(vec[1]);
    const hash = nacl.hash(msg);
    t.equal(enc(hash), enc(goodHash));
  });
  t.end();
});
