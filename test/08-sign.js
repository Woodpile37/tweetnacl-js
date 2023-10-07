const nacl =
  typeof window !== "undefined"
    ? window.nacl
    : require("../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const test = require("tape");

const specVectors = require("./data/sign.spec");

const enc = nacl.util.encodeBase64;
const dec = nacl.util.decodeBase64;

test("nacl.sign and nacl.sign.open specified vectors", function (t) {
  specVectors.forEach(function (vec) {
    const keys = nacl.sign.keyPair.fromSecretKey(dec(vec[0]));
    const msg = dec(vec[1]);
    const goodSig = dec(vec[2]);

    const signedMsg = nacl.sign(msg, keys.secretKey);
    t.equal(
      enc(signedMsg.subarray(0, nacl.sign.signatureLength)),
      enc(goodSig),
      "signatures must be equal"
    );
    const openedMsg = nacl.sign.open(signedMsg, keys.publicKey);
    t.equal(enc(openedMsg), enc(msg), "messages must be equal");
  });
  t.end();
});

test("nacl.sign.detached and nacl.sign.detached.verify some specified vectors", function (t) {
  specVectors.forEach(function (vec, i) {
    // We don't need to test all, as internals are already tested above.
    if (i % 100 !== 0) return;

    const keys = nacl.sign.keyPair.fromSecretKey(dec(vec[0]));
    const msg = dec(vec[1]);
    const goodSig = dec(vec[2]);

    const sig = nacl.sign.detached(msg, keys.secretKey);
    t.equal(enc(sig), enc(goodSig), "signatures must be equal");
    const result = nacl.sign.detached.verify(msg, sig, keys.publicKey);
    t.ok(result, "signature must be verified");
  });
  t.end();
});
