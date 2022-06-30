const nacl =
  typeof window !== "undefined"
    ? window.nacl
    : require("../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const test = require("tape");

const randomVectors = require("./data/secretbox.random");

const enc = nacl.util.encodeBase64;
const dec = nacl.util.decodeBase64;

test("nacl.secretbox random test vectors", function (t) {
  randomVectors.forEach(function (vec) {
    const key = dec(vec[0]);
    const nonce = dec(vec[1]);
    const msg = dec(vec[2]);
    const goodBox = dec(vec[3]);
    const box = nacl.secretbox(msg, nonce, key);
    t.ok(box, "box should be created");
    t.equal(enc(box), enc(goodBox));
    const openedBox = nacl.secretbox.open(goodBox, nonce, key);
    t.ok(openedBox, "box should open");
    t.equal(enc(openedBox), enc(msg));
  });
  t.end();
});
