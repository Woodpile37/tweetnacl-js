const nacl =
  typeof window !== "undefined"
    ? window.nacl
    : require("../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const test = require("tape");

const randomVectors = require("./data/box.random");

const enc = nacl.util.encodeBase64;
const dec = nacl.util.decodeBase64;

test("nacl.box random test vectors", function (t) {
  const nonce = new Uint8Array(nacl.box.nonceLength);
  randomVectors.forEach(function (vec) {
    const pk1 = dec(vec[0]);
    const sk2 = dec(vec[1]);
    const msg = dec(vec[2]);
    const goodBox = dec(vec[3]);
    const box = nacl.box(msg, nonce, pk1, sk2);
    t.equal(enc(box), enc(goodBox));
    const openedBox = nacl.box.open(goodBox, nonce, pk1, sk2);
    t.equal(enc(openedBox), enc(msg));
  });
  t.end();
});
