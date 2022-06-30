const nacl =
  typeof window !== "undefined"
    ? window.nacl
    : require("../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const test = require("tape");

const specVectors = require("./data/hash.spec");

const enc = nacl.util.encodeBase64;

test("nacl.hash length", function (t) {
  t.equal(nacl.hash(new Uint8Array(0)).length, 64);
  t.equal(nacl.hash(new Uint8Array(100)).length, 64);
  t.end();
});

test("nacl.hash exceptions for bad types", function (t) {
  t.throws(
    function () {
      nacl.hash("string");
    },
    TypeError,
    "should throw TypeError for string type"
  );
  t.throws(
    function () {
      nacl.hash([1, 2, 3]);
    },
    TypeError,
    "should throw TypeError for array type"
  );
  t.end();
});

test("nacl.hash specified test vectors", function (t) {
  specVectors.forEach(function (vec) {
    const goodHash = new Uint8Array(vec[0]);
    const msg = new Uint8Array(vec[1]);
    const hash = nacl.hash(msg);
    t.equal(enc(hash), enc(goodHash));
  });
  t.end();
});
