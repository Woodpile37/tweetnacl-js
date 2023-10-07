const nacl = require("../../" + (process.env.NACL_SRC || "nacl.min.js"));
const crypto = require("crypto");
const spawn = require("child_process").spawn;
const path = require("path");
const test = require("tape");

function cbox(msg, sk, pk, n, callback) {
  const hexsk = new Buffer(sk).toString("hex");
  const hexpk = new Buffer(pk).toString("hex");
  const hexn = new Buffer(n).toString("hex");
  const p = spawn(path.resolve(__dirname, "cbox"), [hexsk, hexpk, hexn]);
  const result = [];
  p.stdout.on("data", function (data) {
    result.push(data);
  });
  p.on("close", function (code) {
    return callback(Buffer.concat(result).toString("base64"));
  });
  p.on("error", function (err) {
    throw err;
  });
  p.stdin.write(msg);
  p.stdin.end();
}

test("nacl.box (C)", function (t) {
  const k1 = nacl.box.keyPair();

  function check(num, maxNum, next) {
    const sk2 = nacl.randomBytes(nacl.box.secretKeyLength);
    const msg = nacl.randomBytes(num);
    const nonce = nacl.randomBytes(24);
    const box = nacl.util.encodeBase64(nacl.box(msg, nonce, k1.publicKey, sk2));
    cbox(new Buffer(msg), sk2, k1.publicKey, nonce, function (boxFromC) {
      t.equal(box, boxFromC, "boxes should be equal");
      t.notEqual(
        nacl.box.open(
          nacl.util.decodeBase64(boxFromC),
          nonce,
          k1.publicKey,
          sk2
        ),
        false,
        "opening box should succeed"
      );
      if (num >= maxNum) {
        if (next) next();
        return;
      }
      check(num + 1, maxNum, next);
    });
  }

  check(0, 1024, function () {
    check(16417, 16500, function () {
      t.end();
    });
  });
});
