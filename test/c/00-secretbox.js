const nacl = require("../../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const spawn = require("child_process").spawn;
const path = require("path");
const test = require("tape");

function csecretbox(msg, n, k, callback) {
  const hexk = new Buffer(k).toString("hex");
  const hexn = new Buffer(n).toString("hex");
  const p = spawn(path.resolve(__dirname, "csecretbox"), [hexk, hexn]);
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

test("nacl.secretbox (C)", function (t) {
  const k = new Uint8Array(nacl.secretbox.keyLength);
  const n = new Uint8Array(nacl.secretbox.nonceLength);
  let i;
  for (i = 0; i < 32; i++) k[i] = i;
  for (i = 0; i < 24; i++) n[i] = i;

  function check(num, maxNum, next) {
    const msg = nacl.randomBytes(num);
    const box = nacl.util.encodeBase64(nacl.secretbox(msg, n, k));
    csecretbox(new Buffer(msg), n, k, function (boxFromC) {
      t.equal(box, boxFromC, "secretboxes should be equal");
      t.notEqual(
        nacl.secretbox.open(nacl.util.decodeBase64(boxFromC), n, k),
        false,
        "opening should succeed"
      );
      if (num >= maxNum) {
        if (next) next();
        return;
      }
      check(num + 1, maxNum, next);
    });
  }

  check(0, 1024, function () {
    check(16418, 16500, function () {
      check(1000000, 0, function () {
        t.end();
      });
    });
  });
});
