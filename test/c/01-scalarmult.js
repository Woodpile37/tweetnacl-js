const NUMBER_OF_TESTS = 1000;

const nacl = require("../../" + (process.env.NACL_SRC || "nacl.min.js"));
const execFile = require("child_process").execFile;
const path = require("path");
const test = require("tape");

function cscalarmult(n, p, callback) {
  const hexN = new Buffer(n).toString("hex");
  const hexP = new Buffer(p).toString("hex");

  execFile(
    path.resolve(__dirname, "cscalarmult"),
    [hexN, hexP],
    function (err, stdout) {
      if (err) throw err;
      callback(stdout.toString("utf8"));
    }
  );
}

test("nacl.scalarMult (C)", function (t) {
  const k1 = {
    publicKey: nacl.util.decodeBase64(
      "JRAWWRKVfZS2U/QiV+X2+PaabPfAB4H9p+BZkBN8ji8="
    ),
    secretKey: nacl.util.decodeBase64(
      "5g1pBmI3HL5GAjtt3/2FZDQVfGSMNohngN7OVSizBVE="
    ),
  };

  function check(num) {
    const k2 = nacl.box.keyPair();
    const q1 = nacl.scalarMult(k1.secretKey, k2.publicKey);
    const q2 = nacl.scalarMult(k2.secretKey, k1.publicKey);

    t.equal(
      nacl.util.encodeBase64(q1),
      nacl.util.encodeBase64(q2),
      "scalarMult results should be equal"
    );

    hexQ = new Buffer(q1).toString("hex");
    cscalarmult(k1.secretKey, k2.publicKey, function (cQ) {
      t.equal(hexQ, cQ);
      if (num >= NUMBER_OF_TESTS) {
        t.end();
        return;
      }
      check(num + 1);
    });
  }

  check(0);
});
