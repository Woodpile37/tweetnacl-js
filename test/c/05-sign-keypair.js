const nacl = require("../../" + (process.env.NACL_SRC || "nacl.min.js"));
nacl.util = require("tweetnacl-util");
const spawn = require("child_process").spawn;
const execFile = require("child_process").execFile;
const path = require("path");
const test = require("tape");

function csign(sk, msg, callback) {
  const hexsk = new Buffer(sk).toString("hex");
  const p = spawn(path.resolve(__dirname, "csign"), [hexsk]);
  const result = [];
  p.stdout.on("data", function (data) {
    result.push(data);
  });
  p.on("close", function (code) {
    callback(Buffer.concat(result).toString("base64"));
  });
  p.on("error", function (err) {
    throw err;
  });
  p.stdin.write(msg);
  p.stdin.end();
}

function csignkeypair(callback) {
  execFile(
    path.resolve(__dirname, "csign-keypair"),
    [],
    function (err, stdout) {
      if (err) throw err;
      callback(stdout.toString("utf8"));
    }
  );
}

test("nacl.sign (C) with keypair from C", function (t) {
  function check(num) {
    csignkeypair(function (hexSecretKey) {
      const secretKey = new Uint8Array(nacl.sign.secretKeyLength);
      const b = new Buffer(hexSecretKey, "hex");
      for (let i = 0; i < b.length; i++) secretKey[i] = b[i];
      const msg = nacl.randomBytes(num);
      const signedMsg = nacl.util.encodeBase64(nacl.sign(msg, secretKey));
      csign(secretKey, new Buffer(msg), function (signedFromC) {
        t.equal(signedMsg, signedFromC, "signed messages should be equal");
        if (num >= 100) {
          t.end();
          return;
        }
        check(num + 1);
      });
    });
  }

  check(0);
});
