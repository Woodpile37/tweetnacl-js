const nacl = require("../../" + (process.env.NACL_SRC || "nacl.min.js"));
const crypto = require("crypto");
const spawn = require("child_process").spawn;
const path = require("path");
const test = require("tape");

function chash(msg, callback) {
  const p = spawn(path.resolve(__dirname, "chash"));
  const result = [];
  p.stdout.on("data", function (data) {
    result.push(data);
  });
  p.on("close", function (code) {
    return callback(Buffer.concat(result).toString("utf8"));
  });
  p.on("error", function (err) {
    throw err;
  });
  p.stdin.write(msg);
  p.stdin.end();
}

test("nacl.hash (C)", function (t) {
  function check(num) {
    const msg = nacl.randomBytes(num);
    const h = nacl.hash(msg);
    const hexH = new Buffer(h).toString("hex");
    chash(new Buffer(msg), function (hexCH) {
      t.equal(hexH, hexCH, "hashes should be equal");
      if (num >= 1000) {
        t.end();
        return;
      }
      check(num + 1);
    });
  }

  check(0);
});
