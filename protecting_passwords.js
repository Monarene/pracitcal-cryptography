const crypto = require("crypto");

// using the MD5 hashing tool
const hash = crypto.createHash("md5");
// hash.update("password1"); // this can only be called once
// console.log(hash.digest("hex"));

// using the SHA 256 Hash
// const shaHash = crypto.createHash("sha256");0
// hash.update("password1");
// console.log(shaHash.digest("hex"));

// using pbkdf2 with a dash of salt
const password = "password1";
const salt = crypto.randomBytes(256).toString("hex");
console.log(salt);
const hashedPwd = crypto.pbkdf2Sync(password, salt, 100000, 51, "sha512");
console.log(hashedPwd.toString("hex"));
