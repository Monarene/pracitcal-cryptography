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
// const password = "password1";
// const salt = crypto.randomBytes(256).toString("hex");
// console.log(salt);
// const hashedPwd = crypto.pbkdf2Sync(password, salt, 100000, 51, "sha512");
// console.log(hashedPwd.toString("hex"));

// Encrypting Data at rest
// const algorithm = "aes-256-cbc";
// const password = "Good strong key"; // this is the passswword used to generate the key
// const salt = crypto.randomBytes(32);
// const key = crypto.scryptSync(password, salt, 32);
// const iv = crypto.randomBytes(16);
// const cipher = crypto.createCipheriv(algorithm, key, iv);
// let ssn = "111-000-0000"; // in the end this is the value that was encrypted
// let encrypted = cipher.update(ssn, "utf8", "hex");
// encrypted += cipher.final("hex");
// console.log(encrypted);

// // decrypting data at rest
// const decipher = crypto.createDecipheriv(algorithm, key, iv);
// let decrypted = decipher.update(encrypted, "hex", "utf8");
// decrypted = decipher.final("utf8");
// console.log(decrypted);
