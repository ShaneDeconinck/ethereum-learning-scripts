const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const ethUtil = require('ethereumjs-util');
const { ethers } = require("ethers");

// Heading that explains what will happen
console.log("  ----------------------------------------\n | Generate a Private Key                 |\n | Derive the Public Key                  |\n | Convert public key to Ethereum address |\n | Sign a Message                         |\n | Verify the Signature                   |\n  ----------------------------------------\n\n");


// Generate a Private Key
let privateKey;
do {
  privateKey = crypto.randomBytes(32);
} while (!secp256k1.privateKeyVerify(privateKey));
console.log("Private Key Generated:\n", "0x" + privateKey.toString('hex'), "\n");

// Derive the Public Key
const publicKey = secp256k1.publicKeyCreate(privateKey, false); // uncompressed
console.log("Public Key:\n", "0x"+Buffer.from(publicKey, 'hex').toString('hex'), "\n");

// Convert public key to Ethereum address
// Step 1: Remove the first byte (0x04), which is an uncompressed public key prefix
let pubKeyNoPrefix = publicKey.slice(1);
console.log("Public Key without Prefix:\n", "0x" + Buffer.from(pubKeyNoPrefix, 'hex').toString('hex'),"\n");

// Step 2: Keccak-256 hash of the public key
let pubKeyHash = ethers.keccak256(pubKeyNoPrefix);
console.log("Keccak-256 Hash of Public Key:\n", pubKeyHash, "\n");

// Step 3: Ethereum address is the last 20 bytes of this hash
let ethAddress = "0x" + pubKeyHash.substring(pubKeyHash.length - 40);
console.log("Ethereum Address (last 20 bytes of the hash):\n", ethAddress, "\n");

// Original message
const message = "Hello Wild W3st";

// Prepare the message (Ethereum specific format)
const messageBytes = ethers.toUtf8Bytes(message);
const messageHash = ethers.keccak256(
  ethers.concat([
    ethers.toUtf8Bytes("\x19Ethereum Signed Message:\n"),
    ethers.toUtf8Bytes(String(messageBytes.length)),
    messageBytes
  ])
);
const messageHashBuffer = Buffer.from(messageHash.slice('0x'.length), 'hex');
console.log("Message Hash:\n", messageHash, "\n");

// Sign the message
const signatureObj = secp256k1.ecdsaSign(messageHashBuffer, privateKey);

console.log("Signature:\n", "0x" + Buffer.from(signatureObj.signature).toString('hex') + signatureObj.recid.toString(16), "\n");

// Verify the signature
const verified = secp256k1.ecdsaVerify(Buffer.from(signatureObj.signature), Buffer.from(messageHash.slice(2), 'hex'), publicKey);
const receivedPublicKey = secp256k1.ecdsaRecover(Buffer.from(signatureObj.signature), signatureObj.recid, Buffer.from(messageHash.slice(2), 'hex'), false);
console.log("Signature Verified:", verified, "\n");
console.log("Received Public Key:\n", "0x" + Buffer.from(receivedPublicKey, 'hex').toString('hex'), "\n");