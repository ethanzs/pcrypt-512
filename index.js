/* PCRYPT-512 - Encryption Algorithm
 * Author: Ethan Z. Seligman
 * 4/26/21 
 */

/* Constants
 */
const { performance } = require('perf_hooks');
const BLOCK_SIZE = 64; // 512-bit block size
const X = `2cvk4LNSwfLTwGsdtEodvUyZVTRD3d26ULeE1pbY47bFlNmp64ZGN3xww88ha6s`; // 512-bit string
const Y = `mnyApBmqIhZJysXDBQDUk806bjoLpjuYQREYPT0xQL073dIBX27oQK4ka5zVLShJ`; // 512-bit string
const sha1 = require('sha1');

/* Calculates the number of blocks needed for a given string
 * @args: Int n - length of plaintext
 * @returns: Int
 */
function getNumBlocks(n) {
    return Math.floor(n / BLOCK_SIZE) + 1;
}

/* Calculates the amount of bytes needed for padding in order to complete the last block
 * @args: Int n - length of plaintext
 * @returns: Int
 */
function getPaddingSize(n) {
    let p = n;
    for (let i = 0; i < getNumBlocks(n); i++) {
        p -= BLOCK_SIZE;
    }
    return Math.abs(p);
}

/* Takes in two 64-byte Uint8Arrays to generate a seed as a 64-byte Uint8Array
 * @args: Uint8Array X - 64 byte Uint8Array
 * @args: Uint8Array Y - 64 byte Uint8Array
 * @returns: Uint8Array
 */
function genSeed(X, Y) {
    var Z = new Uint8Array(BLOCK_SIZE); // create new Uint8Array with 64 bytes;
    for (let i = 0; i < BLOCK_SIZE; i++) {
        Z[i] = X[i] ^ Y[i]; // X XOR Y
    }
    return Z;
}

/* Adds padding if there are less than 64 chars in the last block
 * @args: String pt - plaintext string
 * @args: Uint8Array k - 64-byte generated seed
 * @args: Uint8Array X - 64-byte array used to generate seed
 * @returns: Uint8Array
 */
function addPadding(pt, k, X) {
    var uint8 = new Uint8Array((pt.length + getPaddingSize(pt.length)));
    for (let i = 0; i < pt.length; i++) {
        uint8[i] = pt.charCodeAt(i);
    }
    if (Math.abs(getPaddingSize(pt.length) - BLOCK_SIZE) == 1) { // if there is only 1 char for the entire block (63 bytes of padding)
        for (let i = pt.length; i < BLOCK_SIZE * getNumBlocks(pt.length); i++) {
            uint8[i] = X[i] + k[pt.length % BLOCK_SIZE];
        }
    }
    else {
        for (let i = pt.length; i < BLOCK_SIZE * getNumBlocks(pt.length); i++) {
            uint8[i] = (uint8[i - pt.length] ^ uint8[i - 1]) + k[pt.length % BLOCK_SIZE];
        }
    }
    return uint8;
}

/* Converts Uint8Array of bytes into UTF-8 string
 * @args: Uint8Array b - bytes to get converted into UTF-8 string
 * @returns: String
 */
function fromBytes(b) {
    return String.fromCharCode.apply(null, b);
}

/* Converts a string into a Uint8Array of bytes
 * @args: String k - string to be converted into Uint8Array of bytes
 * @returns: Uint8Array
 */
function toBytes(k) {
    var uint8 = new Uint8Array(k.length); // create new Uint8Array with 64 bytes;
    for (let i = 0; i < k.length; i++) {
        uint8[i] = k.charCodeAt(i);
    }
    return uint8;
}

/* Hashes a string and returns a Uint8Array of the hashed string
 * @args: String pt - plaintext to be hashed
 * @returns: Uint8Array
 */
function pcrypt(pt) {
    const seed = genSeed(toBytes(X), toBytes(Y));
    pt = addPadding(pt, seed, toBytes(X)); // converts pt into padded Uint8Array byte data
    for (let i = 0; i < getNumBlocks(pt.length); i++) // for each block
    {
        for (let j = 0; j < BLOCK_SIZE; j++) // for each byte in block
        {
            if (j + (BLOCK_SIZE * i) != 0) { // check to see if block only has 1 byte in it
                pt[j + (BLOCK_SIZE * i)] = ((pt[j + (BLOCK_SIZE * i)] ^ pt[j + (BLOCK_SIZE * i) - 1]) ^ seed[j]);
            } else {
                pt[j + (BLOCK_SIZE * i)] = (pt[j + (BLOCK_SIZE * i)] ^ seed[j]);
            }
        }
    }
    // turn into fixed 64-byte array
    var sum = 0;
    var digest = new Uint8Array(BLOCK_SIZE);
    for (let i = 0; i < pt.length / BLOCK_SIZE; i++) {
        for (let j = 0; j < BLOCK_SIZE; j++) {
            digest[j] += (digest[j] + pt[j + (i * BLOCK_SIZE)]);
            sum += digest[j];
        }
    }
    // obfuscate each byte by the sum of the 512-bit block ensuring avalanche
    for (let i = 0; i < digest.length; i++) {
        digest[i] += sum;
        digest[i] = digest[i] % 127;
        if (digest[i] < 33) { // remove unwanted UTF-8 characters
            digest[i] += 33;
        }
    }
    return digest;
}

/* Hashes the plaintext and compares it with the other hash to check if they are equal
 * @args: String pt - plaintext to be hashed and compared
 * @args: String hash - hash to be compared with hashed plaintext
 * @returns: Boolean
 */
function hashCompare(pt, hash) {
    return fromBytes(pcrypt(pt)) == hash;
}
var pt10 = "Donec vel.";
var pt100 = "Donec vel mauris purus. Ut sit amet nulla mattis, bibendum dolor sit amet, interdum est. Bibendum t.";
var pt1000 = "Donec vel mauris purus. Ut sit amet nulla mattis, bibendum dolor sit amet, interdum est. Fusce nec quam in nisl mattis malesuada. Donec sit amet nulla non purus finibus tempor. Sed dignissim blandit pretium. Donec efficitur pellentesque dolor ac venenatis. Vivamus pulvinar quis neque non suscipit. Interdum et malesuada fames ac ante ipsum primis in faucibus. Aliquam eget viverra lectus, a ornare lacus. Praesent sed nibh placerat, varius odio in, condimentum tortor. Suspendisse tellus magna, pretium at convallis nec, placerat at est. Nam consectetur eget erat id hendrerit. Suspendisse eu mauris non erat porta dignissim vel et leo. Nunc ut justo consequat, pretium sem ut, aliquet enim. Nullam placerat ligula metus, commodo feugiat mauris efficitur vel. Nullam placerat ligula metus, commodo feugiat mauris efficitur vel. Nullam placerat ligula metus, commodo feugiat mauris efficitur vel. Nullam placerat ligula metus, commodo feugiat mauris efficitur vel. Nullam placerat ligula metus, comm.";
var pt10000 = pt1000 + pt1000 + pt1000 + pt1000 + pt1000 + pt1000 + pt1000 + pt1000 + pt1000 + pt1000;
var pt100000 = pt10000 + pt10000 + pt10000 + pt10000 + pt10000 + pt10000 + pt10000 + pt10000 + pt10000 + pt10000;

console.log(`=================[My Implementation]=================`);
var t0 = performance.now();
var et = pcrypt(pt10);
var t1 = performance.now();
console.log(`PT = 10: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = pcrypt(pt100);
t1 = performance.now();
console.log(`PT = 100: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = pcrypt(pt1000);
t1 = performance.now();
console.log(`PT = 1000: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = pcrypt(pt10000);
t1 = performance.now();
console.log(`PT = 10000: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = pcrypt(pt100000);
t1 = performance.now();
console.log(`PT = 100000: Encryption took [${t1 - t0}ms]`);
console.log(`=====================================================\n`)

console.log(`=================[SHA-1]=================`);
t0 = performance.now();
et = sha1(pt10);
t1 = performance.now();
console.log(`SHA-1 = 10: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = sha1(pt100);
t1 = performance.now();
console.log(`SHA-1 = 100: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = sha1(pt1000);
t1 = performance.now();
console.log(`SHA-1 = 1000: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = sha1(pt10000);
t1 = performance.now();
console.log(`SHA-1 = 10000: Encryption took [${t1 - t0}ms]`);

t0 = performance.now();
et = sha1(pt100000);
t1 = performance.now();
console.log(`SHA-1 = 100000: Encryption took [${t1 - t0}ms]`);
console.log(`=====================================================`)


//et = pcrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
//console.log(fromBytes(et));