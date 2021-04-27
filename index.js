/* PCRYPT-512 - Encryption Algorithm
 * Author: Ethan Z. Seligman
 * 4/26/21 
 */

/* Constants
 */
const BLOCK_SIZE = 64; // 512-bit block size
const PRIVATE_KEY = `2cvk4LNSwfLTwGsdtEodvUyZVTRD3d26ULeE0pbY47bFlNmp64ZGN3xww88ha6s`; // 512-bit private key
const PUBLIC_KEY = `mnyApBmqIhZJysXDBQDUk806bjoLpjuYQREYPT0xQL073dIBX27oQK4ka5zVLShJ`; // 512-bit public key

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

/* Takes in the private key and public key to generate the combined key as a Uint8Array of bytes
 * @args: String X - private key string
 * @args: String Y - public key string
 * @returns: Uint8Array
 */
function genKey(X, Y) {
    var Z = new Uint8Array(BLOCK_SIZE); // create new Uint8Array with 64 bytes;
    for (let i = 0; i < BLOCK_SIZE; i++) {
        Z[i] = X[i] ^ Y[i]; // X XOR Y
    }
    return Z;
}

/* Adds padding if there are less than 64 chars in the last block
 * @args: String pt - plaintext string
 * @args: Uint8Array k - combined public and private key
 * @args: String x - private key string
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

/* Encrypts a plaintext string and returns a Uint8Array of the encrypted plaintext
 * @args: String pt - plaintext to be encrypted
 * @args: String X - private key 
 * @args: String Y - public key 
 * @returns: Uint8Array
 */
function pcrypt(pt, X, Y) {
    const key = genKey(toBytes(X), toBytes(Y));
    pt = addPadding(pt, key, toBytes(X)); // converts pt into padded Uint8Array byte data
    for (let i = 0; i < getNumBlocks(pt.length); i++) // for each block
    {
        for (let j = 0; j < BLOCK_SIZE; j++) // for each byte in block
        {
            if (j + (BLOCK_SIZE * i) != 0) { // check to see if block only has 1 byte in it
                pt[j + (BLOCK_SIZE * i)] = ((pt[j + (BLOCK_SIZE * i)] ^ pt[j + (BLOCK_SIZE * i) - 1]) ^ key[j]) % 127;
            } else {
                pt[j + (BLOCK_SIZE * i)] = (pt[j + (BLOCK_SIZE * i)] ^ key[j]) % 127;
            }
            if (pt[j + (BLOCK_SIZE * i)] < 33) { // make sure empty characters are not included in hash
                pt[j + (BLOCK_SIZE * i)] += 33;
            }
        }
    }
    return pt;
}

/* Hashes the plaintext and compares it with the other hash to check if they are equal
 * @args: String pt - plaintext to be hashed and compared
 * @args: String hash - hash to be compared with hashed plaintext
 * @returns: Boolean
 */
function hashCompare(pt, hash) {
    return fromBytes(pcrypt(pt, PRIVATE_KEY, PUBLIC_KEY)) == hash;
}