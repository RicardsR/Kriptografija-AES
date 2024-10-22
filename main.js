const sBox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const Rcon = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
];

function textToHex(text) {
    return text.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function xorBytes(arr1, arr2) {
    return arr1.map((byte, i) => byte ^ arr2[i]);
}

function subBytes(state) {
    return state.map(byte => sBox[byte]);
}

function shiftRows(state) {
    const temp = Array.from(state);

    // 0  5  8 12
    // 1  5  9 13
    // 2  6 10 14
    // 3  7 11 15

    temp[1] = state[5];
    temp[5] = state[9];
    temp[9] = state[13];
    temp[13] = state[1];

    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];

    temp[3] = state[15];
    temp[7] = state[3];
    temp[11] = state[7];
    temp[15] = state[11];

    return temp;
}

function mixColumns(state) {
    const mixed = new Array(16);
    for (let i = 0; i < 4; i++) {
        const col = [state[i * 4], state[i * 4 + 1], state[i * 4 + 2], state[i * 4 + 3]];

        mixed[i * 4] = multiply(0x02, col[0]) ^ multiply(0x03, col[1]) ^ col[2] ^ col[3];
        mixed[i * 4 + 1] = col[0] ^ multiply(0x02, col[1]) ^ multiply(0x03, col[2]) ^ col[3];
        mixed[i * 4 + 2] = col[0] ^ col[1] ^ multiply(0x02, col[2]) ^ multiply(0x03, col[3]);
        mixed[i * 4 + 3] = multiply(0x03, col[0]) ^ col[1] ^ col[2] ^ multiply(0x02, col[3]);
    }
    return mixed;
}

// Multiply in GF(2^8)
function multiply(a, b) {
    let product = 0;
    let highBitSet;

    for (let i = 0; i < 8; i++) {
        if (b & 1) {
            product ^= a;
        }
        highBitSet = a & 0x80; // Check if the high bit is set
        a <<= 1; // Left shift
        if (highBitSet) {
            a ^= 0x1b; // Apply the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1; // Shift b right by 1 bit
    }

    return product & 0xFF; // Ensure the result fits within one byte (8 bits)
}

function keyExpansion(key) {
    const roundKeys = [];
    for (let i = 0; i < 16; i++) {
        roundKeys[i] = key[i];
    }

    for (let i = 1; i <= 10; i++) {
        const temp = roundKeys.slice((i - 1) * 16, i * 16);
        const lastWord = temp.slice(-4);
        const rotatedWord = [lastWord[1], lastWord[2], lastWord[3], lastWord[0]].map((byte) => sBox[byte]);

        // Round constant
        const rcon = Rcon[i - 1];

        // XOR the first byte of rotatedWord with the round constant
        const newKey = xorBytes(rotatedWord, rcon);

        for (let j = 0; j < 4; j++) {
            const index = i * 16 + j * 4;
            roundKeys[index] = roundKeys[(i - 1) * 16 + j * 4] ^ newKey[0];
            roundKeys[index + 1] = roundKeys[(i - 1) * 16 + j * 4 + 1] ^ newKey[1];
            roundKeys[index + 2] = roundKeys[(i - 1) * 16 + j * 4 + 2] ^ newKey[2];
            roundKeys[index + 3] = roundKeys[(i - 1) * 16 + j * 4 + 3] ^ newKey[3];
            
            // Update newKey for the next word
            newKey[0] = roundKeys[index];
            newKey[1] = roundKeys[index + 1];
            newKey[2] = roundKeys[index + 2];
            newKey[3] = roundKeys[index + 3];
        }
    }

    return roundKeys;
}

function aesEncrypt(plainText, plainKey) {
    const extendedKey = generateHexKey(plainKey);
    const hexKey = textToHex(extendedKey);
    console.log("Key: " + hexKey + "\n" + "Regular key: " + extendedKey);
    const key = hexToBytes(hexKey);

    // Generate round keys
    const roundKeys = keyExpansion(key);
    const roundKeysHex = roundKeys.map(byte => byte.toString(16).padStart(2, '0')).join('');
    const formattedRoundKeysHex = roundKeysHex.match(/.{1,8}/g).join(' ');
    console.log("Full Round Keys: " + formattedRoundKeysHex);

    const rounds = 10;

    // Split the input into 16-byte chunks
    const hexInput = textToHex(plainText);
    const blocks = [];
    for (let i = 0; i < hexInput.length; i += 32) {
        blocks.push(hexInput.slice(i, i + 32).padEnd(32, '0'));
    }

    let ciphertext = [];

    blocks.forEach((block, blockIndex) => {
        console.log(`\nProcessing block ${blockIndex + 1}:`);

        const state = hexToBytes(block);
        let currentState = state;

        currentState = xorBytes(currentState, roundKeys);
        console.log("Input to Round 0:", bytesToHex(currentState));

        // Rounds
        for (let round = 1; round <= rounds; round++) {
            console.log(`\n-= Round ${round} =-`);

            const afterSBox = subBytes(currentState);
            console.log("After S-Box:", bytesToHex(afterSBox));

            const afterPermutation = shiftRows(afterSBox);
            console.log("After Permutation (ShiftRows):", bytesToHex(afterPermutation));

            // After MixColumns (only for rounds 1-9)
            let afterMixColumns;
            if (round < rounds) {
                afterMixColumns = mixColumns(afterPermutation);
                console.log("After MixColumns:", bytesToHex(afterMixColumns));
            } else {
                afterMixColumns = afterPermutation; // No mix in the final round
            }

            const usedSubkey = roundKeys.slice(round * 16, (round + 1) * 16);
            console.log("Used Subkey:", bytesToHex(usedSubkey));

            currentState = xorBytes(afterMixColumns, usedSubkey);
            console.log("After Mix with Key:", bytesToHex(currentState));
        }

        ciphertext = ciphertext.concat(currentState);
    });

    return ciphertext;
}

function bytesToHex(bytes) {
    return bytes.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function generateHexKey(input) {
    return input.padEnd(16, '0').slice(0, 16);
}

// Testing
const plainText = "If you can read this.. Hell yeah it bloody works! :D";
const plainKey = "Test Key";
const ciphertext = aesEncrypt(plainText, plainKey);
const hexCiphertext = bytesToHex(ciphertext);
console.log("\nCiphertext (Hex):", hexCiphertext);