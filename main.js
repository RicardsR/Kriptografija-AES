// ==== Core utility functions ====
function textToHex(text) {
  let result = "";
  for (let char of text) {
    let hex = char.charCodeAt(0).toString(16);
    if (hex.length === 1) hex = "0" + hex;
    result += hex;
  }
  return result;
}

function hexToBytes(hexString) {
  let bytes = [];
  for (let i = 0; i < hexString.length; i += 2) {
    let hex = hexString.substr(i, 2);
    let byte = parseInt(hex, 16);
    bytes.push(byte);
  }
  return bytes;
}

function bytesToHex(bytes) {
  let hex = "";
  for (let byte of bytes) {
    let byteHex = byte.toString(16);
    if (byteHex.length === 1) byteHex = "0" + byteHex;
    hex += byteHex;
  }
  return hex;
}

function hexToText(hexString) {
  let bytes = hexToBytes(hexString);
  let text = "";
  for (let byte of bytes) {
    text += String.fromCharCode(byte);
  }
  return text;
}

// XOR function for byte arrays
function xorBytes(array1, array2) {
  let result = [];
  for (let i = 0; i < array1.length; i++) {
    result.push(array1[i] ^ array2[i]);
  }
  return result;
}

// PKCS7 padding function
function pad(data, size) {
  let padding = size - (data.length % size);
  let result = data.slice();
  for (let i = 0; i < padding; i++) {
    result.push(padding);
  }
  return result;
}

function unpad(bytes) {
  let paddingLength = bytes[bytes.length - 1];
  return bytes.slice(0, bytes.length - paddingLength);
}

// ==== AES core operations ====

// Multiplication function in GF(2^8)
function multiply(num1, num2) {
  let result = 0;
  for (let bitPosition = 0; bitPosition < 8; bitPosition++) {
    if (num2 & 1) {
      result = result ^ num1;
    }
    const highestBit = num1 & 0x80;
    num1 = (num1 << 1) & 0xff;
    if (highestBit) {
      num1 = num1 ^ 0x1b;
    }
    num2 = num2 >> 1;
  }

  return result;
}

// Replaces each byte in state array using the S-Box or inverse S-Box table
function subBytes(state, inv = false) {
  let result = [];
  if (inv) {
    for (let byte of state) {
      result.push(invSBox[byte]);
    }
  } else {
    for (let byte of state) {
      result.push(sBox[byte]);
    }
  }
  return result;
}

// AES specification row shift function
function shiftRows(state, inv = false) {
  if (inv) {
    // For inverse shift:
    // Row 0: Stays the same
    // Row 1: Shift right by 1 position
    // Row 2: Shift right by 2 positions
    // Row 3: Shift right by 3 positions
    return [
      state[0], state[13], state[10], state[7],
      state[4], state[1], state[14], state[11],
      state[8], state[5], state[2], state[15],
      state[12], state[9], state[6], state[3]
    ];
  } else {
    // For forward shift:
    // Row 0: Stays the same
    // Row 1: Shift left by 1 position
    // Row 2: Shift left by 2 positions
    // Row 3: Shift left by 3 positions
    return [
      state[0], state[5], state[10], state[15],
      state[4], state[9], state[14], state[3],
      state[8], state[13], state[2], state[7],
      state[12], state[1], state[6], state[11]
    ];
  }
}


// Mixes columns using matrix multiplication in GF(2^8)
function mixColumns(state, inv = false) {
  const mixed = new Array(16);
  for (let i = 0; i < 4; i++) {
    const col = [
      state[i * 4],
      state[i * 4 + 1],
      state[i * 4 + 2],
      state[i * 4 + 3],
    ];

    // Depending on whether we are in forward or inverse mixColumns
    let mix;
    if (inv) {
      mix = [0x0e, 0x0b, 0x0d, 0x09];
    } else {
      mix = [0x02, 0x03, 0x01, 0x01];
    }

    for (let j = 0; j < 4; j++) {
      mixed[i * 4 + j] =
        multiply(mix[0], col[j]) ^
        multiply(mix[1], col[(j + 1) % 4]) ^
        multiply(mix[2], col[(j + 2) % 4]) ^
        multiply(mix[3], col[(j + 3) % 4]);
    }
  }
  return mixed;
}

function keyExpansion(key) {
  const roundKeys = [];
  for (let i = 0; i < 16; i++) {
    roundKeys[i] = key[i];
  }

  for (let i = 1; i <= 10; i++) {
    const temp = roundKeys.slice((i - 1) * 16, i * 16);
    const lastWord = temp.slice(-4);
    const rotatedWord = [
      lastWord[1],
      lastWord[2],
      lastWord[3],
      lastWord[0],
    ].map((byte) => sBox[byte]);

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

function aesEncrypt(plainText, key, iv, verbose = false) {
  // For debugging
  function log(msg) {
    if (verbose) console.log(msg);
  }

  log("Starting encryption with:\nKey: " + key + "\nIV: " + iv + "\nPlain text: " + hexToText(bytesToHex(plainText)));

  // Split input into 16-byte blocks
  const blocks = [];
  for (let i = 0; i < plainText.length; i += 16) {
    blocks.push(plainText.slice(i, i + 16));
  }
  log("Split into blocks:");

  if (verbose) {
    for (let i = 0; i < blocks.length; i++) {
      log("Block " + (i + 1) + ": " + blocks[i]);
    }
  }

  // Prepare the encryption key
  const paddedKey = key.padEnd(16, "0");
  const keyInBytes = hexToBytes(textToHex(paddedKey));
  const expandedKey = keyExpansion(keyInBytes);
  log("Key preparation: \nPadded key: " + paddedKey + "\nKey in bytes: " + keyInBytes + "\nExpanded key: " + expandedKey);

  // Initialize variables
  let previousBlock = hexToBytes(iv);
  let encryptedData = [];
  log("Initial IV block: " + previousBlock);

  // Process each block
  blocks.forEach((block, index) => {
    log("Processing block:" + (index + 1) + " " + block);

    // XOR with previous block (CBC mode)
    let currentBlock = xorBytes(block, previousBlock);
    log("After XOR with previous: " + currentBlock);

    // Initial round
    currentBlock = xorBytes(currentBlock, expandedKey.slice(0, 16));
    log("After initial round: " + currentBlock);

    // Main rounds
    for (let round = 1; round <= 10; round++) {
      log("\nStarting round: " + round);

      currentBlock = subBytes(currentBlock);
      log("After SubBytes: " + currentBlock);

      currentBlock = shiftRows(currentBlock);
      log("After ShiftRows: " + currentBlock);

      if (round < 10) {
        currentBlock = mixColumns(currentBlock);
        log("After MixColumns: " + currentBlock);
      }

      currentBlock = xorBytes(currentBlock, expandedKey.slice(round * 16, (round + 1) * 16));
      log("After round key addition: " + currentBlock);
    }

    previousBlock = currentBlock;
    encryptedData = encryptedData.concat(currentBlock);
  });

  log("\nFinal encrypted data: " + bytesToHex(encryptedData));
  return encryptedData;
}

function aesDecrypt(ciphertext, key, iv, verbose = false) {
  // For debugging
  function log(msg) {
    if (verbose) console.log(msg);
  }

  log("Starting decryption with:\nKey: " + key + "\nIV: " + iv + "\nChipertext: " + bytesToHex(ciphertext));

  // Split input into 16-byte blocks
  const blocks = [];
  for (let i = 0; i < ciphertext.length; i += 16) {
    blocks.push(ciphertext.slice(i, i + 16));
  }
  log("Split into blocks: " + blocks);

  // Prepare the decryption key
  const paddedKey = key.padEnd(16, "0");
  const keyInBytes = hexToBytes(textToHex(paddedKey));
  const expandedKey = keyExpansion(keyInBytes);
  log("Key preparation: \nPadded key: " + paddedKey + "\nKey in bytes: " + keyInBytes + "\nExpanded key: " + expandedKey);

  let decryptedData = [];

  // Process blocks in reverse (CBC mode requirement)
  for (let i = blocks.length - 1; i >= 0; i--) {
    log("Processing block:" + (i + 1) + " " + blocks[i]);

    let currentBlock = blocks[i].slice();
    log("Current block: " + currentBlock);

    // Start with the last round key
    currentBlock = xorBytes(currentBlock, expandedKey.slice(160, 176));
    log("After initial key addition: " + currentBlock);

    // Main rounds
    for (let round = 9; round >= 0; round--) {
      log("\nStarting round " + round);

      currentBlock = shiftRows(currentBlock, true);
      log("After InverseShiftRows: " + currentBlock);

      currentBlock = subBytes(currentBlock, true);
      log("After InverseSubBytes: " + currentBlock);

      currentBlock = xorBytes(currentBlock, expandedKey.slice(round * 16, (round + 1) * 16));
      log("After round key addition: " + currentBlock);

      if (round > 0) {
        currentBlock = mixColumns(currentBlock, true);
        log("After InverseMixColumns: " + currentBlock);
      }
    }

    // XOR with previous block or IV
    const previousBlock = i > 0 ? blocks[i - 1] : hexToBytes(iv);
    currentBlock = xorBytes(currentBlock, previousBlock);
    log("After XOR with previous block: " + currentBlock);

    decryptedData = currentBlock.concat(decryptedData);
  }

  log("\nFinal decrypted data: " + hexToText(bytesToHex(decryptedData)));
  return decryptedData;
}