// Tab switching functionality
document.querySelectorAll('.tab-link').forEach(tab => {
    tab.addEventListener('click', function () {
        const tabId = this.getAttribute('data-tab');
        document.querySelectorAll('.tab-link, .tab-content').forEach(el => el.classList.remove('current'));
        this.classList.add('current');
        document.getElementById(tabId).classList.add('current');
    });
});

// Generate random IV in hex format
function randomIVGen() {
    const iv = new Uint8Array(16);
    for (let i = 0; i < iv.length; i++) {
        iv[i] = Math.floor(Math.random() * 256);
    }
    return bytesToHex(iv);
}

// Validate inputs
function validateInputs(key, iv) {
    if (!key || !iv) {
        alert("Please fill in all fields");
        return false;
    }
    if (!/^[0-9A-Fa-f]{32}$/.test(iv)) {
        alert("IV must be 32 hex characters");
        return false;
    }
    return true;
}

// Text encryption/decryption
function aesText(encryptingToggle) {
    try {
        const key = document.getElementById("key").value;
        const iv = document.getElementById("iv").value;
        const verbose = document.getElementById("verboseToggle").checked;

        if (!validateInputs(key, iv)) return;

        if (encryptingToggle) {
            const text = document.getElementById("plainTextInput").value;
            const paddedData = pad(hexToBytes(textToHex(text)), 16);
            document.getElementById("output").value = bytesToHex(aesEncrypt(paddedData, key, iv, verbose));
        } else {
            const cipher = document.getElementById("cipherText").value;
            const decrypted = aesDecrypt(hexToBytes(cipher), key, iv, verbose);
            document.getElementById("output").value = hexToText(bytesToHex(unpad(decrypted)));
        }
    } catch (e) {
        alert("Error: " + e.message);
    }
}

// File handling functions
async function aesFile(encryptingToggle) {
    try {
        const file = document.getElementById("fileInput").files[0];
        const key = document.getElementById("keyFile").value;
        const iv = document.getElementById("ivFile").value;
        const verbose = document.getElementById("verboseToggle").checked;

        if (!file) {
            alert("Please select a file");
            return;
        }
        if (!validateInputs(key, iv)) return;

        const buffer = await file.arrayBuffer();
        const data = Array.from(new Uint8Array(buffer));
        const processed = encryptingToggle ? aesEncrypt(data, key, iv, verbose) : aesDecrypt(data, key, iv, verbose);

        const blob = new Blob([new Uint8Array(processed)]);
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = encryptingToggle ? `${file.name}.enc` : file.name.replace('.enc', '');
        link.click();
    } catch (e) {
        alert("Error: " + e.message);
    }
}