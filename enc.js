// Function to generate a random AES key
async function generateKey() {
    let key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    let keyBuffer = await crypto.subtle.exportKey("raw", key);
    return { key, keyBase64: btoa(String.fromCharCode(...new Uint8Array(keyBuffer))) };
}

// Function to encrypt text to encrypt the code given by the user as it will comes firt to this function and then deviated to generate 
async function encryptText() {
    let message = document.getElementById("message").value;
    if (!message) {
        alert("Please enter a message to encrypt!");
        return;
    }

    let { key, keyBase64 } = await generateKey();
    let iv = crypto.getRandomValues(new Uint8Array(12)); 
    let encodedMessage = new TextEncoder().encode(message);

    let encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedMessage
    );

    let encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
    let ivBase64 = btoa(String.fromCharCode(...iv));

    document.getElementById("encryptedMessage").value = `${ivBase64}:${encryptedBase64}`;
    document.getElementById("encryptionKey").value = keyBase64;
}

// Function to decrypt text
async function decryptText() {
    let encryptedInput = document.getElementById("decryptMessage").value;
    let keyBase64 = document.getElementById("decryptKey").value;

    if (!encryptedInput || !keyBase64) {
        alert("Please enter an encrypted message and key!");
        return;
    }

    let [ivBase64, encryptedBase64] = encryptedInput.split(":");
    let iv = new Uint8Array(atob(ivBase64).split("").map(c => c.charCodeAt(0)));
    let encryptedData = new Uint8Array(atob(encryptedBase64).split("").map(c => c.charCodeAt(0)));
    let keyBuffer = new Uint8Array(atob(keyBase64).split("").map(c => c.charCodeAt(0)));

    let key = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        true,
        ["decrypt"]
    );

    try {
        let decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedData
        );

        let decryptedMessage = new TextDecoder().decode(decryptedBuffer);
        document.getElementById("decryptedOutput").value = decryptedMessage;
    } catch (e) {
        alert("Decryption failed! Check the key and encrypted message.");
    }
}
