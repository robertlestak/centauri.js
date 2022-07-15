# centauri.js

A one-line import to implement Centauri cryptographic functions in client side JavaScript.

```html
<script src="https://centauri.sh/js/v0.0.1/centauri.js"></script>
```

This will export the following global functions:

**Centauri_GenerateKeyPair()**

Generate a new public / private RSA key pair and return as a JSON object.

**Centauri_CreateSignature(privateKeyString)**

Create a new signature for an API request using the provided private key.

**Centauri_PubKeyFromPrivate(privateKeyString)**

Return the public key from the provided private key.

**Centauri_PubKeyID(publicKeyString)**

Return the public key ID from the provided public key.

**Centauri_CreateMessage(toPublicKeyString, rawMessageData)**

Create a new message with raw message data, encrypted by the provided public key.

**Centauri_DecryptMessage(privateKeyString, encryptedMessageData)**

Decrypt the provided encrypted message data using the provided private key.