(function () {
  'use strict';

  if (window.__beeperCrypto) return;

  var subtle = window.crypto && window.crypto.subtle;
  if (!subtle) {
    throw new Error('Web Crypto API is unavailable');
  }

  var ECDH_ALGORITHM = {
    name: 'ECDH',
    namedCurve: 'P-256'
  };

  var AES_ALGORITHM = 'AES-GCM';
  var AES_KEY_LENGTH = 256;
  var IV_LENGTH = 12;

  function bytesToBase64(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    var binary = atob(value);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function generateKeyPair() {
    return subtle.generateKey(
      ECDH_ALGORITHM,
      true,
      ['deriveBits']
    );
  }

  async function exportPublicKey(publicKey) {
    var raw = await subtle.exportKey('raw', publicKey);
    return bytesToBase64(new Uint8Array(raw));
  }

  async function importPublicKey(publicKeyBase64) {
    return subtle.importKey(
      'raw',
      base64ToBytes(publicKeyBase64),
      ECDH_ALGORITHM,
      false,
      []
    );
  }

  async function deriveSharedKey(privateKey, peerPublicKey) {
    var bits = await subtle.deriveBits(
      {
        name: 'ECDH',
        public: peerPublicKey
      },
      privateKey,
      256
    );

    /*
     * HKDF is deliberately used after ECDH rather than using the raw
     * ECDH output directly as the AES key.
     */
    var hkdfKey = await subtle.importKey(
      'raw',
      bits,
      'HKDF',
      false,
      ['deriveKey']
    );

    return subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('MB88-PHASE5'),
        info: new TextEncoder().encode('MB88-MESSAGE-KEY')
      },
      hkdfKey,
      {
        name: AES_ALGORITHM,
        length: AES_KEY_LENGTH
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(key, plaintext) {
    var iv = new Uint8Array(IV_LENGTH);
    window.crypto.getRandomValues(iv);

    var encoded = new TextEncoder().encode(plaintext);

    var ciphertext = await subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv: iv
      },
      key,
      encoded
    );

    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
  }

  async function decrypt(key, payload) {
    if (!payload || typeof payload.iv !== 'string' ||
        typeof payload.ciphertext !== 'string') {
      throw new Error('invalid-encrypted-message');
    }

    var plaintext = await subtle.decrypt(
      {
        name: AES_ALGORITHM,
        iv: base64ToBytes(payload.iv)
      },
      key,
      base64ToBytes(payload.ciphertext)
    );

    return new TextDecoder().decode(plaintext);
  }

  /*
   * Session fingerprint: SHA-256 over the two exchanged public-key base64
   * strings in canonical (sorted) order, shown as six short hex groups
   * (96 bits). Both keys already cross the wire in the clear, so hashing them
   * exposes nothing new — and the AES key and raw ECDH secret are never touched,
   * keeping them non-extractable. A substituted key necessarily changes the
   * fingerprint; displaying it fixes nothing by itself, it only gives the
   * two humans something to compare over a separate trusted channel.
   */
  async function fingerprint(ownPublicKeyBase64, peerPublicKeyBase64) {
    if (typeof ownPublicKeyBase64 !== 'string' || !ownPublicKeyBase64 ||
        typeof peerPublicKeyBase64 !== 'string' || !peerPublicKeyBase64) {
      throw new Error('invalid-public-key');
    }
    var ordered = [ownPublicKeyBase64, peerPublicKeyBase64].sort();
    var input = new TextEncoder().encode(
      'AFTERTONE-FINGERPRINT:' + ordered[0] + ':' + ordered[1]
    );
    var digest = await subtle.digest('SHA-256', input);
    var hex = Array.prototype.map.call(
      new Uint8Array(digest),
      function (b) { return (b < 16 ? '0' : '') + b.toString(16); }
    ).join('');
    return hex.slice(0, 4) + '-' + hex.slice(4, 8) + '-' + hex.slice(8, 12) + '-' +
           hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20, 24);
  }

  window.__beeperCrypto = {
    generateKeyPair: generateKeyPair,
    exportPublicKey: exportPublicKey,
    importPublicKey: importPublicKey,
    deriveSharedKey: deriveSharedKey,
    encrypt: encrypt,
    decrypt: decrypt,
    fingerprint: fingerprint
  };
})();
