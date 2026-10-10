# AFTERTONE

**Two devices. One private line.**

A retro-inspired, real-time messaging terminal for two people. Pair two devices using a private invite code and exchange encrypted messages through a minimal CRT-style interface.

**[Live Demo](https://aftertone-u6rr.onrender.com/)** · **[Report a Bug](https://github.com/tejenderlib/aftertone/issues)**

![License: MIT](https://img.shields.io/badge/license-MIT-8bf03c?style=flat-square)
![Node.js](https://img.shields.io/badge/Node.js-Runtime-339933?style=flat-square&logo=nodedotjs&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-Vanilla-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![CSS3](https://img.shields.io/badge/CSS3-Styling-1572B6?style=flat-square&logo=css3&logoColor=white)
![Web Crypto API](https://img.shields.io/badge/Web_Crypto_API-Encryption-8A2BE2?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-89_Passing-2EA44F?style=flat-square)

---

## Security

AFTERTONE encrypts message content in the browser using P-256 ECDH, HKDF-SHA256, and AES-256-GCM.

**Important:** The public-key exchange is not authenticated. An active man-in-the-middle, including a malicious relay, could substitute public keys and read messages. Do not treat AFTERTONE as suitable for highly sensitive communications.

The server relays encrypted message envelopes but can observe connection metadata, including message timing and pairing events.

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) 18 or newer
- npm (included with Node.js)

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/tejenderlib/aftertone.git
cd aftertone
npm ci
```

### Run Locally

Start the server:

```bash
npm start
```

To test messaging, open the application in two browser windows or use two devices that can reach your server.

1. Create an invite on the first device.
2. Join using the invite code on the second device.
3. Accept the connection to start messaging.

### Available Commands

| Command | Description |
| --- | --- |
| `npm start` | Start the application server |
| `npm test` | Run the automated test suite |

The server listens on port `3000` by default. To use a different port:
```bash
PORT=4000 npm start
```



## Contributing

Contributions and bug reports are welcome through [GitHub Issues](https://github.com/tejenderlib/aftertone/issues).


## License

[MIT](LICENSE)
