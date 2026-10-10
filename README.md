# AFTERTONE

**Two devices. One private line.**

A retro-inspired, real-time messaging terminal for two people. Pair two devices using a private invite code and exchange short, encrypted messages through a minimal CRT-style interface.

**[Live Demo](https://aftertone-u6rr.onrender.com/)** · **[Report a Bug](https://github.com/tejenderlib/aftertone/issues)**

![License: MIT](https://img.shields.io/badge/license-MIT-8bf03c?style=flat-square)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?style=flat-square)

## Features

- **Private pairing** — Connect two devices using an invite code or link.
- **Real-time messaging** — Exchange messages over WebSockets.
- **Encrypted message content** — Messages are encrypted in the browser using the Web Crypto API.
- **Temporary connections** — Connections expire automatically and can be extended.
- **Retro terminal interface** — CRT-inspired visuals and pager-style message slips.
- **No accounts** — No registration or user directory.
- **Lightweight architecture** — Plain HTML, CSS, and JavaScript with a Node.js server.

## Security

AFTERTONE encrypts message content on the devices using P-256 ECDH, HKDF-SHA256, and AES-256-GCM.

**Important:** The public-key exchange is not authenticated. An active man-in-the-middle, including a malicious relay, could substitute public keys and read messages. Do not treat AFTERTONE as suitable for highly sensitive communications.

The server relays encrypted message envelopes but can observe connection metadata, including message timing and pairing events.

## Getting Started

### Requirements

- Node.js 18 or newer
- npm

### Installation

```bash
git clone https://github.com/tejenderlib/aftertone.git
cd aftertone
npm ci
npm start
```

Open <http://localhost:3000> in two browser windows or on two devices that can reach the server.

Create an invite on one device, join from the other, and accept the connection to begin messaging.

### Commands

| Command | Description |
| --- | --- |
| `npm start` | Start the server |
| `npm test` | Run the test suite |

The server listens on port `3000` by default. Set `PORT` to use another port.

## Tech Stack

- Node.js
- WebSockets (`ws`)
- HTML, CSS, and JavaScript
- Web Crypto API
- Node.js built-in test runner

## Project Structure

```text
aftertone/
├── client/     # Interface, messaging client, cryptography
├── server/     # HTTP server, WebSocket relay, pairing
├── test/       # Automated tests
├── media/      # Project media
├── package.json
└── README.md
```

## Development

Run the test suite before submitting changes:

```bash
npm test
```

Contributions and bug reports are welcome through [GitHub Issues](https://github.com/tejenderlib/aftertone/issues).

## License

[MIT](LICENSE)
