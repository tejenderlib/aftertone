// test/netclient.test.js — client-side Phase 5 behaviour, tested against the
// REAL client/net.js running in a minimal browser shim (test/helpers/netenv.js).
//
// net.js encrypts on the way out and decrypts on the way in, so the interesting
// failures are all local: a tampered envelope must be dropped, and a dead
// session must not be able to send. Those cannot be seen from the server side,
// which is why these run the shipped client rather than a copy of its logic.
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, Client } from './helpers/client.js';
import { createNet, once, waitReady, expectNoEvent } from './helpers/netenv.js';
import { crypto, envelope } from './helpers/e2ee.js';

/**
 * Pair a real net.js instance with a raw protocol client that does the other
 * half of the key exchange by hand. Returns the raw client's session key, so
 * tests can encrypt toward net.js and read what net.js sends.
 */
async function pairWithRaw(net, srv, { durationMin } = {}) {
  await waitReady(net);
  const code = await net.createInvite(durationMin);

  const raw = new Client(srv.wsUrl);
  await raw.open();

  const requested = once(net, 'connection-request');
  await raw.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
  await requested;

  const netPubForRaw = raw.waitFor('key-exchange');
  const netReady = once(net, 'crypto-ready');
  await net.acceptConnection(code);
  const { publicKey: netPublicKey } = await netPubForRaw;

  const rawPair = await crypto.generateKeyPair();
  raw.send({ type: 'key-exchange', publicKey: await crypto.exportPublicKey(rawPair.publicKey) });
  await netReady;

  const rawKey = await crypto.deriveSharedKey(
    rawPair.privateKey,
    await crypto.importPublicKey(netPublicKey)
  );

  return { raw, rawKey, netPublicKey, code };
}

describe('Phase 5 — client (client/net.js)', () => {
  let srv;
  let net;
  let ctx;

  before(async () => {
    srv = await startServer();
    ctx = createNet(srv.port);
    net = ctx.net;
  });

  after(async () => {
    ctx.cleanup();
    await srv.stop();
  });

  test('net.js sends an envelope and never a plaintext text field', async () => {
    const { raw, rawKey } = await pairWithRaw(net, srv);
    try {
      const got = raw.waitFor('message');
      await net.sendMessage('HELLO BEACON');
      const m = await got;
      assert.equal(m.text, undefined, 'no plaintext may reach the socket');
      assert.equal(typeof m.iv, 'string');
      assert.equal(await crypto.decrypt(rawKey, m), 'HELLO BEACON');
    } finally {
      raw.close();
    }
  });

  test('net.js emits the pre-Phase-5 message shape, so the UI is unchanged', async () => {
    const { raw, rawKey } = await pairWithRaw(net, srv);
    try {
      const inbound = once(net, 'message');
      raw.send(await envelope(rawKey, 'UI SHAPE CHECK'));
      const m = await inbound;
      assert.deepEqual(Object.keys(m).sort(), ['messageId', 'text', 'timestamp']);
      assert.equal(m.text, 'UI SHAPE CHECK');
      assert.match(m.messageId, /^[0-9a-f-]{36}$/i);
    } finally {
      raw.close();
    }
  });

  test('the 160-character limit is enforced where the plaintext is readable', async () => {
    const { raw, rawKey } = await pairWithRaw(net, srv);
    try {
      // Outgoing: net.js owns the limit now, because it is the only side that
      // can see the plaintext. Over-long text never becomes an envelope.
      await assert.rejects(() => net.sendMessage('   '), /empty-message/);
      await assert.rejects(() => net.sendMessage('x'.repeat(161)), /message-too-long/);

      // Incoming: what a peer sent is what the UI shows, unaltered.
      const inbound = once(net, 'message');
      raw.send(await envelope(rawKey, '   padded   '));
      assert.equal((await inbound).text, '   padded   ');

      // ...and a sender that trims first still lands the trimmed text.
      const outbound = raw.waitFor('message');
      await net.sendMessage('   padded   ');
      assert.equal(await crypto.decrypt(rawKey, await outbound), 'padded');
    } finally {
      raw.close();
    }
  });

  test('tampered ciphertext fails authentication and produces no message', async () => {
    const { raw, rawKey } = await pairWithRaw(net, srv);
    try {
      const env = await envelope(rawKey, 'DO NOT MODIFY');
      const bytes = Buffer.from(env.ciphertext, 'base64');
      bytes[0] ^= 1;

      const failed = once(net, 'error');
      raw.send({ ...env, ciphertext: bytes.toString('base64') });

      assert.equal((await failed).error, 'decrypt-failed');
      assert.equal(await expectNoEvent(net, 'message'), true, 'a message must never be emitted');
    } finally {
      raw.close();
    }
  });

  test('a tampered IV also fails authentication', async () => {
    const { raw, rawKey } = await pairWithRaw(net, srv);
    try {
      const env = await envelope(rawKey, 'IV IS AUTHENTICATED TOO');
      const iv = Buffer.from(env.iv, 'base64');
      iv[0] ^= 1;

      const failed = once(net, 'error');
      raw.send({ ...env, iv: iv.toString('base64') });

      assert.equal((await failed).error, 'decrypt-failed');
      assert.equal(await expectNoEvent(net, 'message'), true);
    } finally {
      raw.close();
    }
  });

  test('a ciphertext from a different session key is rejected', async () => {
    const first = await pairWithRaw(net, srv);
    let staleEnvelope;
    try {
      staleEnvelope = await envelope(first.rawKey, 'STALE SESSION PAYLOAD');
    } finally {
      first.raw.close();
    }

    const second = await pairWithRaw(net, srv);
    try {
      // Same server, same net.js instance, brand new pairing. The envelope from
      // the dead session must not authenticate under the new key.
      const failed = once(net, 'error');
      second.raw.send(staleEnvelope);
      assert.equal((await failed).error, 'decrypt-failed');
      assert.equal(await expectNoEvent(net, 'message'), true);
    } finally {
      second.raw.close();
    }
  });

  test('a new peer session derives a fresh keypair', async () => {
    const first = await pairWithRaw(net, srv);
    const firstKey = first.netPublicKey;
    first.raw.close();
    await once(net, 'peer-disconnected');

    const second = await pairWithRaw(net, srv);
    try {
      assert.notEqual(firstKey, second.netPublicKey, 'ephemeral key must be regenerated');
      // And the two sessions' keys are not interchangeable.
      const fromOld = await envelope(first.rawKey, 'FROM THE OLD SESSION');
      const failed = once(net, 'error');
      second.raw.send(fromOld);
      assert.equal((await failed).error, 'decrypt-failed');
    } finally {
      second.raw.close();
    }
  });

  test('net.js clears the session key when the peer disconnects', async () => {
    const { raw } = await pairWithRaw(net, srv);
    const lost = once(net, 'peer-disconnected');
    raw.close();
    await lost;

    // A dead session must refuse to send rather than encrypt into the void.
    await assert.rejects(() => net.sendMessage('anyone there?'), /not-connected/);
  });
});

describe('Phase 5 — client session teardown', () => {
  let srv;

  before(async () => { srv = await startServer(); });
  after(async () => { await srv.stop(); });

  test('the session key is dropped when the connection expires', async () => {
    const short = await startServer({ env: { MB88_TEST_DURATIONS: '0.03' } });
    const ctx = createNet(short.port);
    try {
      const { raw } = await pairWithRaw(ctx.net, short, { durationMin: 0.03 });
      const expired = once(ctx.net, 'connection-expired', { timeout: 10_000 });
      await expired;
      // Expiry is the same teardown as a lost peer: no key, no sends.
      await assert.rejects(() => ctx.net.sendMessage('after expiry'), /not-connected/);
      raw.close();
    } finally {
      ctx.cleanup();
      await short.stop();
    }
  });

  test('the session key is dropped when the socket closes', async () => {
    const ctx = createNet(srv.port);
    try {
      const { raw } = await pairWithRaw(ctx.net, srv);
      const gone = once(ctx.net, 'status', { timeout: 5000 });
      // net.disconnect() closes the socket, which is what a tab close does.
      ctx.net.disconnect();
      const status = await gone;
      await new Promise((r) => setTimeout(r, 100));
      await assert.rejects(() => ctx.net.sendMessage('after close'), /not-connected/);
      assert.equal(status.status, 'DISCONNECTED');
      raw.close();
    } finally {
      ctx.cleanup();
    }
  });
});

describe('Phase 5 — session fingerprint verification', () => {
  let srv;

  before(async () => { srv = await startServer(); });
  after(async () => { await srv.stop(); });

  /** Pair a real net.js with a raw client; capture the crypto-ready payload. */
  async function pairCapturing(net, attackerPub = null) {
    await waitReady(net);
    const code = await net.createInvite(60);
    const raw = new Client(srv.wsUrl);
    await raw.open();
    const requested = once(net, 'connection-request');
    await raw.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await requested;
    const netPubForRaw = raw.waitFor('key-exchange');
    const netReady = once(net, 'crypto-ready');
    await net.acceptConnection(code);
    const { publicKey: netPub } = await netPubForRaw;
    const rawPair = await crypto.generateKeyPair();
    const rawPub = await crypto.exportPublicKey(rawPair.publicKey);
    // Honest path delivers rawPub; a substituting relay delivers attackerPub.
    raw.send({ type: 'key-exchange', publicKey: attackerPub || rawPub });
    const ready = await netReady;
    const rawKey = await crypto.deriveSharedKey(
      rawPair.privateKey, await crypto.importPublicKey(netPub));
    return { net, raw, rawPair, rawPub, netPub, rawKey, ready, code };
  }

  test('honest paired clients show matching fingerprints', async () => {
    const a = createNet(srv.port);
    const b = createNet(srv.port);
    try {
      await waitReady(a.net);
      await waitReady(b.net);
      const code = await a.net.createInvite(60);
      const readyA = once(a.net, 'crypto-ready');
      const readyB = once(b.net, 'crypto-ready');
      await b.net.joinInvite(code);
      await a.net.acceptConnection(code);
      const [{ fingerprint: fpA }, { fingerprint: fpB }] = await Promise.all([readyA, readyB]);
      assert.match(fpA, /^[0-9a-f]{4}(-[0-9a-f]{4}){5}$/);
      assert.equal(fpA, fpB);
    } finally {
      a.cleanup();
      b.cleanup();
    }
  });

  test('a substituted public key produces a different fingerprint — and reads traffic', async () => {
    const ctx = createNet(srv.port);
    try {
      const atk = await crypto.generateKeyPair();
      const atkPub = await crypto.exportPublicKey(atk.publicKey);
      const { net, raw, netPub, rawPub, ready } =
        await pairCapturing(ctx.net, atkPub);
      const fpHonest = await crypto.fingerprint(netPub, rawPub);
      assert.notEqual(ready.fingerprint, fpHonest,
        'the victim must not show the fingerprint of the honest session');
      // The substitution is a working session for the attacker: it decrypts
      // victim-bound messages, which is exactly the MITM under test.
      const atkKey = await crypto.deriveSharedKey(
        atk.privateKey, await crypto.importPublicKey(netPub));
      const heard = once(net, 'message');
      raw.send(await envelope(atkKey, 'intercept me'));
      assert.equal((await heard).text, 'intercept me');
      raw.close();
    } finally {
      ctx.cleanup();
    }
  });

  test('verification is never automatic', async () => {
    const ctx = createNet(srv.port);
    try {
      const { net, raw, ready } = await pairCapturing(ctx.net);
      assert.deepEqual(Object.keys(ready).sort(), ['fingerprint', 'ready']);
      assert.equal(typeof net.verify, 'undefined', 'no verify API may exist to call itself');
      assert.ok(await expectNoEvent(net, 'verified'),
        'nothing may emit verification on the client’s behalf');
      raw.close();
    } finally {
      ctx.cleanup();
    }
  });

  test('re-keying emits a new fingerprint, invalidating previous verification', async () => {
    const ctx = createNet(srv.port);
    try {
      const { net, raw, ready } = await pairCapturing(ctx.net);
      const rekeyed = once(net, 'crypto-ready');
      const fresh = await crypto.generateKeyPair();
      raw.send({ type: 'key-exchange',
                 publicKey: await crypto.exportPublicKey(fresh.publicKey) });
      const fp2 = (await rekeyed).fingerprint;
      assert.notEqual(fp2, ready.fingerprint,
        'a replacement key must never keep displaying the old fingerprint');
      raw.close();
    } finally {
      ctx.cleanup();
    }
  });

  test('disconnect followed by re-pairing yields a fresh fingerprint', async () => {
    const ctx = createNet(srv.port);
    try {
      const first = await pairCapturing(ctx.net);
      const gone = once(ctx.net, 'peer-disconnected');
      first.raw.close();
      await gone;
      const second = await pairCapturing(ctx.net);
      assert.notEqual(second.ready.fingerprint, first.ready.fingerprint,
        'no stale session state may survive teardown');
      second.raw.close();
    } finally {
      ctx.cleanup();
    }
  });

  test('a cancelled request never produces a fingerprint', async () => {
    const ctx = createNet(srv.port);
    try {
      await waitReady(ctx.net);
      const code = await ctx.net.createInvite(60);
      const raw = new Client(srv.wsUrl);
      await raw.open();
      try {
        const requested = once(ctx.net, 'connection-request');
        await raw.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
        await requested;
        await ctx.net.rejectConnection(code);
        assert.ok(await expectNoEvent(ctx.net, 'crypto-ready'),
          'no session, no key, no fingerprint');
      } finally {
        raw.close();
      }
    } finally {
      ctx.cleanup();
    }
  });
});
