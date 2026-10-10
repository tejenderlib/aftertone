// test/protocol.test.js — Phase 1 (transport) and Phase 2 (invites, pairing,
// connection lifetime) baseline.
//
// This is the CURRENT plaintext protocol captured as-is, before E2EE.
// It asserts real server/server.js behaviour over real WebSockets; no
// production code is stubbed, mocked, or re-implemented.
import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';
import { startServer, pair, Client, CODE_RE, probeUntilError, sleep } from './helpers/client.js';

// Phase 5: `message` carries {iv, ciphertext}, never plaintext. This dummy
// envelope is only used where a test asserts pairing or lifetime, not crypto —
// the encryption behaviour itself is covered in regression.test.js.
const ENVELOPE = {
  type: 'message',
  iv: 'AAAAAAAAAAAAAAAA',
  ciphertext: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A',
};
// The dummy ciphertext must survive the server's base64 and size checks, or
// the test would pass for the wrong reason (invalid-message, not not-connected).
assert.ok(ENVELOPE.ciphertext.length % 4 === 0, 'ENVELOPE ciphertext must be valid base64');

describe('Phase 1 — transport', () => {
  let srv;
  const open = [];

  before(async () => { srv = await startServer(); });
  after(async () => {
    for (const c of open) c.close();
    await srv.stop();
  });

  function client() {
    const c = new Client(srv.wsUrl);
    open.push(c);
    return c.open();
  }

  test('GET /health reports ok', async () => {
    const res = await fetch(`${srv.base}/health`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') || '', /application\/json/);
    assert.deepEqual(await res.json(), { ok: true });
  });

  test('serves the AFTERTONE UI at / and at /connect/<code>', async () => {
    for (const path of ['/', '/connect/MB88-ABCD-EFGH']) {
      const res = await fetch(`${srv.base}${path}`);
      assert.equal(res.status, 200, `expected 200 for ${path}`);
      assert.match(res.headers.get('content-type') || '', /text\/html/);
      assert.match(await res.text(), /AFTERTONE/);
    }
  });

  test('serves client/net.js', async () => {
    const res = await fetch(`${srv.base}/net.js`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') || '', /javascript/);
    assert.match(await res.text(), /__beeperNet/);
  });

  test('serves client/crypto.js and the UI loads it before net.js', async () => {
    const res = await fetch(`${srv.base}/crypto.js`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') || '', /javascript/);
    assert.match(await res.text(), /__beeperCrypto/);

    const html = await (await fetch(`${srv.base}/`)).text();
    const cryptoAt = html.indexOf('src="/crypto.js"');
    const netAt = html.indexOf('src="/net.js"');
    assert.ok(cryptoAt > -1, 'the UI must load crypto.js');
    assert.ok(netAt > -1, 'the UI must load net.js');
    assert.ok(cryptoAt < netAt, 'crypto.js must be loaded before net.js');
  });

  test('rejects path traversal outside the client directory', async () => {
    const res = await fetch(`${srv.base}/../server/server.js`);
    assert.ok(res.status === 403 || res.status === 404, `got ${res.status}`);
  });

  test('a malformed percent-encoded path is rejected with 400 and the server survives', async () => {
    // Own server: pre-fix this request kills the process, so it must not
    // share the describe-level server with other tests.
    const only = await startServer();
    try {
      const bad = await fetch(`${only.base}/%E0%A4%A`);
      assert.equal(bad.status, 400);
      const health = await fetch(`${only.base}/health`);
      assert.equal(health.status, 200);
      assert.deepEqual(await health.json(), { ok: true });
    } finally {
      await only.stop();
    }
  });

  test('greets every new socket with welcome + clientId + serverTime', async () => {
    const c = await client();
    const welcome = await c.waitFor('welcome');
    assert.equal(typeof welcome.clientId, 'string');
    assert.ok(welcome.clientId.length > 0);
    assert.ok(Number.isFinite(Date.parse(welcome.serverTime)), 'serverTime must be ISO-8601');
  });

  test('issues a distinct clientId per connection', async () => {
    const a = await client();
    const b = await client();
    const [wa, wb] = await Promise.all([a.waitFor('welcome'), b.waitFor('welcome')]);
    assert.notEqual(wa.clientId, wb.clientId);
  });

  test('hello is acknowledged with the same clientId', async () => {
    const c = await client();
    const welcome = await c.waitFor('welcome');
    const ack = await c.sendAndWait({ type: 'hello' }, 'hello-ack');
    assert.equal(ack.clientId, welcome.clientId);
  });

  test('ping is answered with pong, echoing the token', async () => {
    const c = await client();
    await c.waitFor('welcome');
    const pong = await c.sendAndWait({ type: 'ping', echo: 'TICK-42' }, 'pong');
    assert.equal(pong.echo, 'TICK-42');
  });

  test('pong truncates an oversized echo to 64 characters', async () => {
    const c = await client();
    await c.waitFor('welcome');
    const pong = await c.sendAndWait({ type: 'ping', echo: 'x'.repeat(500) }, 'pong');
    assert.equal(pong.echo.length, 64);
  });

  test('malformed JSON is rejected with invalid-json', async () => {
    const c = await client();
    await c.waitFor('welcome');
    const err = await new Promise((resolve) => {
      c.waitFor('error').then(resolve);
      c.sendRaw('{not json');
    });
    assert.equal(err.error, 'invalid-json');
  });

  test('a message without a type is rejected with invalid-message', async () => {
    const c = await client();
    await c.waitFor('welcome');
    const err = await c.sendAndWait({ nope: 1 }, 'error');
    assert.equal(err.error, 'invalid-message');
  });

  test('an unrecognised type is rejected with unknown-type', async () => {
    const c = await client();
    await c.waitFor('welcome');
    const err = await c.sendAndWait({ type: 'no-such-thing' }, 'error');
    assert.equal(err.error, 'unknown-type');
  });
});

describe('Phase 2 — invites and pairing', () => {
  let srv;
  const open = [];

  before(async () => { srv = await startServer(); });
  after(async () => {
    for (const c of open) c.close();
    await srv.stop();
  });

  function client() {
    const c = new Client(srv.wsUrl);
    open.push(c);
    return c.open();
  }

  test('create-invite yields a well-formed code and echoes the duration', async () => {
    const c = await client();
    const msg = await c.sendAndWait({ type: 'create-invite', durationMin: 30 }, 'invite-created');
    assert.match(msg.code, CODE_RE);
    assert.equal(msg.durationMin, 30);
  });

  test('create-invite defaults to 60 minutes', async () => {
    const c = await client();
    const msg = await c.sendAndWait({ type: 'create-invite' }, 'invite-created');
    assert.equal(msg.durationMin, 60);
  });

  test('create-invite rejects a duration outside the allowed set', async () => {
    const c = await client();
    const err = await c.sendAndWait({ type: 'create-invite', durationMin: 999 }, 'error');
    assert.equal(err.error, 'invalid-duration');
  });

  test('two invites on one connection get different codes', async () => {
    const c = await client();
    const one = await c.sendAndWait({ type: 'create-invite' }, 'invite-created');
    const two = await c.sendAndWait({ type: 'create-invite' }, 'invite-created');
    assert.notEqual(one.code, two.code);
  });

  test('join-invite tells the joiner pending and the creator about the request', async () => {
    const a = await client();
    const b = await client();
    const idB = (await b.waitFor('welcome')).clientId;
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;

    const pending = b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    const request = a.waitFor('connection-request');
    const [mp, mr] = await Promise.all([pending, request]);

    assert.equal(mp.code, code);
    assert.equal(mr.code, code);
    assert.equal(mr.requesterId, idB, 'creator learns the requester id');
  });

  test('accept-connection establishes both sides with the correct peer ids', async () => {
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');

    const idA = (await a.waitFor('welcome')).clientId;
    const idB = (await b.waitFor('welcome')).clientId;

    const forA = a.sendAndWait({ type: 'accept-connection', code }, 'connection-established');
    const forB = b.waitFor('connection-established');
    const [ma, mb] = await Promise.all([forA, forB]);

    // Each side is told the *other* side's id, never its own.
    assert.equal(ma.peerId, idB);
    assert.equal(mb.peerId, idA);
    assert.notEqual(ma.peerId, idA, 'creator is not told itself as the peer');
    assert.notEqual(mb.peerId, idB, 'requester is not told itself as the peer');
  });

  test('connection-established carries an authoritative expiresAt and durationMin', async () => {
    const { a, b, establishedA, establishedB } = await pair(srv, { durationMin: 30 });
    assert.ok(a); assert.ok(b);
    for (const m of [establishedA, establishedB]) {
      assert.equal(typeof m.expiresAt, 'number');
      assert.equal(m.durationMin, 30);
      // expiresAt must be in the future and consistent with a 30 minute window.
      assert.ok(m.expiresAt > Date.now(), 'expiresAt must be in the future');
      assert.ok(m.expiresAt - Date.now() <= 30 * 60 * 1000 + 5000);
    }
    assert.equal(establishedA.expiresAt, establishedB.expiresAt, 'both sides share one deadline');
  });

  test('a client cannot accept an invite it does not own', async () => {
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');

    const err = await b.sendAndWait({ type: 'accept-connection', code }, 'error');
    assert.equal(err.error, 'not-invite-owner');
  });

  test('accepting with no pending request fails with no-pending-request', async () => {
    const a = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    const err = await a.sendAndWait({ type: 'accept-connection', code }, 'error');
    assert.equal(err.error, 'no-pending-request');
  });

  test('join-invite rejects a malformed code', async () => {
    const c = await client();
    const err = await c.sendAndWait({ type: 'join-invite', code: 'MB88-XX' }, 'error');
    assert.equal(err.error, 'invalid-code-format');
  });

  test('join-invite rejects an unknown code', async () => {
    const c = await client();
    const err = await c.sendAndWait({ type: 'join-invite', code: 'MB88-ZZZZ-ZZZZ' }, 'error');
    assert.equal(err.error, 'invite-not-found');
  });

  test('join-invite is case-insensitive and trimmed', async () => {
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    const pending = await b.sendAndWait({ type: 'join-invite', code: `  ${code.toLowerCase()} ` }, 'connection-pending');
    assert.equal(pending.code, code);
  });

  test('the creator cannot join its own invite', async () => {
    const a = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    const err = await a.sendAndWait({ type: 'join-invite', code }, 'error');
    assert.equal(err.error, 'cannot-join-own-invite');
  });

  test('joining an already-pending invite fails with invite-pending', async () => {
    const a = await client();
    const b = await client();
    const d = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');
    const err = await d.sendAndWait({ type: 'join-invite', code }, 'error');
    assert.equal(err.error, 'invite-pending');
  });

  test('a used (connected) invite cannot be joined again', async () => {
    const { code, b } = await pair(srv);
    const late = await client();
    const err = await late.sendAndWait({ type: 'join-invite', code }, 'error');
    assert.equal(err.error, 'invite-already-used');
    assert.ok(b);
  });

  test('a creator disconnect reaps its invite, so a later join reports invite-not-found', async () => {
    // NOTE: connections.js also has a 'creator-offline' branch, but it is not
    // reachable through a clean close — handleDisconnect() deletes the
    // creator's invites first, so the code is simply gone by the time anyone
    // tries to join. The baseline records the behaviour that actually occurs.
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    a.close();
    const err = await probeUntilError(b, { type: 'join-invite', code }, 'invite-not-found');
    assert.equal(err.error, 'invite-not-found');
  });

  test('reject notifies the requester and acks the creator', async () => {
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');

    const denied = b.waitFor('connection-rejected');
    const acked = a.sendAndWait({ type: 'reject-connection', code }, 'reject-acked');
    const [md, ma] = await Promise.all([denied, acked]);
    assert.equal(md.code, code);
    assert.equal(ma.code, code);
  });

  test('an invite stays reusable after a rejection', async () => {
    const a = await client();
    const b = await client();
    const c = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');
    await a.sendAndWait({ type: 'reject-connection', code }, 'reject-acked');
    await b.waitFor('connection-rejected');

    // A different client can now claim the same code.
    const pending = c.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    const request = a.waitFor('connection-request');
    const [mp, mr] = await Promise.all([pending, request]);
    assert.equal(mp.code, code);
    assert.equal(mr.code, code);
  });

  test('only the creator may reject an invite', async () => {
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');
    const err = await b.sendAndWait({ type: 'reject-connection', code }, 'error');
    assert.equal(err.error, 'not-invite-owner');
  });

  test('a vanished requester cancels the request, so accept then finds nothing', async () => {
    // Same shape as above: connections.js has a 'requester-offline' branch,
    // but handleDisconnect() resets the pending request on a clean close, so
    // the creator is told the request was cancelled instead.
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');
    b.close();

    const cancelled = await a.waitFor('connection-cancelled');
    assert.equal(cancelled.code, code, 'creator is told the request went away');

    const err = await a.sendAndWait({ type: 'accept-connection', code }, 'error');
    assert.equal(err.error, 'no-pending-request');
  });

  test('a peer disconnect notifies the surviving side', async () => {
    const { a, b } = await pair(srv);
    const gone = a.waitFor('peer-disconnected');
    b.close();
    const msg = await gone;
    assert.equal(msg.type, 'peer-disconnected');
  });

  test('a requester that disconnects mid-request cancels the creator invite request', async () => {
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');

    const cancelled = a.waitFor('connection-cancelled');
    b.close();
    const msg = await cancelled;
    assert.equal(msg.code, code);
  });

  test('a creator that disconnects mid-request cancels the waiting requester', async () => {
    const a = await client();
    const b = await client();
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');

    const cancelled = b.waitFor('connection-cancelled');
    a.close();
    const msg = await cancelled;
    assert.equal(msg.code, code);
  });

  test('a reconnecting socket gets a fresh clientId and no peer', async () => {
    const { a, b } = await pair(srv);
    const idBefore = (await a.waitFor('welcome')).clientId;
    a.close();
    const again = await client();
    const idAfter = (await again.waitFor('welcome')).clientId;
    assert.notEqual(idBefore, idAfter, 'a new socket is a new client');
    const err = await b.sendAndWait(ENVELOPE, 'error');
    assert.equal(err.error, 'not-connected', 'pair is broken by the disconnect');
  });

  test('a sixth live invite is rejected but the first five stay usable', async () => {
    const c = await client();
    const codes = [];
    for (let i = 0; i < 5; i++) {
      codes.push((await c.sendAndWait({ type: 'create-invite', durationMin: 30 }, 'invite-created')).code);
    }
    const err = await c.sendAndWait({ type: 'create-invite', durationMin: 30 }, 'error');
    assert.equal(err.error, 'too-many-invites');
    // The first five are unaffected and still joinable.
    const d = await client();
    const pending = await d.sendAndWait({ type: 'join-invite', code: codes[0] }, 'connection-pending');
    assert.equal(pending.code, codes[0]);
  });

  test('a used invite frees its slot for a new invite', async () => {
    const { a, b, code } = await pair(srv, { durationMin: 30 });
    assert.ok(a); assert.ok(b);
    const fresh = await a.sendAndWait({ type: 'create-invite', durationMin: 30 }, 'invite-created');
    assert.match(fresh.code, CODE_RE);
    assert.notEqual(fresh.code, code, 'the consumed code is not reissued as the new one');
  });

  test('used and expired invites free their slots', async () => {
    // NOTE: only CONNECTED pairs are swept; an unused AVAILABLE invite never
    // expires on its own (pre-existing lifecycle design, now bounded by the
    // per-connection cap). Expiry frees a slot by reaping the used pair.
    const short = await startServer({ env: { MB88_TEST_DURATIONS: '0.03' } });
    const extra = [];
    try {
      const c = new Client(short.wsUrl);
      await c.open();
      extra.push(c);
      const d = new Client(short.wsUrl);
      await d.open();
      extra.push(d);
      const codes = [];
      for (let i = 0; i < 5; i++) {
        codes.push((await c.sendAndWait({ type: 'create-invite', durationMin: 0.03 }, 'invite-created')).code);
      }
      const err = await c.sendAndWait({ type: 'create-invite', durationMin: 0.03 }, 'error');
      assert.equal(err.error, 'too-many-invites');
      // Pair on the first code with a short lifetime, then wait it out.
      await d.sendAndWait({ type: 'join-invite', code: codes[0] }, 'connection-pending');
      await c.waitFor('connection-request');
      const goneC = c.waitFor('connection-expired', { timeout: 10000 });
      const goneD = d.waitFor('connection-expired', { timeout: 10000 });
      await c.sendAndWait({ type: 'accept-connection', code: codes[0] }, 'connection-established');
      await d.waitFor('connection-established');
      await Promise.all([goneC, goneD]);
      // The expired pair reaped ALL of the creator's invites (expirePair
      // removes either member's invites by design): capacity fully recovered
      // — five succeed, the sixth is rejected again.
      for (let i = 0; i < 5; i++) {
        await c.sendAndWait({ type: 'create-invite', durationMin: 0.03 }, 'invite-created');
      }
      const full = await c.sendAndWait({ type: 'create-invite', durationMin: 0.03 }, 'error');
      assert.equal(full.error, 'too-many-invites');
    } finally {
      for (const c of extra) c.close();
      await short.stop();
    }
  });

  test('disconnected creators free their slots; cancelled requests stay live and reusable', async () => {
    const c = await client();
    const codes = [];
    for (let i = 0; i < 5; i++) {
      codes.push((await c.sendAndWait({ type: 'create-invite', durationMin: 30 }, 'invite-created')).code);
    }
    // A requester joins one code, then vanishes: the invite returns to
    // AVAILABLE — still live and reusable, so the creator stays at its limit.
    const d = await client();
    await d.sendAndWait({ type: 'join-invite', code: codes[0] }, 'connection-pending');
    await c.waitFor('connection-request');
    d.close();
    await c.waitFor('connection-cancelled');
    const still = await c.sendAndWait({ type: 'create-invite', durationMin: 30 }, 'error');
    assert.equal(still.error, 'too-many-invites');
    const e = await client();
    const reusable = await e.sendAndWait({ type: 'join-invite', code: codes[0] }, 'connection-pending');
    assert.equal(reusable.code, codes[0]);
    // The creator disconnecting reaps everything: the codes are simply gone.
    c.close();
    const g = await client();
    const gone = await probeUntilError(g, { type: 'join-invite', code: codes[1] }, 'invite-not-found');
    assert.equal(gone.error, 'invite-not-found');
  });

  test('message bursts are rate-limited but the connection stays usable', async () => {
    const { a, b } = await pair(srv, { durationMin: 30 });
    // 40 rapid frames against a 30-burst bucket: ~30 relay, ~10 limited.
    // (50 would overdraw even the ~20 tokens refilled during the test.)
    for (let i = 0; i < 40; i++) a.send(ENVELOPE);
    await sleep(500);
    const limited = a.log.filter((m) => m.type === 'error' && m.error === 'rate-limited').length;
    assert.ok(limited >= 5, `expected a 40-message burst to be limited, saw ${limited}`);
    // Still connected and usable: control frames answer...
    const pong = await a.sendAndWait({ type: 'ping', echo: 'STILL-HERE' }, 'pong');
    assert.equal(pong.echo, 'STILL-HERE');
    // ...and after a generous refill one more message relays. Drain exactly
    // what the burst relayed (40 minus limited) plus the new one — the pair
    // handshake itself consumed a few burst tokens, so the relayed count is
    // derived, not assumed.
    await sleep(5000);
    a.send(ENVELOPE);
    const relayed = 40 - limited;
    for (let i = 0; i < relayed + 1; i++) await b.waitFor('message', { timeout: 5000 });
  });

  test('join attempts are throttled but legitimate retries work', async () => {
    const retry = await client();
    const real = await retry.sendAndWait({ type: 'create-invite', durationMin: 30 }, 'invite-created');
    const guesser = await client();
    const seen = new Set();
    for (let i = 0; i < 25; i++) {
      const err = await guesser.sendAndWait({ type: 'join-invite', code: 'MB88-ZZZZ-ZZZZ' }, 'error');
      seen.add(err.error);
    }
    assert.ok(seen.has('invite-not-found'), 'early guesses get the normal error');
    assert.ok(seen.has('rate-limited'), 'a join flood must be throttled');
    // A couple of typo retries, then the real code — well within allowance.
    const joiner = await client();
    for (const bad of ['MB88-AAAA-AAAA', 'MB88-BBBB-BBBB']) {
      const err = await joiner.sendAndWait({ type: 'join-invite', code: bad }, 'error');
      assert.equal(err.error, 'invite-not-found');
    }
    const pending = await joiner.sendAndWait({ type: 'join-invite', code: real.code }, 'connection-pending');
    assert.equal(pending.code, real.code);
  });

  test('global cap rejects excess connections without leaking state', async () => {
    const cap = await startServer({ env: { MB88_MAX_CONN: '2' } });
    const open = [];
    try {
      const a = await new Client(cap.wsUrl).open();
      open.push(a);
      const b = await new Client(cap.wsUrl).open();
      open.push(b);
      await a.waitFor('welcome');
      await b.waitFor('welcome');
      const raw = new WebSocket(cap.wsUrl);
      const outcome = await new Promise((resolve) => {
        const seenTypes = [];
        raw.on('message', (data) => {
          try { seenTypes.push(JSON.parse(data.toString()).type); } catch { /* ignore */ }
        });
        raw.on('close', (code) => resolve({ code, seenTypes }));
        setTimeout(() => resolve({ code: 'timeout', seenTypes }), 5000);
      });
      assert.equal(outcome.code, 1008);
      assert.ok(!outcome.seenTypes.includes('welcome'), 'a rejected socket is never welcomed');
      // No leak: the admitted pair still forms and relays over the same server,
      // and the rejection notified nobody.
      const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
      const pending = b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
      const request = a.waitFor('connection-request');
      await Promise.all([pending, request]);
      const established = a.sendAndWait({ type: 'accept-connection', code }, 'connection-established');
      const establishedB = b.waitFor('connection-established');
      await Promise.all([established, establishedB]);
      a.send(ENVELOPE);
      const relayed = await b.waitFor('message', { timeout: 5000 });
      assert.equal(relayed.ciphertext, ENVELOPE.ciphertext);
      assert.ok(await b.expectNone('peer-disconnected'), 'the rejection notified nobody');
    } finally {
      for (const c of open) c.close();
      await cap.stop();
    }
  });
});

describe('Phase 2 — connection lifetime', () => {
  test('either side may extend, and both learn the new deadline', async () => {
    const srv = await startServer();
    try {
      const { a, b, establishedA } = await pair(srv, { durationMin: 30 });
      const before = establishedA.expiresAt;

      const forA = a.sendAndWait({ type: 'extend-connection', minutes: 60 }, 'connection-extended');
      const forB = b.waitFor('connection-extended');
      const [ma, mb] = await Promise.all([forA, forB]);

      assert.equal(ma.addedMin, 60);
      assert.equal(mb.addedMin, 60);
      assert.equal(ma.expiresAt, mb.expiresAt, 'both sides agree');
      assert.ok(ma.expiresAt > before, 'deadline moved forward');
    } finally {
      await srv.stop();
    }
  });

  test('extensions accumulate on the remaining time', async () => {
    const srv = await startServer();
    try {
      const { a } = await pair(srv, { durationMin: 30 });
      const one = await a.sendAndWait({ type: 'extend-connection', minutes: 30 }, 'connection-extended');
      const two = await a.sendAndWait({ type: 'extend-connection', minutes: 60 }, 'connection-extended');
      assert.equal(two.addedMin, 60);
      assert.equal(two.expiresAt - one.expiresAt, 60 * 60 * 1000, 'adds to the current deadline');
    } finally {
      await srv.stop();
    }
  });

  test('extend-connection rejects a duration outside the allowed set', async () => {
    const srv = await startServer();
    try {
      const { a } = await pair(srv, { durationMin: 30 });
      const err = await a.sendAndWait({ type: 'extend-connection', minutes: 7 }, 'error');
      assert.equal(err.error, 'invalid-duration');
    } finally {
      await srv.stop();
    }
  });

  test('extend-connection from an unpaired client fails with not-connected', async () => {
    const srv = await startServer();
    const extra = [];
    try {
      const c = new Client(srv.wsUrl);
      await c.open();
      extra.push(c);
      const err = await c.sendAndWait({ type: 'extend-connection', minutes: 30 }, 'error');
      assert.equal(err.error, 'not-connected');
    } finally {
      for (const c of extra) c.close();
      await srv.stop();
    }
  });

  test('a connection expires at expiresAt and reaps the invite', async () => {
    // Sub-minute durations are gated behind the server's own test hook.
    const srv = await startServer({ env: { MB88_TEST_DURATIONS: '0.03' } });
    try {
      const { a, b, code, establishedA } = await pair(srv, { durationMin: 0.03 });
      const lifetimeMs = establishedA.expiresAt - Date.now();
      assert.ok(lifetimeMs > 0 && lifetimeMs < 60_000, 'short test lifetime');

      const goneA = a.waitFor('connection-expired', { timeout: 10_000 });
      const goneB = b.waitFor('connection-expired', { timeout: 10_000 });
      await Promise.all([goneA, goneB]);

      // The pair is dead: no more relaying. (Phase 5: an opaque envelope —
      // these tests assert pairing, not payload.)
      const err = await a.sendAndWait(ENVELOPE, 'error');
      assert.equal(err.error, 'not-connected');

      // The single-use invite was reaped, reported as simply not found.
      const late = new Client(srv.wsUrl);
      await late.open();
      const nf = await late.sendAndWait({ type: 'join-invite', code }, 'error');
      assert.equal(nf.error, 'invite-not-found');
      late.close();
    } finally {
      await srv.stop();
    }
  });

  test('a sub-minute test duration is refused when the hook is off', async () => {
    const srv = await startServer();
    const extra = [];
    try {
      const c = new Client(srv.wsUrl);
      await c.open();
      extra.push(c);
      const err = await c.sendAndWait({ type: 'create-invite', durationMin: 0.03 }, 'error');
      assert.equal(err.error, 'invalid-duration', 'test durations are production-disabled');
    } finally {
      for (const c of extra) c.close();
      await srv.stop();
    }
  });
});
