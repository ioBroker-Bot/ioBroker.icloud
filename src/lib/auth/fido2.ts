/**
 * FIDO2 / security-key support via the libfido2 command-line tools (`fido2-token`, `fido2-assert`).
 *
 * Apple accounts that have hardware security keys (FIDO2 / YubiKey) enrolled can no longer use
 * SMS- or trusted-device-based 2FA — Apple disables those paths entirely. The only way to satisfy
 * the MFA challenge for such an account is to produce a WebAuthn assertion with the physical key.
 *
 * This module is intentionally self-contained and free of any ioBroker/adapter dependencies so it
 * can be unit-tested and reasoned about in isolation. It shells out to the `fido2-tools` package
 * (Debian/Ubuntu: `apt install fido2-tools`) rather than pulling a native USB-HID binding into the
 * adapter — one optional system dependency instead of an npm build chain.
 *
 * Platform note: libfido2 talks to the authenticator over USB-HID, so this only works on Linux with
 * the tools installed and read access to the `/dev/hidraw*` nodes. On any other platform, or when
 * the tools are missing, {@link detectFido2Support} reports `supported: false` and the adapter
 * degrades gracefully ("security-key login not available on this platform").
 *
 * The exact Apple verify flow (endpoint, request body, base64 vs base64url encoding) mirrors
 * pyicloud's `confirm_security_key()` — see src/lib/index.ts `authenticateWithSecurityKey()`.
 */

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

/** Result of probing the host for FIDO2 capability. */
export interface Fido2Capability {
    /** True only when the platform is Linux AND both libfido2 CLI tools are on PATH. */
    supported: boolean;
    /** Human-readable reason when `supported` is false (shown in the log / admin). */
    reason?: string;
    /** The detected platform (`process.platform`). */
    platform: string;
}

/** A successfully obtained WebAuthn assertion, with all fields as raw bytes. */
export interface Fido2Assertion {
    /** CBOR-encoded authenticator data (raw). */
    authenticatorData: Buffer;
    /** Assertion signature (raw). */
    signature: Buffer;
    /** The credential id (keyHandle) that produced this assertion (raw). */
    credentialId: Buffer;
    /** User handle, if the credential was resident (rarely the case for Apple). */
    userHandle?: Buffer;
    /** The exact clientDataJSON bytes that were hashed and signed — must be sent to Apple verbatim. */
    clientDataJSON: Buffer;
}

/** Options for a single assertion attempt against one device + one credential. */
export interface GetAssertionOptions {
    /** Device path from {@link listFido2Devices}, e.g. `/dev/hidraw0`. */
    device: string;
    /** Relying party id from Apple's fsaChallenge, e.g. `apple.com`. */
    rpId: string;
    /** The credential id (keyHandle), raw bytes. */
    credentialId: Buffer;
    /** The clientDataJSON bytes (built via {@link buildClientDataJSON}). */
    clientDataJSON: Buffer;
    /** Require user verification (PIN/biometric). Apple uses "discouraged" → false. */
    userVerification?: boolean;
    /**
     * Hard timeout (ms) for this single attempt. On the *correct* key the call blocks until the
     * user touches it; this bounds how long we wait per attempt before giving up and retrying.
     * Defaults to 25 s.
     */
    timeoutMs?: number;
    /** Optional logger. */
    log?: (msg: string) => void;
}

/** Thrown for genuinely unexpected CLI failures (not the benign "this key doesn't hold the credential"). */
export class Fido2Error extends Error {
    constructor(
        message: string,
        public readonly stderr?: string,
    ) {
        super(message);
        this.name = 'Fido2Error';
    }
}

// ── base64 helpers ──────────────────────────────────────────────────────────
// Apple's fsaChallenge uses base64url for `challenge`/`keyHandles`, but is tolerant of standard
// base64 (the sample challenges contain '+'). We decode url-safely with padding repair, and the
// std `base64` Buffer encoding already accepts both alphabets on input. Outputs to Apple use
// standard base64, matching pyicloud's `b64_encode`.

/**
 * Decode a base64 / base64url string (with or without padding) to raw bytes.
 *
 * @param s The base64 / base64url encoded string.
 */
export function b64decode(s: string): Buffer {
    // Node's 'base64' decoder accepts both '+/' and '-_' and tolerates missing padding.
    return Buffer.from(s, 'base64');
}

/**
 * Standard base64 encode (with padding) — the encoding Apple's verify endpoint expects.
 *
 * @param buf The raw bytes to encode.
 */
export function b64encode(buf: Buffer): string {
    return buf.toString('base64');
}

/**
 * base64url encode WITHOUT padding — the encoding used inside clientDataJSON's `challenge`.
 *
 * @param buf The raw bytes to encode.
 */
export function b64urlNoPad(buf: Buffer): string {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Unwrap a CBOR definite-length byte string (major type 2) to its raw payload.
 *
 * libfido2's `fido2-assert` emits the authenticator data as a CBOR byte string so that its own
 * `-V` verify mode can round-trip it — a 37-byte authData comes out prefixed with `0x58 0x25`
 * (`0x58` = byte string with a 1-byte length, `0x25` = 37). WebAuthn and Apple's verify endpoint
 * expect the RAW authenticator data that was actually signed; sending the CBOR-wrapped bytes makes
 * the signature verification fail server-side (Apple serviceError -27962 "Failed to verify security
 * key"). This strips the bstr header when (and only when) the leading bytes form a valid header
 * whose declared length accounts for exactly the remaining bytes, so already-raw input is returned
 * untouched.
 *
 * @param buf The bytes decoded from fido2-assert's authenticator-data output line.
 */
export function unwrapCborByteString(buf: Buffer): Buffer {
    if (buf.length < 1 || buf[0] >> 5 !== 2) {
        return buf; // not a CBOR byte string (major type 2) → already raw
    }
    const ai = buf[0] & 0x1f;
    let headerLen: number;
    let len: number;
    if (ai < 24) {
        headerLen = 1;
        len = ai;
    } else if (ai === 24) {
        headerLen = 2;
        len = buf[1];
    } else if (ai === 25) {
        headerLen = 3;
        len = buf.readUInt16BE(1);
    } else if (ai === 26) {
        headerLen = 5;
        len = buf.readUInt32BE(1);
    } else {
        return buf; // indefinite-length / 64-bit length — not used for authData, leave as-is
    }
    // Only unwrap when the declared length matches exactly; otherwise the leading byte was a
    // coincidental type-2 match and the buffer already holds raw authenticator data.
    return headerLen + len === buf.length ? buf.subarray(headerLen) : buf;
}

/**
 * Probe the host for FIDO2 capability: Linux + both libfido2 CLI tools present.
 * Cheap and synchronous — safe to call during adapter startup.
 */
export function detectFido2Support(): Fido2Capability {
    const platform = process.platform;
    if (platform !== 'linux') {
        return {
            supported: false,
            platform,
            reason: `Security-key (FIDO2) login requires Linux with libfido2; current platform is "${platform}".`,
        };
    }
    // `command -v` returns 0 only if both tools resolve on PATH.
    const probe = spawnSync('sh', ['-c', 'command -v fido2-assert >/dev/null && command -v fido2-token >/dev/null'], {
        timeout: 5000,
    });
    if (probe.status !== 0) {
        return {
            supported: false,
            platform,
            reason: 'libfido2 CLI tools not found — install the "fido2-tools" package (e.g. `sudo apt install fido2-tools`).',
        };
    }
    return { supported: true, platform };
}

/**
 * List connected FIDO2 authenticator device paths via `fido2-token -L`.
 * Returns an array of device paths (e.g. `["/dev/hidraw0"]`); empty when no key is plugged in.
 */
export async function listFido2Devices(): Promise<string[]> {
    return new Promise((resolve, reject) => {
        const proc = spawn('fido2-token', ['-L'], { timeout: 5000 });
        let stdout = '';
        let stderr = '';
        proc.stdout.on('data', d => (stdout += d.toString()));
        proc.stderr.on('data', d => (stderr += d.toString()));
        proc.on('error', err => {
            reject(new Fido2Error(`Failed to run fido2-token: ${err.message}`));
        });
        proc.on('close', code => {
            if (code !== 0 && code !== null) {
                // `-L` exits 0 even with no devices; a non-zero code is a real failure.
                reject(new Fido2Error(`fido2-token -L exited with code ${code}`, stderr));
                return;
            }
            // Each line looks like: "/dev/hidraw0: vendor=0x1050, product=0x0407 (Yubico ...)"
            const devices = stdout
                .split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0)
                .map(line => line.split(':')[0].trim())
                .filter(path => path.length > 0);
            resolve(devices);
        });
    });
}

/**
 * Build the WebAuthn clientDataJSON for a `get` (assertion) ceremony.
 * The `challenge` is base64url-without-padding of the raw challenge bytes, per the WebAuthn spec.
 * The byte layout produced here is exactly what gets hashed (for fido2-assert) AND sent to Apple,
 * so the two stay consistent.
 *
 * @param challengeRaw Raw challenge bytes (decoded from Apple's fsaChallenge.challenge).
 * @param origin       The WebAuthn origin — for Apple this is `https://apple.com`.
 */
export function buildClientDataJSON(challengeRaw: Buffer, origin: string): Buffer {
    const clientData = {
        type: 'webauthn.get',
        challenge: b64urlNoPad(challengeRaw),
        origin,
        crossOrigin: false,
    };
    return Buffer.from(JSON.stringify(clientData), 'utf8');
}

/**
 * Attempt to obtain an assertion from ONE device for ONE credential id.
 *
 * Returns:
 *  - a {@link Fido2Assertion} on success (the user touched the blinking key);
 *  - `null` when this device does not hold the credential (CTAP2 `FIDO_ERR_NO_CREDENTIALS`) — the
 *    benign "wrong key" case: no user-presence prompt is raised, so it returns near-instantly;
 *  - rejects with {@link Fido2Error} on a genuine failure (tool missing, timeout, protocol error).
 *
 * This is the primitive the iterate-over-all-keys flow is built from: probe every device with every
 * Apple keyHandle; only the matching key blinks and waits for a touch.
 *
 * @param opts The device, relying party id, credential id, clientDataJSON and tuning options.
 */
export async function getAssertion(opts: GetAssertionOptions): Promise<Fido2Assertion | null> {
    const { device, rpId, credentialId, clientDataJSON, userVerification = false, timeoutMs = 25_000, log } = opts;

    const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
    const args = ['-G', '-t', `uv=${userVerification ? 'true' : 'false'}`, device];

    // stdin: clientDataHash (b64), rpId, credentialId (b64) — one per line.
    const stdin = `${b64encode(clientDataHash)}\n${rpId}\n${b64encode(credentialId)}\n`;

    return new Promise((resolve, reject) => {
        const proc = spawn('fido2-assert', args, { timeout: timeoutMs });
        let stdout = '';
        let stderr = '';
        let settled = false;

        proc.stdout.on('data', d => (stdout += d.toString()));
        proc.stderr.on('data', d => (stderr += d.toString()));

        proc.on('error', err => {
            if (settled) {
                return;
            }
            settled = true;
            reject(new Fido2Error(`Failed to run fido2-assert: ${err.message}`));
        });

        proc.on('close', code => {
            if (settled) {
                return;
            }
            settled = true;

            if (code === 0) {
                // stdout lines: [0] clientDataHash echo, [1] rpId, [2] authData(b64), [3] signature(b64), [4] userId(b64?)
                const lines = stdout
                    .split('\n')
                    .map(l => l.trim())
                    .filter(l => l.length > 0);
                if (lines.length < 4) {
                    reject(new Fido2Error(`Unexpected fido2-assert output (${lines.length} lines)`, stdout));
                    return;
                }
                resolve({
                    // fido2-assert wraps authData in a CBOR byte string; Apple needs the raw bytes.
                    authenticatorData: unwrapCborByteString(b64decode(lines[2])),
                    signature: b64decode(lines[3]),
                    credentialId,
                    userHandle: lines[4] ? b64decode(lines[4]) : undefined,
                    clientDataJSON,
                });
                return;
            }

            // Non-zero exit. The benign case is "this key doesn't hold the credential".
            const combined = stderr.toLowerCase();
            if (combined.includes('no_credentials') || combined.includes('no credentials')) {
                log?.(`device ${device} does not hold this credential (skipping)`);
                resolve(null);
                return;
            }
            reject(new Fido2Error(`fido2-assert failed (exit ${code ?? 'timeout'})`, stderr.trim()));
        });

        proc.stdin.write(stdin);
        proc.stdin.end();
    });
}
