"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var fido2_exports = {};
__export(fido2_exports, {
  Fido2Error: () => Fido2Error,
  b64decode: () => b64decode,
  b64encode: () => b64encode,
  b64urlNoPad: () => b64urlNoPad,
  buildClientDataJSON: () => buildClientDataJSON,
  detectFido2Support: () => detectFido2Support,
  getAssertion: () => getAssertion,
  listFido2Devices: () => listFido2Devices,
  unwrapCborByteString: () => unwrapCborByteString
});
module.exports = __toCommonJS(fido2_exports);
var import_node_child_process = require("node:child_process");
var import_node_crypto = require("node:crypto");
class Fido2Error extends Error {
  constructor(message, stderr) {
    super(message);
    this.stderr = stderr;
    this.name = "Fido2Error";
  }
}
function b64decode(s) {
  return Buffer.from(s, "base64");
}
function b64encode(buf) {
  return buf.toString("base64");
}
function b64urlNoPad(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unwrapCborByteString(buf) {
  if (buf.length < 1 || buf[0] >> 5 !== 2) {
    return buf;
  }
  const ai = buf[0] & 31;
  let headerLen;
  let len;
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
    return buf;
  }
  return headerLen + len === buf.length ? buf.subarray(headerLen) : buf;
}
function detectFido2Support() {
  const platform = process.platform;
  if (platform !== "linux") {
    return {
      supported: false,
      platform,
      reason: `Security-key (FIDO2) login requires Linux with libfido2; current platform is "${platform}".`
    };
  }
  const probe = (0, import_node_child_process.spawnSync)("sh", ["-c", "command -v fido2-assert >/dev/null && command -v fido2-token >/dev/null"], {
    timeout: 5e3
  });
  if (probe.status !== 0) {
    return {
      supported: false,
      platform,
      reason: 'libfido2 CLI tools not found \u2014 install the "fido2-tools" package (e.g. `sudo apt install fido2-tools`).'
    };
  }
  return { supported: true, platform };
}
async function listFido2Devices() {
  return new Promise((resolve, reject) => {
    const proc = (0, import_node_child_process.spawn)("fido2-token", ["-L"], { timeout: 5e3 });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => stdout += d.toString());
    proc.stderr.on("data", (d) => stderr += d.toString());
    proc.on("error", (err) => {
      reject(new Fido2Error(`Failed to run fido2-token: ${err.message}`));
    });
    proc.on("close", (code) => {
      if (code !== 0 && code !== null) {
        reject(new Fido2Error(`fido2-token -L exited with code ${code}`, stderr));
        return;
      }
      const devices = stdout.split("\n").map((line) => line.trim()).filter((line) => line.length > 0).map((line) => line.split(":")[0].trim()).filter((path) => path.length > 0);
      resolve(devices);
    });
  });
}
function buildClientDataJSON(challengeRaw, origin) {
  const clientData = {
    type: "webauthn.get",
    challenge: b64urlNoPad(challengeRaw),
    origin,
    crossOrigin: false
  };
  return Buffer.from(JSON.stringify(clientData), "utf8");
}
async function getAssertion(opts) {
  const { device, rpId, credentialId, clientDataJSON, userVerification = false, timeoutMs = 25e3, log } = opts;
  const clientDataHash = (0, import_node_crypto.createHash)("sha256").update(clientDataJSON).digest();
  const args = ["-G", "-t", `uv=${userVerification ? "true" : "false"}`, device];
  const stdin = `${b64encode(clientDataHash)}
${rpId}
${b64encode(credentialId)}
`;
  return new Promise((resolve, reject) => {
    const proc = (0, import_node_child_process.spawn)("fido2-assert", args, { timeout: timeoutMs });
    let stdout = "";
    let stderr = "";
    let settled = false;
    proc.stdout.on("data", (d) => stdout += d.toString());
    proc.stderr.on("data", (d) => stderr += d.toString());
    proc.on("error", (err) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(new Fido2Error(`Failed to run fido2-assert: ${err.message}`));
    });
    proc.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      if (code === 0) {
        const lines = stdout.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
        if (lines.length < 4) {
          reject(new Fido2Error(`Unexpected fido2-assert output (${lines.length} lines)`, stdout));
          return;
        }
        resolve({
          // fido2-assert wraps authData in a CBOR byte string; Apple needs the raw bytes.
          authenticatorData: unwrapCborByteString(b64decode(lines[2])),
          signature: b64decode(lines[3]),
          credentialId,
          userHandle: lines[4] ? b64decode(lines[4]) : void 0,
          clientDataJSON
        });
        return;
      }
      const combined = stderr.toLowerCase();
      if (combined.includes("no_credentials") || combined.includes("no credentials")) {
        log == null ? void 0 : log(`device ${device} does not hold this credential (skipping)`);
        resolve(null);
        return;
      }
      reject(new Fido2Error(`fido2-assert failed (exit ${code != null ? code : "timeout"})`, stderr.trim()));
    });
    proc.stdin.write(stdin);
    proc.stdin.end();
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Fido2Error,
  b64decode,
  b64encode,
  b64urlNoPad,
  buildClientDataJSON,
  detectFido2Support,
  getAssertion,
  listFido2Devices,
  unwrapCborByteString
});
//# sourceMappingURL=fido2.js.map
