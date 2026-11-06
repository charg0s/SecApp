// Strict, bounded LF-framed UTF-8 JSON. No unbounded readline accumulation.
import { decodeDesktopCommand } from "../../src/ui/defender-desktop-session.mjs";

export function createDesktopCommandReader(onCommand, onFailure) {
  let pending = Buffer.alloc(0), failed = false;
  const fail = () => { if (!failed) { failed = true; pending.fill(0); pending = Buffer.alloc(0); onFailure(); } };
  return Object.freeze({
    receive(chunk) {
      if (failed) return;
      if (!Buffer.isBuffer(chunk) || chunk.length > 4096) { fail(); return; }
      for (const byte of chunk) {
        if (byte === 10) {
          try { const command = decodeDesktopCommand(pending); pending.fill(0); pending = Buffer.alloc(0); onCommand(command); }
          catch { fail(); return; }
        } else {
          if (pending.length >= 256) { fail(); return; }
          pending = Buffer.concat([pending, Buffer.from([byte])]);
        }
      }
    },
    end() { if (pending.length) fail(); },
    fail
  });
}
