import { StringDecoder } from "node:string_decoder";

// Bounded keyboard input, not readline's unbounded pasted-line accumulation.
export function readDefenderConfirmation(input, output, { signal, timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    if (!input.isTTY || !output.isTTY || signal?.aborted) { resolve(null); return; }
    let finished = false, timer;
    const wasRaw = input.isRaw === true, letters = [], decoder = new StringDecoder("utf8");
    const finish = (value) => {
      if (finished) return;
      finished = true; clearTimeout(timer);
      input.removeListener("data", data); input.removeListener("end", cancel); input.removeListener("error", cancel);
      signal?.removeEventListener("abort", cancel);
      try { input.setRawMode(wasRaw); input.pause(); } catch { /* Terminal may have closed. */ }
      try { output.write("\n"); } catch { /* No raw error output. */ }
      resolve(value);
    };
    const cancel = () => finish(null);
    const data = (chunk) => {
      try {
        if (!Buffer.isBuffer(chunk) || chunk.length > 256) { cancel(); return; }
        for (const character of decoder.write(chunk)) {
          if (character === "\r" || character === "\n") { finish(letters.join("")); return; }
          if (character === "\x03" || character === "\x04" || character === "\x1b") { cancel(); return; }
          if (character === "\x7f" || character === "\b") { if (letters.length) { letters.pop(); output.write("\b \b"); } continue; }
          if (!/^[\p{L}\p{N} ]$/u.test(character) || letters.length >= 64) { cancel(); return; }
          letters.push(character); output.write(character);
        }
      } catch { cancel(); }
    };
    try {
      input.setRawMode(true);
      input.on("data", data); input.once("end", cancel); input.once("error", cancel);
      signal?.addEventListener("abort", cancel, { once: true });
      timer = setTimeout(cancel, timeoutMs);
      input.resume();
      if (signal?.aborted) cancel();
    } catch { cancel(); }
  });
}
