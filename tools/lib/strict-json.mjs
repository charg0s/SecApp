import fs from "node:fs";

function syntax(message, position) {
  return new SyntaxError(`${message} at character ${position}`);
}

function scanJson(text) {
  let position = 0;

  function whitespace() {
    while (/\s/u.test(text[position] ?? "")) position += 1;
  }

  function string() {
    const start = position;
    if (text[position] !== '"') throw syntax("Expected string", position);
    position += 1;
    while (position < text.length) {
      const character = text[position];
      if (character === '"') {
        position += 1;
        return JSON.parse(text.slice(start, position));
      }
      if (character === "\\") {
        position += 1;
        if (text[position] === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(position + 1, position + 5))) {
            throw syntax("Invalid Unicode escape", position);
          }
          position += 5;
        } else {
          if (!'["\\/bfnrt]'.includes(text[position] ?? "")) {
            throw syntax("Invalid string escape", position);
          }
          position += 1;
        }
        continue;
      }
      if (character.charCodeAt(0) <= 0x1f) throw syntax("Control character in string", position);
      position += 1;
    }
    throw syntax("Unterminated string", start);
  }

  function value() {
    whitespace();
    const character = text[position];
    if (character === "{") return object();
    if (character === "[") return array();
    if (character === '"') {
      string();
      return;
    }
    const tail = text.slice(position);
    const token = tail.match(/^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/u);
    if (!token) throw syntax("Invalid JSON value", position);
    position += token[0].length;
  }

  function object() {
    position += 1;
    whitespace();
    const keys = new Set();
    if (text[position] === "}") {
      position += 1;
      return;
    }
    while (position < text.length) {
      whitespace();
      const keyPosition = position;
      const key = string();
      if (keys.has(key)) throw syntax(`Duplicate object key ${JSON.stringify(key)}`, keyPosition);
      keys.add(key);
      whitespace();
      if (text[position] !== ":") throw syntax("Expected colon", position);
      position += 1;
      value();
      whitespace();
      if (text[position] === "}") {
        position += 1;
        return;
      }
      if (text[position] !== ",") throw syntax("Expected comma or object end", position);
      position += 1;
    }
    throw syntax("Unterminated object", position);
  }

  function array() {
    position += 1;
    whitespace();
    if (text[position] === "]") {
      position += 1;
      return;
    }
    while (position < text.length) {
      value();
      whitespace();
      if (text[position] === "]") {
        position += 1;
        return;
      }
      if (text[position] !== ",") throw syntax("Expected comma or array end", position);
      position += 1;
    }
    throw syntax("Unterminated array", position);
  }

  value();
  whitespace();
  if (position !== text.length) throw syntax("Unexpected trailing data", position);
}

export function parseStrictJson(text, source = "JSON input") {
  if (text.charCodeAt(0) === 0xfeff) throw new SyntaxError(`${source}: UTF-8 BOM is forbidden`);
  try {
    scanJson(text);
    return JSON.parse(text);
  } catch (error) {
    error.message = `${source}: ${error.message}`;
    throw error;
  }
}

export function readStrictJson(file, displayName = file) {
  return parseStrictJson(fs.readFileSync(file, "utf8"), displayName);
}

export function jsonPointerGet(value, pointer) {
  if (pointer === "" || pointer === undefined) return value;
  if (typeof pointer !== "string" || !pointer.startsWith("/")) {
    throw new Error(`Invalid JSON Pointer ${JSON.stringify(pointer)}`);
  }
  return pointer.slice(1).split("/").reduce((current, token) => {
    const key = token.replace(/~1/gu, "/").replace(/~0/gu, "~");
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, key)) {
      throw new Error(`JSON Pointer does not exist: ${pointer}`);
    }
    return current[key];
  }, value);
}
