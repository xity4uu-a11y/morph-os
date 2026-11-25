#!/usr/bin/env node
/**
 * Deterministic zero-dependency WebAssembly 1.0 binary assembler for `wasm/dom_mutator.wat`.
 * Emits `wasm/dom_mutator.wasm`, syncs `ui/public/dom_mutator.wasm`, and verifies the binary
 * with native `WebAssembly.validate()` and `WebAssembly.instantiate()` functional assertions.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

// WebAssembly 1.0 value types & opcodes
const TYPE_I32 = 0x7f;
const BLOCK_VOID = 0x40;

const OP_BLOCK = 0x02;
const OP_LOOP = 0x03;
const OP_IF = 0x04;
const OP_ELSE = 0x05;
const OP_END = 0x0b;
const OP_BR = 0x0c;
const OP_BR_IF = 0x0d;
const OP_RETURN = 0x0f;
const OP_LOCAL_GET = 0x20;
const OP_LOCAL_SET = 0x21;
const OP_I32_LOAD8_U = 0x2d;
const OP_I32_STORE8 = 0x3a;
const OP_I32_CONST = 0x41;
const OP_I32_EQZ = 0x45;
const OP_I32_EQ = 0x46;
const OP_I32_NE = 0x47;
const OP_I32_GT_S = 0x4a;
const OP_I32_LE_S = 0x4c;
const OP_I32_LE_U = 0x4d;
const OP_I32_GE_S = 0x4e;
const OP_I32_GE_U = 0x4f;
const OP_I32_ADD = 0x6a;
const OP_I32_SUB = 0x6b;
const OP_I32_MUL = 0x6c;
const OP_I32_AND = 0x71;
const OP_I32_OR = 0x72;
const OP_I32_XOR = 0x73;

function encodeUleb128(value) {
  const bytes = [];
  let v = value >>> 0;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (v !== 0);
  return bytes;
}

function encodeSleb128(value) {
  const bytes = [];
  let v = value | 0;
  let more = true;
  while (more) {
    let byte = v & 0x7f;
    v >>= 7;
    const signBit = (byte & 0x40) !== 0;
    if ((v === 0 && !signBit) || (v === -1 && signBit)) {
      more = false;
    } else {
      byte |= 0x80;
    }
    bytes.push(byte);
  }
  return bytes;
}

function encodeString(str) {
  const utf8 = Buffer.from(str, "utf8");
  return [...encodeUleb128(utf8.length), ...utf8];
}

function encodeSection(id, payload) {
  return [id, ...encodeUleb128(payload.length), ...payload];
}

function encodeVec(items) {
  const out = [...encodeUleb128(items.length)];
  for (const item of items) {
    out.push(...item);
  }
  return out;
}

function encodeFuncBody(localDecls, bodyBytes) {
  const body = [...encodeVec(localDecls), ...bodyBytes, OP_END];
  return [...encodeUleb128(body.length), ...body];
}

function i32Const(n) {
  return [OP_I32_CONST, ...encodeSleb128(n)];
}

function localGet(idx) {
  return [OP_LOCAL_GET, ...encodeUleb128(idx)];
}

function localSet(idx) {
  return [OP_LOCAL_SET, ...encodeUleb128(idx)];
}

function load8u() {
  return [OP_I32_LOAD8_U, 0x00, 0x00]; // align=0, offset=0
}

function store8() {
  return [OP_I32_STORE8, 0x00, 0x00]; // align=0, offset=0
}

// Func 0: count_tag_matches(ptr=0, len=1, needle_ptr=2, needle_len=3) -> i32
// Extra locals: i=4, j=5, count=6, limit=7, matched=8
function buildCountTagMatches() {
  const body = [
    // if (needle_len <= 0) return 0
    ...localGet(3), ...i32Const(0), OP_I32_LE_S,
    OP_IF, BLOCK_VOID,
      ...i32Const(0), OP_RETURN,
    OP_END,
    // if (needle_len > len) return 0
    ...localGet(3), ...localGet(1), OP_I32_GT_S,
    OP_IF, BLOCK_VOID,
      ...i32Const(0), OP_RETURN,
    OP_END,
    // limit = len - needle_len
    ...localGet(1), ...localGet(3), OP_I32_SUB, ...localSet(7),
    // i = 0; count = 0
    ...i32Const(0), ...localSet(4),
    ...i32Const(0), ...localSet(6),

    OP_BLOCK, BLOCK_VOID, // $outer_break (depth 1 from $outer)
      OP_LOOP, BLOCK_VOID, // $outer (depth 0)
        // br_if $outer_break (i > limit)
        ...localGet(4), ...localGet(7), OP_I32_GT_S,
        OP_BR_IF, 1,

        // j = 0; matched = 1
        ...i32Const(0), ...localSet(5),
        ...i32Const(1), ...localSet(8),

        OP_BLOCK, BLOCK_VOID, // $inner_break (depth 1 from $inner)
          OP_LOOP, BLOCK_VOID, // $inner (depth 0)
            // br_if $inner_break (j >= needle_len)
            ...localGet(5), ...localGet(3), OP_I32_GE_S,
            OP_BR_IF, 1,

            // if (mem[ptr + i + j] != mem[needle_ptr + j]) { matched = 0; br $inner_break; }
            ...localGet(0), ...localGet(4), ...localGet(5), OP_I32_ADD, OP_I32_ADD, ...load8u(),
            ...localGet(2), ...localGet(5), OP_I32_ADD, ...load8u(),
            OP_I32_NE,
            OP_IF, BLOCK_VOID,
              ...i32Const(0), ...localSet(8),
              OP_BR, 2, // breaks out of if -> $inner -> $inner_break
            OP_END,

            // j = j + 1; br $inner
            ...localGet(5), ...i32Const(1), OP_I32_ADD, ...localSet(5),
            OP_BR, 0,
          OP_END,
        OP_END,

        // if (matched) count += 1
        ...localGet(8),
        OP_IF, BLOCK_VOID,
          ...localGet(6), ...i32Const(1), OP_I32_ADD, ...localSet(6),
        OP_END,

        // i = i + 1; br $outer
        ...localGet(4), ...i32Const(1), OP_I32_ADD, ...localSet(4),
        OP_BR, 0,
      OP_END,
    OP_END,

    ...localGet(6),
  ];

  return encodeFuncBody([[5, TYPE_I32]], body);
}

// Func 1: mask_ascii_digits(ptr=0, len=1, replacement=2) -> i32
// Extra locals: i=3, count=4, ch=5
function buildMaskAsciiDigits() {
  const body = [
    ...i32Const(0), ...localSet(3),
    ...i32Const(0), ...localSet(4),

    OP_BLOCK, BLOCK_VOID,
      OP_LOOP, BLOCK_VOID,
        ...localGet(3), ...localGet(1), OP_I32_GE_S,
        OP_BR_IF, 1,

        // ch = mem[ptr + i]
        ...localGet(0), ...localGet(3), OP_I32_ADD, ...load8u(), ...localSet(5),

        // if (ch >= 48 && ch <= 57)
        ...localGet(5), ...i32Const(48), OP_I32_GE_U,
        ...localGet(5), ...i32Const(57), OP_I32_LE_U,
        OP_I32_AND,
        OP_IF, BLOCK_VOID,
          ...localGet(0), ...localGet(3), OP_I32_ADD, ...localGet(2), ...store8(),
          ...localGet(4), ...i32Const(1), OP_I32_ADD, ...localSet(4),
        OP_END,

        ...localGet(3), ...i32Const(1), OP_I32_ADD, ...localSet(3),
        OP_BR, 0,
      OP_END,
    OP_END,

    ...localGet(4),
  ];

  return encodeFuncBody([[3, TYPE_I32]], body);
}

// Func 2: fnv1a_hash(ptr=0, len=1) -> i32
// Extra locals: i=2, hash=3
function buildFnv1aHash() {
  const body = [
    ...i32Const(0), ...localSet(2),
    ...i32Const(-2128831035), ...localSet(3), // 0x811c9dc5

    OP_BLOCK, BLOCK_VOID,
      OP_LOOP, BLOCK_VOID,
        ...localGet(2), ...localGet(1), OP_I32_GE_S,
        OP_BR_IF, 1,

        ...localGet(3),
        ...localGet(0), ...localGet(2), OP_I32_ADD, ...load8u(),
        OP_I32_XOR,
        ...i32Const(16777619), // 0x01000193
        OP_I32_MUL,
        ...localSet(3),

        ...localGet(2), ...i32Const(1), OP_I32_ADD, ...localSet(2),
        OP_BR, 0,
      OP_END,
    OP_END,

    ...localGet(3),
  ];

  return encodeFuncBody([[2, TYPE_I32]], body);
}

// Func 3: normalize_whitespace(ptr=0, len=1) -> i32
// Extra locals: r=2, w=3, in_ws=4, ch=5, is_ws=6
function buildNormalizeWhitespace() {
  const body = [
    ...i32Const(0), ...localSet(2),
    ...i32Const(0), ...localSet(3),
    ...i32Const(1), ...localSet(4),

    OP_BLOCK, BLOCK_VOID,
      OP_LOOP, BLOCK_VOID,
        ...localGet(2), ...localGet(1), OP_I32_GE_S,
        OP_BR_IF, 1,

        // ch = mem[ptr + r]
        ...localGet(0), ...localGet(2), OP_I32_ADD, ...load8u(), ...localSet(5),

        // is_ws = (ch == 32 || ch == 9) || (ch == 10 || ch == 13)
        ...localGet(5), ...i32Const(32), OP_I32_EQ,
        ...localGet(5), ...i32Const(9), OP_I32_EQ,
        OP_I32_OR,
        ...localGet(5), ...i32Const(10), OP_I32_EQ,
        ...localGet(5), ...i32Const(13), OP_I32_EQ,
        OP_I32_OR,
        OP_I32_OR,
        ...localSet(6),

        ...localGet(6),
        OP_IF, BLOCK_VOID,
          ...localGet(4), OP_I32_EQZ,
          OP_IF, BLOCK_VOID,
            ...localGet(0), ...localGet(3), OP_I32_ADD, ...i32Const(32), ...store8(),
            ...localGet(3), ...i32Const(1), OP_I32_ADD, ...localSet(3),
            ...i32Const(1), ...localSet(4),
          OP_END,
        OP_ELSE,
          ...localGet(0), ...localGet(3), OP_I32_ADD, ...localGet(5), ...store8(),
          ...localGet(3), ...i32Const(1), OP_I32_ADD, ...localSet(3),
          ...i32Const(0), ...localSet(4),
        OP_END,

        ...localGet(2), ...i32Const(1), OP_I32_ADD, ...localSet(2),
        OP_BR, 0,
      OP_END,
    OP_END,

    // Trim single trailing space if present
    ...localGet(3), ...i32Const(0), OP_I32_GT_S,
    OP_IF, BLOCK_VOID,
      ...localGet(0), ...localGet(3), ...i32Const(1), OP_I32_SUB, OP_I32_ADD, ...load8u(),
      ...i32Const(32), OP_I32_EQ,
      OP_IF, BLOCK_VOID,
        ...localGet(3), ...i32Const(1), OP_I32_SUB, ...localSet(3),
      OP_END,
    OP_END,

    ...localGet(3),
  ];

  return encodeFuncBody([[5, TYPE_I32]], body);
}

function buildWasmBinary() {
  const header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

  // Type section (id = 1)
  const typeSection = encodeSection(
    1,
    encodeVec([
      [0x60, 4, TYPE_I32, TYPE_I32, TYPE_I32, TYPE_I32, 1, TYPE_I32], // type 0
      [0x60, 3, TYPE_I32, TYPE_I32, TYPE_I32, 1, TYPE_I32], // type 1
      [0x60, 2, TYPE_I32, TYPE_I32, 1, TYPE_I32], // type 2
    ])
  );

  // Function section (id = 3): maps func index -> type index
  const funcSection = encodeSection(3, encodeVec([[0], [1], [2], [2]]));

  // Memory section (id = 5): min 1 page (64 KiB), no upper cap
  const memSection = encodeSection(5, encodeVec([[0x00, 0x01]]));

  // Export section (id = 7)
  const exportSection = encodeSection(
    7,
    encodeVec([
      [...encodeString("memory"), 0x02, 0x00],
      [...encodeString("count_tag_matches"), 0x00, 0x00],
      [...encodeString("mask_ascii_digits"), 0x00, 0x01],
      [...encodeString("fnv1a_hash"), 0x00, 0x02],
      [...encodeString("normalize_whitespace"), 0x00, 0x03],
    ])
  );

  // Code section (id = 10)
  const codeSection = encodeSection(
    10,
    encodeVec([
      buildCountTagMatches(),
      buildMaskAsciiDigits(),
      buildFnv1aHash(),
      buildNormalizeWhitespace(),
    ])
  );

  return Uint8Array.from([
    ...header,
    ...typeSection,
    ...funcSection,
    ...memSection,
    ...exportSection,
    ...codeSection,
  ]);
}

async function main() {
  const bytes = buildWasmBinary();
  assert.equal(WebAssembly.validate(bytes), true, "WebAssembly.validate() must return true");

  const { instance } = await WebAssembly.instantiate(bytes);
  const exports = instance.exports;
  const mem = new Uint8Array(exports.memory.buffer);
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // 1. Verify count_tag_matches
  const sampleHtml = "<table><tr><td>1</td><td>2</td></tr><tr><td>3</td></tr></table>";
  const htmlBytes = enc.encode(sampleHtml);
  const needleBytes = enc.encode("<td");
  mem.set(htmlBytes, 0);
  mem.set(needleBytes, 1024);
  const tdCount = exports.count_tag_matches(0, htmlBytes.length, 1024, needleBytes.length);
  assert.equal(tdCount, 3, "count_tag_matches must count 3 <td tags");

  // 2. Verify mask_ascii_digits
  const piiText = enc.encode("acct=4092-8810");
  mem.set(piiText, 2048);
  const maskedCount = exports.mask_ascii_digits(2048, piiText.length, 42); // '*'
  assert.equal(maskedCount, 8, "mask_ascii_digits must mask 8 digits");
  assert.equal(dec.decode(mem.slice(2048, 2048 + piiText.length)), "acct=****-****");

  // 3. Verify fnv1a_hash against standard FNV-1a 32-bit vector ("morph-os")
  const hashInput = enc.encode("morph-os");
  mem.set(hashInput, 3072);
  const wasmHash = exports.fnv1a_hash(3072, hashInput.length) >>> 0;
  let expectedHash = 0x811c9dc5;
  for (const b of hashInput) {
    expectedHash ^= b;
    expectedHash = Math.imul(expectedHash, 0x01000193) >>> 0;
  }
  assert.equal(wasmHash, expectedHash, "fnv1a_hash must match reference FNV-1a 32-bit digest");

  // 4. Verify normalize_whitespace
  const messy = enc.encode("  \t hello   morph\r\n  os \t ");
  mem.set(messy, 4096);
  const newLen = exports.normalize_whitespace(4096, messy.length);
  assert.equal(dec.decode(mem.slice(4096, 4096 + newLen)), "hello morph os");

  const wasmOutPath = path.join(repoRoot, "wasm", "dom_mutator.wasm");
  fs.mkdirSync(path.dirname(wasmOutPath), { recursive: true });
  fs.writeFileSync(wasmOutPath, bytes);

  const uiPublicPath = path.join(repoRoot, "ui", "public", "dom_mutator.wasm");
  fs.mkdirSync(path.dirname(uiPublicPath), { recursive: true });
  fs.writeFileSync(uiPublicPath, bytes);

  console.log(
    `OK  Compiled & verified ${wasmOutPath} (${bytes.length} bytes, WebAssembly.validate=true, 4/4 exports tested)`
  );
  console.log(`OK  Synced ${uiPublicPath}`);
}

main().catch((err) => {
  console.error("WASM compilation failed:", err);
  process.exit(1);
});
