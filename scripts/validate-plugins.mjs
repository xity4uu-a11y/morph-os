#!/usr/bin/env node
/**
 * Zero-dependency validator for morph-os community mutation plugin manifests (`plugins/*.json`).
 * Enforces every structural and safety constraint defined in `plugins/schema.json`.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const pluginsDir = process.argv[2]
  ? path.resolve(process.cwd(), process.argv[2])
  : path.join(repoRoot, "plugins");

const KEBAB_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SEMVER_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?$/;
const VALID_TARGETS = new Set(["cli-stdio", "http-proxy", "dom-wasm", "stream-generic"]);
const VALID_FAIL_POLICIES = new Set(["fail-open", "fail-closed"]);
const VALID_FORMATS = new Set(["json", "ndjson", "csv", "text"]);
const VALID_OPS = new Set([
  "ascii_table_to_json",
  "kv_to_json",
  "xml_to_json",
  "html_table_to_json",
  "parse_json",
  "rename_fields",
  "redact_pii",
  "wrap_envelope",
]);
const ALLOWED_TOP_KEYS = new Set([
  "id",
  "aliases",
  "name",
  "version",
  "target_kind",
  "description",
  "author",
  "fail_policy",
  "output_format",
  "rules",
  "llm_prompt",
  "rust_hook_template",
  "sample_input",
]);

function validateManifest(filePath, data) {
  const errors = [];
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return ["manifest root must be a JSON object"];
  }

  for (const key of Object.keys(data)) {
    if (!ALLOWED_TOP_KEYS.has(key)) {
      errors.push(`unexpected top-level field '${key}'`);
    }
  }

  const required = [
    "id",
    "name",
    "version",
    "target_kind",
    "description",
    "author",
    "rules",
    "llm_prompt",
    "rust_hook_template",
  ];
  for (const field of required) {
    if (data[field] === undefined || data[field] === null) {
      errors.push(`missing required field '${field}'`);
    }
  }

  if (typeof data.id !== "string" || !KEBAB_RE.test(data.id)) {
    errors.push(`invalid id '${data.id}': must be kebab-case ASCII`);
  }

  const expectedFile = `${data.id}.json`;
  if (path.basename(filePath) !== expectedFile) {
    errors.push(`filename '${path.basename(filePath)}' must match id '${expectedFile}'`);
  }

  if (data.aliases !== undefined) {
    if (!Array.isArray(data.aliases)) {
      errors.push("aliases must be an array of kebab-case strings");
    } else {
      for (const alias of data.aliases) {
        if (typeof alias !== "string" || !KEBAB_RE.test(alias)) {
          errors.push(`invalid alias '${alias}'`);
        }
      }
    }
  }

  if (typeof data.name !== "string" || data.name.trim().length < 3) {
    errors.push("name must be at least 3 characters");
  }
  if (typeof data.version !== "string" || !SEMVER_RE.test(data.version)) {
    errors.push(`invalid semver version '${data.version}'`);
  }
  if (!VALID_TARGETS.has(data.target_kind)) {
    errors.push(`invalid target_kind '${data.target_kind}'`);
  }
  if (typeof data.description !== "string" || data.description.trim().length < 10) {
    errors.push("description must be at least 10 characters");
  }
  if (typeof data.author !== "string" || data.author.trim().length < 2) {
    errors.push("author must be at least 2 characters");
  }
  if (data.fail_policy !== undefined && !VALID_FAIL_POLICIES.has(data.fail_policy)) {
    errors.push(`invalid fail_policy '${data.fail_policy}'`);
  }
  if (data.output_format !== undefined && !VALID_FORMATS.has(data.output_format)) {
    errors.push(`invalid output_format '${data.output_format}'`);
  }
  if (!Array.isArray(data.rules) || data.rules.length === 0) {
    errors.push("rules must be a non-empty array");
  } else {
    for (let i = 0; i < data.rules.length; i += 1) {
      const step = data.rules[i];
      if (!step || typeof step !== "object" || !VALID_OPS.has(step.op)) {
        errors.push(`rules[${i}] has invalid op '${step?.op}'`);
      }
    }
  }
  if (
    typeof data.llm_prompt !== "string" ||
    data.llm_prompt.trim().length < 10 ||
    data.llm_prompt.length > 8192
  ) {
    errors.push("llm_prompt must be between 10 and 8192 characters");
  }
  if (typeof data.rust_hook_template !== "string" || data.rust_hook_template.trim().length < 10) {
    errors.push("rust_hook_template must be a non-empty Rust snippet");
  }

  return errors;
}

if (!fs.existsSync(pluginsDir)) {
  console.error(`ERROR: plugins directory not found at ${pluginsDir}`);
  process.exit(1);
}

const files = fs
  .readdirSync(pluginsDir)
  .filter((name) => name.endsWith(".json") && name !== "schema.json")
  .sort();

if (files.length === 0) {
  console.error(`ERROR: no plugin manifests found in ${pluginsDir}`);
  process.exit(1);
}

const seenIds = new Set();
let passed = 0;
let failed = 0;

for (const file of files) {
  const fullPath = path.join(pluginsDir, file);
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(fullPath, "utf8"));
  } catch (err) {
    console.error(`FAIL  ${file} — JSON parse error: ${err.message}`);
    failed += 1;
    continue;
  }

  const errors = validateManifest(fullPath, parsed);
  if (seenIds.has(parsed.id)) {
    errors.push(`duplicate plugin id '${parsed.id}'`);
  }
  seenIds.add(parsed.id);

  if (errors.length === 0) {
    console.log(
      `PASS  ${parsed.id.padEnd(32)} v${parsed.version.padEnd(8)} target=${parsed.target_kind.padEnd(14)} rules=${parsed.rules.length}`
    );
    passed += 1;
  } else {
    console.error(`FAIL  ${file}`);
    for (const e of errors) {
      console.error(`      - ${e}`);
    }
    failed += 1;
  }
}

console.log(`Summary: ${passed}/${files.length} PASS`);
if (failed > 0) {
  process.exit(1);
}
