#!/usr/bin/env node
/**
 * Zero-dependency 1-click CLI launcher for morph-os (`npx create-morph-os`).
 * Initializes local `morph-os.json` mutation rule configs and runs quick local deterministic
 * checks without sending any data off-device.
 */

import fs from "node:fs";
import path from "node:path";

const VERSION = "1.0.0";

const DEFAULT_CONFIG = {
  schema_version: "1.0",
  engine: "deterministic",
  ollama: {
    base_url: "http://127.0.0.1:11434",
    model: "llama3.2",
    timeout_ms: 4000,
    circuit_breaker: {
      failure_threshold: 3,
      cooldown_ms: 15000,
    },
  },
  proxy: {
    listen: "127.0.0.1:8787",
    upstream: "http://127.0.0.1:9000",
    default_rule: "legacy-xml-to-rest-json",
  },
  stdio: {
    default_rule: "cli-table-to-json",
    timeout_ms: 15000,
    max_output_bytes: 8388608,
  },
  plugins_dir: "./plugins",
};

function printHelp() {
  console.log(`create-morph-os v${VERSION}
Local runtime stream, HTTP API, and DOM mutator initializer

USAGE:
  npx create-morph-os [options] [target-dir]

OPTIONS:
  --help, -h         Show this help message
  --version, -v      Print version
  --dry-run          Preview generated morph-os.json without writing to disk
  --rule <id>        Set default mutation rule (default: cli-table-to-json)
  --upstream <url>   Set default reverse-proxy upstream URL (default: http://127.0.0.1:9000)

EXAMPLES:
  npx create-morph-os --dry-run
  npx create-morph-os ./my-legacy-bridge --rule legacy-xml-to-rest-json --upstream http://127.0.0.1:9000
`);
}

function parseArgs(argv) {
  const opts = {
    help: false,
    version: false,
    dryRun: false,
    rule: null,
    upstream: null,
    targetDir: ".",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg === "--version" || arg === "-v") {
      opts.version = true;
    } else if (arg === "--dry-run") {
      opts.dryRun = true;
    } else if (arg === "--rule" && argv[i + 1]) {
      opts.rule = argv[++i];
    } else if (arg === "--upstream" && argv[i + 1]) {
      opts.upstream = argv[++i];
    } else if (!arg.startsWith("-")) {
      opts.targetDir = arg;
    }
  }
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    printHelp();
    return;
  }
  if (opts.version) {
    console.log(`create-morph-os ${VERSION}`);
    return;
  }

  const config = structuredClone(DEFAULT_CONFIG);
  if (opts.rule) {
    config.stdio.default_rule = opts.rule;
    config.proxy.default_rule = opts.rule;
  }
  if (opts.upstream) {
    config.proxy.upstream = opts.upstream;
  }

  const resolvedDir = path.resolve(process.cwd(), opts.targetDir);
  const configPath = path.join(resolvedDir, "morph-os.json");
  const serialized = `${JSON.stringify(config, null, 2)}\n`;

  if (opts.dryRun) {
    console.log(`[dry-run] Would initialize morph-os workspace at: ${resolvedDir}`);
    console.log(`[dry-run] Target config file: ${configPath}`);
    console.log(serialized);
    console.log("[dry-run] Next steps after writing config:");
    console.log("  1. morph-os run --rule cli-table-to-json -- morph-os demo-cli");
    console.log("  2. morph-os proxy --listen 127.0.0.1:8787 --upstream http://127.0.0.1:9000 --rule legacy-xml-to-rest-json");
    return;
  }

  fs.mkdirSync(resolvedDir, { recursive: true });
  fs.writeFileSync(configPath, serialized, "utf8");
  console.log(`OK  Created ${configPath}`);
  console.log("Run your first local stream mutation:");
  console.log("  morph-os run --rule cli-table-to-json -- morph-os demo-cli");
}

main();
