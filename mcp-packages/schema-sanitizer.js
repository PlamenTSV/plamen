#!/usr/bin/env node
/**
 * MCP compatibility proxy.
 *
 * Responsibilities:
 * - sanitize tool schemas (oneOf/allOf/anyOf/$defs/$ref)
 * - proxy the explicitly selected newline-delimited JSON MCP transport
 * - force JS entrypoints to execute via Node on Windows
 *
 * Both admitted clients and servers use newline-delimited JSON on stdio.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const { TextDecoder } = require('util');

const args = process.argv.slice(2);
const backendOption = args.shift();
if (!['--backend=claude', '--backend=codex'].includes(backendOption) || args.length === 0) {
  console.error('Usage: node schema-sanitizer.js --backend=<claude|codex> <command> [args...]');
  process.exit(1);
}

// Both current Claude Code and Codex MCP stdio clients use the MCP-specified
// newline-delimited JSON transport. The explicit backend token is still
// required so a future transport change cannot be guessed or auto-detected.
let command = args[0];
let commandArgs = args.slice(1);

// On Windows, launching a .js file directly can invoke the shell file association
// instead of Node. If the target is a JS entrypoint, force execution via Node.
if (/\.(c?m?js)$/i.test(command)) {
  commandArgs = [command, ...commandArgs];
  command = process.execPath;
}

// Spawn the actual MCP server
const child = spawn(command, commandArgs, {
  stdio: ['pipe', 'pipe', 'inherit'],
  env: process.env,
  shell: false,
  // POSIX descendants inherit this owned process group unless they
  // deliberately escape it. Windows requires a Job Object at the launcher
  // boundary; stock Node does not expose a Job API.
  detached: process.platform !== 'win32'
});

// `process.stdout.write()` may synchronously block on Windows pipes, preventing
// its boolean backpressure result and every timeout/signal handler from running.
// An fd-backed WriteStream uses asynchronous writes on all supported platforms.
const parentOutput = fs.createWriteStream(null, {
  fd: 1,
  autoClose: false,
  highWaterMark: 64 * 1024,
});

let parentBuf = Buffer.alloc(0);
let childBuf = Buffer.alloc(0);
const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
// Node normally supplies much smaller stream chunks. This extra allowance lets
// a chunk contain a maximum-sized line plus framing while keeping retained
// transport state mechanically bounded if a custom stream supplies huge data.
const MAX_BUFFERED_BYTES = MAX_MESSAGE_BYTES + 64 * 1024;
const MAX_TOOLS = 4096;
const MAX_SCHEMA_NODES = 16 * 1024;
const MAX_SCHEMA_PROPERTIES = 16 * 1024;
const MAX_SCHEMA_VARIANTS = 4096;
const FORCE_EXIT_MS = 1000;
const PARENT_EOF_GRACE_MS = 1000;
const TERMINATION_GRACE_MS = 250;
let terminating = false;
let waitingForChildDrain = false;
let waitingForParentDrain = false;
let parentEnded = false;
let pendingChildClose = null;
let forcedExitTimer = null;
let parentEofTimer = null;
let terminationTimer = null;

function forceExitWithin(code) {
  if (forcedExitTimer !== null) return;
  forcedExitTimer = setTimeout(() => process.exit(code), FORCE_EXIT_MS);
}

function terminateProxyNow(code) {
  process.exitCode = code;
  try {
    // Unlike process.exit(), self-SIGKILL does not wait for an outstanding
    // Windows pipe write. The OS closes every remaining stdio handle.
    process.kill(process.pid, 'SIGKILL');
  } catch (_error) {
    process.exit(code);
  }
}

function signalOwnedChildTree(signal) {
  if (!Number.isInteger(child.pid) || child.pid <= 0) return false;
  try {
    if (process.platform === 'win32') return child.kill(signal);
    process.kill(-child.pid, signal);
    return true;
  } catch (_error) {
    try { return child.kill(signal); } catch (_fallbackError) { return false; }
  }
}

function beginBoundedTermination(code) {
  signalOwnedChildTree('SIGTERM');
  if (terminationTimer !== null) return;
  terminationTimer = setTimeout(() => {
    signalOwnedChildTree('SIGKILL');
    terminateProxyNow(code);
  }, TERMINATION_GRACE_MS);
}

function closeInputAndChildPipes({ destroyChildOutput = true } = {}) {
  process.stdin.pause();
  process.stdin.removeListener('data', processParentInput);
  if (!process.stdin.destroyed) process.stdin.destroy();
  if (!child.stdin.destroyed) child.stdin.destroy();
  child.stdout.pause();
  if (destroyChildOutput && !child.stdout.destroyed) child.stdout.destroy();
}

function failClosed(message) {
  if (terminating) return;
  terminating = true;
  const denial = `MCP sanitizer denied: ${String(message).slice(0, 512)}\n`;
  try { fs.writeSync(2, denial); } catch (_error) {}
  // A large outstanding child read can make a synchronous destroy wait on
  // Windows. Pause it now; forced process termination closes that pipe handle.
  closeInputAndChildPipes({ destroyChildOutput: false });
  beginBoundedTermination(1);
}

function decodeUtf8(raw, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch (_error) {
    throw new Error(`invalid UTF-8 in ${label}`);
  }
}

function appendBounded(current, chunk, label) {
  if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
  if (current.length + chunk.length > MAX_BUFFERED_BYTES) {
    throw new Error(`${label} buffered state exceeds limit`);
  }
  if (current.length === 0) return chunk;
  if (chunk.length === 0) return current;
  return Buffer.concat([current, chunk], current.length + chunk.length);
}

function rejectBufferedTail(raw, label) {
  if (raw.length === 0) return;
  let decoded;
  try {
    decoded = decodeUtf8(raw, `${label} tail`);
  } catch (error) {
    return failClosed(error.message);
  }
  if (decoded.trim() !== '') failClosed(`truncated ${label} message at EOF`);
}

function finishParentEof() {
  if (terminating) return;
  rejectBufferedTail(parentBuf, 'parent');
  if (terminating) return;
  if (!child.stdin.destroyed) child.stdin.end();
  if (parentEofTimer === null) {
    parentEofTimer = setTimeout(() => {
      failClosed('child did not exit after parent EOF');
    }, PARENT_EOF_GRACE_MS);
  }
}

function sanitizeMessage(msg) {
  const budget = { nodes: 0, properties: 0, variants: 0 };
  if (msg.result && msg.result.tools && Array.isArray(msg.result.tools)) {
    if (msg.result.tools.length > MAX_TOOLS) throw new Error('tool denominator exceeds limit');
    msg.result.tools = msg.result.tools.map(tool => {
      if (tool.inputSchema) {
        tool.inputSchema = sanitizeSchema(tool.inputSchema, undefined, 0, budget);
      }
      if (tool.outputSchema) {
        tool.outputSchema = sanitizeSchema(tool.outputSchema, undefined, 0, budget);
      }
      return tool;
    });
  }
  return msg;
}

function writeJsonLineToChild(msg) {
  const raw = JSON.stringify(msg) + '\n';
  if (Buffer.byteLength(raw) > MAX_MESSAGE_BYTES) throw new Error('parent MCP message exceeds limit');
  if (!child.stdin.write(raw)) {
    waitingForChildDrain = true;
    process.stdin.pause();
    return false;
  }
  return true;
}

function processParentInput(chunk = Buffer.alloc(0)) {
  if (terminating) return;
  try {
    parentBuf = appendBounded(parentBuf, chunk, 'parent');
  } catch (error) {
    return failClosed(error.message);
  }
  if (waitingForChildDrain) return;
  while (true) {
    const newline = parentBuf.indexOf('\n');
    if (newline === -1) {
      if (parentBuf.length > MAX_MESSAGE_BYTES) failClosed('unterminated parent message exceeds limit');
      return;
    }
    if (newline > MAX_MESSAGE_BYTES) return failClosed('parent message exceeds limit');
    let line;
    try {
      line = decodeUtf8(parentBuf.subarray(0, newline), 'parent message').trim();
    } catch (error) {
      return failClosed(error.message);
    }
    parentBuf = parentBuf.subarray(newline + 1);
    if (!line) continue;
    try {
      if (!writeJsonLineToChild(JSON.parse(line))) return;
    } catch (error) {
      return failClosed(error.message || 'malformed parent message');
    }
  }
}

function processChildOutput(chunk = Buffer.alloc(0)) {
  if (terminating) return;
  try {
    childBuf = appendBounded(childBuf, chunk, 'child');
  } catch (error) {
    return failClosed(error.message);
  }
  if (waitingForParentDrain) return;
  while (true) {
    const newline = childBuf.indexOf('\n');
    if (newline === -1) {
      if (childBuf.length > MAX_MESSAGE_BYTES) failClosed('unterminated child message exceeds limit');
      return;
    }
    if (newline > MAX_MESSAGE_BYTES) return failClosed('child message exceeds limit');
    let line;
    try {
      line = decodeUtf8(childBuf.subarray(0, newline), 'child message').trim();
    } catch (error) {
      return failClosed(error.message);
    }
    childBuf = childBuf.subarray(newline + 1);
    if (!line) continue;
    try {
      const raw = JSON.stringify(sanitizeMessage(JSON.parse(line))) + '\n';
      if (Buffer.byteLength(raw) > MAX_MESSAGE_BYTES) throw new Error('sanitized child message exceeds limit');
      if (!parentOutput.write(raw)) {
        waitingForParentDrain = true;
        child.stdout.pause();
        return;
      }
    } catch (error) {
      return failClosed(error.message || 'malformed child message');
    }
  }
}

/**
 * Recursively strip oneOf/allOf/anyOf from a JSON Schema object.
 * Strategy:
 * - Top-level oneOf/anyOf: pick the first non-null variant
 * - Top-level allOf: merge all sub-schemas
 * - Property-level: same treatment recursively
 */
function consumeSchemaWork(budget, field, amount, maximum, label) {
  if (!Number.isSafeInteger(amount) || amount < 0) throw new Error(`invalid ${label} work`);
  budget[field] += amount;
  if (budget[field] > maximum) throw new Error(`${label} work exceeds limit`);
}

function defineOwnProperties(target, source) {
  if (!source || typeof source !== 'object') return;
  for (const [name, value] of Object.entries(source)) {
    Object.defineProperty(target, name, {
      value, enumerable: true, configurable: true, writable: true,
    });
  }
}

function sanitizeSchema(schema, defs, depth = 0, budget = { nodes: 0, properties: 0, variants: 0 }) {
  if (depth > 32) throw new Error('schema nesting exceeds limit');
  if (!schema || typeof schema !== 'object') return schema;
  consumeSchemaWork(budget, 'nodes', 1, MAX_SCHEMA_NODES, 'schema node');
  if (Array.isArray(schema)) {
    consumeSchemaWork(budget, 'variants', schema.length, MAX_SCHEMA_VARIANTS, 'schema variant');
    return schema.map(s => sanitizeSchema(s, defs, depth + 1, budget));
  }
  consumeSchemaWork(
    budget, 'properties', Object.keys(schema).length,
    MAX_SCHEMA_PROPERTIES, 'schema property',
  );

  // Resolve $ref references using $defs
  if (schema['$ref'] && defs) {
    const refPath = schema['$ref'].replace('#/$defs/', '');
    const resolved = defs[refPath];
    if (resolved) {
      return sanitizeSchema({ ...resolved }, defs, depth + 1, budget);
    }
  }

  // Capture $defs from root schema for ref resolution
  const localDefs = schema['$defs'] || defs;

  const result = { ...schema };

  // Remove $defs from output (already inlined via $ref resolution)
  delete result['$defs'];

  // Handle top-level anyOf (from z.optional / z.union)
  if (result.anyOf) {
    if (!Array.isArray(result.anyOf)) throw new Error('schema anyOf is not an array');
    consumeSchemaWork(
      budget, 'variants', result.anyOf.length,
      MAX_SCHEMA_VARIANTS, 'schema variant',
    );
    const variants = result.anyOf.filter(v => v.type !== 'null' && v.type !== undefined || v.properties);
    if (variants.length === 1) {
      // Single non-null variant — unwrap it
      const unwrapped = sanitizeSchema(variants[0], localDefs, depth + 1, budget);
      delete result.anyOf;
      defineOwnProperties(result, unwrapped);
    } else if (variants.length > 1) {
      // Multiple variants — pick the object one if exists, otherwise first
      const objVariant = variants.find(v => v.type === 'object' || v.properties);
      const picked = sanitizeSchema(objVariant || variants[0], localDefs, depth + 1, budget);
      delete result.anyOf;
      defineOwnProperties(result, picked);
    } else {
      // All null variants — just make it any type
      delete result.anyOf;
    }
  }

  // Handle top-level oneOf (from z.discriminatedUnion)
  if (result.oneOf) {
    if (!Array.isArray(result.oneOf)) throw new Error('schema oneOf is not an array');
    consumeSchemaWork(
      budget, 'variants', result.oneOf.length,
      MAX_SCHEMA_VARIANTS, 'schema variant',
    );
    // Pick the first variant that looks like an object schema
    const objVariant = result.oneOf.find(v => v.type === 'object' || v.properties);
    if (objVariant) {
      const picked = sanitizeSchema(objVariant, localDefs, depth + 1, budget);
      delete result.oneOf;
      defineOwnProperties(result, picked);
    } else {
      const picked = sanitizeSchema(result.oneOf[0], localDefs, depth + 1, budget);
      delete result.oneOf;
      defineOwnProperties(result, picked);
    }
  }

  // Handle top-level allOf (from z.intersection)
  if (result.allOf) {
    if (!Array.isArray(result.allOf)) throw new Error('schema allOf is not an array');
    consumeSchemaWork(
      budget, 'variants', result.allOf.length,
      MAX_SCHEMA_VARIANTS, 'schema variant',
    );
    delete result.allOf;
    if (result.properties && (
      typeof result.properties !== 'object' || Array.isArray(result.properties)
    )) throw new Error('schema properties is not an object');
    const mergedRequired = new Set(Array.isArray(result.required) ? result.required : []);
    for (const sub of schema.allOf) {
      const sanitized = sanitizeSchema(sub, localDefs, depth + 1, budget);
      // Merge properties
      if (sanitized.properties) {
        if (typeof sanitized.properties !== 'object' || Array.isArray(sanitized.properties)) {
          throw new Error('schema properties is not an object');
        }
        if (!result.properties) result.properties = {};
        defineOwnProperties(result.properties, sanitized.properties);
      }
      if (sanitized.required) {
        if (!Array.isArray(sanitized.required)) throw new Error('schema required is not an array');
        for (const name of sanitized.required) mergedRequired.add(name);
      }
      if (sanitized.type && !result.type) {
        result.type = sanitized.type;
      }
    }
    if (mergedRequired.size > 0) result.required = [...mergedRequired];
  }

  // Recurse into properties
  if (result.properties) {
    if (typeof result.properties !== 'object' || Array.isArray(result.properties)) {
      throw new Error('schema properties is not an object');
    }
    consumeSchemaWork(
      budget, 'properties', Object.keys(result.properties).length,
      MAX_SCHEMA_PROPERTIES, 'schema property',
    );
    for (const [key, value] of Object.entries(result.properties)) {
      result.properties[key] = sanitizeSchema(value, localDefs, depth + 1, budget);
    }
  }

  // Recurse into items (arrays)
  if (result.items) {
    result.items = sanitizeSchema(result.items, localDefs, depth + 1, budget);
  }

  // Recurse into additionalProperties
  if (result.additionalProperties && typeof result.additionalProperties === 'object') {
    result.additionalProperties = sanitizeSchema(result.additionalProperties, localDefs, depth + 1, budget);
  }

  return result;
}

process.stdin.on('data', processParentInput);
child.stdout.on('data', processChildOutput);
child.stdin.on('drain', () => {
  if (terminating) return;
  waitingForChildDrain = false;
  processParentInput();
  if (terminating || waitingForChildDrain) return;
  if (parentEnded) {
    finishParentEof();
  } else {
    process.stdin.resume();
  }
});
parentOutput.on('drain', () => {
  if (terminating) return;
  waitingForParentDrain = false;
  processChildOutput();
  if (terminating || waitingForParentDrain) return;
  if (pendingChildClose !== null) {
    finishChildClose();
  } else {
    child.stdout.resume();
  }
});
parentOutput.on('error', (error) => {
  failClosed(`parent stdout failed: ${error.message}`);
});
process.stdin.on('end', () => {
  if (terminating) return;
  parentEnded = true;
  processParentInput();
  if (terminating || waitingForChildDrain) return;
  finishParentEof();
});

function finishChildClose() {
  if (terminating) return;
  if (waitingForParentDrain) return;
  processChildOutput();
  if (terminating || waitingForParentDrain) return;
  rejectBufferedTail(childBuf, 'child');
  if (terminating) return;
  const { code, signal } = pendingChildClose;
  if (parentEofTimer !== null) {
    clearTimeout(parentEofTimer);
    parentEofTimer = null;
  }
  terminating = true;
  closeInputAndChildPipes();
  if (signal) {
    console.error(`MCP child terminated by ${signal}`);
    process.exitCode = 1;
  } else {
    process.exitCode = Number.isInteger(code) ? code : 1;
  }
  if (!parentOutput.destroyed) parentOutput.end();
  forceExitWithin(process.exitCode);
}

child.on('close', (code, signal) => {
  if (terminating) return;
  pendingChildClose = { code, signal };
  finishChildClose();
  if (!terminating && waitingForParentDrain) {
    // A client that stops reading must not retain the proxy and its bounded
    // output buffer forever after the child has already terminated.
    setTimeout(() => {
      if (!terminating && waitingForParentDrain) {
        failClosed('parent stdout did not drain after child exit');
      }
    }, FORCE_EXIT_MS);
  }
});
child.on('error', (err) => {
  failClosed(`failed to start child: ${err.message}`);
});
child.stdin.on('error', (err) => {
  if (!terminating) failClosed(`child stdin failed: ${err.message}`);
});
child.stdout.on('error', (err) => {
  if (!terminating) failClosed(`child stdout failed: ${err.message}`);
});
process.stdin.on('error', (err) => {
  if (!terminating) failClosed(`parent stdin failed: ${err.message}`);
});

function forwardSignal(signal) {
  if (terminating) return;
  terminating = true;
  closeInputAndChildPipes({ destroyChildOutput: false });
  signalOwnedChildTree(signal);
  beginBoundedTermination(signal === 'SIGINT' ? 130 : 143);
}
process.on('SIGTERM', () => forwardSignal('SIGTERM'));
process.on('SIGINT', () => forwardSignal('SIGINT'));
