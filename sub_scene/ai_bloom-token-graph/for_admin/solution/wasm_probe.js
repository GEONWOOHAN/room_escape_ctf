const fs = require("fs");

async function main() {
  const wasmPath = process.argv[2];
  const values = JSON.parse(fs.readFileSync(0, "utf8"));
  const module = await WebAssembly.instantiate(fs.readFileSync(wasmPath), {});
  const {memory, tokenize} = module.instance.exports;
  const encoder = new TextEncoder();
  const inputPtr = 32768;
  const outputPtr = 49152;
  const result = [];
  for (const value of values) {
    const raw = encoder.encode(value);
    new Uint8Array(memory.buffer, inputPtr, raw.length).set(raw);
    const count = tokenize(inputPtr, raw.length, outputPtr, 256);
    if (count > 256) throw new Error(`tokenizer error: ${count}`);
    result.push(Array.from(new Uint16Array(memory.buffer, outputPtr, count)));
  }
  process.stdout.write(JSON.stringify(result));
}

main().catch((error) => {
  process.stderr.write(String(error));
  process.exitCode = 1;
});
