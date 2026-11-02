// Fails fast with a clear message when Node is older than the engines range (the suite hangs on Node 18).
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 20 || (major === 20 && minor < 19)) {
  console.error(`paseo-rooms needs Node >= 20.19 (found ${process.versions.node}). Use a newer Node, or Paseo's own: ELECTRON_RUN_AS_NODE=1 "$PASEO_NODE" (see CONTRIBUTING.md).`);
  process.exit(1);
}
