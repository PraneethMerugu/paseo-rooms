// Fake relay for `up-v2.sh --offline`: test/unit/fake-relay.ts on 127.0.0.1:<port>, port 6912 to 6919
// only (the e2e wrapper accepts 6920-6929 only). Logs one line per socket; never logs payloads.
import { startFakeRelay } from "../test/unit/fake-relay";

const port = Number(process.argv[2]);
if (!Number.isInteger(port) || port < 6912 || port > 6919) {
  console.error("fake relay: port must be in 6912-6919");
  process.exit(2);
}

startFakeRelay({ host: "127.0.0.1", port, log: (line) => console.log(`${new Date().toISOString()} ${line}`) })
  .then((relay) => {
    console.log(`${new Date().toISOString()} fake relay listening on ${relay.endpoint}`);
    const stop = () => {
      void relay.close().then(() => process.exit(0));
    };
    process.on("SIGTERM", stop);
    process.on("SIGINT", stop);
  })
  .catch((e) => {
    console.error(`fake relay failed: ${String((e as Error)?.message ?? e)}`);
    process.exit(1);
  });
