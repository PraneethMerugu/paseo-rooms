// Loopback relay for the security modules (credential-negative, resource-stress): the in-process fake
// relay of test/unit/fake-relay.ts on 127.0.0.1:<port>, port 6930 to 6939 only. run.sh starts it
// before those modules and restarts the owner test daemon so that the rooms they create register here,
// not on relay.paseo.sh. Logs one line per socket; never logs payloads.
import { startFakeRelay } from "../unit/fake-relay";

const port = Number(process.argv[2]);
if (!Number.isInteger(port) || port === 6767 || port < 6930 || port > 6939) {
  console.error("fake relay: port must be in 6930-6939");
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
