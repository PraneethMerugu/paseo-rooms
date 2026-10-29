# Shared settings for the attack harness. Ports 6900-6909 only. Never touches ~/.paseo.
ATTACK_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PLUGIN_DIR=$(cd "$ATTACK_DIR/../.." && pwd)
P=/opt/Paseo/resources/bin/paseo
NODE=(env ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin)
TSX=("${NODE[@]}" "$PLUGIN_DIR/node_modules/tsx/dist/cli.mjs")
HOMES=$ATTACK_DIR/.homes
C=$HOMES/owner-c
A=$HOMES/member-a
C_PORT=6900
A_PORT=6901
LOGDIR=$ATTACK_DIR/logs
SCRATCH=$ATTACK_DIR/scratch
export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false
pa() { local home=$1; shift; PASEO_HOME=$home "$P" "$@" --home "$home" < /dev/null; }
write_config() {
  local home=$1 port=$2
  mkdir -p "$home"; chmod 700 "$HOMES" "$home"
  cat > "$home/config.json" <<JSON
{
  "daemon": { "listen": "127.0.0.1:$port", "relay": { "enabled": false } },
  "pluginsEnabled": true,
  "features": { "dictation": { "enabled": false }, "voiceMode": { "enabled": false } }
}
JSON
  chmod 600 "$home/config.json"
}
