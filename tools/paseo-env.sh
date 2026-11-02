# Sourced (bash) by the test and ui-check scripts. Finds the Paseo CLI and a Node runtime, and sets:
#
#   P          the paseo CLI                     (override: PASEO_BIN)
#   NODE       an array that runs Node           (override: PASEO_NODE)
#   PASEO_BIN  exported, so TypeScript drivers use the same CLI
#
# PASEO_NODE may be Paseo's own executable (it runs as Node with ELECTRON_RUN_AS_NODE=1, which is
# always set here and ignored by a plain Node) or any Node >= 20.19.
#
# Per-OS defaults, used when the variable is unset:
#   Linux    /opt/Paseo/resources/bin/paseo, /opt/Paseo/Paseo.bin              (verified, .deb install)
#   macOS    /Applications/Paseo.app/Contents/Resources/bin/paseo,
#            /Applications/Paseo.app/Contents/Frameworks/Paseo Helper.app/Contents/MacOS/Paseo Helper
#                                                                              (unverified)
#   Windows  %LOCALAPPDATA%\Programs\Paseo\resources\bin\paseo, ...\Paseo.exe   (unverified; the
#            scripts need bash, for example Git Bash, and have never run on Windows)
# If the CLI default is missing, `paseo` on PATH is used. If the Node default is missing, `node` on
# PATH is used when it is version 20.19 or later.

# Only ever sourced from a script, so a failure ends that script.
_paseo_env_fail() {
  echo "paseo-env: $*" >&2
  exit 2
}

case "$(uname -s)" in
  Linux)
    _paseo_default_bin=/opt/Paseo/resources/bin/paseo
    _paseo_default_node=/opt/Paseo/Paseo.bin
    ;;
  Darwin)
    _paseo_default_bin=/Applications/Paseo.app/Contents/Resources/bin/paseo
    _paseo_default_node="/Applications/Paseo.app/Contents/Frameworks/Paseo Helper.app/Contents/MacOS/Paseo Helper"
    ;;
  MINGW* | MSYS* | CYGWIN*)
    _paseo_lad=${LOCALAPPDATA:-}
    command -v cygpath > /dev/null 2>&1 && [ -n "$_paseo_lad" ] && _paseo_lad=$(cygpath -u "$_paseo_lad")
    _paseo_default_bin="$_paseo_lad/Programs/Paseo/resources/bin/paseo"
    _paseo_default_node="$_paseo_lad/Programs/Paseo/Paseo.exe"
    ;;
  *)
    _paseo_default_bin=""
    _paseo_default_node=""
    ;;
esac

if [ -n "${PASEO_BIN:-}" ]; then
  [ -x "$PASEO_BIN" ] || _paseo_env_fail "PASEO_BIN=$PASEO_BIN is not an executable file"
  P=$PASEO_BIN
elif [ -n "$_paseo_default_bin" ] && [ -x "$_paseo_default_bin" ]; then
  P=$_paseo_default_bin
elif command -v paseo > /dev/null 2>&1; then
  P=$(command -v paseo)
else
  _paseo_env_fail "Paseo CLI not found (looked at '${_paseo_default_bin:-<no default for this OS>}' and PATH). Set PASEO_BIN to the paseo CLI."
fi
export PASEO_BIN=$P

if [ -n "${PASEO_NODE:-}" ]; then
  [ -x "$PASEO_NODE" ] || _paseo_env_fail "PASEO_NODE=$PASEO_NODE is not an executable file"
  _paseo_node=$PASEO_NODE
elif [ -n "$_paseo_default_node" ] && [ -x "$_paseo_default_node" ]; then
  _paseo_node=$_paseo_default_node
elif command -v node > /dev/null 2>&1 && node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 20 || (a === 20 && b >= 19) ? 0 : 1)' 2> /dev/null; then
  _paseo_node=$(command -v node)
else
  _paseo_env_fail "No Node >= 20.19 found (looked at '${_paseo_default_node:-<no default for this OS>}' and node on PATH). Set PASEO_NODE to Paseo's executable or a Node >= 20.19."
fi
NODE=(env ELECTRON_RUN_AS_NODE=1 "$_paseo_node")
unset _paseo_default_bin _paseo_default_node _paseo_node _paseo_lad
