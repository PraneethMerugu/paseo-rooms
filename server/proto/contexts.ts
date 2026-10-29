// Domain separation strings (signatures-and-encoding.md sections 3.2 and 3.3).
// One constant per context and label. Adding a signed, hashed or derived object needs a new
// constant here, a row in the spec tables and a new vector.

/** Version prefix of every TBS, hash, KDF and prologue input (section 3.1, section 7 rule 2). */
export const PROTOCOL_PREFIX = "paseo-rooms/v2";

/** Allowed `ctx` strings: ASCII, so the 0x00 separators are unambiguous. */
export const CTX_RE = /^[a-z0-9.:-]{1,64}$/;

// Signature contexts (section 3.2).
export const CTX_GENESIS = "genesis";
export const CTX_LOG_ENTRY = "log-entry";
export const CTX_LANE_GRANT = "lane-grant";
export const CTX_ENROLL_REQUEST = "enroll-request";
export const CTX_KEY_CHANGE_NEW = "key-change-new";
export const CTX_MLS_IDENTITY = "mls-identity";
/** Prefix of per-type statement contexts: `stmt:<type>` (room-log-v2.md section 4). */
export const CTX_STMT_PREFIX = "stmt:";
/** Statement type of the `LogWitness` object that travels inside MLS. */
export const STMT_LOG_WITNESS = "log.witness";

/**
 * Statement type names use `[a-z0-9.-]` (room-log-v2.md section 4), so `stmt:<type>` stays inside the
 * context alphabet of signatures-and-encoding.md section 3.1 and never contains a second `:`.
 */
export function isSignableStatementType(type: string): boolean {
  return /^[a-z0-9.-]+$/.test(type) && CTX_RE.test(CTX_STMT_PREFIX + type);
}

/** Signature context of one statement type, e.g. `stmt:member.admitted`. */
export function stmtContext(type: string): string {
  if (!isSignableStatementType(type)) throw new Error("bad statement type");
  return CTX_STMT_PREFIX + type;
}

// MAC label (section 3.3): HMAC-SHA256 over TBS(label, payload).
export const MAC_ENROLL_TOKEN = "enroll-token";

// HKDF info labels (section 3.3): info = TBS(label, payload).
export const KDF_INVITE_TOKEN_KEY = "invite-token-key";
export const KDF_LINK_TOKEN_KEY = "link-token-key";
export const KDF_SAS = "sas";
export const KDF_FILE_KEY = "file-key";

/** Prefix that puts hash labels in their own namespace: H(label, data) uses ctx `h:<label>`. */
export const HASH_CTX_PREFIX = "h:";

// Hash labels (section 3.3), passed to H() without the `h:` prefix.
export const H_KID = "kid";
export const H_GENESIS = "genesis";
export const H_LOG_ENTRY = "log-entry";
export const H_LOG_BODY = "log-body";
export const H_ROSTER = "roster";
export const H_INVITE_REF = "invite-ref";
export const H_LINK_REF = "link-ref";
export const H_ADMIN_SET = "admin-set";
export const H_MLS_GROUP = "mls-group";
export const H_SAS_COMMIT = "sas-commit";
export const H_SAS_TRANSCRIPT = "sas-transcript";
/** Recovery code checksum (identity-model.md section 5.4.1). */
export const H_RECOVERY_CODE = "recovery-code";

// Noise prologue label (section 3.3; enrollment-v2.md section 3.3).
export const PROLOGUE_NOISE_IK = "noise-ik";

export const SIGNATURE_CONTEXTS = [CTX_GENESIS, CTX_LOG_ENTRY, CTX_LANE_GRANT, CTX_ENROLL_REQUEST, CTX_KEY_CHANGE_NEW, CTX_MLS_IDENTITY] as const;
export const HASH_LABELS = [H_KID, H_GENESIS, H_LOG_ENTRY, H_LOG_BODY, H_ROSTER, H_INVITE_REF, H_LINK_REF, H_ADMIN_SET, H_MLS_GROUP, H_SAS_COMMIT, H_SAS_TRANSCRIPT, H_RECOVERY_CODE] as const;
export const DERIVATION_LABELS = [MAC_ENROLL_TOKEN, KDF_INVITE_TOKEN_KEY, KDF_LINK_TOKEN_KEY, KDF_SAS, KDF_FILE_KEY, PROLOGUE_NOISE_IK] as const;
