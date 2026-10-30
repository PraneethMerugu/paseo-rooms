// Dialogs of the v2 Rooms UI (I-14): the admin confirmation with its one-time token and the
// `stale_base` re-confirmation (identity-model 5.3, room-log-v2 2 R-9), the recovery code shown once
// (identity-model 5.4, 5.4.1, 7.3), typed confirmations and the SAS digits (enrollment 6.3, 6.4).
import type { PluginTheme } from "@getpaseo/plugin";
import { useRpc } from "@getpaseo/plugin/client";
import { copyText, Modal, TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useState, type ReactNode } from "react";
import { Platform, Text, View } from "react-native";
import type { z } from "zod";
import { roomsV2AdminPrepare, type AdminActionV2, type AdminDescriptionV2, type RecoveryOfferV2 } from "../shared/rpc-v2";
import { saveTextFile } from "./save-file";
import { Button, errorText, type Styles } from "./ui";
import { fmtSas, recoveryCheckGroup, recoveryCodeLines } from "./v2-text";

type Description = z.infer<typeof AdminDescriptionV2>;
export type RecoveryOffer = z.infer<typeof RecoveryOfferV2>;

type Open = {
  action: AdminActionV2;
  perform(confirmToken: string): Promise<unknown>;
  onDone?(result: unknown): void;
  success?: string;
  prep: { confirmToken: string; description: Description } | null;
  /** Set after `stale_base` (or an expired token): the dialog is shown again with the new value. */
  changed: string | null;
  error: string | null;
};

/**
 * Interactive admin actions: `open(action, perform)` asks the daemon to describe the action, shows
 * the dialog, and calls `perform(confirmToken)` only after the person confirms. Render `element`.
 */
export function useAdminConfirm(theme: PluginTheme, styles: Styles) {
  const prepare = useRpc(roomsV2AdminPrepare);
  const toast = useToast();
  const [st, setSt] = useState<Open | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async (base: Omit<Open, "prep" | "error">) => {
    setTyped("");
    try {
      const p = await prepare({ action: base.action });
      setSt({ ...base, prep: { confirmToken: p.confirmToken, description: p.description }, error: null });
    } catch (e) {
      setSt({ ...base, prep: null, error: errorText(e) });
    }
  };

  function open<T>(action: AdminActionV2, perform: (confirmToken: string) => Promise<T>, opts: { onDone?(r: T): void; success?: string } = {}) {
    void load({ action, perform, onDone: opts.onDone as ((r: unknown) => void) | undefined, success: opts.success, changed: null });
  }

  const close = () => {
    if (busy) return;
    setSt(null);
    setTyped("");
  };

  const confirm = async () => {
    if (!st?.prep) return;
    setBusy(true);
    try {
      const r = await st.perform(st.prep.confirmToken);
      setSt(null);
      setTyped("");
      if (st.success) toast.show(st.success, { variant: "success" });
      st.onDone?.(r);
    } catch (e) {
      const msg = errorText(e);
      if (/stale_base|bad_token/.test(msg)) {
        // R-9: never re-sign silently; describe the new state and ask again.
        const why = /stale_base/.test(msg) ? "This changed since you opened the dialog. Check the current value and confirm again." : "The confirmation expired. Check the details and confirm again.";
        await load({ action: st.action, perform: st.perform, onDone: st.onDone, success: st.success, changed: why });
      } else setSt({ ...st, error: msg });
    } finally {
      setBusy(false);
    }
  };

  const d = st?.prep?.description ?? null;
  const needTyped = d?.typeToConfirm ?? null;
  const typedOk = !needTyped || typed.trim().toLowerCase() === needTyped.toLowerCase();
  const c = theme.colors;
  const element = st ? (
    <Modal title={d?.title ?? "Confirm"} open onOpenChange={(o) => (o ? undefined : close())}>
      <Modal.Content>
        <View style={{ gap: 10 }} accessibilityLiveRegion="polite">
          {st.changed ? (
            <View style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: c.statusWarning }]}>
              <Text style={styles.body}>{st.changed}</Text>
            </View>
          ) : null}
          {!st.prep && !st.error ? <Text style={styles.muted}>Loading what will be signed…</Text> : null}
          {d?.current ? <Text style={[styles.body, { fontWeight: "600" }]}>Now: {d.current}</Text> : null}
          {d?.details.map((line, i) => (
            <Text key={i} style={styles.body}>
              {line}
            </Text>
          ))}
          {d?.warning ? <Text style={[styles.small, { color: c.statusWarning }]}>{d.warning}</Text> : null}
          {needTyped ? (
            <View style={{ gap: 4 }}>
              <Text style={styles.small}>Type "{needTyped}" to confirm.</Text>
              <TextInput
                accessibilityLabel={`Type ${needTyped} to confirm`}
                value={typed}
                onChangeText={setTyped}
                autoCapitalize="none"
                autoCorrect={false}
                placeholder={needTyped}
                placeholderTextColor={c.foregroundMuted}
                style={styles.input}
              />
            </View>
          ) : null}
          {st.error ? <Text style={styles.danger}>{st.error}</Text> : null}
          <Text style={styles.small}>Signed with this daemon's admin key and recorded in the room log.</Text>
          <View style={styles.row}>
            {st.prep ? <Button theme={theme} variant={needTyped ? "danger" : "primary"} label="Confirm" busy={busy} disabled={!typedOk} onPress={() => void confirm()} /> : null}
            <Button theme={theme} label={st.prep ? "Cancel" : "Close"} disabled={busy} onPress={close} />
          </View>
        </View>
      </Modal.Content>
    </Modal>
  ) : null;

  return { open, element };
}

/**
 * The recovery code, shown once (identity-model 5.4): on screen, copy, and save as the file of 5.4.1
 * (download on web and desktop, share sheet on iOS and Android). The dialog closes only after the
 * person types the last group back, so a stray tap cannot lose the only copy.
 */
export function RecoveryCodeModal({ theme, styles, offer, context, onClosed }: { theme: PluginTheme; styles: Styles; offer: RecoveryOffer | null; context: string; onClosed(): void }) {
  const toast = useToast();
  const [check, setCheck] = useState("");
  const [nudge, setNudge] = useState(false);
  if (!offer) return null;
  const last = recoveryCheckGroup(offer.code);
  const ok = check.trim().toLowerCase() === last;
  const tryClose = () => {
    if (ok) {
      setCheck("");
      setNudge(false);
      onClosed();
    } else setNudge(true);
  };
  const c = theme.colors;
  return (
    <Modal title="Save your recovery code" open onOpenChange={(o) => (o ? undefined : tryClose())}>
      <Modal.Content>
        <View style={{ gap: 10 }}>
          <Text style={styles.body}>{context}</Text>
          <Text style={styles.body}>This code is shown once. The daemon does not keep it. Store it offline or in a password manager, not in the room's chat.</Text>
          <View style={[styles.codeBox, { gap: 2 }]} accessibilityLabel="Recovery code">
            {recoveryCodeLines(offer.code).map((l, i) => (
              <Text key={i} selectable style={[styles.mono, { fontSize: 15, letterSpacing: 1 }]}>
                {l}
              </Text>
            ))}
          </View>
          <View style={styles.row}>
            <Button
              theme={theme}
              variant="primary"
              label={Platform.OS === "ios" || Platform.OS === "android" ? "Save or share file" : "Download file"}
              onPress={() =>
                void saveTextFile(offer.file.name, offer.file.text).then((r) => {
                  if (r === "downloaded") toast.show(`Saved ${offer.file.name}`, { variant: "success" });
                  else if (r === "shared") toast.show("Recovery file shared", { variant: "success" });
                  else if (r === "unavailable") toast.error("Saving is not available here. Use Copy instead.");
                })
              }
            />
            <Button theme={theme} label="Copy code" onPress={() => void copyText(offer.code).then(() => toast.show("Recovery code copied", { variant: "success" }), () => toast.error("Copy failed"))} />
            <Button theme={theme} label="Copy file contents" onPress={() => void copyText(offer.file.text).then(() => toast.show("File contents copied", { variant: "success" }), () => toast.error("Copy failed"))} />
          </View>
          <Text style={styles.small}>File name: {offer.file.name}</Text>
          <View style={{ gap: 4 }}>
            <Text style={styles.small}>To close, type the last group of the code ({last.length} characters).</Text>
            <TextInput
              accessibilityLabel="Last group of the recovery code"
              value={check}
              onChangeText={setCheck}
              autoCapitalize="none"
              autoCorrect={false}
              placeholderTextColor={c.foregroundMuted}
              style={styles.input}
            />
          </View>
          {nudge && !ok ? <Text style={[styles.small, { color: c.statusWarning }]}>Save the code first, then type its last group. Closing without it loses the code.</Text> : null}
          <Button theme={theme} variant="primary" label="I saved it" disabled={!ok} onPress={tryClose} />
        </View>
      </Modal.Content>
    </Modal>
  );
}

/** Large SAS digits (enrollment 6.3, 6.4). */
export function SasDigits({ theme, sas }: { theme: PluginTheme; sas: string | null }) {
  return (
    <Text
      accessibilityLabel={sas ? `Code ${sas.split("").join(" ")}` : "Code not available yet"}
      selectable
      style={{ color: theme.colors.foreground, fontSize: 32, fontWeight: "700", letterSpacing: 4, fontFamily: Platform.select({ ios: "Menlo", default: "monospace" }) }}
    >
      {fmtSas(sas)}
    </Text>
  );
}

/** A destructive member-side action with a typed confirmation (no admin token: not an admin statement). */
export function TypedConfirm(props: {
  theme: PluginTheme;
  styles: Styles;
  label: string;
  title: string;
  word: string;
  children: ReactNode;
  onConfirm(): Promise<unknown>;
  variant?: "danger" | "secondary";
}) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ok = typed.trim().toLowerCase() === props.word.toLowerCase();
  const close = () => {
    if (busy) return;
    setOpen(false);
    setTyped("");
    setError(null);
  };
  return (
    <>
      <Button theme={props.theme} variant={props.variant ?? "danger"} label={props.label} onPress={() => setOpen(true)} />
      {open ? (
        <Modal title={props.title} open onOpenChange={(o) => (o ? undefined : close())}>
          <Modal.Content>
            <View style={{ gap: 10 }}>
              {props.children}
              <Text style={props.styles.small}>Type "{props.word}" to confirm.</Text>
              <TextInput
                accessibilityLabel={`Type ${props.word} to confirm`}
                value={typed}
                onChangeText={setTyped}
                autoCapitalize="none"
                autoCorrect={false}
                placeholderTextColor={props.theme.colors.foregroundMuted}
                style={props.styles.input}
              />
              {error ? <Text style={props.styles.danger}>{error}</Text> : null}
              <View style={props.styles.row}>
                <Button
                  theme={props.theme}
                  variant="danger"
                  label="Confirm"
                  busy={busy}
                  disabled={!ok}
                  onPress={() => {
                    setBusy(true);
                    void props
                      .onConfirm()
                      .then(() => {
                        setOpen(false);
                        setTyped("");
                        setError(null);
                      })
                      .catch((e) => setError(errorText(e)))
                      .finally(() => setBusy(false));
                  }}
                />
                <Button theme={props.theme} label="Cancel" disabled={busy} onPress={close} />
              </View>
            </View>
          </Modal.Content>
        </Modal>
      ) : null}
    </>
  );
}
