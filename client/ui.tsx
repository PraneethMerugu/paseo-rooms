// Small presentational building blocks. React Native primitives only; every color from theme.colors.
import type { PluginTheme } from "@getpaseo/plugin";
import { useMemo, useState, type ReactNode } from "react";
import { ActivityIndicator, Platform, Pressable, Text, View } from "react-native";

export function useStyles(theme: PluginTheme, compact: boolean) {
  return useMemo(() => {
    const c = theme.colors;
    return {
      screen: { flex: 1, backgroundColor: c.surface0 },
      content: { padding: compact ? 12 : 20, gap: compact ? 12 : 16, maxWidth: 880, width: "100%" as const, alignSelf: "center" as const },
      h1: { color: c.foreground, fontSize: compact ? 18 : 20, fontWeight: "600" as const },
      h2: { color: c.foreground, fontSize: 15, fontWeight: "600" as const },
      body: { color: c.foreground, fontSize: 14 },
      muted: { color: c.foregroundMuted, fontSize: 13 },
      small: { color: c.foregroundMuted, fontSize: 12 },
      mono: { color: c.foreground, fontSize: 12, fontFamily: Platform.select({ ios: "Menlo", default: "monospace" }) },
      danger: { color: c.statusDanger, fontSize: 13 },
      card: { backgroundColor: c.surface1, borderColor: c.border, borderWidth: 1, borderRadius: 10, padding: compact ? 10 : 14, gap: 10 },
      row: { flexDirection: "row" as const, alignItems: "center" as const, gap: 8, flexWrap: "wrap" as const },
      between: { flexDirection: "row" as const, alignItems: "center" as const, justifyContent: "space-between" as const, gap: 8 },
      divider: { height: 1, backgroundColor: c.border },
      input: {
        color: c.foreground,
        backgroundColor: c.surface0,
        borderColor: c.border,
        borderWidth: 1,
        borderRadius: 8,
        paddingHorizontal: 10,
        paddingVertical: 8,
        fontSize: 14,
      },
      codeBox: { backgroundColor: c.surface2, borderRadius: 8, padding: 10 },
    };
  }, [theme, compact]);
}

export type Styles = ReturnType<typeof useStyles>;

export function Button(props: {
  theme: PluginTheme;
  label: string;
  onPress(): void;
  variant?: "primary" | "secondary" | "danger";
  disabled?: boolean;
  busy?: boolean;
  accessibilityLabel?: string;
}) {
  const c = props.theme.colors;
  const variant = props.variant ?? "secondary";
  const bg = variant === "primary" ? c.accent : c.surface2;
  const fg = variant === "primary" ? c.accentForeground : variant === "danger" ? c.statusDanger : c.foreground;
  const inactive = props.disabled || props.busy;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={props.accessibilityLabel ?? props.label}
      accessibilityState={{ disabled: !!inactive, busy: !!props.busy }}
      disabled={inactive}
      onPress={props.onPress}
      style={({ pressed }) => ({
        backgroundColor: bg,
        borderRadius: 8,
        paddingHorizontal: 12,
        paddingVertical: 7,
        opacity: inactive ? 0.55 : pressed ? 0.8 : 1,
        flexDirection: "row",
        alignItems: "center",
        gap: 6,
      })}
    >
      {props.busy ? <ActivityIndicator size="small" color={fg} /> : null}
      <Text style={{ color: fg, fontSize: 13, fontWeight: "500" }}>{props.label}</Text>
    </Pressable>
  );
}

export function Segmented<V extends string>(props: {
  theme: PluginTheme;
  value: V;
  options: readonly { value: V; label: string; hint?: string }[];
  onChange(value: V): void;
}) {
  const c = props.theme.colors;
  return (
    <View accessibilityRole="radiogroup" style={{ flexDirection: "row", gap: 6, flexWrap: "wrap" }}>
      {props.options.map((o) => {
        const active = o.value === props.value;
        return (
          <Pressable
            key={o.value}
            accessibilityRole="radio"
            accessibilityState={{ selected: active }}
            accessibilityLabel={o.hint ? `${o.label}. ${o.hint}` : o.label}
            onPress={() => props.onChange(o.value)}
            style={{
              borderRadius: 8,
              borderWidth: 1,
              borderColor: active ? c.accent : c.border,
              backgroundColor: active ? c.surface2 : c.surface1,
              paddingHorizontal: 12,
              paddingVertical: 8,
              flexGrow: 1,
              flexBasis: 160,
              gap: 2,
            }}
          >
            <Text style={{ color: c.foreground, fontSize: 13, fontWeight: active ? "600" : "400" }}>{o.label}</Text>
            {o.hint ? <Text style={{ color: c.foregroundMuted, fontSize: 12 }}>{o.hint}</Text> : null}
          </Pressable>
        );
      })}
    </View>
  );
}

/**
 * Destructive action with an inline confirmation step: the first press shows what will happen and a
 * confirm/cancel pair; the confirm button is busy while the action runs, so it cannot fire twice.
 */
export function ConfirmButton(props: {
  theme: PluginTheme;
  label: string;
  confirmLabel: string;
  message: string;
  onConfirm(): Promise<unknown>;
  accessibilityLabel?: string;
  variant?: "secondary" | "danger";
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const c = props.theme.colors;
  if (!confirming)
    return (
      <Button
        theme={props.theme}
        variant={props.variant ?? "danger"}
        label={props.label}
        accessibilityLabel={props.accessibilityLabel}
        onPress={() => setConfirming(true)}
      />
    );
  return (
    <View style={{ gap: 6, flexShrink: 1 }} accessibilityLiveRegion="polite">
      <Text style={{ color: c.foreground, fontSize: 12 }}>{props.message}</Text>
      <View style={{ flexDirection: "row", gap: 8, flexWrap: "wrap" }}>
        <Button
          theme={props.theme}
          variant="danger"
          label={props.confirmLabel}
          busy={busy}
          accessibilityLabel={`Confirm: ${props.accessibilityLabel ?? props.label}`}
          onPress={() => {
            setBusy(true);
            void props.onConfirm().finally(() => {
              setBusy(false);
              setConfirming(false);
            });
          }}
        />
        <Button theme={props.theme} label="Cancel" disabled={busy} onPress={() => setConfirming(false)} />
      </View>
    </View>
  );
}

export function Dot({ color }: { color: string }) {
  return <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: color }} />;
}

export function Badge({ theme, label, tone }: { theme: PluginTheme; label: string; tone: "ok" | "warn" | "danger" | "muted" }) {
  const c = theme.colors;
  const color = tone === "ok" ? c.statusSuccess : tone === "warn" ? c.statusWarning : tone === "danger" ? c.statusDanger : c.foregroundMuted;
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: 5, paddingHorizontal: 8, paddingVertical: 2, borderRadius: 999, backgroundColor: c.surface2, flexShrink: 1, maxWidth: 220 }}>
      <Dot color={color} />
      <Text numberOfLines={1} style={{ color: c.foreground, fontSize: 12, flexShrink: 1 }}>
        {label}
      </Text>
    </View>
  );
}

export function Section({ styles, title, trailing, children }: { styles: Styles; title: string; trailing?: ReactNode; children: ReactNode }) {
  return (
    <View style={{ gap: 8 }}>
      <View style={styles.between}>
        <Text accessibilityRole="header" style={styles.h2}>
          {title}
        </Text>
        {trailing}
      </View>
      {children}
    </View>
  );
}

export function relativeTime(iso: string | null, now = Date.now()): string {
  if (!iso) return "never";
  const ms = Date.parse(iso) - now;
  const abs = Math.abs(ms);
  const unit = abs < 60_000 ? [Math.round(abs / 1000), "s"] : abs < 3_600_000 ? [Math.round(abs / 60_000), "min"] : abs < 172_800_000 ? [Math.round(abs / 3_600_000), "h"] : [Math.round(abs / 86_400_000), "d"];
  return ms >= 0 ? `in ${unit[0]} ${unit[1]}` : `${unit[0]} ${unit[1]} ago`;
}

/** Where to find the Command Center: a keyboard shortcut on desktop, the agent menu on phones. */
export function commandCenterHint(compact: boolean): string {
  return compact ? "open the Command Center from the agent's menu" : "press Ctrl+K or ⌘K";
}

export function errorText(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  return m.replace(/^Request failed:\s*/i, "").slice(0, 240);
}
