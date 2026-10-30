// Offer a small text file to the person on every client (identity-model 7.3 "Clients hold no room
// keys": show the secret, offer it as a download or share-sheet file, never assume a desktop file
// dialog). No Node APIs and no DOM types: the web path probes globals at run time.
//
// - web and desktop (react-native-web): a Blob download through a temporary link;
// - iOS and Android: the system share sheet with the file's text (the person can save it to Files,
//   a password manager, or print it); the same parser reads the code from that text;
// - anything else, or a failure: "unavailable", and the caller keeps "Copy" as the fallback.
import { Platform, Share } from "react-native";

export type SaveResult = "downloaded" | "shared" | "dismissed" | "unavailable";

type WebGlobals = {
  document?: {
    createElement(tag: "a"): { href: string; download: string; rel: string; click(): void; remove(): void; style: { display: string } };
    body?: { appendChild(n: unknown): void };
  };
  Blob?: new (parts: string[], options: { type: string }) => unknown;
  URL?: { createObjectURL(b: unknown): string; revokeObjectURL(u: string): void };
};

export async function saveTextFile(name: string, text: string, mime = "application/json"): Promise<SaveResult> {
  if (Platform.OS === "web") {
    const g = globalThis as unknown as WebGlobals;
    if (g.document?.body && g.Blob && g.URL?.createObjectURL) {
      try {
        const url = g.URL.createObjectURL(new g.Blob([text], { type: mime }));
        const a = g.document.createElement("a");
        a.href = url;
        a.download = name;
        a.rel = "noopener";
        a.style.display = "none";
        g.document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => g.URL?.revokeObjectURL(url), 5000);
        return "downloaded";
      } catch {
        // fall through to the share sheet
      }
    }
  }
  try {
    const r = await Share.share({ title: name, message: text });
    return r.action === Share.dismissedAction ? "dismissed" : "shared";
  } catch {
    return "unavailable";
  }
}
