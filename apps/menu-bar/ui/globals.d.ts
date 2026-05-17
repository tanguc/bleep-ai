// Tauri 2 injects window.__TAURI__ when withGlobalTauri = true (see tauri.conf.json).
// Typed loosely — we only use a small surface (invoke, listen).
interface TauriGlobal {
  core: { invoke: <T = unknown>(cmd: string, args?: Record<string, unknown>) => Promise<T> };
  event: {
    listen: <T = unknown>(
      event: string,
      handler: (e: { payload: T }) => void,
    ) => Promise<() => void>;
  };
}

interface Window {
  __TAURI__: TauriGlobal;
}
