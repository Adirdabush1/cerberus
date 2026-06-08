/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AG_WS?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
