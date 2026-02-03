interface ImportMetaEnv {
  readonly VITE_CYBERSTRIKE_SERVER_HOST: string
  readonly VITE_CYBERSTRIKE_SERVER_PORT: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
