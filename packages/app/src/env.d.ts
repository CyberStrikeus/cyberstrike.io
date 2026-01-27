interface ImportMetaEnv {
  readonly VITE_WHYKIDO_SERVER_HOST: string
  readonly VITE_WHYKIDO_SERVER_PORT: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
