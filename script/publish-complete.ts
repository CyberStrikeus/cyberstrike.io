#!/usr/bin/env bun

// import { Script } from "@cyberstrike/script"
import { $ } from "bun"

// if (!Script.preview) {
// await $`gh release edit v${Script.version} --draft=false`
// }

await $`bun install`

await $`gh release download --pattern "cyberstrike-linux-*64.tar.gz" --pattern "cyberstrike-darwin-*64.zip" -D dist`

await import(`../packages/cyberstrike/script/publish-registries.ts`)
