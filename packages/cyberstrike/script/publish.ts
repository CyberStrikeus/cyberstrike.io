#!/usr/bin/env bun
import { $ } from "bun"
import pkg from "../package.json"
import { Script } from "@cyberstrike-io/script"
import { fileURLToPath } from "url"

const dir = fileURLToPath(new URL("..", import.meta.url))
process.chdir(dir)

const { binaries } = await import("./build.ts")

// Smoke test - run the binary for current platform
{
  const platformSuffix = `${process.platform}-${process.arch}`
  const dirName = `cli-${platformSuffix}`
  console.log(`smoke test: running dist/${dirName}/bin/cyberstrike --version`)
  await $`./dist/${dirName}/bin/cyberstrike --version`
}

// Create main metapackage @cyberstrike-io/cli
const mainPkgDir = "./dist/cli"
await $`mkdir -p ${mainPkgDir}`
await $`cp -r ./bin ${mainPkgDir}/bin`
await $`cp ./script/postinstall.mjs ${mainPkgDir}/postinstall.mjs`

await Bun.file(`${mainPkgDir}/package.json`).write(
  JSON.stringify(
    {
      name: "@cyberstrike-io/cli",
      bin: {
        cyberstrike: "./bin/cyberstrike",
      },
      scripts: {
        postinstall: "bun ./postinstall.mjs || node ./postinstall.mjs",
      },
      version: Script.version,
      optionalDependencies: binaries,
    },
    null,
    2,
  ),
)

const tags = [Script.channel]
const otp = process.env.NPM_OTP ? `--otp=${process.env.NPM_OTP}` : ""

// Publish platform-specific binaries
const tasks = Object.entries(binaries).map(async ([name, version]) => {
  // Extract directory name from package name (e.g., "@cyberstrike-io/cli-darwin-arm64" -> "cli-darwin-arm64")
  const dirName = name.replace("@cyberstrike-io/", "")
  if (process.platform !== "win32") {
    await $`chmod -R 755 .`.cwd(`./dist/${dirName}`)
  }
  await $`bun pm pack`.cwd(`./dist/${dirName}`)
  for (const tag of tags) {
    await $`npm publish *.tgz --access public --tag ${tag} ${otp}`.cwd(`./dist/${dirName}`)
  }
})
await Promise.all(tasks)

// Publish main metapackage
for (const tag of tags) {
  await $`cd ${mainPkgDir} && bun pm pack && npm publish *.tgz --access public --tag ${tag} ${otp}`
}

if (!Script.preview) {
  // Create archives for GitHub release
  for (const name of Object.keys(binaries)) {
    const dirName = name.replace("@cyberstrike-io/", "")
    const archiveName = dirName // cli-darwin-arm64, cli-linux-x64, etc.
    if (name.includes("linux")) {
      await $`tar -czf ../../${archiveName}.tar.gz *`.cwd(`dist/${dirName}/bin`)
    } else {
      await $`zip -r ../../${archiveName}.zip *`.cwd(`dist/${dirName}/bin`)
    }
  }

  const image = "ghcr.io/cyberstrike-io/cli"
  const platforms = "linux/amd64,linux/arm64"
  const tags = [`${image}:${Script.version}`, `${image}:latest`]
  const tagFlags = tags.flatMap((t) => ["-t", t])
  await $`docker buildx build --platform ${platforms} ${tagFlags} --push .`
}
