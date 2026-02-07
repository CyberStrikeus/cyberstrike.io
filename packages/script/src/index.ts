import { $, semver } from "bun"
import path from "path"

const rootPkgPath = path.resolve(import.meta.dir, "../../../package.json")
const rootPkg = await Bun.file(rootPkgPath).json()
const expectedBunVersion = rootPkg.packageManager?.split("@")[1]

if (!expectedBunVersion) {
  throw new Error("packageManager field not found in root package.json")
}

// relax version requirement
const expectedBunVersionRange = `^${expectedBunVersion}`

if (!semver.satisfies(process.versions.bun, expectedBunVersionRange)) {
  throw new Error(`This script requires bun@${expectedBunVersionRange}, but you are using bun@${process.versions.bun}`)
}

const env = {
  CYBERSTRIKE_CHANNEL: process.env["CYBERSTRIKE_CHANNEL"],
  CYBERSTRIKE_BUMP: process.env["CYBERSTRIKE_BUMP"],
  CYBERSTRIKE_VERSION: process.env["CYBERSTRIKE_VERSION"],
  GITHUB_REF: process.env["GITHUB_REF"],
}

// Extract version from tag name (e.g., "refs/tags/v1.2.0-beta.1" -> "1.2.0-beta.1")
function getVersionFromTag(ref: string): string | null {
  const tagMatch = ref.match(/^refs\/tags\/v?(.+)$/)
  if (!tagMatch) return null
  return tagMatch[1]
}

// Extract channel from tag name (e.g., "v1.2.0-beta.1" -> "beta", "v1.2.0" -> "latest")
function getChannelFromTag(ref: string): string | null {
  const tagMatch = ref.match(/^refs\/tags\/v?(\d+\.\d+\.\d+)(?:-([a-zA-Z]+))?/)
  if (!tagMatch) return null
  // If there's a prerelease identifier (e.g., "beta", "alpha"), use it as channel
  // Otherwise, it's a stable release, use "latest"
  return tagMatch[2] || "latest"
}

// Extract channel from version string (e.g., "1.2.0-beta.1" -> "beta", "1.2.0" -> "latest")
function getChannelFromVersion(version: string): string {
  const match = version.match(/^(\d+\.\d+\.\d+)(?:-([a-zA-Z]+))?/)
  if (match && match[2]) return match[2]
  return "latest"
}

const CHANNEL = await (async () => {
  if (env.CYBERSTRIKE_CHANNEL) return env.CYBERSTRIKE_CHANNEL
  if (env.CYBERSTRIKE_BUMP) return "latest"

  // If version is explicitly set, derive channel from it (e.g., "1.2.0-beta.1" -> "beta")
  if (env.CYBERSTRIKE_VERSION) {
    return getChannelFromVersion(env.CYBERSTRIKE_VERSION)
  }

  // Check if we're running from a tag push (GITHUB_REF = refs/tags/v1.2.0-beta.1)
  if (env.GITHUB_REF?.startsWith("refs/tags/")) {
    const channelFromTag = getChannelFromTag(env.GITHUB_REF)
    if (channelFromTag) return channelFromTag
  }

  const branch = await $`git branch --show-current`.text().then((x) => x.trim())
  // If no branch (detached HEAD on tag), try to get tag name
  if (!branch) {
    const tag = await $`git describe --tags --exact-match`.text().then((x) => x.trim()).catch(() => "")
    if (tag) {
      const match = tag.match(/^v?(\d+\.\d+\.\d+)(?:-([a-zA-Z]+))?/)
      if (match) return match[2] || "latest"
    }
    // Fallback to "latest" if we can't determine
    return "latest"
  }
  return branch
})()
const IS_PREVIEW = CHANNEL !== "latest"
const FROM_TAG = env.GITHUB_REF?.startsWith("refs/tags/") ?? false

const VERSION = await (async () => {
  if (env.CYBERSTRIKE_VERSION) return env.CYBERSTRIKE_VERSION

  // Check if we're running from a tag push (GITHUB_REF = refs/tags/v1.2.0-beta.1)
  if (env.GITHUB_REF?.startsWith("refs/tags/")) {
    const versionFromTag = getVersionFromTag(env.GITHUB_REF)
    if (versionFromTag) return versionFromTag
  }

  // For local builds (not CI), use package.json version as fallback
  if (!process.env.CI) {
    const pkgPath = path.resolve(import.meta.dir, "../../cyberstrike/package.json")
    const pkg = await Bun.file(pkgPath).json().catch(() => null)
    if (pkg?.version) return pkg.version
  }

  // If preview and in CI, generate timestamp-based version for preview channels
  if (IS_PREVIEW) return `0.0.0-${CHANNEL}-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "")}`

  const version = await fetch("https://registry.npmjs.org/cyberstrike/latest")
    .then((res) => {
      if (!res.ok) throw new Error(res.statusText)
      return res.json()
    })
    .then((data: any) => data.version)
  const [major, minor, patch] = version.split(".").map((x: string) => Number(x) || 0)
  const t = env.CYBERSTRIKE_BUMP?.toLowerCase()
  if (t === "major") return `${major + 1}.0.0`
  if (t === "minor") return `${major}.${minor + 1}.0`
  return `${major}.${minor}.${patch + 1}`
})()

export const Script = {
  get channel() {
    return CHANNEL
  },
  get version() {
    return VERSION
  },
  get preview() {
    return IS_PREVIEW
  },
  get fromTag() {
    return FROM_TAG
  },
}
console.log(`cyberstrike script`, JSON.stringify(Script, null, 2))
