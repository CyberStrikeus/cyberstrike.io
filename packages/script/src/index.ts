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
  CYBERSTRIKE_VERSION: process.env["CYBERSTRIKE_VERSION"],
  GITHUB_REF: process.env["GITHUB_REF"],
}

// Extract version from tag name (e.g., "refs/tags/v2026.2.7" -> "2026.2.7")
function getVersionFromTag(ref: string): string | null {
  const tagMatch = ref.match(/^refs\/tags\/v?(.+)$/)
  if (!tagMatch) return null
  return tagMatch[1]
}

// CalVer format: YYYY.M.DD or YYYY.M.DD-N (same-day suffix)
// Preview channels: -beta, -rc, -alpha etc.
// Same-day releases: -2, -3 etc. (still "latest" channel)
function getChannelFromTag(ref: string): string | null {
  const tagMatch = ref.match(/^refs\/tags\/v?(\d{4}\.\d{1,2}\.\d{1,2})(?:-(\d+|[a-zA-Z]+[.\d]*))?/)
  if (!tagMatch) return null
  const suffix = tagMatch[2]
  if (!suffix) return "latest"
  // Numeric suffix (e.g., -2, -3) = same-day release, still "latest"
  if (/^\d+$/.test(suffix)) return "latest"
  // Alpha suffix (e.g., -beta, -rc.1) = preview channel
  return suffix.replace(/[.\d]+$/, "")
}

// Extract channel from version string (e.g., "2026.2.7-beta.1" -> "beta", "2026.2.7" -> "latest")
function getChannelFromVersion(version: string): string {
  const match = version.match(/^(\d{4}\.\d{1,2}\.\d{1,2})(?:-(\d+|[a-zA-Z]+[.\d]*))?/)
  if (match && match[2]) {
    const suffix = match[2]
    if (/^\d+$/.test(suffix)) return "latest"
    return suffix.replace(/[.\d]+$/, "")
  }
  return "latest"
}

const CHANNEL = await (async () => {
  if (env.CYBERSTRIKE_CHANNEL) return env.CYBERSTRIKE_CHANNEL

  // If version is explicitly set, derive channel from it
  if (env.CYBERSTRIKE_VERSION) {
    return getChannelFromVersion(env.CYBERSTRIKE_VERSION)
  }

  // Check if we're running from a tag push (GITHUB_REF = refs/tags/v2026.2.7)
  if (env.GITHUB_REF?.startsWith("refs/tags/")) {
    const channelFromTag = getChannelFromTag(env.GITHUB_REF)
    if (channelFromTag) return channelFromTag
  }

  const branch = await $`git branch --show-current`.text().then((x) => x.trim())
  // If no branch (detached HEAD on tag), try to get tag name
  if (!branch) {
    const tag = await $`git describe --tags --exact-match`.text().then((x) => x.trim()).catch(() => "")
    if (tag) {
      const match = tag.match(/^v?(\d{4}\.\d{1,2}\.\d{1,2})(?:-(\d+|[a-zA-Z]+[.\d]*))?/)
      if (match) {
        const suffix = match[2]
        if (!suffix || /^\d+$/.test(suffix)) return "latest"
        return suffix.replace(/[.\d]+$/, "")
      }
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

  // Check if we're running from a tag push (GITHUB_REF = refs/tags/v2026.2.7)
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

  // CalVer: use today's date as version, check npm for same-day releases
  const today = new Date()
  const calver = `${today.getFullYear()}.${today.getMonth() + 1}.${today.getDate()}`

  const versions: string[] = await fetch("https://registry.npmjs.org/cyberstrike")
    .then((res) => {
      if (!res.ok) throw new Error(res.statusText)
      return res.json()
    })
    .then((data: any) => Object.keys(data.versions || {}))
    .catch(() => [] as string[])

  // Find existing releases for today: exact match or with -N suffix
  const todayVersions = versions.filter(
    (v) => v === calver || v.startsWith(`${calver}-`)
  )

  if (todayVersions.length === 0) return calver

  // Find the highest suffix number
  let maxSuffix = 1
  for (const v of todayVersions) {
    if (v === calver) continue
    const suffixMatch = v.match(new RegExp(`^${calver.replace(/\./g, "\\.")}-(\\d+)$`))
    if (suffixMatch) {
      const n = Number(suffixMatch[1])
      if (n >= maxSuffix) maxSuffix = n + 1
    }
  }

  // If only the base version exists, next is -2
  if (todayVersions.length === 1 && todayVersions[0] === calver) return `${calver}-2`

  return `${calver}-${maxSuffix}`
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
