#!/usr/bin/env node

import fs from "fs"
import path from "path"
import os from "os"
import https from "https"
import { fileURLToPath } from "url"
import { createWriteStream } from "fs"
import { pipeline } from "stream/promises"
import { execSync } from "child_process"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PACKAGE_DIR = path.dirname(__dirname)

// Read version from package.json
const packageJson = JSON.parse(fs.readFileSync(path.join(PACKAGE_DIR, "package.json"), "utf8"))
const VERSION = packageJson.version

// GitHub release URL base
const GITHUB_RELEASE_BASE = "https://github.com/CyberStrikeus/cyberstrike/releases/download"

function detectPlatformAndArch() {
  let platform
  switch (os.platform()) {
    case "darwin":
      platform = "darwin"
      break
    case "linux":
      platform = "linux"
      break
    case "win32":
      platform = "windows"
      break
    default:
      throw new Error(`Unsupported platform: ${os.platform()}`)
  }

  let arch
  switch (os.arch()) {
    case "x64":
      arch = "x64"
      break
    case "arm64":
      arch = "arm64"
      break
    default:
      throw new Error(`Unsupported architecture: ${os.arch()}`)
  }

  return { platform, arch }
}

function getDownloadUrl(platform, arch) {
  const extension = platform === "darwin" ? "zip" : "tar.gz"
  const filename = `cyberstrike-${platform}-${arch}.${extension}`
  return `${GITHUB_RELEASE_BASE}/v${VERSION}/${filename}`
}

function getBinaryPath() {
  const binDir = path.join(PACKAGE_DIR, "bin")
  // Use different name to avoid conflict with wrapper script
  const binaryName = os.platform() === "win32" ? "cyberstrike-bin.exe" : "cyberstrike-bin"
  const archiveBinaryName = os.platform() === "win32" ? "cyberstrike.exe" : "cyberstrike"
  return { binDir, binaryPath: path.join(binDir, binaryName), binaryName, archiveBinaryName }
}

async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const follow = (url, redirectCount = 0) => {
      if (redirectCount > 5) {
        reject(new Error("Too many redirects"))
        return
      }

      https.get(url, (response) => {
        // Handle redirects
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          follow(response.headers.location, redirectCount + 1)
          return
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download: HTTP ${response.statusCode}`))
          return
        }

        const file = createWriteStream(destPath)
        response.pipe(file)
        file.on("finish", () => {
          file.close()
          resolve()
        })
        file.on("error", (err) => {
          fs.unlinkSync(destPath)
          reject(err)
        })
      }).on("error", reject)
    }

    follow(url)
  })
}

async function extractArchive(archivePath, destDir, platform) {
  // Ensure destination directory exists
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true })
  }

  if (platform === "darwin") {
    // Extract zip on macOS
    execSync(`unzip -o "${archivePath}" -d "${destDir}"`, { stdio: "inherit" })
  } else {
    // Extract tar.gz on Linux
    execSync(`tar -xzf "${archivePath}" -C "${destDir}"`, { stdio: "inherit" })
  }
}

async function main() {
  console.log(`\n🚀 Installing Cyberstrike v${VERSION}...\n`)

  try {
    const { platform, arch } = detectPlatformAndArch()
    const { binDir, binaryPath, binaryName, archiveBinaryName } = getBinaryPath()

    // Check if binary already exists and is correct version
    if (fs.existsSync(binaryPath)) {
      try {
        const versionOutput = execSync(`"${binaryPath}" --version`, { encoding: "utf8" })
        if (versionOutput.includes(VERSION)) {
          console.log(`✅ Cyberstrike v${VERSION} already installed`)
          return
        }
      } catch {
        // Version check failed, proceed with download
      }
    }

    const downloadUrl = getDownloadUrl(platform, arch)
    const extension = platform === "darwin" ? "zip" : "tar.gz"
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberstrike-"))
    const archivePath = path.join(tempDir, `cyberstrike.${extension}`)

    console.log(`📦 Platform: ${platform}-${arch}`)
    console.log(`📥 Downloading from GitHub Releases...`)

    await downloadFile(downloadUrl, archivePath)
    console.log(`📂 Extracting...`)

    // Ensure bin directory exists
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true })
    }

    // Extract to temp directory first
    const extractDir = path.join(tempDir, "extracted")
    await extractArchive(archivePath, extractDir, platform)

    // Find the binary in extracted files (archive contains 'cyberstrike', we save as 'cyberstrike-bin')
    const extractedBinary = path.join(extractDir, archiveBinaryName)
    if (!fs.existsSync(extractedBinary)) {
      // Try to find it in a subdirectory
      const files = fs.readdirSync(extractDir, { recursive: true })
      const binaryFile = files.find(f => f.endsWith(archiveBinaryName))
      if (binaryFile) {
        fs.copyFileSync(path.join(extractDir, binaryFile), binaryPath)
      } else {
        throw new Error(`Binary not found in archive`)
      }
    } else {
      fs.copyFileSync(extractedBinary, binaryPath)
    }

    // Make executable
    fs.chmodSync(binaryPath, 0o755)

    // Cleanup temp files
    fs.rmSync(tempDir, { recursive: true, force: true })

    console.log(`\n✅ Cyberstrike v${VERSION} installed successfully!`)
    console.log(`   Binary: ${binaryPath}\n`)

  } catch (error) {
    console.error(`\n❌ Installation failed: ${error.message}`)
    console.error(`\nAlternative installation methods:`)
    console.error(`  • Homebrew: brew install CyberStrikeus/tap/cyberstrike`)
    console.error(`  • curl: curl -fsSL https://cyberstrike.io/install.sh | bash`)
    console.error(`\nFor more info: https://docs.cyberstrike.io/docs/getting-started/installation\n`)
    process.exit(1)
  }
}

main()
