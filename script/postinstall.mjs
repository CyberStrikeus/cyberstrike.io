#!/usr/bin/env node

import { execSync } from "child_process";
import { existsSync, mkdirSync, chmodSync, unlinkSync, statSync, readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const binDir = join(__dirname, "..", "bin");
const binPath = join(binDir, process.platform === "win32" ? "cyberstrike.exe" : "cyberstrike");

const VERSION = "1.0.0";
const REPO = "CyberStrikeus/cyberstrike.io";

function getPlatformInfo() {
  const platform = process.platform;
  const arch = process.arch;

  const platformMap = {
    darwin: "darwin",
    linux: "linux",
    win32: "windows",
  };

  const archMap = {
    x64: "x64",
    arm64: "arm64",
  };

  const os = platformMap[platform];
  const cpu = archMap[arch];

  if (!os || !cpu) {
    throw new Error(`Unsupported platform: ${platform}-${arch}`);
  }

  return { os, cpu, ext: platform === "win32" ? "zip" : "tar.gz" };
}

function isRealBinary(path) {
  try {
    // Read the file content and check size + content in one pass to avoid TOCTOU race
    const content = readFileSync(path);
    if (content.length < 10000) {
      return false;
    }
    const head = content.slice(0, 100).toString('utf8');
    if (head.includes('Run: npm run postinstall') || head.includes('#!/bin/sh')) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function main() {
  // Skip only if REAL binary exists (not placeholder)
  if (existsSync(binPath) && isRealBinary(binPath)) {
    console.log("cyberstrike binary already exists");
    return;
  }

  // Remove placeholder if exists
  if (existsSync(binPath)) {
    unlinkSync(binPath);
  }

  const { os, cpu, ext } = getPlatformInfo();
  const assetName = `cyberstrike-${os}-${cpu}.${ext}`;
  const downloadUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;

  console.log(`Downloading cyberstrike for ${os}-${cpu}...`);

  if (!existsSync(binDir)) {
    mkdirSync(binDir, { recursive: true });
  }

  const tempFile = join(binDir, assetName);

  try {
    // Use curl/wget for download
    if (process.platform === "win32") {
      execSync(`powershell -Command "Invoke-WebRequest -Uri '${downloadUrl}' -OutFile '${tempFile}'"`, { stdio: "inherit" });
      execSync(`powershell -Command "Expand-Archive -Path '${tempFile}' -DestinationPath '${binDir}' -Force"`, { stdio: "inherit" });
    } else {
      execSync(`curl -fsSL "${downloadUrl}" -o "${tempFile}"`, { stdio: "inherit" });
      execSync(`tar -xzf "${tempFile}" -C "${binDir}"`, { stdio: "inherit" });
    }

    unlinkSync(tempFile);

    if (process.platform !== "win32") {
      chmodSync(binPath, 0o755);
    }

    console.log("cyberstrike installed successfully!");
  } catch (error) {
    console.error("Failed to install cyberstrike:", error.message);
    console.log("\nYou can install manually:");
    console.log("  curl -fsSL https://cyberstrike.io/install.sh | bash");
    process.exit(0); // Don't fail npm install
  }
}

main();
