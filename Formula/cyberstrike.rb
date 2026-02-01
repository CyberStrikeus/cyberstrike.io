# Homebrew Formula for Cyberstrike
# https://cyberstrike.io
#
# To install:
#   brew tap CyberStrikeus/tap
#   brew install cyberstrike
#
# Or directly:
#   brew install CyberStrikeus/tap/cyberstrike

class Cyberstrike < Formula
  desc "AI-powered penetration testing and security assessment CLI"
  homepage "https://cyberstrike.io"
  license "AGPL-3.0"
  version "1.0.0"

  on_macos do
    on_arm do
      url "https://github.com/CyberStrikeus/cyberstrike.io/releases/download/v1.0.0/cyberstrike-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    end

    on_intel do
      url "https://github.com/CyberStrikeus/cyberstrike.io/releases/download/v1.0.0/cyberstrike-darwin-x64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_X64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/CyberStrikeus/cyberstrike.io/releases/download/v1.0.0/cyberstrike-linux-arm64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    end

    on_intel do
      url "https://github.com/CyberStrikeus/cyberstrike.io/releases/download/v1.0.0/cyberstrike-linux-x64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_X64"
    end
  end

  def install
    bin.install "cyberstrike"
  end

  def caveats
    <<~EOS
      To get started with Cyberstrike, you need to set up your API key:

        export ANTHROPIC_API_KEY=your_key_here

      Then run:

        cyberstrike

      For documentation, visit: https://docs.cyberstrike.io
    EOS
  end

  test do
    assert_match "cyberstrike", shell_output("#{bin}/cyberstrike --version")
  end
end
