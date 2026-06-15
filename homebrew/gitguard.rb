class Gitguard < Formula
  desc "AI-powered git security scanner that detects secrets, vulnerabilities, and fixes your code"
  homepage "https://github.com/gitguard/gitguard"
  url "https://github.com/gitguard/gitguard/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  depends_on "python@3.12"

  def install
    virtual_install_with_resources
  end

  test do
    assert_match "GitGuard", shell_output("#{bin}/gitguard --version")
    assert_match "scan", shell_output("#{bin}/gitguard --help")
  end
end
