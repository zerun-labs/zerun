class Zerun < Formula
  desc "Daemonless, single-binary Linux container runtime"
  homepage "https://github.com/zerun-labs/zerun"
  url "https://github.com/zerun-labs/zerun/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "de27c5e973f5a285fde34525787cc49f68c9ba6969986711abbcf2e61c7f54fa"
  license "Apache-2.0"

  depends_on :linux
  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", *std_cargo_args
    bin.install_symlink "zerun" => "ze"
  end

  def caveats
    <<~EOS
      Zerun supports Linux only; macOS is not a container host target.
    EOS
  end

  test do
    system "#{bin}/zerun", "doctor"
  end
end
