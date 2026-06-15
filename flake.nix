{
  description = "ip-watch — keep cloud-provider IP ranges applied to your webserver/firewall";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # Bump on each release (also stamped into the binary via ldflags).
        version = "0.0.4";
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "ip-watch";
          inherit version;
          src = self;
          # Zero external dependencies (stdlib only) → nothing to vendor.
          vendorHash = null;
          subPackages = [ "cmd/ip-watch" ];
          ldflags = [
            "-s"
            "-w"
            "-X"
            "main.version=${version}"
          ];
          meta = with pkgs.lib; {
            description = "Keep cloud-provider IP ranges applied to your webserver/firewall";
            homepage = "https://github.com/rezmoss/ip-watch";
            license = licenses.mit;
            mainProgram = "ip-watch";
            # Manages Linux webservers, firewalls and systemd — Linux only.
            platforms = platforms.linux;
          };
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };
      }
    );
}
