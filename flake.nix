{
  description = "Kickoutchi, a TUI and CLI port janitor";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      cargoPackage = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system:
          f system (import nixpkgs { inherit system; }));
    in
    {
      packages = forAllSystems (system: pkgs:
        let
          kickoutchi = pkgs.rustPlatform.buildRustPackage {
            pname = "kickoutchi";
            version = cargoPackage.package.version;

            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            cargoBuildFlags = [ "--all-features" ];
            cargoTestFlags = [ "--all-features" "--lib" ];

            # `kick` is the same program; a symlink avoids a second copy.
            postInstall = ''
              ln -sf kickoutchi "$out/bin/kick"
            '';

            meta = with pkgs.lib; {
              description = "A clean TUI and CLI port janitor";
              homepage = "https://kickoutchi.com";
              license = licenses.mit;
              mainProgram = "kickoutchi";
              platforms = systems;
            };
          };
        in
        {
          default = kickoutchi;
          kickoutchi = kickoutchi;
        });

      apps = forAllSystems (system: pkgs:
        let
          package = self.packages.${system}.kickoutchi;
        in
        {
          default = {
            type = "app";
            program = "${package}/bin/kickoutchi";
          };
          kickoutchi = {
            type = "app";
            program = "${package}/bin/kickoutchi";
          };
          kick = {
            type = "app";
            program = "${package}/bin/kick";
          };
        });

      devShells = forAllSystems (_system: pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.clippy
            pkgs.rustc
            pkgs.rustfmt
          ];
        };
      });
    };
}
