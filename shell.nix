let
  pkgs = import <nixpkgs> {};
  lib = pkgs.lib;
in
  pkgs.mkShell {
    packages = with pkgs; [
      hugo
      nodejs_22
    ];
    shellHook = ''
      ${lib.getExe pkgs.fish}
    '';
  }
