{
  description = "Rainfall development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        config.android_sdk.accept_license = true;
        config.allowUnfree = true;
      };
      android = pkgs.androidenv.composeAndroidPackages {
        platformVersions = [ "36" ];
        buildToolsVersions = [ "35.0.0" "36.0.0" ];
        includeEmulator = false;
        includeSystemImages = false;
        includeCmake = true;
        cmakeVersions = [ "3.22.1" ];
        includeNDK = true;
        ndkVersions = [ "27.1.12297006" ];
      };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.nodejs_22
          pkgs.jdk17
          android.androidsdk
        ];

        ANDROID_HOME = "${android.androidsdk}/libexec/android-sdk";
        ANDROID_SDK_ROOT = "${android.androidsdk}/libexec/android-sdk";
      };

      packages.${system} = rec {
        android-env = pkgs.buildFHSEnv {
          name = "rainfall-android-env";
          targetPkgs = p: [
            p.bash
            p.nodejs_22
            p.jdk17
            android.androidsdk
          ];
          profile = ''
            export ANDROID_HOME="${android.androidsdk}/libexec/android-sdk"
            export ANDROID_SDK_ROOT="$ANDROID_HOME"
            export JAVA_HOME="${pkgs.jdk17.home}"
          '';
          runScript = "bash";
        };

        default = android-env;
      };
    };
}
