# AUR packaging

Swamp packages for Arch users.

## What lives here

`kickoutchi-bin/` installs the Linux archive from the GitHub Release. It ships
the `kickoutchi` binary and the `kick` shortcut. The old source-built
`kickoutchi` AUR package is retired, so Arch users have one package to follow.

Kickoutchi never checks for releases on its own. Update it through the AUR
helper that installed it.

## Install from the AUR

```sh
yay -S kickoutchi-bin
kick --version
kick list
```

A normal full-system upgrade (`yay -Syu`) picks up new versions, or ask your AUR
helper to rebuild the package.

## Maintainer notes

Only update this package after the `cargo-dist` GitHub Release assets exist. A
version bump pushed before then gives Arch users a package that can't build.
Never use placeholder checksums or `SKIP`.

For each release:

1. Publish the release with `cargo-dist`.
2. Read the checksums from the published release assets.
3. Update `pkgver`, `source`, `provides`, and `sha256sums` in `PKGBUILD`.
4. Regenerate `.SRCINFO`:

   ```sh
   makepkg --printsrcinfo > .SRCINFO
   ```

5. Build and check locally:

   ```sh
   makepkg -C --clean --syncdeps --noconfirm -f
   PATH=/usr/bin:/bin namcap PKGBUILD *.pkg.tar.zst
   ```

If `namcap` complains about `gcc-libs`, ignore it. The release binaries link
`libgcc_s`, so the dependency stays.
