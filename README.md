# Rainfall

*Clouds concentrate. Rainfall distributes.*

Rainfall is an open social network protocol where friendship means more than a
follow. Friends help one another recover their identities when devices are lost,
and their devices can hold encrypted pieces of one another's backups.

Instead of making a company the final authority over an account, Rainfall
distributes that responsibility among people the account owner already trusts.
The protocol is designed so that no single friend can read a backup or take over
an identity; recovery requires agreement from several friends.

Rainfall has one primary social relationship: **friend**, established through
an in-person NFC ceremony as a deliberate act with real consequences:

> **Add Bob as a friend?**
>
> Friends store an encrypted part of your backup and may be asked to confirm your
> identity if you lose your devices. Only add someone you know personally.

That shared responsibility gives the social graph meaning. It also provides the
foundation for portable identity, private communication, distributed backup,
and local resistance to bots and fabricated accounts.

Rainfall is currently at the research and protocol-design stage.

## Development

### Identity-chain client

The [local identity-chain client](apps/chain-client/README.md) implements signed
per-person histories, time-specific key-change claims, friendship attestations,
two-hop peer sync and explicit local branch selection. Run it with Node.js 22:

```sh
cd apps/chain-client
npm start
```

Open http://127.0.0.1:8787. `npm test` runs the protocol and relay tests;
`npm run demo` prepares a multi-client recovery scenario. The client is a local
reference implementation; consensus policy and protection against backdated
friendships remain open design questions.

### Android prototype

The first implementation target is an Android friendship-ceremony prototype.
The mobile application is shared with the future iOS client, while transports
and secure key storage are implemented behind platform-specific boundaries.

### Run the mobile app

The project uses Expo SDK 57 and Node.js 22. On NixOS:

```sh
nix develop
cd apps/mobile
npm install
npm run android
```

The Android development build includes a native BLE ceremony transport. Each
phone advertises and scans concurrently, then opens a direct GATT connection to
another Rainfall phone advertising the protocol service.

Build an ARM64 development APK on NixOS:

```sh
cd apps/mobile/android
nix run path:../../..#android-env -- \
  -c './gradlew assembleDebug -PreactNativeArchitectures=arm64-v8a --no-daemon'
```

The APK is written to `apps/mobile/android/app/build/outputs/apk/debug/app-debug.apk`.
Install it on both phones, start the Metro server from `apps/mobile`, open the
development project in each Rainfall app, and press **Add a friend in person**
on both devices. Android will ask for Nearby devices access on first use.

### First milestone

1. Discover another Rainfall device directly over BLE.
2. Establish an ephemeral encrypted session.
3. Present a deliberate, mutual friendship ceremony.
4. Persist mutually authenticated friendship records.

Identity recovery and backup shares follow only after this ceremony is proven
reliable across real Android devices.
