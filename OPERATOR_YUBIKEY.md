# Operator YubiKey setup

Each mainnet operator holds one YubiKey. It signs manifest approvals (PIV slot `9c`) and decrypts that operator's quorum key share (slot `9d`). Two of the three operators must approve before a mainnet release goes live, so keep one key per person and never share one.

Do this once per person, before the session that creates the mainnet quorum key. It takes about 15 minutes and needs no Turnkey login. The steps follow `YUBIKEY.md` in the tvc 0.16.0 crate.

## 1. Check the key

```sh
brew install ykman
cargo install tvc --version 0.16.0 --locked
ykman info
```

You need all of:

- Device type `YubiKey 5...`. A `Security Key` model only does FIDO logins and has no PIV, so it cannot be used, and nothing turns PIV on.
- Firmware 5.3 or later.
- `PIV` enabled over USB. If it shows `Disabled`, run `ykman config usb --enable PIV`.

Then check that slots `9c` and `9d` are empty:

```sh
ykman piv info
```

If either slot already holds a key, stop and ask. Generating a key in that slot replaces it.

Optional: if touching the key types `cccc...` strings, that is Yubico OTP. Turn it off unless something you use relies on it, since tvc has you touch the key often:

```sh
ykman config usb --disable OTP
```

## 2. Set the PIN, PUK and management key

Save the new PIN and PUK in your private password manager vault before you type them. The PIN is 6 to 8 characters and case-sensitive. Three wrong PINs lock it until the PUK unblocks it; three wrong PUKs mean the key has to be reset.

| | Factory default |
|---|---|
| PIN | `123456` |
| PUK | `12345678` |

```sh
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

`change-management-key` first asks for the current management key, `Enter the current management key [blank to use default key]`. Leave it blank: a new YubiKey still has the factory key. It then asks for the PIN. `--generate` creates a random new key and `--protect` stores it on the device behind the PIN, so there is nothing to save for it.

Confirm all three changed:

```sh
ykman piv info
```

It must say `Management key is stored on the YubiKey, protected by PIN.` and show no `WARNING: Using default` lines. If any warning is left, repeat that step before generating keys.

## 3. Generate the keys

Run each command once. Running it again replaces that slot's private key.

```sh
ykman piv keys generate --algorithm eccp256 --pin-policy always --touch-policy always 9c - >/dev/null
ykman piv keys generate --algorithm eccp256 --pin-policy always --touch-policy always 9d - >/dev/null
```

The public key output is discarded on purpose; tvc reads it back from the device.

## 4. Create and import the certificates

Run this in a scratch folder outside any repository. It writes two public `.pem` files named with the serial in hex, which differs from the decimal serial `ykman info` shows.

```sh
mkdir -p ~/yubikey-<serial> && cd ~/yubikey-<serial>
tvc yubikey create-certs
ykman piv certificates import --verify 9c tvc-yubikey-<hex serial>-signing.pem
ykman piv certificates import --verify 9d tvc-yubikey-<hex serial>-key-agreement.pem
tvc keys refresh-yubikey
```

Each step asks for the PIN, and the key blinks when it needs a touch. The certificates are public; attach them to the password manager item for auditing, then delete the folder. They can be exported again with `ykman piv certificates export 9c -`.

## 5. Send your operator details

`tvc keys refresh-yubikey` prints the hex serial and the operator public key, 260 hex characters starting with `04`. Both are public. Send them to the person running the quorum key session, and keep a copy next to your PIN.

At the session each operator runs `tvc login` to the mainnet org and `tvc operator create --kind yubikey --serial <hex serial>`; in `tvc-configs/app.mint-attester.mainnet.json`, each operator's name and public key go in `manifestSetParams.newOperators` and the id from `operator create` goes in `shareSetParams.existingOperatorIds`. See [Creating an environment](README.md#creating-an-environment).
