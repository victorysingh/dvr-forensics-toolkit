# Examiner signatures

The custody ledger is a hash chain, and its seal is an HMAC. Together they prove the
record was not rewritten, but only the machine holding the seal key can check that. An
examiner signature removes the need to trust that machine. The examiner signs a
statement about the case with a private key that stays in their keeping. Anyone with
the matching **public** key can check, offline and with no secret, that nothing it
covers has changed and that it was signed with that key.

## What is signed

A *case statement* (`acquire/signatures.py`) covers:

- the device: model, serial number, size, sector size and write-block method;
- the acquisition: every hash with its scope (MD5, SHA-256, the SHA-256 Merkle root);
- the custody ledger: its entry count and head hash. Every entry up to that point is
  pinned, because a hash chain cannot be edited behind a signed head;
- the SHA-256 of every output the case holds when it is signed: scan report, block map,
  parses, carve report and extraction manifest, timeline, analytics, preserved-metadata
  manifest, report, s.63 certificate, CASE/UCO export.

The scheme is **RSA-PSS with SHA-256** (MGF1-SHA256, maximum salt) over **3072-bit**
keys. RSA, because it is what Indian Class 3 signature tokens carry, so a deployment can
move the key onto the officer's own token later. PSS, because it is the provably secure
RSA signature padding. The cryptography comes from the `cryptography` package
(OpenSSL); none of it is written here.

Each statement is kept in `<case>/signatures/NNN_<key id>.json` and is itself an entry
(`case_signed`) in the custody ledger.

## Commands

```bash
cli.py keygen --name "Examiner name"   # once: ~/.ps26150/signing_key.pem (+ .pub.pem)
cli.py keygen --show                   # the public key and fingerprint, to publish
cli.py sign --out out/CASE --reason "handed to the court"
cli.py verify --out out/CASE --trust examiner.pub.pem
```

`scan` and `report` sign by themselves when the key opens without a passphrase. A
protected key reads `PS26150_SIGNING_PASSPHRASE`, or is used by hand with `cli.py sign`.

## What `verify` checks

- **Signature:** the statement is exactly what that key signed, and the key carried in
  it is the one the statement names.
- **Acquisition:** the hashes and Merkle root still match `scan_report.json`. This is
  checked for every statement.
- **Ledger:** the ledger still has the signed head at the signed position. This is
  checked for every statement.
- **Files:** each file the **newest** statement lists still has its signed hash. Older
  statements are not file-checked, because a report regenerated and re-signed is
  intended. An output made after the newest signing is named as "not yet signed",
  not failed.
- **Trust:** whether the key is one *you* trust: your own key, keys in
  `~/.ps26150/trusted/`, or a key passed with `--trust`.

A key carried inside a statement proves **integrity**, not **identity**: anyone can make
a key and sign. That is why `verify` says plainly whether the key is a trusted one, and
why the examiner should publish their fingerprint (`keygen --show`) somewhere a verifier
can find it independently.

## Optional by design

Without `cryptography`, every command runs as before. `verify` reports that signatures
are present but cannot be checked here, and `keygen`/`sign` say what to install. CI runs
the suite both ways.

## Sealed packages: handing evidence over

`cli.py seal` packs case files for **one recipient**, and `cli.py unseal` opens them
(`acquire/sealed.py`). It is hybrid encryption, the standard construction:

- **Contents:** the files go into a tar that is encrypted while it is written, with a
  fresh random **AES-256** key in **GCM** mode. No plaintext copy ever touches the disk,
  and GCM's tag makes any changed byte fail.
- **Recipient:** that key is encrypted to the recipient's **RSA** public key (OAEP,
  SHA-256). Only the matching private key opens it.
- **Header:** the recipient, the sender, and the file list with each file's SHA-256.
  The header is GCM's associated data, so editing it fails decryption too.
- **Sender:** the examiner signs the header, the ciphertext hash and the tag
  (RSA-PSS, as above). Anyone can check who sealed it with `unseal --info`, before
  opening anything and without any private key.
- **Custody:** the sealing is an `evidence_sealed` entry in the case's custody ledger,
  with the recipient's key fingerprint and the package's SHA-256.

```bash
cli.py keygen --name "District Court" --key court.pem      # the recipient, once
cli.py seal --out out/CASE --to court.pub.pem --note "for the trial court"
cli.py unseal out/CASE/sealed/<package>.adseal --info --trust examiner.pub.pem
cli.py unseal <package>.adseal --key court.pem --dest opened/ --trust examiner.pub.pem
```

By default a package carries the record a recipient needs to check the case: the
report, the scan report, the ledger, the signatures, the certificate, the parses, the
timeline and the carve manifests. Footage is added with `--include carve/<clip>`.

Opening is all-or-nothing, and leaves nothing behind if any of these fails, in order:

1. the sender's signature;
2. the recipient key;
3. AES-GCM authentication of the whole package;
4. the SHA-256 of every file.

It never opens into a folder that already holds files. Tar entries carry no user or
group names, and no path can climb out of the destination.
