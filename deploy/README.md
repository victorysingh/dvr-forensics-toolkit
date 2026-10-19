# Hosting the console on a new server

The hosted console is one small Ubuntu machine on AWS, behind the Vercel
project that serves the public link. Accounts, approvals and the access log
live in Supabase, so moving to a new machine (or a new AWS account) changes
only the machine and its IP. Nobody has to sign up again.

```
visitor -> anookhidrishti.vercel.app -> https://<ip-with-dashes>.sslip.io (Caddy) -> 127.0.0.1:8150 (cli.py serve)
```

## What you need

* **The three secret files** from Shrestha: `supabase.env`, `mail.env` and
  `field.key`. Keep them in a folder **outside** the repo (no `.gitignore` rule
  covers them) and never paste them into chat, issues or commits.
  `field.key` must be this exact file: the email addresses in Supabase are
  encrypted with it, and any other key leaves them unreadable.
* **A shell with `git`, `ssh` and `tar`.** On Windows that is Git Bash, not
  PowerShell, because the upload pipes binary data.
* The repo, with `setup` pulled.

## 1. Launch the machine (AWS console)

Region **Asia Pacific (Mumbai) `ap-south-1`**, the same region as Supabase.
Each page makes about four database calls, each ~120 ms from India, so any
other region makes every page slower.

* **EC2 > Key pairs > Import key pair**: paste your SSH public key
  (`ssh-keygen -t ed25519 -f ~/.ssh/anokhidrishti-<you>` makes one).
* **EC2 > Launch instance**:
  * Name `anokhidrishti`, tag `Project=SIH26150`
  * Ubuntu Server 24.04 LTS, 64-bit (x86) for `t3.small`, or Arm for `t4g.small`
    (2 GiB of memory either way; 1 GiB is too little for the test suite)
  * Key pair: the one you imported
  * Security group: SSH 22 from **My IP** only; HTTP 80 and HTTPS 443 from
    anywhere (Caddy needs 80 to get its certificate)
  * Storage 20 GiB gp3, encrypted
  * Advanced > Metadata version: V2 only
* **EC2 > Elastic IPs > Allocate**, then **Associate** it with the instance.
  Without an Elastic IP the address changes at every stop and start, and
  Vercel loses the server.

About $15-20 a month (instance, public IPv4, disk).

## 2. Set it up (one command)

```bash
IP=13.200.1.2                                   # your Elastic IP
export ANOKHI_KEY=~/.ssh/anokhidrishti-<you>    # the private half of the key
bash deploy/new_server.sh ubuntu@$IP setup ~/anokhi-secrets
```

`deploy/new_server.sh` uploads the commit, puts the three files in
`/etc/anokhidrishti` (mode 600), runs `deploy/setup_server.sh`
`<ip-with-dashes>.sslip.io`, and turns on what the old server had:

* mail notices
* encrypted addresses
* real cases for the `demo` account only

It ends by printing the service's start-up lines. These three must be there:

```
mail notices: on, via smtp.gmail.com
email addresses: encrypted at rest (AES-256-GCM)
real cases: only demo and administrators; ...
```

Then `https://<ip-with-dashes>.sslip.io/` should open the sign-in page. sslip.io
is public DNS that answers `13-200-1-2.sslip.io` with `13.200.1.2`, so Caddy can
get a real certificate without a domain.

## 3. Point Vercel at it

`deploy/vercel/vercel.json` forwards the public link to the server's sslip.io
name. Change it to the new name, commit, and redeploy the Vercel project
`anokhi-drishti`. The project is in Shrestha's Vercel team, so the redeploy is
theirs unless you are a member.

```bash
sed -i "s/[0-9]*-[0-9]*-[0-9]*-[0-9]*\.sslip\.io/${IP//./-}.sslip.io/g" deploy/vercel/vercel.json
cd deploy/vercel && npx vercel link --project anokhi-drishti && npx vercel deploy --prod
```

Links in the mails use `PUBLIC_URL` from `mail.env` (the deck link, which
redirects to the Vercel project), so they need no change.

## 4. Later updates

```bash
bash deploy/update_server.sh ubuntu@$IP <commit>
```

It tests the new copy on the server first and swaps it in only on "0 failed".
If the service does not answer afterwards, it puts the old copy back.

## What does not move by itself

* **Real cases.** A new server has only the two generated cases (folders with
  a `SYNTHETIC` file). Until Shrestha copies the real ones into
  `/srv/anokhidrishti/out`, the `demo` account sees an empty list. The real
  cases hold real people's faces and a recorder's serial numbers. They go only
  to this server, behind the sign-in, and never to GitHub or any other host
  without the gate.
* **The access-log seal key** (`/var/lib/anokhidrishti/ledger_seal.key`) stays
  on the old machine's disk. The log itself is in Supabase and carries on.
  The new server seals it under a new key from its first entry. The old seal
  can be checked again only with the old disk.
* **SSH from a new address.** Port 22 is open to one IP. When yours changes,
  edit the security group's port-22 rule to My IP.

## When something is wrong

```bash
ssh -i $ANOKHI_KEY ubuntu@$IP 'sudo journalctl -u anokhidrishti -n 50 --no-pager'
ssh -i $ANOKHI_KEY ubuntu@$IP 'sudo journalctl -u caddy -n 50 --no-pager'
```

| Message | Fix |
|---|---|
| `... can be read by other users` | `sudo chmod 600` that file in `/etc/anokhidrishti` |
| `... exists but this user cannot read it` | `sudo chown anokhi:anokhi` that file |
| `... needs the optional 'cryptography' package` | `sudo apt-get install python3-cryptography` |
| Caddy cannot get a certificate | port 80 must be open to anywhere, and the name must match the Elastic IP |
