---
title: "A Cowrie honeypot in front of BRUTU$: what the internet did in 9 hours"
date: 2026-10-30
tags: [honeypot, cowrie, ssh, brute-force, threat-intel, mitre-attack]
---

# A Cowrie honeypot in front of BRUTU$: what the internet did in 9 hours

I run [BRUTU$](https://github.com/sp0ko/BRUTUS), a brute-force detector I wrote in Python. For a day I put a
[Cowrie](https://github.com/cowrie/cowrie) SSH honeypot on port 22 of a small VPS, moved the real `sshd` to
another port, and let BRUTU$ read both the real `auth.log` and Cowrie's `cowrie.json`.

This post covers the first night: who showed up, what they tried, what I learned, and one mistake of my own.

> **TL;DR**
> - **455 sessions from 81 IPs** in 9 hours (00:03-09:16 UTC), **380 "successful" logins**. Cowrie accepts almost anything, by design.
> - **0 breaches** on the real `sshd`. It is key-only and not on port 22.
> - One campaign dominates: **29 IPs ran the same "replace `~/.ssh`" one-liner** (the well-known `mdrfckr` key).
> - One slow scanner (`195.178.110.30`) tried **52 usernames** themed around **crypto validator infrastructure**, one session every 2-3 minutes.
> - **76 of 83 BRUTU$ alerts (about 92%)** matched a threat-intel list (Spamhaus DROP / FireHOL level 1).
> - I logged into my own honeypot by mistake. It recorded what I typed. More on that below.

## Setup

| Part | What |
|---|---|
| Host | small VPS, Ubuntu |
| Decoy | Cowrie in Docker, published on port 22 |
| Real SSH | key-only (`PasswordAuthentication no`), non-standard port |
| Detector | BRUTU$ as a systemd service with `--dashboard`, two sources: `auth.log` (`linux_ssh`) and `cowrie.json` (`cowrie`) |
| Enrichment | offline GeoIP + Spamhaus DROP / FireHOL lists |

BRUTU$ turns every Cowrie login into a `HONEYPOT` alert, never into a "breach", because Cowrie lets
bots in on purpose. The dashboard has a honeypot section: top passwords, commands, campaigns, MITRE ATT&CK techniques.

## What came in

All numbers come from `cowrie.json` for 2026-10-30 00:03-09:16 UTC, with my own sessions removed.

- **455 sessions**, **81 unique IPs**, **382 login events** (380 success, 2 failed).
- **81 distinct usernames** and **154 distinct passwords**.
- Only **35 IPs** ran a command. The other **46** logged in and left, so most traffic is automated scanning that goes no further.
- **1121 commands** in 192 sessions.

Sessions per hour (UTC): 00: 25 · 01: 68 · 02: 26 · 03: 38 · 04: 30 · 05: 34 · 06: 42 · 07: 49 · **08: 128** · 09: 15 (partial).

Top source countries by sessions (GeoIP): Andorra 89, Netherlands 52, Switzerland 48, United States 34, Sweden 26, UK 23, Hong Kong 23, France 19.
GeoIP only tells you where the *server* is. Most of these are hosting providers.

### Credentials

| Pair / password | Count | Notes |
|---|---|---|
| `345gs5662d34` / `345gs5662d34` | 50 | a botnet signature, repeated across IPs |
| `3245gs5662d34` as a password | 50 | the same string with a prefix |
| `0` / `0` | 51 | looks like a broken scanner |
| `root`, `ubuntu`, `admin`, `intel`, `cb` with simple passwords | many | classic dictionary |
| `firedancer`, `lighthouse`, `lhconsensus`, `solana`, `sol`, `solv`, `eth-docker`, `ethd` | dozens | **account names used by blockchain validator setups** |

The last row is the interesting one. These are not random usernames. Someone is hunting for servers that run
Solana and Ethereum validators. If you run such a node, a default-style username with a weak password is exactly what gets tried first.

## Campaign 1: the `mdrfckr` key (29 IPs, 52 runs)

The most common command, run from 29 different IPs, is:

```
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA... mdrfckr">>.ssh/authorized_keys ...
cd ~; chattr -ia .ssh; lockr -ia .ssh
```

- It wipes `~/.ssh` and writes the attacker's own public key, so they keep access. (`lockr` is not a real command; the script looks like a typo of `chattr +ia`.)
- The key comment `mdrfckr` is a long-running signature documented by many honeypot operators.
- Key fingerprint: `SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw`
- Cowrie recorded one file hash (`a8460f44...f8f2`) 52 times, matching the 52 runs. It is written by the shell command, not downloaded from a server.
- ATT&CK: **T1098.004** (SSH authorized keys), **T1070.004** (file deletion), **T1222.002** (permissions).

BRUTU$ grouped it in the *Campaigns* panel ("same command from many IPs"). Per-IP counting would have shown 29 small
events. Grouping by command shows one campaign.

> These commands ran in Cowrie's **fake** filesystem. The real `~/.ssh/authorized_keys` was untouched.
> I checked it from a rescue system afterwards (see the story below).

## Campaign 2: the `.16` dropper and `sudo` password guessing

Two IPs (`92.118.39.49`, `80.94.92.234`) upload a file named `.16` over `scp`, then run `chmod +x /root/.16`.
When that fails, they try `echo '<password>' | sudo -S ... chmod +x /root/.16` with **25 different passwords**
(`111111`, `123123`, `1234`, `12345`...), so they guess `sudo` passwords after getting in.

Cowrie captured the upload hashes (`a151d3f4...b125` uploaded 31 times, plus one more `.16` variant `52038cfc...`),
but I have **not** analysed the binaries yet.

- ATT&CK: **T1105** (ingress tool transfer), **T1110** (password guessing).

## The slow scanner: `195.178.110.30`

- 88 sessions and **52 usernames**.
- One session every 2-3 minutes, which stays under most rate-based detectors.
- Its only command is `uname -s -v -n -r -m` (87 times), a system fingerprint (**T1082**).
- Usernames follow the validator theme (`sol`, `solv`, `solana`, `eth-docker`, `ethd`, `postgres`), with passwords such as `Solana!123` and `Ubuntu@123`.

BRUTU$ has a low-and-slow detector (`slow_threshold` / `slow_window`). The IP is also in **Spamhaus DROP**.

## Proxy probing

196 `direct-tcpip` requests from 9 IPs (96 from one). Bots ask the server to open outbound connections to
`google.com:443`, Yahoo address ranges on port 80, and one host on port 2535. They test whether the SSH server
can be used as a **proxy**. Cowrie logs these requests.

## What the detector added

- **Threat intel:** 76 of 83 alerts matched Spamhaus DROP or FireHOL level 1. A list lookup is a cheap first filter.
- **Zero breaches:** the only successful "logins" were on the decoy, and BRUTU$ labels them differently from real ones.
- **Campaigns and ATT&CK tags** turn a pile of commands into a short list of things worth reading.

## What I learned

1. **A honeypot is cheap and the data is rich.** One container gave me over 1000 commands in a night.
2. **Move the real SSH and make it key-only.** Almost everything that hits port 22 is a bot.
3. **Usernames show intent.** The password list is boring. The username list tells you who is hunting what.
4. **Counting failures per minute misses patient attackers.** `195.178.110.30` would not trigger "10 failures in 60 s". A longer window does.
5. **A "success" on a honeypot is not a breach.** Treat it as intelligence, not an incident.
6. **Reputation lists are worth the few lines of code.**

## My own mistake: I logged into my own honeypot

The next morning I ran `ssh ubuntu@<server-ip>` instead of my usual alias (which has the right port).
That connected me to **Cowrie**, and the sequence looked like a compromise:

- a "host key changed" warning (Cowrie has its own host key),
- an unfamiliar hostname (Cowrie's default `svr04`),
- no `systemctl` or `journalctl` (it is a fake shell),
- an automatic logout after idle time,
- and a **password login that worked** on a server that is key-only. That was the part that made me suspicious.

I confirmed it from the provider's rescue mode: the disk was untouched, the real `authorized_keys` was unchanged,
and the real `sshd` had password logins disabled.

Lessons:

- **A honeypot records whatever you type, in plain text.** My password ended up in `cowrie.json`. Keep that file out of git and change any password you typed into it.
- **Use an SSH alias with the right port.**
- **Out-of-band access matters.** The provider's web console and rescue mode kept this from being a lockout.

## Ideas for BRUTU$

These are ideas, not promises:

- Label known campaigns (for example by the `mdrfckr` key fingerprint).
- Look up the SHA256 of captured files on a reputation service automatically.
- Export a ready-made incident summary like this one from the dashboard.

## Indicators

Everything here was seen on a honeypot. Treat it as a hint, not a verdict.

| Type | Value |
|---|---|
| SSH key fingerprint | `SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw` (`mdrfckr`) |
| File written by the `mdrfckr` command | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` |
| `.16` dropper | `a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125` |
| other uploads | `52038cfc082ec409184c9a6a13956416a79adbd0b14976c0c7fd461b1051941f`, `6d1fe6ab3cd04ca5d1ab790339ee2b6577553bc042af3b7587ece0c195267c9b` |
| IPs | `195.178.110.30`, `92.118.39.49`, `80.94.92.234`, `185.246.128.133`, `179.43.153.10`, `179.43.133.154` |
| Botnet credential | `345gs5662d34` |

## Reproduce it

1. Run Cowrie on port 22 and move your real SSH elsewhere (key-only).
2. Point BRUTU$ at `cowrie.json` (`type: cowrie`) and `auth.log`.
3. Start it with `--dashboard` and reach the dashboard through an SSH tunnel. It only listens on localhost.

The setup guide is in the BRUTU$ repository: [docs/DEPLOY.md](https://github.com/sp0ko/BRUTUS/blob/main/docs/DEPLOY.md).
