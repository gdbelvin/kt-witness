# witness-network.org

[witness-network.org](https://witness-network.org/) is a coordination point
for public transparency-log witnesses. It publishes lists of logs, each with an
origin, a verifier key and a push rate, and it lists witnesses that have agreed
to cosign them. A log operator picks witnesses from it; a witness follows one or
more lists and accepts `POST /add-checkpoint` from every log on them. There is
no protocol beyond C2SP `tlog-witness` itself: joining is a matter of following
a list and publishing an about page.

## What this witness does with a list

`internal/loglist` fetches each configured `logs/v0` list and re-reads it on the
configured interval, which is capped at seven days. Every
log it names is added to the set allowed to push (`internal/push`), with the
list's stated requests-per-day as its budget.

It only ever adds. A list that later changes a log's key, or drops a log, does
not update or remove anything already configured; and a log configured
statically in `witness.json` always takes precedence over the same origin on a
list. A list is an input this operator does not control, and a list that could
rewrite a key would let whoever edits it redirect our signature. Removing a log
is an operator decision, made in the config.

## The caveat

A listed log comes with no monitoring URL, so it is witnessed by **push only**.
For those logs this witness sees only what the operator chooses to send it,
which is the dependence [design.md](design.md#polling-and-re-signing) argues a
witness should avoid. Every pushed checkpoint still goes through the same
`witness.Process` gates as a polled one — a fork, a rollback or a stale head is
refused whichever way it arrives — but a head never pushed is a head never
seen. The logs this witness polls on its own it also accepts pushes for, and
there push only adds timeliness. `/about` states this.

## Which lists, and why staging

Start with the smaller staging list only:

- `https://staging.witness-network.org/log-list-10qps-4klogs.1`

and add the larger one once the signer is measured:

- `https://staging.witness-network.org/log-list-100qps-40klogs.1`

Staging first, because nothing yet depends on this witness and staging is the
place to find out whether the push path keeps up before anything does. The list
names state their load envelope (10 qps / 4k logs and 100 qps / 40k logs).

**Every accepted push is an HSM signature**, re-pushes included. The poller
signs about 82 times an hour; the 100 qps list's CT logs alone push at about
one per second each, around 13 signs a second today and a stated envelope of
100. Nobody has measured how many `sign-eddsa` operations a second the YubiHSM
sustains, and HSM operations serialise: if pushes saturate it, polled logs
start missing `max_sign_delay` and are withheld for reasons of our own. Time a
loop of signs on the device before joining the larger list. Registering for a
load we cannot carry is the overpromise a witness must not make.

A testing list under `lists/testing/` is optional and can be added alongside
for integration work.

Production lists come later, once `/about` has been live for a while and the
push path has run under the staging load without withholding for reasons of
our own.

## Config

```json
"witness_network": {
  "lists": [
    "https://staging.witness-network.org/log-list-10qps-4klogs.1"
  ],
  "refresh": "24h",
  "public_url": "https://witness.gdbsecurity.com",
  "operator": "GDB Security",
  "contact": "gdb@gdbsecurity.com"
}
```

`public_url` is what `/about` builds the add-checkpoint URL from. Left empty,
the page derives it from the request (`X-Forwarded-Proto`, then `Host`), which
is right behind the Cloudflare Tunnel but is better stated than inferred.

## Registration email — DRAFT, NOT SENT

> **Draft pending deployment.** Send only once `/about` is live at the URL
> below, shows the lists above, and `POST /add-checkpoint` answers.

```
To: participate@lists.witness-network.org
Subject: Witness registration: witness.gdbsecurity.com

Hello,

I would like to register a witness with witness-network.org.

Operator:     GDB Security (Gary Belvin)
Contact:      gdb@gdbsecurity.com
About page:   https://witness.gdbsecurity.com/about

The about page gives the witness's cosignature/v1 verifier key, its
add-checkpoint URL, and the lists it follows.

Lists followed (staging):
  https://staging.witness-network.org/log-list-10qps-4klogs.1

I plan to add the 100qps staging list once I have measured the signer's
sustained rate; the witness signs with a YubiHSM.

The witness downloads and applies these lists automatically every 24 hours.
It never removes or updates a log that is already configured; a change to an
existing entry is left for the operator to apply by hand.

The software is kt-witness, which also witnesses several key transparency
logs by polling. Logs discovered from the lists are witnessed by push.

Thanks,
Gary Belvin
GDB Security
```
