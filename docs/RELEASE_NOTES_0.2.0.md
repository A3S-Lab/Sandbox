# a3s-sandbox 0.2.0

## Highlights

- **Gate 8 — credential containment (secrets never land).**
  `NativeSandbox::execute_with_secrets` accepts host-held secret environment
  entries and delivers only `a3s:secret:<NAME>` sentinels to the child; the
  host re-injects real bytes at the mediation point. Entries fail closed
  without `mediated_network`, on reserved names, on collisions with explicit
  env entries, or on malformed entries. The CONNECT/HTTP mediator now also
  mediates absolute-form plain HTTP under the existing `network.allow`
  authority, and typed `SecretHeaderInjection` rules inject
  `{header}: {value_prefix}<secret>` on matching origins, replacing any
  client-supplied instance so sentinels never leak upstream. `https://`
  absolute forms, chunked bodies, oversized bodies, and
  control-character-bearing secrets all fail closed (TLS interception stays
  a non-goal).
- **Gate 9 slice 1 — Linux mediated SOCKS5.** `Socks5Mediator::bind_unix`
  hosts SOCKS5 on a bind-mounted scratch socket; the in-guest relay wrapper
  starts one TCP→Unix relay per mediated protocol (HTTP 24731, SOCKS 24732).
  `mediated_socks` is now claimed on Linux with live netns wire proofs.
  Windows SOCKS and non-macOS unix-socket allowlists stay fail-closed.
- **Gate 10 slice 1 — typed policy grants.** `NetworkGrant` +
  `NativeSandbox::apply_network_grant`: the only sanctioned broadening path.
  Digest-pinned lineage (stale approvals refuse and are audited), minimal
  widening (a deny-all baseline gains `mediated_network` scoped to exactly
  the granted origin), idempotent regrants, and `GrantApplied` audit events.
  A macOS live test proves the full loop: denied command → grant → the same
  command flows.

## Notes

- Breaking: `ConnectMediator::bind*` constructors now take a
  `secrets: Option<Arc<HashMap<String, String>>>` parameter (pass `None` for
  the previous behavior). New capability claims follow `THREAT_MODEL.md`.
- Claim B (mediated-network-as-default) remains **refused** pending
  independent review; grants make scoped, user-approved activation possible
  without changing the default profile.

## Verify

```bash
cargo test --all-targets
GATE7_SOAK_ROUNDS=256 ./scripts/collect-release-evidence.sh
```
