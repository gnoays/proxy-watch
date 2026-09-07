# Contributing

## Running what CI runs

`.github/workflows/ci.yml` is the authority; these are the same gates in a cheaper local
order. `--no-fail-fast` earns its place: without it `cargo test` stops at the first target
that fails and the later ones never run at all.

```sh
cargo fmt --all -- --check
cargo test --all-features --no-fail-fast -- --test-threads=1
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy -p proxy-watch-repo-audit --all-targets -- -D warnings
cargo xtask audit-docs
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

`--test-threads=1` is not decoration. Several tests read and write process-wide state — the
environment, and on Windows the registry — so running them concurrently makes them observe
each other's writes.

`--all-features` never sees what breaks only with a feature *off*: with `resolve` off,
`mod resolve` disappears and every intra-doc link to it goes unresolved in a build that line
never makes. CI runs clippy, rustdoc and the suite once per row of `FEATURE_MATRIX` and
`TEST_FEATURE_MATRIX` at the top of the workflow. Reproduce a row, or type-check the Linux
backends from any host — clippy and rustdoc never link:

```sh
cargo clippy --no-default-features --features resolve,linux-kde --all-targets -- -D warnings
cargo clippy --target x86_64-unknown-linux-gnu --no-default-features --features linux-kde --all-targets -- -D warnings
```

macOS does not run from a non-Mac host. `cargo check --target aarch64-apple-darwin
--all-targets` reaches `src/sys/mac/` and `tests/mac_watch.rs` and catches a rename or a
signature drift — not an assertion that is simply false. `.github/workflows/mac-tests.yml`
is a `workflow_dispatch` that answers the rest on one runner.

## `#[ignore]` means "rewrites your real settings"

Here `#[ignore]` does not mean broken or pending. It marks the tests that rewrite the
development machine's own configuration — the Windows registry under `Internet Settings`.
Plain `cargo test` skips them, and CI passes `--include-ignored` because a GitHub-hosted
runner is discarded when the job ends. Pass it on your own machine only if you accept that
your proxy settings are the subject of the test. For something that should run neither by
default nor in the ordinary CI step, use an environment-variable gate instead —
`tests/mac_configd_denied.rs` is the shape to copy.

## The prose gates

`cargo xtask audit-docs` runs five checks over the tree's own comments and documentation,
one file each under `xtask/tests/`. They are stricter than a reviewer would be,
deliberately: each catches a class of mistake that is invisible to whoever makes it, because
it reads correctly to the person who has the missing context in their head. A fact restated
in two files must match its source; a comment that counts something is recounted against the
tree; no comment may describe the text it replaced, since a reader cannot act on a version
they have never seen; a comment naming an external project must land the reader on a
specific document; and an admission that a surface is unverified must also say what could
break and how a reader would notice. A failure names the file, the line and the rule, and
the repair is nearly always to reword the sentence.

## Reports worth more than a review

Some surfaces cannot be reached from CI at all: a proxy changed through the macOS GUI, a
network-location switch, an MDM `GlobalHTTPProxy` payload, the Flatpak and Snap portals.
The failure there is the silent one — no proxy reported while the host has one, and no
error — so what settles it is a pair taken on one machine at one moment: what the host is
set to, read back from the OS, and what the crate answered against it. There is a form that
asks for exactly that pair, under `.github/ISSUE_TEMPLATE/`.

## License

Contributions are licensed under `MIT OR Apache-2.0`, the same terms as the crate, and no
separate agreement is required.
