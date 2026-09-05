# Guitar Girl Memorial Patcher

A fail-closed CLI and single-worker web patcher for user-supplied,
hash-verified Guitar Girl packages.

The project never publishes or embeds the original game. A user uploads their
own XAPK, the service verifies its SHA-256 against an explicit compatibility
allowlist, applies reproducible transforms, changes the application ID and app
label to **Guitar Girl Fan Memorial Build**, signs the result with a user or
deployment-specific key, and deletes transient source material.

An operator may privately provide a known source package to avoid repeated work,
but it may be selected only after the browser proves possession with a random
chunk challenge after matching the local SHA-256. The public
repository contains no source or generated game package.

The Rust workspace contains reusable `patcher-core`, a CLI, and a web service
whose heavy-work semaphore is fixed to one. Release deployments mount the
Patch repository at `patch/` as a pinned Git submodule. Web deployments require
a real, clean 40-hex Patch commit; zero-valued development sentinels are rejected.
Server binaries are release artifacts selected by ABI and SHA-256 and are never
compiled per user request.

No transformation runs until the outer XAPK and every required split match the
compatibility manifest. Implemented validation covers ZIP path and size limits,
IL2CPP build-id/prologues, metadata and master-bundle hashes, structured
master-data transforms, binary manifest assertions, package and authority
rewriting, ELF SONAME/dependencies, Server/Patch policy agreement, uniform
split certificates, bounded tool execution and workspace disk quotas.

Temporary workspaces are request-scoped. Signing material is accepted only by
path and environment variables and is never copied into cache or repository.
See `docs/DEPLOYMENT.md`.
