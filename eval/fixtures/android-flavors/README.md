# android-flavors (evaluation fixture)

A tiny, never-built Android app with `dev` and `prod` flavors, used to check that the deep dive
states *which builds* a finding affects. Everything here is
fake: the passphrase is invented and the app does nothing. Shape of the issue, modeled on a real
audit finding: a Keystore-wrapped database key exists, but it is only used when
`BuildConfig.ENCRYPT_DB` is true, which the `prod` flavor sets; `dev` builds (debug **and**
release) fall back to a hardcoded legacy passphrase, and the dev network config allows cleartext.
