# age-plugin-phone-platform-storage

Private Windows, macOS and other Unix filesystem operations. `windows::network`
and `macos::network` separately provide IPv4 interface enumeration.

`macos::Directory` provides bounded descriptor-relative operations with no-follow
path traversal, owner/mode/ACL/type/link checks, exclusive locks, and file/directory
`F_FULLFSYNC`. Existing insecure permissions are rejected, not repaired. Preparing
a root sets Time Machine exclusion through its descriptor. Business callers retain
ownership of names, record encoding, replay policy and pending-write markers.

Use an absolute path without symlink components and an owner-only private root.
Only the final root can be created; ancestors must already exist and pass checks.
The default desktop root is `~/Library/Application Support/age-plugin-phone`.
Backup exclusion and hardware-key binding do not prevent same-Mac state rollback.
The M2 record retains rollback, sudden-power-loss and expanded-platform acceptance
gates; successful local filesystem tests do not close those gates.

Experimental alpha software, unsuitable for real secrets. macOS has an initial Secure Enclave key backend; complete product support remains pending the macOS support plan. Other non-Windows desktop targets remain software prototypes.

See https://github.com/biulight/age-plugin-phone for architecture and installation.
