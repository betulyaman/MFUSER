namespace mfuser.Models;

/// <summary>
/// Per-path protection mode shown in the UI and persisted in
/// operations.json. The kernel only ever sees the resulting
/// (untrusted, trusted) bitmask pair; the mode is a UX-level grouping
/// of the three sensible bitmask combinations.
///
/// Lock-in-place — content editable, identity locked:
///   untrusted gets READ | WRITE | EXECUTE
///   trusted   gets READ | WRITE | EXECUTE | DELETE | RENAME | MOVE
///   Use case: Office documents. Untrusted callers (ransomware,
///   miscellaneous tools) can read/write but cannot rename or delete
///   the file. Trusted apps (Word, Excel) can complete atomic-save.
///
/// Read-only — content immutable, viewing allowed:
///   untrusted = trusted = READ | EXECUTE
///   Use case: archived records, immutable configs.
///
/// Private — agent-only:
///   untrusted = trusted = NONE
///   Use case: secrets, key material. Only the agent process itself
///   (which bypasses authorization) can touch the file.
/// </summary>
public enum ShieldMode
{
    LockInPlace = 0,
    ReadOnly = 1,
    Private = 2,
}
