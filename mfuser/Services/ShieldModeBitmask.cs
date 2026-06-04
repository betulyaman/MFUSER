using mfuser.Models;

namespace mfuser.Services;

/// <summary>
/// Single source of truth for translating a UI-level <see cref="ShieldMode"/>
/// into the kernel-level (untrusted, trusted) bitmask pair. Three call sites
/// need this mapping — the realtime POLICY_SYNC, the CONNECTION_CONTEXT
/// bulk sync at port-open time, and the encrypted boot snapshot — so it
/// lives here to keep them in lockstep. Diverging mappings would be a
/// subtle correctness bug: a Read-only file could end up Lock-in-place after
/// a reboot if the snapshot disagreed with the realtime path.
/// </summary>
public static class ShieldModeBitmask
{
    public static (MessageContract.AccessPolicy untrusted,
                   MessageContract.AccessPolicy trusted) ToBitmasks(ShieldMode mode) =>
        mode switch
        {
            // Untrusted can read / write / execute. Trusted gets the
            // additional path-mutation rights (delete / rename / move) so
            // atomic-save in trusted apps (Word, Excel, signed installers)
            // works.
            ShieldMode.LockInPlace => (
                MessageContract.AccessPolicy.AllButDestructive,
                MessageContract.AccessPolicy.AllAccess),

            // Both halves equal -> kernel's optimization skips the
            // SeLocateProcessImageName + trusted-process ART lookup
            // entirely. Read + execute only; no writes from anyone.
            ShieldMode.ReadOnly => (
                MessageContract.AccessPolicy.Read | MessageContract.AccessPolicy.Execute,
                MessageContract.AccessPolicy.Read | MessageContract.AccessPolicy.Execute),

            // Both halves empty -> every operation denied for every
            // non-agent caller. The agent itself bypasses authorization
            // (verify_process_id_and_creation_time in preop) and remains
            // able to manage the file.
            ShieldMode.Private => (
                MessageContract.AccessPolicy.None,
                MessageContract.AccessPolicy.None),

            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown ShieldMode."),
        };
}
