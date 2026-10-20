//! The two numbers the kernel keeps that a handshake benchmark needs: how much
//! CPU a process has used, and how busy the machine is.
//!
//! Both are read from `/proc`, so they are as exact as the kernel's own
//! accounting rather than sampled from inside the program — the process under
//! measurement is a different process most of the time, and the whole point is
//! to see it from outside.

use std::time::Duration;

/// CPU time a process has used, from `/proc/<pid>/stat` fields 14 and 15
/// (`utime + stime`), converted to the host's `USER_HZ`.
///
/// The process's `comm` sits in parentheses and may contain spaces and
/// parentheses of its own, so everything before the *last* `)` is skipped:
/// that is the only unambiguous way to find the numbered fields.
pub fn process_cpu(pid: u32) -> Option<Duration> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = text.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    // After the comm field: state, ppid, pgrp, session, tty_nr, tpgid, flags,
    // minflt, cminflt, majflt, cmajflt, then utime and stime.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(ticks(utime + stime))
}

/// The same for the process doing the measuring.
pub fn self_cpu() -> Option<Duration> {
    process_cpu(std::process::id())
}

/// Ticks to wall-clock time, using the host's own clock tick.
fn ticks(count: u64) -> Duration {
    let hertz = clock_ticks_per_second();
    Duration::from_secs_f64(count as f64 / hertz)
}

fn clock_ticks_per_second() -> f64 {
    static HERTZ: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *HERTZ.get_or_init(|| {
        // SAFETY: `sysconf` has no invariants beyond a valid name; `_SC_CLK_TCK`
        // is one. A failure is reported as -1, which is not a tick rate.
        let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if value > 0 {
            value as f64
        } else {
            100.0
        }
    })
}

/// The machine's CPU jiffies from `/proc/stat`, as `(busy, total)`.
///
/// This is what the harness judges the *conditions* of a run by, rather than
/// the load average: it is measured over exactly the seconds a round took, so
/// a build that finished a minute ago does not make a clean run look busy, and
/// one that starts in the middle of a round does not hide.
pub fn machine_jiffies() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let mut fields = line.split_whitespace().skip(1);
    let mut next = || fields.next().and_then(|value| value.parse::<u64>().ok());
    let user = next()?;
    let nice = next()?;
    let system = next()?;
    let idle = next()?;
    let iowait = next()?;
    let irq = next()?;
    let softirq = next()?;
    // `steal` is absent on kernels that do not report it.
    let steal = next().unwrap_or(0);
    let busy = user + nice + system + irq + softirq + steal;
    Some((busy, busy + idle + iowait))
}

/// The machine's one-minute load average, which is how a run notices that
/// something else — a build, another agent — was competing for the CPU.
pub fn load_average() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/loadavg").ok()?;
    text.split_whitespace().next()?.parse().ok()
}

/// How many CPUs the machine has, for judging that load average.
pub fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

/// Resident set size of a process in bytes, from `/proc/<pid>/statm`, so the
/// report can say what each server costs to keep around. Reported for
/// context; it is not a claim about the handshake.
pub fn resident_bytes(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    // SAFETY: as above, a valid name with no preconditions.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    Some(pages * page_size.max(0) as u64)
}
