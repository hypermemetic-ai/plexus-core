//! A process's syscalls, CPU and context switches, from /proc — no
//! privileges. `syscr`/`syscw` count read-like and write-like syscalls
//! (read, recv*, readv / write, send*, writev); epoll_wait and futex are not
//! in them, so the strace table (in a container) completes the picture.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Proc {
    pub syscr: u64,
    pub syscw: u64,
    pub rchar: u64,
    pub wchar: u64,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub vol_cs: u64,
    pub invol_cs: u64,
    pub threads: u64,
    /// on-CPU time of every live thread (schedstat), ns
    pub cpu_ns: u64,
}

impl std::ops::Sub for Proc {
    type Output = Proc;
    fn sub(self, o: Proc) -> Proc {
        Proc {
            syscr: self.syscr - o.syscr,
            syscw: self.syscw - o.syscw,
            rchar: self.rchar - o.rchar,
            wchar: self.wchar - o.wchar,
            utime_ticks: self.utime_ticks - o.utime_ticks,
            stime_ticks: self.stime_ticks - o.stime_ticks,
            vol_cs: self.vol_cs - o.vol_cs,
            invol_cs: self.invol_cs - o.invol_cs,
            threads: self.threads,
            cpu_ns: self.cpu_ns - o.cpu_ns,
        }
    }
}

fn field(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(key).map(|v| v.trim().split_whitespace().next().unwrap_or("0").parse().unwrap_or(0)))
        .unwrap_or(0)
}

/// The whole process: /proc/<pid>/io, stat, and every thread's status summed.
pub fn read(pid: u32) -> anyhow::Result<Proc> {
    let io = std::fs::read_to_string(format!("/proc/{pid}/io"))?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after = &stat[stat.rfind(')').unwrap() + 2..];
    let f: Vec<&str> = after.split_whitespace().collect();
    let (ut, st) = (f[11].parse()?, f[12].parse()?);
    let (mut vol, mut inv, mut threads, mut cpu_ns) = (0, 0, 0, 0u64);
    for t in std::fs::read_dir(format!("/proc/{pid}/task"))? {
        let t = t?;
        if let Ok(s) = std::fs::read_to_string(t.path().join("status")) {
            vol += field(&s, "voluntary_ctxt_switches:");
            inv += field(&s, "nonvoluntary_ctxt_switches:");
            threads += 1;
        }
        if let Ok(s) = std::fs::read_to_string(t.path().join("schedstat")) {
            cpu_ns += s.split_whitespace().next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        }
    }
    Ok(Proc {
        syscr: field(&io, "syscr:"),
        syscw: field(&io, "syscw:"),
        rchar: field(&io, "rchar:"),
        wchar: field(&io, "wchar:"),
        utime_ticks: ut,
        stime_ticks: st,
        vol_cs: vol,
        invol_cs: inv,
        threads,
        cpu_ns,
    })
}

pub fn ticks_per_s() -> u64 {
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 }
}
