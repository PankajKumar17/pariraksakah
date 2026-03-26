use blake3;
use std::fs;
use std::process::Command;
use std::collections::BTreeMap;

pub fn collect_hardware_fingerprint() -> String {
    let mut hasher = blake3::Hasher::new();
    
    hasher.update(get_cpu_fingerprint().as_bytes());
    hasher.update(get_memory_fingerprint().as_bytes());
    hasher.update(get_disk_fingerprint().as_bytes());
    hasher.update(get_network_fingerprint().as_bytes());
    hasher.update(get_container_fingerprint().as_bytes());
    hasher.update(get_kernel_fingerprint().as_bytes());
    hasher.update(get_tpm_simulation().as_bytes());
    
    let hash = hasher.finalize();
    hash.to_hex().to_string()
}

fn get_cpu_fingerprint() -> String {
    let mut cpudata = String::new();
    if let Ok(info) = fs::read_to_string("/proc/cpuinfo") {
        for line in info.lines() {
            if line.starts_with("model name") || line.starts_with("vendor_id") || line.starts_with("cpu family") {
                cpudata.push_str(line);
            }
        }
    }
    // Try to get CPUID-like output if lscpu is available
    if let Ok(lscpu) = Command::new("lscpu").output() {
        if let Ok(out) = String::from_utf8(lscpu.stdout) {
            cpudata.push_str(&out);
        }
    }
    blake3::hash(cpudata.as_bytes()).to_hex().to_string()
}

fn get_memory_fingerprint() -> String {
    let mut memdata = String::new();
    if let Ok(info) = fs::read_to_string("/proc/meminfo") {
        for line in info.lines() {
            if line.starts_with("MemTotal") {
                memdata.push_str(line);
            }
        }
    }
    blake3::hash(memdata.as_bytes()).to_hex().to_string()
}

fn get_disk_fingerprint() -> String {
    let mut diskdata = String::new();
    if let Ok(lsblk) = Command::new("lsblk").arg("-o").arg("UUID").output() {
        if let Ok(out) = String::from_utf8(lsblk.stdout) {
            diskdata.push_str(&out);
        }
    }
    blake3::hash(diskdata.as_bytes()).to_hex().to_string()
}

fn get_network_fingerprint() -> String {
    let mut netdata = String::new();
    if let Ok(ip) = Command::new("ip").arg("link").output() {
        if let Ok(out) = String::from_utf8(ip.stdout) {
            netdata.push_str(&out);
        }
    }
    blake3::hash(netdata.as_bytes()).to_hex().to_string()
}

fn get_container_fingerprint() -> String {
    let mut countdata = String::new();
    if let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") {
        countdata.push_str(&cgroup);
    }
    if let Ok(namespaces) = Command::new("ls").arg("-l").arg("/proc/self/ns").output() {
        if let Ok(out) = String::from_utf8(namespaces.stdout) {
            countdata.push_str(&out);
        }
    }
    blake3::hash(countdata.as_bytes()).to_hex().to_string()
}

fn get_kernel_fingerprint() -> String {
    let mut kdata = String::new();
    if let Ok(uname) = Command::new("uname").arg("-a").output() {
        if let Ok(out) = String::from_utf8(uname.stdout) {
            kdata.push_str(&out);
        }
    }
    if let Ok(modules) = fs::read_to_string("/proc/modules") {
        kdata.push_str(&modules);
    }
    blake3::hash(kdata.as_bytes()).to_hex().to_string()
}

fn get_tpm_simulation() -> String {
    // In dev, simulate TPM metrics. If swtpm were running we'd query its PCRs.
    // Here we generate a stable simulated signature of a TPM endorsement key based on host traits.
    let simulated_pcr0 = blake3::hash(b"simulate_tpm_pcr0").to_hex().to_string();
    simulated_pcr0
}
