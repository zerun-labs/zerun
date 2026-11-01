//! Parent-side cgroup v2 device policy.
//!
//! cgroup v2 has no writable `devices.*` control files. Like runc and Docker,
//! Zerun therefore loads a tiny `BPF_PROG_TYPE_CGROUP_DEVICE` allowlist and
//! attaches it to the container's lifecycle cgroup before the worker starts.
//! The program permits the minimal `/dev` set plus explicitly requested
//! devices with their requested `rwm` subset; everything else is denied.
use crate::error::ZResult;
use crate::mounts::{DeviceKind, DeviceMount, DEVICE_NODES};
use std::collections::BTreeMap;
use std::path::Path;

const ACCESS_MKNOD: u32 = 1;
const ACCESS_READ: u32 = 2;
const ACCESS_WRITE: u32 = 4;
const ACCESS_RWM: u32 = ACCESS_MKNOD | ACCESS_READ | ACCESS_WRITE;

const DEVICE_BLOCK: u32 = 1;
const DEVICE_CHAR: u32 = 2;

// eBPF instruction classes and fields from the stable Linux UAPI.
const BPF_LDX: u8 = 0x01;
const BPF_ALU64: u8 = 0x07;
const BPF_JMP: u8 = 0x05;
const BPF_W: u8 = 0x00;
const BPF_MEM: u8 = 0x60;
const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;
const BPF_MOV: u8 = 0xb0;
const BPF_AND: u8 = 0x50;
const BPF_RSH: u8 = 0x70;
const BPF_JEQ: u8 = 0x10;
const BPF_JNE: u8 = 0x50;
const BPF_EXIT: u8 = 0x95;

const REG_0: u8 = 0;
const REG_1: u8 = 1;
const REG_5: u8 = 5;
const REG_6: u8 = 6;
const REG_7: u8 = 7;
const REG_8: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceRule {
    kind: u32,
    major: u32,
    /// `None` permits every minor number for the major.
    minor: Option<u32>,
    access: u32,
}

/// Install the device allowlist on a newly-created container cgroup.
pub fn attach(cgroup: &Path, devices: &[DeviceMount]) -> ZResult<()> {
    let program = build_program(&policy(devices));
    crate::syscalls::attach_cgroup_device_program(cgroup, &program)
}

fn policy(devices: &[DeviceMount]) -> Vec<DeviceRule> {
    let mut rules = BTreeMap::new();
    for &(_, major, minor) in DEVICE_NODES {
        add_rule(&mut rules, DEVICE_CHAR, major, Some(minor), ACCESS_RWM);
    }
    // devpts allocates a dynamic minor for every terminal. The runtime never
    // creates these nodes, so mknod permission is not needed.
    add_rule(
        &mut rules,
        DEVICE_CHAR,
        136,
        None,
        ACCESS_READ | ACCESS_WRITE,
    );
    // /dev/ptmx is a symlink to /dev/pts/ptmx and may be recreated explicitly.
    add_rule(&mut rules, DEVICE_CHAR, 5, Some(2), ACCESS_RWM);

    for device in devices {
        let kind = match device.kind {
            DeviceKind::Char => DEVICE_CHAR,
            DeviceKind::Block => DEVICE_BLOCK,
        };
        let mut access = 0;
        if device.permissions.mknod {
            access |= ACCESS_MKNOD;
        }
        if device.permissions.read {
            access |= ACCESS_READ;
        }
        if device.permissions.write {
            access |= ACCESS_WRITE;
        }
        add_rule(&mut rules, kind, device.major, Some(device.minor), access);
    }

    rules
        .into_iter()
        .map(|((kind, major, minor), access)| DeviceRule {
            kind,
            major,
            minor,
            access,
        })
        .collect()
}

fn add_rule(
    rules: &mut BTreeMap<(u32, u32, Option<u32>), u32>,
    kind: u32,
    major: u32,
    minor: Option<u32>,
    access: u32,
) {
    *rules.entry((kind, major, minor)).or_default() |= access;
}

fn build_program(rules: &[DeviceRule]) -> Vec<u64> {
    let mut program = vec![
        bpf_insn(BPF_LDX | BPF_W | BPF_MEM, REG_6, REG_1, 0, 0),
        bpf_insn(BPF_LDX | BPF_W | BPF_MEM, REG_7, REG_1, 4, 0),
        bpf_insn(BPF_LDX | BPF_W | BPF_MEM, REG_8, REG_1, 8, 0),
    ];
    for rule in rules {
        let mut block = vec![
            bpf_insn(BPF_ALU64 | BPF_MOV | BPF_X, REG_5, REG_6, 0, 0),
            bpf_insn(BPF_ALU64 | BPF_AND | BPF_K, REG_5, 0, 0, 0xffff),
        ];
        let mut jumps = Vec::new();
        jumps.push(block.len());
        block.push(bpf_insn(
            BPF_JMP | BPF_JNE | BPF_K,
            REG_5,
            0,
            0,
            rule.kind as i32,
        ));
        block.push(bpf_insn(BPF_ALU64 | BPF_MOV | BPF_X, REG_5, REG_6, 0, 0));
        block.push(bpf_insn(BPF_ALU64 | BPF_RSH | BPF_K, REG_5, 0, 0, 16));
        block.push(bpf_insn(
            BPF_ALU64 | BPF_AND | BPF_K,
            REG_5,
            0,
            0,
            rule.access as i32,
        ));
        jumps.push(block.len());
        block.push(bpf_insn(BPF_JMP | BPF_JEQ | BPF_K, REG_5, 0, 0, 0));
        jumps.push(block.len());
        block.push(bpf_insn(
            BPF_JMP | BPF_JNE | BPF_K,
            REG_7,
            0,
            0,
            rule.major as i32,
        ));
        if let Some(minor) = rule.minor {
            jumps.push(block.len());
            block.push(bpf_insn(
                BPF_JMP | BPF_JNE | BPF_K,
                REG_8,
                0,
                0,
                minor as i32,
            ));
        }
        block.push(bpf_insn(BPF_ALU64 | BPF_MOV | BPF_K, REG_0, 0, 0, 1));
        block.push(bpf_insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));

        let next_rule = block.len();
        for index in jumps {
            set_jump_offset(&mut block[index], index, next_rule);
        }
        program.extend(block);
    }
    program.push(bpf_insn(BPF_ALU64 | BPF_MOV | BPF_K, REG_0, 0, 0, 0));
    program.push(bpf_insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    program
}

fn bpf_insn(code: u8, dst: u8, src: u8, offset: i16, immediate: i32) -> u64 {
    u64::from(code)
        | (u64::from(dst & 0xf) << 8)
        | (u64::from(src & 0xf) << 12)
        | (u64::from(offset as u16) << 16)
        | (u64::from(immediate as u32) << 32)
}

fn set_jump_offset(instruction: &mut u64, index: usize, target: usize) {
    let offset = target
        .checked_sub(index + 1)
        .expect("BPF jump target must follow its instruction");
    assert!(offset <= i16::MAX as usize, "BPF jump offset is too large");
    *instruction = (*instruction & !(0xffff_u64 << 16)) | (u64::from(offset as u16) << 16);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mounts::parse_device;

    #[test]
    fn policy_always_allows_the_minimal_devices_and_devpts() {
        let rules = policy(&[]);
        assert!(allows(
            &rules,
            DEVICE_CHAR,
            1,
            3,
            ACCESS_READ | ACCESS_WRITE
        ));
        assert!(allows(&rules, DEVICE_CHAR, 1, 3, ACCESS_MKNOD));
        assert!(allows(
            &rules,
            DEVICE_CHAR,
            136,
            42,
            ACCESS_READ | ACCESS_WRITE
        ));
        assert!(!allows(&rules, DEVICE_CHAR, 136, 42, ACCESS_MKNOD));
        assert!(!allows(&rules, DEVICE_BLOCK, 8, 0, ACCESS_READ));
    }

    #[test]
    fn explicit_devices_merge_permissions_without_widening_baseline_rules() {
        let devices = [
            parse_device("/dev/null:r").unwrap(),
            parse_device("/dev/kmsg:/dev/zerun-kmsg:r").unwrap(),
        ];
        let rules = policy(&devices);
        assert_eq!(
            access(&rules, DEVICE_CHAR, 1, 3),
            Some(ACCESS_RWM),
            "a subset request cannot narrow a built-in device"
        );
        assert_eq!(access(&rules, DEVICE_CHAR, 1, 11), Some(ACCESS_READ));
    }

    #[test]
    fn generated_jumps_stay_inside_the_program() {
        let devices = [
            parse_device("/dev/null:/dev/a:rwm").unwrap(),
            parse_device("/dev/zero:/dev/b:r").unwrap(),
        ];
        let program = build_program(&policy(&devices));
        for (index, instruction) in program.iter().enumerate() {
            let code = *instruction as u8;
            if code & 0x07 == BPF_JMP && code != BPF_JMP | BPF_EXIT {
                let offset = ((*instruction >> 16) & 0xffff) as u16 as i16 as isize;
                let target = index as isize + 1 + offset;
                assert!(target >= 0 && (target as usize) < program.len());
            }
        }
    }

    fn allows(rules: &[DeviceRule], kind: u32, major: u32, minor: u32, requested: u32) -> bool {
        access(rules, kind, major, minor).is_some_and(|allowed| allowed & requested != 0)
    }

    fn access(rules: &[DeviceRule], kind: u32, major: u32, minor: u32) -> Option<u32> {
        let mut matched = false;
        let mut access = 0;
        for rule in rules {
            if rule.kind == kind
                && rule.major == major
                && rule.minor.is_none_or(|candidate| candidate == minor)
            {
                matched = true;
                access |= rule.access;
            }
        }
        matched.then_some(access)
    }
}
