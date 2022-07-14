#![no_std]
#![no_main]

extern crate rlibc;

mod map;
use crate::map::*;

mod helpers;
mod linux;
mod stub;

//use crate::linux::bpf::bpf_perf_event_data; // maybe not?
use crate::helpers::*;
use crate::linux::bpf::*;
use crate::linux::bpf_perf_event::bpf_perf_event_data;
use core::panic::PanicInfo;
use core::mem::size_of_val;
use core::mem::size_of;


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct key_t {
    pub comm: [u8; 16], // 16 == TASK_COMM_LEN
    pub kernstack: u32,
    pub userstack: u32,
}

MAP_DEF!(counts, __counts, key_t, u64, BPF_MAP_TYPE_HASH, 10000, 0);
MAP_DEF!(stackmap, __stackmap, u32, [u64; 127], BPF_MAP_TYPE_STACK_TRACE, 10000, 0);

pub const KERN_STACKID_FLAGS: u64 = (0 | (1 << 9) | (1 << 8));
pub const USER_STACKID_FLAGS: u64 = (0 | (1 << 9) );

#[no_mangle]
#[link_section = "perf_event"]
pub extern "C" fn _start(ctx: &bpf_perf_event_data) -> i32 {
    let cpu = bpf_get_smp_processor_id();
    let value_buf: bpf_perf_event_value = bpf_perf_event_value { counter: 0,
                                                                enabled: 0,
                                                                running: 0,
                                                                };
    let mut key: key_t = key_t { comm: [0; 16],
                                kernstack: 0,
                                userstack: 0,
                                };
    let one: u64 = 1;

    if ctx.sample_period < 10000 {
        // check for warmup
        return 0;
    }

    bpf_get_current_comm(&key.comm, size_of_val(&key.comm)); // check
    key.kernstack = bpf_get_stackid(ctx, stackmap, KERN_STACKID_FLAGS) as u32;
    key.userstack = bpf_get_stackid(ctx, stackmap, USER_STACKID_FLAGS) as u32;

    if (key.kernstack as i32) < 0 && (key.userstack as i32) < 0 {
        bpf_trace_printk!("CPU-%d period %lld ip %llx",
            u64: (ctx.sample_period as u64),
            u64: (ctx.regs.rip as u64));
        return 0;
    }

    let ret:i32 = bpf_perf_prog_read_value(ctx, &value_buf, size_of::<bpf_perf_event_value>()) as i32; // added
    if ret == 0 {   // Returns 0 on success
        bpf_trace_printk!("Time Enabled: %llu, Time Running: %llu",
            u64: (value_buf.enabled as u64),
            u64: (value_buf.running as u64));
    }
    else {
        bpf_trace_printk!("Get Time Failed, ErrCode: %d", i32: ret);
    }

    if (ctx.addr != 0) {
        bpf_trace_printk!("Address recorded on event: %llx",
            u64: (ctx.addr as u64));
    }

    match bpf_map_lookup_elem::<key_t, u64>(counts, key) {
        Some(val) => {
            bpf_map_update_elem(counts, key, (val + 1), BPF_ANY.into());
        }
        None => {
            bpf_map_update_elem(counts, key, one, BPF_NOEXIST.into());
        }
    }

    return 0;
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
