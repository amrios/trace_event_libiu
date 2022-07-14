//extern crate compiler_builtins;
use crate::map::IUMap;
use crate::linux::errno::*;
use crate::linux::bpf::*;
use crate::linux::bpf_perf_event::*;
use crate::stub;

#[macro_export]
macro_rules! bpf_trace_printk {
    ($s:expr) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32)
        }
    };

    ($s:expr,$($t:ty : $a:expr),*) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32, $($t),*) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32, $($a),*)
        }
    };
}

pub fn bpf_get_smp_processor_id() -> u32 {
    let f_ptr = stub::STUB_BPF_GET_SMP_PROCESSOR_ID as *const ();
    let helper: extern "C" fn() -> u32 =
        unsafe { core::mem::transmute(f_ptr) };

    helper()
}

// Changed
pub fn bpf_get_current_comm<T>(buf: &T, buf_size: usize) {
    let f_ptr = stub::STUB_BPF_GET_CURRENT_COMM as *const ();
    let helper: extern "C" fn(&T, u32) =
        unsafe { core::mem::transmute(f_ptr) };

    helper(
        buf,
        buf_size as u32,   // Maybe correct? https://doc.rust-lang.org/std/mem/fn.size_of.html
    )

}


pub fn bpf_get_stackid<T, K, V>(ctx: &T, map: &IUMap<K, V>, flags: u64) -> u64 {
    let f_ptr = stub::STUB_BPF_GET_STACKID as *const ();
    let helper: extern "C" fn(*const (), &IUMap<K, V>, u64) -> u64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(ctx as *const T as *const (),
        map, flags)
}

// ORIGINAL, BAD
/*
pub fn bpf_get_stackid<T, K, V>(ctx: &T, map: &IUMap<K, V>, flags: u64) -> u64 {
    let f_ptr = stub::STUB_BPF_MAP_UPDATE_ELEM as *const ();
    let helper: extern "C" fn(*const (), &IUMap<K, V>, u64) -> u64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(ctx as *const T as *const (),
        map, flags)
}
*/

pub fn bpf_perf_prog_read_value(ctx: &bpf_perf_event_data, buf: &bpf_perf_event_value, buf_size: usize) -> i64 {
    let f_ptr = stub::STUB_BPF_PERF_PROG_READ_VALUE as *const ();
    let helper: extern "C" fn(&bpf_perf_event_data, &bpf_perf_event_value, u32) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(
        ctx, buf,
        buf_size as u32,
    )
}

// ORIGINAL, BAD
/*
pub fn bpf_perf_prog_read_value(ctx: &bpf_perf_event_data, buf: &bpf_perf_event_value, buf_size: usize) -> i64 {
    let f_ptr = stub::STUB_BPF_GET_CURRENT_COMM as *const ();
    let helper: extern "C" fn(&bpf_perf_event_data, &bpf_perf_event_value, u32) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(
        ctx, buf,
        buf_size as u32,
    )
}
*/


pub fn bpf_map_lookup_elem<K, V>(map: &IUMap<K, V>, key: K) -> Option<V>
where
    V: Copy,
{
    let f_ptr = stub::STUB_BPF_MAP_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K) -> *mut V =
        unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}


pub fn bpf_map_update_elem<K, V>(map: &IUMap<K, V>, key: K, value: V, flags: u64) -> i64 {
    let f_ptr = stub::STUB_BPF_MAP_UPDATE_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K, *const V, u64) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(map, &key, &value, flags)
}
