extern crate capstone;
extern crate libc;

use core::{
    fmt::{Debug, Formatter},
    mem::size_of,
};
use std::{
    convert::TryInto,
    env,
    fs::File,
    io::{self, Read},
    str,
};

#[cfg(debug_assertions)]
use unicornafl::utils::add_debug_prints_ARM;
use unicornafl::{
    unicorn_const::{uc_error, Arch, Mode, Permission},
    utils::{init_emu_with_heap, uc_alloc, uc_free},
    RegisterARM, UnicornHandle,
};

#[allow(dead_code)]
#[repr(packed)]
struct MsgStructHdr {
    op1: u16,
    op2: u16,
    size: u16,
    msg_group: u16,
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
    }
}

/// A TOC header in the `modem.bin` file
#[derive(Clone, Copy)]
struct TocSectionHeader {
    name: [u8; 12],
    offset: u32,
    load_addr: u32,
    size: u32,
    unknown: u32,
    section_id: u32,
}

impl Debug for TocSectionHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("TocSectionHeader {{ section_id: {}, name: \"{}\", offset: {:#x}, load_addr: {:#x}, size: {:#x}, unknown: {:#x} }}",
        self.section_id, str_from_u8_unchecked(&self.name), self.offset, self.load_addr, self.size, self.unknown))?;
        Ok(())
    }
}

const INPUT_MAX: u32 = 512;
static mut INPUT_STRUCT: MsgStructHdr = MsgStructHdr {
    op1: 0xaa,
    op2: 0x20,
    size: 0,
    msg_group: 0x2a3c,
};

const BINARY: &str = "modem.bin";

/// the function we are trying to parse
const CC_PARSE_ADDR: u64 = 0x40e3811c;
/// Where to run to
const CC_END_ADDRS: [u64; 2] = [0x40e381ee, 0x405cc188];

const INPUT_ADDRESS: u64 = 0x100000;
/// Location where the input will be placed (make sure the uclated program knows this somehow, too ;) )
const INPUT_ADDRESS_PTR: u64 = 0x41801538;
/// Address of the stack (Some random address again)
const STACK_ADDRESS: u64 = 0x00400000;
/// Size of the stack (arbitrarily chosen, just make it big enough)
const STACK_SIZE: u64 = 0x000F0000;

fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    let mut f = File::open(filename)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// find null terminated string in vec
pub fn str_from_u8_unchecked(utf8_src: &[u8]) -> &str {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len());
    unsafe { str::from_utf8_unchecked(&utf8_src[0..nul_range_end]) }
}

fn align(size: u64) -> u64 {
    const ALIGNMENT: u64 = 0x1000;
    if size % ALIGNMENT == 0 {
        size
    } else {
        ((size / ALIGNMENT) + 1) * ALIGNMENT
    }
}

/// Set pc to lr to return
fn uc_reg_ret<D>(uc: &mut UnicornHandle<D>) {
    uc.reg_write(
        RegisterARM::PC as i32,
        uc.reg_read(RegisterARM::LR as i32).unwrap(),
    )
    .unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("Missing parameter <uclation_input> (@@ for AFL)");
        return;
    }
    let input_file = &args[1];
    println!("The input testcase is set to {}", input_file);
    fuzz(input_file).unwrap();
}

fn parse_tocs(file: &[u8]) -> Vec<TocSectionHeader> {
    let mut ret = vec![];
    let mut file_offset = 0;
    loop {
        let name: [u8; 12] = file[file_offset..file_offset + 12].try_into().unwrap();
        file_offset += size_of::<[u8; 12]>();

        if name == [0; 12] {
            break;
        }

        let offset = u32::from_le_bytes(file[file_offset..file_offset + 4].try_into().unwrap());
        file_offset += size_of::<u32>();
        let load_addr = u32::from_le_bytes(file[file_offset..file_offset + 4].try_into().unwrap());
        file_offset += size_of::<u32>();
        let size = u32::from_le_bytes(file[file_offset..file_offset + 4].try_into().unwrap());
        file_offset += size_of::<u32>();
        let unknown = u32::from_le_bytes(file[file_offset..file_offset + 4].try_into().unwrap());
        file_offset += size_of::<u32>();
        let section_id = u32::from_le_bytes(file[file_offset..file_offset + 4].try_into().unwrap());
        file_offset += size_of::<u32>();
        ret.push(TocSectionHeader {
            name,
            offset,
            load_addr,
            size,
            unknown,
            section_id,
        });
    }
    ret
}

fn fuzz(input_file: &str) -> Result<(), uc_error> {
    let mut unicorn = init_emu_with_heap(Arch::ARM, Mode::THUMB, 1048576 * 20, 0x90000000, false)?;
    let mut uc: UnicornHandle<'_, _> = unicorn.borrow();

    let binary =
        read_file(BINARY).unwrap_or_else(|_| panic!("Could not read modem image: {}", BINARY));
    //let _aligned_binary_size = align(binary.len() as u64);
    // Apply constraints to the mutated input
    /*if binary.len() as u64 > CODE_SIZE_MAX {
        println!("Binary code is too large (> {} bytes)", CODE_SIZE_MAX);
    }*/

    let tocs = parse_tocs(&binary);
    for toc in &tocs {
        let mapping_size = if &toc.name[..4] == b"MAIN" {
            // get some extra space for Data (we don't want to parse the MPU information)
            0x560_0000 - 0x10_0000
        } else {
            toc.size
        };

        uc.mem_map(
            toc.load_addr as u64,
            align(mapping_size as u64) as usize,
            Permission::ALL,
        )
        .unwrap();
        uc.mem_write(
            toc.load_addr as u64,
            &binary[toc.offset as usize..(toc.offset + toc.size) as usize],
        )
        .unwrap();
    }

    // Setup the stack.
    uc.mem_map(
        STACK_ADDRESS,
        STACK_SIZE as usize,
        Permission::READ | Permission::WRITE,
    )?;
    // Setup the stack pointer, but allocate two pointers for the pointers to input.
    uc.reg_write(RegisterARM::SP as i32, STACK_ADDRESS + STACK_SIZE - 16)?;
    uc.reg_write(
        RegisterARM::PC as i32,
        CC_PARSE_ADDR | 1, // thumb
    )?;

    // Setup our input space, and push the pointer to it in the function params
    uc.mem_map(
        INPUT_ADDRESS,
        align((INPUT_MAX as usize + size_of::<MsgStructHdr>()) as _) as _,
        Permission::READ | Permission::WRITE,
    )?;
    uc.mem_write(INPUT_ADDRESS_PTR, &(INPUT_ADDRESS as u32).to_le_bytes())?;

    // We have argc = 2
    //uc.reg_write(RDI as i32, 2)?;
    // RSI points to our little 2 QWORD space at the beginning of the stack...
    //uc.reg_write(RSI as i32, STACK_ADDRESS + STACK_SIZE - 16)?;
    // ... which points to the Input. Write the ptr to mem in little endian.
    uc.mem_write(
        STACK_ADDRESS + STACK_SIZE - 16,
        &(INPUT_ADDRESS as u32).to_le_bytes(),
    )?;

    let log_fn = Box::new(move |mut uc: UnicornHandle<'_, _>, _addr, _size| {
        if cfg!(debug_assertions) {
            // print the log messages

            let r0 = uc.reg_read(RegisterARM::R0 as i32).unwrap();
            let mut trace_entry_ptr: [u8; 4] = [0_u8; 4];
            uc.mem_read(r0, &mut trace_entry_ptr).unwrap();
            let log_string_ptr_ptr = u32::from_le_bytes(trace_entry_ptr) + 16;
            // another indirection.
            uc.mem_read(log_string_ptr_ptr as u64, &mut trace_entry_ptr)
                .unwrap();
            let mut log_string_ptr = u32::from_le_bytes(trace_entry_ptr);

            print!(
                "LOG[{:#x}] ptr: {:#x}: ",
                uc.reg_read(RegisterARM::LR as i32).unwrap(),
                log_string_ptr
            );
            loop {
                let mut char_buf = [0_u8; 1];
                uc.mem_read(log_string_ptr as u64, &mut char_buf).unwrap();
                if char_buf[0] == 0 {
                    break;
                }
                print!("{}", char_buf[0] as char);
                log_string_ptr += 1;
            }
            println!();
        }

        uc_reg_ret(&mut uc);
    });

    const LOG_PRINTF_ADDR: u64 = 0x405815fa;
    uc.add_code_hook(LOG_PRINTF_ADDR, LOG_PRINTF_ADDR, log_fn.clone())?;

    // another printf hook
    uc.add_code_hook(0x40581d90, 0x40581d90, log_fn)?;

    // memalloc
    uc.add_code_hook(
        0x40e8f0bc,
        0x40e8f0bc,
        Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
            #[cfg(debug_assertions)]
            println!("MALLOC");
            //let mut size_buf = [0_u8; 4];
            let size = uc.reg_read(RegisterARM::R1 as i32).unwrap();
            let ret = uc_alloc(&mut uc, size as _).unwrap();
            uc.reg_write(RegisterARM::R0 as i32, ret).unwrap();
            uc_reg_ret(&mut uc);
        }),
    )
    .unwrap();

    // pal_memfree
    uc.add_code_hook(
        0x40cbb29c,
        0x40cbb29c,
        Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
            #[cfg(debug_assertions)]
            println!("FREE");
            let ptr_ptr = uc.reg_read(RegisterARM::R0 as i32).unwrap();
            let mut addr_buf = [0_u8; 4];
            uc.mem_read(ptr_ptr as u64, &mut addr_buf).unwrap();
            let ptr = u32::from_le_bytes(addr_buf);
            uc_free(&mut uc, ptr as u64).unwrap();
            uc.mem_write(ptr_ptr as u64, &[0_u8; 4]).unwrap();
            uc_reg_ret(&mut uc);
        }),
    )
    .unwrap();

    // nv item lookup
    uc.add_code_hook(
        0x40c9217e,
        0x40c9217e,
        Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
            #[cfg(debug_assertions)]
            println!("NV Item Lookup");
            uc.reg_write(RegisterARM::R0 as i32, 0x0).unwrap();
            uc_reg_ret(&mut uc);
        }),
    )
    .unwrap();

    // pal Semaphore madness
    uc.add_code_hook(
        0x40586484,
        0x40586484,
        Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
            #[cfg(debug_assertions)]
            println!("pal Semaphore");
            uc_reg_ret(&mut uc);
        }),
    )
    .unwrap();

    // pal Semaphore release
    uc.add_code_hook(
        0x405864ba,
        0x405864ba,
        Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
            #[cfg(debug_assertions)]
            println!("pal release Semaphore");
            uc_reg_ret(&mut uc);
        }),
    )
    .unwrap();

    let memzero = Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
        #[cfg(debug_assertions)]
        println!("Memzero");
        let ptr = uc.reg_read(RegisterARM::R0 as i32).unwrap();
        let size = uc.reg_read(RegisterARM::R1 as i32).unwrap();
        let buf = vec![0_u8; size as usize];
        uc.mem_write(ptr as u64, &buf).unwrap();
        uc_reg_ret(&mut uc);
    });

    // memzero
    uc.add_code_hook(0x40e8f0cc, 0x40e8f0cc, memzero.clone())
        .unwrap();

    // memzero
    uc.add_code_hook(0x40e8f090, 0x40e8f090, memzero).unwrap();

    // memcpy
    uc.add_code_hook(
        0x40e8f09c,
        0x40e8f09c,
        Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
            #[cfg(debug_assertions)]
            println!("Memcpy");
            let dst = uc.reg_read(RegisterARM::R0 as i32).unwrap();
            let src = uc.reg_read(RegisterARM::R1 as i32).unwrap();
            let size = uc.reg_read(RegisterARM::R2 as i32).unwrap();
            let mut buf = vec![0_u8; size as usize];
            uc.mem_read(src as u64, &mut buf).unwrap();
            uc.mem_write(dst as u64, &buf).unwrap();
            uc_reg_ret(&mut uc);
        }),
    )
    .unwrap();

    // pal_msgSendTo
    // CC intialization sends a mesage to CC_SS_SAP that we cannot handle
    uc.add_code_hook(
        0x40fd365a,
        0x40fd365a,
        Box::new(|mut uc: UnicornHandle<'_, _>, _addr, _size: u32| {
            #[cfg(debug_assertions)]
            println!("pal_msgSendTo");
            uc.reg_write(RegisterARM::R0 as i32, 0xa).unwrap();
            uc_reg_ret(&mut uc);
        }),
    )
    .unwrap();

    let place_input_callback =
        |uc: &mut UnicornHandle<'_, _>, afl_input: &mut [u8], _persistent_round| {
            #[cfg(debug_assertions)]
            println!("doing things");
            // apply constraints to the mutated input
            if afl_input.len() > INPUT_MAX as usize {
                //println!("Skipping testcase with leng {}", afl_input.len());
                return false;
            }

            uc.reg_write(
                RegisterARM::PC as i32,
                CC_PARSE_ADDR | 1, // thumb
            )
            .unwrap();

            unsafe {
                INPUT_STRUCT.size = afl_input.len() as _;
                uc.mem_write(INPUT_ADDRESS, any_as_u8_slice(&INPUT_STRUCT))
                    .unwrap();
                uc.mem_write(
                    INPUT_ADDRESS as u64 + size_of::<MsgStructHdr>() as u64,
                    afl_input,
                )
                .unwrap();
            }
            true
        };

    // return `true` if the last run should be counted as crash
    let crash_validation_callback =
        |_uc: &mut UnicornHandle<'_, _>, result, _input: &[u8], _persistent_round| {
            if result == uc_error::OK {
                // not an error
                return false;
            }
            #[cfg(debug_assertions)]
            println!(
                "exiting at {:#x} (lr: {:#x}) with {:?}",
                _uc.reg_read(RegisterARM::PC as i32).unwrap(),
                _uc.reg_read(RegisterARM::LR as i32).unwrap(),
                result
            );
            #[cfg(debug_assertions)]
            println!(
                "Reg r0={:#x} r1={:#x}",
                _uc.reg_read(RegisterARM::R0 as i32).unwrap(),
                _uc.reg_read(RegisterARM::R1 as i32).unwrap()
            );
            true
        };

    //let end_addrs = parse_tocs(&"main_ends").unwrap();

    // writing an input to uc to set up state.
    let state_setup_input = MsgStructHdr {
        size: 1,
        op1: 0,
        op2: 0,
        msg_group: 0x2a01,
    };
    uc.mem_write(INPUT_ADDRESS, any_as_u8_slice(&state_setup_input))
        .unwrap();
    uc.mem_write(
        INPUT_ADDRESS as u64 + size_of::<MsgStructHdr>() as u64,
        &[0_u8; 1],
    )
    .unwrap();

    // Setting up state. We're sending a CC_INITIALIZED.
    uc.emu_start(
        CC_PARSE_ADDR | 1, // thumb
        CC_END_ADDRS[0],
        0,
        0,
    )
    .unwrap();

    println!("Doing fuzz");

    // Add debug after initalization.
    #[cfg(debug_assertions)]
    {
        add_debug_prints_ARM(&mut uc, 0x0, 0xFFFFFFFF);
        let regions = uc
            .mem_regions()
            .expect("failed to retrieve memory mappings");
        println!("Regions : {}", regions.len());

        for region in &regions {
            println!("{:#010x?}", region);
        }

        println!("heap: {:#010x?}", uc.get_data());
    }

    uc.mem_write(INPUT_ADDRESS_PTR, &(INPUT_ADDRESS as u32).to_le_bytes())?;

    let ret = uc.afl_fuzz(
        input_file,
        place_input_callback,
        &CC_END_ADDRS,
        crash_validation_callback,
        false,
        1,
    );

    match ret {
        Ok(_) => {}
        Err(e) => panic!("found non-ok unicorn exit: {:?}", e),
    }

    Ok(())
}

#[cfg(test)]
#[test]
fn test_parse_tocs() {
    let modem = read_file("modem.bin").unwrap();
    let tocs = parse_tocs(&modem);
    println!("{:?}", tocs);
    assert_ne!(tocs.len(), 0);
    assert!(tocs.iter().any(|x| &x.name[..4] == b"MAIN"));
}
