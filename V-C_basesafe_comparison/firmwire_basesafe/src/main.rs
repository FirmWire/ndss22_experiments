extern crate capstone;
extern crate libc;

use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{self, BufRead, Read},
    path::Path,
    str,
};
#[cfg(debug_assertions)]
use unicornafl::utils::add_debug_prints_ARM;
use unicornafl::{
    unicorn_const::{uc_error, Arch, Mode, Permission},
    RegisterARM, UnicornHandle,
};

// the size of the afl_fuzz buffer
const INPUT_MAX: usize = 4096;

static mut AFL_IN_LEN_PTR: u64 = 0;
static mut AFL_INPUT_PTR: u64 = 0;

type Unicorn<'a> = unicornafl::UnicornHandle<'a, ()>;

fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    let mut f = File::open(filename)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// find null terminated string in vec
pub fn str_from_u8_unchecked(utf8_src: &[u8]) -> &str {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len());
    unsafe { str::from_utf8_unchecked(&utf8_src[0..nul_range_end]) }
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

#[allow(dead_code)]
#[repr(packed(2))]
struct MsgStructHdr {
    op1: u16,
    op2: u16,
    size: u16,
    msg_group: u16,
}

fn fuzz(input_file: &str) -> Result<(), uc_error> {
    let mut unicorn = unicornafl::Unicorn::new(Arch::ARM, Mode::THUMB, ())?;
    let mut uc: UnicornHandle<'_, _> = unicorn.borrow();

    let symbols = parse_symbols("./snapshot/symbols.csv");
    unsafe {
        AFL_INPUT_PTR = symbols["afl_buf"];
        assert!(AFL_INPUT_PTR != 0);
    }

    let ranges = parse_ranges("./snapshot/ranges.csv");

    // Write the binary to its place in mem
    for range in ranges {
        println!("Mapping {:?}", range);

        // Ignore non-aligned pages - they are peripherals etc.
        if range.length % 0x1000 != 0 {
            if range.filename == "tim0" {
                // Special case for timer peripherals, we yolo-map the first one with the correct size.
                // The following timers are on the same qemu page (on shannon).
                // We can ignore the peripheral map's contents.
                uc.mem_map(range.start, 0x1000, range.mode).unwrap();
            }

            continue;
        }

        uc.mem_map(range.start, range.length, range.mode).unwrap();
        let content = read_file(&format!("./snapshot/{}", &range.filename)).unwrap();
        uc.mem_write(range.start, &content).unwrap();
    }

    let regs = parse_regs("./snapshot/regs.csv");

    for reg in regs {
        match reg.name.as_str() {
            // the first param of getWork is the pointer to the length of the input
            "r0" => unsafe {
                AFL_IN_LEN_PTR = reg.value;
            },
            "r1" => uc.reg_write(RegisterARM::R1 as i32, reg.value)?,
            "r2" => uc.reg_write(RegisterARM::R2 as i32, reg.value)?,
            "r3" => uc.reg_write(RegisterARM::R3 as i32, reg.value)?,
            "r4" => uc.reg_write(RegisterARM::R4 as i32, reg.value)?,
            "r5" => uc.reg_write(RegisterARM::R5 as i32, reg.value)?,
            "r6" => uc.reg_write(RegisterARM::R6 as i32, reg.value)?,
            "r7" => uc.reg_write(RegisterARM::R7 as i32, reg.value)?,
            "r8" => uc.reg_write(RegisterARM::R8 as i32, reg.value)?,
            "r9" => uc.reg_write(RegisterARM::R9 as i32, reg.value)?,
            "r10" => uc.reg_write(RegisterARM::R10 as i32, reg.value)?,
            "r11" => uc.reg_write(RegisterARM::R11 as i32, reg.value)?,
            "r12" => uc.reg_write(RegisterARM::R12 as i32, reg.value)?,
            // add 1 for thumb
            // We immediately "return" from getWork by setting the lr instead of pc as PC
            "lr" => uc.reg_write(RegisterARM::PC as i32, reg.value | 1)?,
            "sp" => uc.reg_write(RegisterARM::SP as i32, reg.value)?,
            // no need to set lr, we just "returned" from getWork.
            //"lr" => uc.reg_write(RegisterARM::LR as i32, reg.value)?,
            "cpsr" => uc.reg_write(RegisterARM::CPSR as i32, reg.value)?,
            _ => println!("Ignored {:?}", reg),
        }
    }
    assert!(unsafe { AFL_IN_LEN_PTR != 0 });

    // We patch in a return at "startWork" -> it's only needed for firmwire. A hook would be slower than binary patching.
    let blr = 0x4770_u16;
    // We need to clear the thumb bit when patching, hence we and with 0xFF....
    uc.mem_write(symbols["startWork"] & 0xFFFFFFFE, &blr.to_le_bytes())
        .unwrap();

    /*uc.add_code_hook(symbols["startWork"], symbols["startWork"], |uc, addr| {
        uc.reg_write(RegisterARM::PC as i32, uc.reg_read(RegisterARM::LR as i32).unwrap() | 1).unwrap();
    });*/

    // r0 after getWork is the place we put input to.
    uc.reg_write(RegisterARM::R0 as i32, unsafe { AFL_INPUT_PTR })?;

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

    /*
        BEGIN FUNCTION HOOKS
    */

    let abort_hook = |_uc: Unicorn, addr: u64, _size: u32| {
        panic!("Found abort at {:#x}", addr);
    };

    let abort_addr = symbols["OS_fatal_error"];
    uc.add_code_hook(abort_addr, abort_addr, abort_hook)
        .unwrap();

    let place_input_callback =
        |uc: &mut UnicornHandle<'_, _>, afl_input: &mut [u8], _persistent_round| {
            if afl_input.len() > INPUT_MAX {
                return false;
            }
            unsafe {
                // Write the input length
                uc.mem_write(AFL_IN_LEN_PTR, &(afl_input.len() as u32).to_le_bytes())
                    .unwrap();
                // Write pdu type
                uc.mem_write(AFL_INPUT_PTR, afl_input).unwrap();
            }
            true
        };

    // return true if the last run should be counted as crash
    let crash_validation_callback =
        |_uc: &mut UnicornHandle<'_, _>, result, _input: &[u8], _persistent_round| {
            if result == uc_error::OK {
                false
            } else {
                println!(
                    "UC Error: {:?}, current PC: {:#x}",
                    result,
                    _uc.reg_read(RegisterARM::PC as i32).unwrap()
                );
                true
            }
        };

    // We need to clear the thumb bit for doneWork, too.
    let done_work_addr = symbols["doneWork"] & 0xFFFFFFFE;
    //println!("done Work at {:#x}", done_work_addr);

    let ret = {
        uc.afl_fuzz(
            input_file,
            place_input_callback,
            &[done_work_addr],
            crash_validation_callback,
            false,
            1,
        )
    };

    match ret {
        Ok(_) => {}
        Err(e) => panic!("found non-ok unicorn exit: {:?}", e),
    }

    Ok(())
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[derive(Debug)]
struct Range {
    filename: String,
    start: u64,
    length: usize,
    mode: Permission,
}

fn parse_protection_mode(prot_str: &str) -> Permission {
    let mut ret = Permission::NONE;
    let mut prot_chars = prot_str.chars();
    if prot_chars.next().unwrap() == 'r' {
        ret |= Permission::READ;
    }
    if prot_chars.next().unwrap() == 'w' {
        ret |= Permission::WRITE;
    }
    if prot_chars.next().unwrap() == 'x' {
        ret |= Permission::EXEC;
    }
    ret
}

fn parse_ranges(ranges_file: &str) -> Vec<Range> {
    let lines = read_lines(ranges_file);
    lines
        .unwrap()
        .map(|line| {
            let line = line.unwrap();
            let mut split = line.split(',');
            Range {
                filename: split.next().unwrap().into(),
                start: split.next().unwrap().parse().unwrap(),
                length: split.next().unwrap().parse().unwrap(),
                mode: parse_protection_mode(split.next().unwrap()),
            }
        })
        .collect()
}

#[derive(Debug)]
struct Reg {
    name: String,
    value: u64,
}

fn parse_regs(filename: &str) -> Vec<Reg> {
    let lines = read_lines(filename);
    lines
        .unwrap()
        .filter_map(|line| {
            let line = line.unwrap();
            let mut split = line.split(',');
            let name = split.next().unwrap().into();
            // ignore lines where the value is `None`
            if let Ok(value) = split.next().unwrap().parse() {
                Some(Reg { name, value })
            } else {
                None
            }
        })
        .collect()
}

fn parse_symbols(filename: &str) -> HashMap<String, u64> {
    let lines = read_lines(filename);
    let mut ret = HashMap::new();
    for line in lines.unwrap() {
        let line = line.unwrap();
        let mut split = line.split(',');
        let name = split.next().unwrap().into();
        // ignore lines where the value is `None`
        if let Ok(value) = split.next().unwrap().parse() {
            ret.insert(name, value);
        } else {
            println!("Ignored symbol {}", name);
        }
    }
    ret
}

#[cfg(test)]
#[test]
fn test_parse_metadata() {
    let ranges = parse_ranges("./snapshot/ranges.csv");
    assert_ne!(ranges.len(), 0);
    let regs = parse_regs("./snapshot/regs.csv");
    assert_ne!(regs.len(), 0);
    let symbols = parse_symbols("./snapshot/symbols.csv");
    assert_ne!(symbols.len(), 0);
}
