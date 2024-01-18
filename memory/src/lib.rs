use std::ops::Range;
use std::os::windows::raw::HANDLE;
use std::sync::Arc;
use std::time::Duration;
use std::{any::type_name, vec};

use dynasmrt::x64::X64Relocation;
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use faithe::{process::Process, types::access_rights::PROCESS_ALL_ACCESS};
use pointers_map::{PointersTable, Push};
use tokio::sync::{Mutex, MutexGuard, OnceCell};
use try_for_x::make_attempts_throughout;
use types::*;
use ValueTypes as VT;

pub mod assembly;
pub mod types;

const PROCESS_NAME: &str = "Risk of Rain 2.exe";

static MEMORY_MENU: OnceCell<Mutex<MemoryMenu>> = OnceCell::const_new();

pub async fn menu() -> MutexGuard<'static, MemoryMenu> {
    MEMORY_MENU
        .get_or_init(|| async { Mutex::new(MemoryMenu::init()) })
        .await
        .lock()
        .await
}

unsafe impl Send for MemoryMenu {}
unsafe impl Sync for MemoryMenu {}
pub struct MemoryMenu {
    pub pointers: PointersTable,
}
impl MemoryMenu {
    pub fn init() -> Self {
        let process = {
            loop {
                match Process::open_by_name(PROCESS_NAME, false, PROCESS_ALL_ACCESS) {
                    Ok(p) => break p,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(400));
                    }
                }
            }
        };
        let process = Arc::new(process);

        let pointers = main_menu(process);

        Self { pointers }
    }
}

pub fn process_id() -> AutoResult<u32> {
    let process = Process::open_by_name(PROCESS_NAME, false, PROCESS_ALL_ACCESS)?;
    Ok(process.id())
}

mod ptr_data {
    use crate::assembly::inject::InjectHandle;

    use super::*;

    pub enum Base {
        Address(Address),
        Handle(InjectHandle),
    }
    impl Base {
        pub fn address(&self) -> &'_ Address {
            match self {
                Base::Address(a) => a,
                Base::Handle(h) => h.data_address().unwrap(),
            }
        }
    }
    impl From<Address> for Base {
        fn from(value: Address) -> Self {
            Self::Address(value)
        }
    }
    impl TryFrom<InjectHandle> for Base {
        type Error = &'static str;
        fn try_from(value: InjectHandle) -> Result<Self, Self::Error> {
            if value.data_address().is_none() {
                return Err("data address is none");
            }
            Ok(Self::Handle(value))
        }
    }

    pub struct PtrData {
        name: String,

        value: ValueTypes,
        address: Address,
        offsets: Vec<UPtr>,
        base: Base,

        check_range: Option<Range<i64>>,
        process: Arc<Process>,
    }
    impl PtrData {
        pub fn new(
            name: String,
            value: ValueTypes,
            offsets: Vec<UPtr>,
            base: Base,
            check_range: Option<Range<i64>>,
            process: Arc<Process>,
        ) -> Self {
            Self {
                name,
                value,
                address: 0x0,
                offsets: offsets.clone(),
                base,
                check_range,
                process,
            }
        }
        pub fn name(&self) -> &'_ String {
            &self.name
        }
        pub fn calc_ptr(&mut self) -> Result<Address, IOError> {
            match &self.base {
                Base::Address(a) => {
                    let mut ptr = *a;

                    for (i, offset) in self.offsets.clone().into_iter().enumerate() {
                        ptr += offset;

                        if i != self.offsets.len() - 1 {
                            ptr = self.process.read(ptr)?;
                        }
                    }

                    Ok(ptr)
                }
                Base::Handle(h) => Ok(*h.data_address().unwrap()),
            }
        }
        pub fn get_base(&self) -> Address {
            *self.base.address()
        }
        fn check(&mut self) -> Result<(), IOError> {
            if self.address == 0x0 {
                self.address = self.calc_ptr()?;
            };

            // other runtime sanity checks

            Ok(())
        }
        fn read(&mut self) -> Result<ValueTypes, IOError> {
            self.check()?;
            let process = self.process.as_ref();
            match self.value {
                ValueTypes::Undefined => return Err(IOError::UndefinedType),
                ValueTypes::Address(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Bytes1(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Bytes2(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Bytes2U(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Bytes4(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Bytes4U(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Bytes8(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Bytes8U(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Float(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::Double(ref mut v) => *v = process.read(self.address)?,
                ValueTypes::RawBytes(ref mut v) => *v = process.read(self.address)?,
            };
            Ok(self.value.clone())
        }
        fn write(&mut self, new_value: ValueTypes) -> Result<(), IOError> {
            if self.value != new_value {
                return Err(IOError::TypeError {
                    expected: self.value.to_string(),
                    found: new_value.to_string(),
                });
            }
            self.check()?;
            let process = self.process.as_ref();
            match self.value {
                ValueTypes::Undefined => return Err(IOError::UndefinedType),
                ValueTypes::Address(ref v) => process.write(self.address, v)?,
                ValueTypes::Bytes1(ref v) => process.write(self.address, v)?,
                ValueTypes::Bytes2(ref v) => process.write(self.address, v)?,
                ValueTypes::Bytes2U(ref v) => process.write(self.address, v)?,
                ValueTypes::Bytes4(ref v) => process.write(self.address, v)?,
                ValueTypes::Bytes4U(ref v) => process.write(self.address, v)?,
                ValueTypes::Bytes8(ref v) => process.write(self.address, v)?,
                ValueTypes::Bytes8U(ref v) => process.write(self.address, v)?,
                ValueTypes::Float(ref v) => process.write(self.address, v)?,
                ValueTypes::Double(ref v) => process.write(self.address, v)?,
                ValueTypes::RawBytes(ref v) => process.write(self.address, v)?,
            };
            Ok(())
        }
    }
}
use ptr_data::*;

use crate::{
    assembly::inject::{try_inject, InstructionSized},
    pattern::find_pattern,
};

/// Module containing a function for making attempts throughout a specified time period.
/// This module provides a function for making repeated attempts until a condition is met within a specified time limit.
///
/// The `make_attempts_throughout` function takes the following parameters:
/// - `max_time`: The maximum duration within which the attempts should be made.
/// - `repeat_time`: The duration to wait between each attempt.
/// - `f`: A closure that performs the attempt and returns a `Result` indicating success or failure.
/// - `callback`: An optional callback function that is called with the attempt number and the error if an attempt fails.
///
/// The function returns a `Result` containing the result of the successful attempt or an error message if all attempts fail within the specified time limit.
///
/// # Examples
///
/// ```
/// use memory::try_for_x;
/// use std::time::Duration;
///
/// fn attempt() -> Result<(), &'static str> {
///     // Perform the attempt here
///     // Return Ok(()) if successful, otherwise return Err with an error message
///     Ok(())
/// }
///
/// let result = try_for_x::make_attempts_throughout(
///     Duration::from_secs(10),
///     Duration::from_secs(1),
///     attempt,
///     Some(|i, _err| println!("Attempt {}", i))
/// );
///
/// match result {
///     Ok(_) => println!("Attempt succeeded"),
///     Err(err) => println!("All attempts failed: {}", err),
/// }
/// ```
///
/// In the above example, the `attempt` function is called repeatedly until it returns `Ok(())` or the maximum time limit of 10 seconds is reached.
/// The function waits for 1 second between each attempt and does not provide a callback function.
/// If all attempts fail within the time limit, an error message is returned.
/// Otherwise, the function returns `Ok(())` indicating a successful attempt.
///
pub mod try_for_x {
    use std::time::Duration;

    use tokio::time::Instant;

    pub fn make_attempts_throughout<T, E, F>(
        max_time: Duration,
        repeat_time: Duration,
        f: F,
        callback: Option<impl Fn(u32, E)>,
    ) -> Result<T, String>
    where
        F: Fn() -> Result<T, E>,
    {
        let deadline = Instant::now().checked_add(max_time);
        let condition: Box<dyn Fn() -> bool> = {
            if let Some(deadline) = deadline {
                Box::new(move || Instant::now() < deadline)
            } else {
                Box::new(move || true)
            }
        };

        let mut i = 0;
        while condition() {
            match f() {
                Ok(t) => return Ok(t),
                Err(e) => {
                    if let Some(cb) = callback.as_ref() { cb(i, e) }
                    i += 1;
                    std::thread::sleep(repeat_time);
                }
            }
        }
        Err(format!(
            "make_attempts_throughout failed after: {:?}",
            max_time
        ))
    }
}

fn main_menu(process: Arc<Process>) -> PointersTable {
    let player_base = {
        let player_view_pattern: Pattern = "F3 41 0F 10 46 68 F3 0F 5A C0 41".try_into().unwrap();
        let original_code = InstructionSized::try_from("F3 41 0F 10 46 68").unwrap();

        let inject_point = make_attempts_throughout(
            Duration::MAX,
            Duration::from_millis(500),
            || find_pattern(&process, player_view_pattern.clone()),
            Some(|iter, _err| {
                if iter == 1 {
                    info!("Waiting for game completely launch..");
                }
            }),
        )
        .unwrap();
        // let injectable_memory =

        // let injectable_code = {
        //     let mut ops: dynasmrt::VecAssembler<X64Relocation> = dynasmrt::VecAssembler::new(0);
        //     dynasm!(ops
        //         ; mov rax, QWORD 0x0
        //         ; mov rax, QWORD [rax]
        //         ; mov rax, QWORD [rax + 0x68]
        //         ; ret
        //     );

        //     ops.finalize().unwrap()
        // };

        let inject_handle = try_inject(
            inject_point,
            original_code,
            // injectable_code,
            Vec::new(),
            None,
            Arc::clone(&process),
        )
        .unwrap();

        PtrData::new(
            "player_base".to_string(),
            VT::Address(0x0),
            Vec::new(),
            inject_handle.try_into().unwrap(),
            None,
            Arc::clone(&process),
        )
    };

    let god_mode = PtrData::new(
        "god_mode".to_string(),
        VT::Bytes1(Default::default()),
        vec![0x8c],
        player_base.get_base().into(),
        None,
        Arc::clone(&process),
    );
    let health = PtrData::new(
        "health".to_string(),
        VT::Float(Default::default()),
        Vec::new(),
        Base::Address(player_base.get_base()),
        None,
        Arc::clone(&process),
    );
    let money = PtrData::new(
        "money".to_string(),
        VT::Bytes4(Default::default()),
        vec![0x68],
        Base::Address(player_base.get_base()),
        None,
        Arc::clone(&process),
    );

    let mut table = PointersTable::new("main_menu");
    table.push(player_base).unwrap();
    table.push(god_mode).unwrap();
    table.push(health).unwrap();
    table.push(money).unwrap();

    table
}

mod pointers_map {
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use thiserror::Error;

    use crate::ptr_data::PtrData;

    pub trait Push<T> {
        fn push(&mut self, data: T) -> Result<(), &str>;
    }

    #[derive(Error, Debug)]
    pub enum PtrFindError {
        #[error("Pointer not found")]
        NotFound,
        #[error("Many pointers were found")]
        ManyFound,
    }

    pub struct PointersTable {
        name: &'static str,
        pointers: Vec<PtrData>,
        children: Vec<PointersTable>,
    }
    impl PointersTable {
        pub fn new(name: &'static str) -> Self {
            Self {
                name,
                pointers: Vec::new(),
                children: Vec::new(),
            }
        }
        pub fn find_pointer(&self, name: &str) -> Option<&PtrData> {
            self.pointers.par_iter().find_any(|p| p.name() == name)
        }
        pub fn find_child(&self, name: &str) -> Option<&PointersTable> {
            self.children.par_iter().find_any(|p| p.name == name)
        }
    }
    impl Push<PtrData> for PointersTable {
        fn push(&mut self, data: PtrData) -> Result<(), &str> {
            if !self.pointers.par_iter().any(|p| p.name() == data.name()) {
                self.pointers.push(data);
                Ok(())
            } else {
                Err("pointer already exists")
            }
        }
    }
    impl Push<PointersTable> for PointersTable {
        fn push(&mut self, data: PointersTable) -> Result<(), &str> {
            if !self.children.par_iter().any(|p| p.name == data.name) {
                self.children.push(data);
                Ok(())
            } else {
                Err("child already exists")
            }
        }
    }
}

mod pattern {
    use faithe::{
        process::Process,
        types::protection_flags::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY},
    };
    use thiserror::Error;

    use crate::types::{Address, ExternPattern};

    #[derive(Error, Debug)]
    pub enum PatternFindError {
        #[error("Pattern not found")]
        PatternNotFound,
        #[error("Many patterns were found")]
        ManyPatternsFound,
        #[error("Some memory error")]
        MemoryError(#[from] faithe::FaitheError),
    }

    pub fn find_pattern(
        process: &Process,
        pattern: impl Into<ExternPattern>,
    ) -> Result<Address, PatternFindError> {
        let pattern = pattern.into();
        const CHUNK_SIZE: usize = 2_usize.pow(12);
        const MAX_SIZE: usize = 0x7FF800000000;

        let mut last_processed = 0;
        let mut result: Vec<usize> = Vec::new();

        while last_processed <= MAX_SIZE {
            let mem = process.query(last_processed)?;
            let mut processed_inc = || {
                last_processed = mem.base_address + mem.region_size;
            };

            let p = mem.alloc_protection;
            if p == PAGE_EXECUTE_WRITECOPY || p == PAGE_EXECUTE_READWRITE {
                for address in
                    (mem.base_address..mem.base_address + mem.region_size).step_by(CHUNK_SIZE)
                {
                    let mut buf = [0; CHUNK_SIZE];
                    let _ = process.read_buf(address, buf.as_mut())?;
                    let _ = pattern.scan(&buf, |offset| {
                        let addr = address + offset;
                        result.push(addr);
                        true
                    });
                }
            }

            processed_inc();
        }

        match result.len() {
            0 => Err(PatternFindError::PatternNotFound),
            1 => Ok(result[0]),
            2.. => Err(PatternFindError::ManyPatternsFound),
        }
    }
}
