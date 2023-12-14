use std::any::type_name;
use std::ops::Range;
use std::os::windows::raw::HANDLE;

use aobscan::{Pattern, PatternBuilder};
use either::Either;
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use faithe::{process::Process, types::access_rights::PROCESS_ALL_ACCESS};
use tokio::sync::{Mutex, MutexGuard, OnceCell};
use types::*;
use ValueTypes as VT;

pub mod assembly;
pub mod offsets;
pub mod types;

const PROCESS_NAME: &str = "Risk of Rain 2.exe";

static MEMORY_MENU: OnceCell<Mutex<MemoryMenu>> = OnceCell::const_new();

pub async fn menu() -> MutexGuard<'static, MemoryMenu<'static>> {
    MEMORY_MENU
        .get_or_init(|| async { Mutex::new(MemoryMenu::init()) })
        .await
        .lock()
        .await
}

unsafe impl Send for MemoryMenu<'_> {}
unsafe impl Sync for MemoryMenu<'_> {}
pub struct MemoryMenu<'a> {
    pointers: PointersData<'a>,
}
impl<'a> MemoryMenu<'a> {
    pub fn init() -> Self {
        let pointers = PointersData::default();

        Self { pointers }
    }
    pub async fn process_id(&self) -> AutoResult<u32> {
        let process = Process::open_by_name(PROCESS_NAME, false, PROCESS_ALL_ACCESS)?;
        Ok(process.id())
    }
    pub fn get(&self, memory_selector: MemorySelector) -> AutoResult<&PtrData> {
        use MemorySelector as MS;
        let p = &self.pointers;
        Ok(match memory_selector {
            MS::GodMode => &p.god_mode,
            MS::Health => &p.health,
            MS::Money => &p.money,
        })
    }
}

mod ptr_data {
    use tokio::runtime::Handle;

    use super::*;
    
    #[derive(Clone)]
    pub struct PtrData<'a> {
        value: ValueTypes,
        ptr: Address,
        offsets: Vec<UPtr>,
        base: &'a Address, 

        check_range: Option<Range<i64>>,
        process: &'a Process,
    }
    impl<'a> PtrData<'a> {
        pub fn new(
            value: ValueTypes,
            offsets: Vec<UPtr>,
            base: &Address,
            check_range: Option<Range<i64>>,
            process: &'a Process,
        ) -> Self {
            Self {
                value,
                ptr: 0x0,
                offsets: offsets.clone(),
                base,
                check_range,
                process,
            }
        }
        pub fn calc_ptr(&mut self) -> Result<UPtr, IOError> {
            let process = self.process;
            let mut ptr = self.base;

            for (i, offset) in self.offsets.clone().into_iter().enumerate() {
                *ptr += offset;

                if i != self.offsets.len() {
                    ptr = process.read(*ptr)?;
                }
            }

            Ok(*ptr)
        }
        fn check(&mut self) -> Result<(), IOError> {
            if self.ptr == 0x0 {
                self.ptr = self.calc_ptr()?;
            };
            if self.check_range.is_some() && !self.check_range.unwrap().contains(&(self.ptr as i64)) {
                return Err(IOError::RuntimeSanityCheckError)
            }
            Ok(())
        }
        fn read(&mut self) -> Result<ValueTypes, IOError> {
            self.check()?;
            let process = self.process;
            match self.value {
                ValueTypes::Undefined => return Err(IOError::UndefinedType),
                ValueTypes::Ptr(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Bytes1(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Bytes2(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Bytes2U(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Bytes4(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Bytes4U(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Bytes8(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Bytes8U(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Float(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::Double(ref mut v) => *v = process.read(self.ptr)?,
                ValueTypes::RawBytes(ref mut v) => *v = process.read(self.ptr)?,
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
            let process = self.process;
            match self.value {
                ValueTypes::Undefined => return Err(IOError::UndefinedType),
                ValueTypes::Ptr(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Bytes1(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Bytes2(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Bytes2U(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Bytes4(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Bytes4U(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Bytes8(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Bytes8U(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Float(ref v) => process.write(self.ptr, v)?,
                ValueTypes::Double(ref v) => process.write(self.ptr, v)?,
                ValueTypes::RawBytes(ref v) => process.write(self.ptr, v)?,
            };
            Ok(())
        }
    }
}
use ptr_data::*;
struct PointersData<'a> {
    process: Process,
    player_base: PtrData<'a>,

    god_mode: PtrData<'a>,
    health: PtrData<'a>,
    money: PtrData<'a>,
}
impl<'a> Default for PointersData<'a> {
    fn default() -> Self {
        let process = {
            loop {
                match Process::open_by_name(PROCESS_NAME, false, PROCESS_ALL_ACCESS) {
                    Ok(p) => break p,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(400));
                        // tokio::task::block_in_place(|| {
                        //     tokio::runtime::Handle::current().block_on(async move {
                        //         sleep(std::time::Duration::from_millis(400)).await;
                        //     })
                        // });
                    }
                }
            }
        };

        const PLAYER_VIEW_PATTERN: &str = "F3 41 0F 10 46 68 F3 0F 5A C0 41";

        let player_base = process.find_pattern(mod_name, pat)
        
        let god_mode = PtrData::new(
            VT::Bytes1(Default::default()),
            Vec::new(),
            player_base.,
            None,
            &process,
        );
        let health = PtrData::new(
            VT::Float(Default::default()),
            Vec::new(),
            &player_base,
            None,
            &process,
        );
        let money = PtrData::new(
            VT::Bytes4(Default::default()),
            Vec::new(),
            &player_base,
            None,
            &process,
        );

        Self {
            process,
            player_base,
            god_mode,
            health,
            money,
        }
    }
}


mod pattern {
    use std::ptr;

    use faithe::process::Process;
    use thiserror::Error;

    use crate::types::{Address, Pattern, ExternPattern};

    #[derive(Error, Debug)]
    pub enum PatternFindError {
        #[error("Pattern not found")]
        PatternNotFound,
        #[error("Many patterns were found")]
        ManyPatternsFound,
    } 

    trait PatternScanner {
        fn find_pattern(process: &Process, pattern: Pattern) -> Result<Address, PatternFindError>;
    }

    impl PatternScanner for Process {
        fn find_pattern(process: &Process, pattern: Pattern) -> Result<Address, PatternFindError> {
            const STEP_SIZE: usize = 0x10000;
            let pattern: ExternPattern = pattern.into();

            let modules = process.modules().unwrap();
            let mut result: Vec<Address>;

            for m in modules {
                let start_addr = m.mod_base_addr;
                let size = m.mod_base_size;

                let parts: Vec<usize> = {
                    let mut result = Vec::new();
                    let range = 0..size / STEP_SIZE;
                    let remainder = size % STEP_SIZE;
                
                    result.extend(range.map(|i| i * STEP_SIZE));
                
                    if remainder > 0 {
                        result.push(size - remainder);
                    }
                
                    result
                };

                for current in parts {
                    let mut buf: [u8; STEP_SIZE];
                    let _bytes_read = process.read_buf(start_addr + current, buf).unwrap();

                    let _ = pattern.scan(&buf, |addr| { result.push(addr); true });
                }
            }

            match result.len() {
                0 => Err(PatternFindError::PatternNotFound),
                1 => Ok(result[0]),
                2.. => Err(PatternFindError::ManyPatternsFound),
            }
        }
    }
}