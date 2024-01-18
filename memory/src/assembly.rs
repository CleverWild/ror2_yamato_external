use tokio::runtime::Handle;

pub mod inject {
    pub mod sized {
        /// Represents a one instruction sized vector.
        ///
        /// Ensures that the length of the `non-empty` vector does `not exceed 8 bytes`.
        pub struct InstructionSized(Vec<u8>);
        impl InstructionSized {
            pub fn new(vec: Vec<u8>) -> Self {
                assert!(Self::condition_check(&vec));
                Self(vec)
            }
            pub fn inner(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn condition_check(vec: &Vec<u8>) -> bool {
                !vec.is_empty() && vec.len() <= 8
            }
        }
        impl TryFrom<&str> for InstructionSized {
            type Error = std::num::ParseIntError;

            /// Creates a new `InstructionSized` from a string representation.
            ///
            /// # Arguments
            ///
            /// * `value` - The string representation of the assembly instruction.
            ///
            /// # Examples
            ///
            /// ```
            /// let instruction = InstructionSized::try_from("F3 41 0F 10 46 68").unwrap();
            /// ```
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                let vec = value
                    .split_whitespace()
                    .map(|s| u8::from_str_radix(s, 16).unwrap())
                    .collect::<Vec<u8>>();
                assert!(Self::condition_check(&vec));
                Ok(Self(vec))
            }
        }
    }

    pub mod memory_controller {
        use self::traits::AutoImpl as _;

        use super::MemoryRegion;
        use faithe::process::Process;
        use std::fmt::Debug;
        use std::sync::{Arc, Mutex};
        use thiserror::Error;
        use tracing::trace;

        pub mod prelude {
            pub use super::traits::{AccessBase, AutoImpl as _};
        }

        pub mod traits {
            use super::*;

            pub trait AccessBase<'a> {
                fn rel_address(&self) -> usize;
                fn abs_address(&self) -> usize;
                fn size(&self) -> usize;
                fn name(&self) -> Option<&'static str>;
                fn process(&self) -> Arc<Process>;
            }
            pub trait AutoImpl<'a>: AccessBase<'a> {
                fn clear(&self) {
                    self.process()
                        .write(self.rel_address(), &vec![0x0; self.size()])
                        .unwrap();
                }
            }
            impl<'a> AutoImpl<'a> for dyn AccessBase<'a> {}
            impl<'a> Debug for dyn AccessBase<'a> {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct("AccessBase")
                        .field("name", &self.name())
                        .field("relative_address", &self.rel_address())
                        .field("absolute_address", &self.abs_address())
                        .field("size", &self.size())
                        .field("process", &format!("id {:?}", self.process().id()))
                        .finish()
                }
            }

            pub trait CellIO<'a>: AccessBase<'a> {}
            pub trait RawIO<'a>: AccessBase<'a> {}
        }

        #[derive(Error, Debug)]
        pub enum Error {
            #[error("The specified name is already in use by another rental")]
            DuplicateName,
            #[error("The area to be filled is larger than the available memory region, requested: {requested}, available: {available}")]
            MemoryRegionOverflow { requested: usize, available: usize },
            #[error("The specified address is not within the memory region")]
            InvalidAddress {
                received: usize,
                allowed_from_to: (usize, usize),
            },
            #[error("Nothing found when searching for `{received}` in MemoryAccess name's")]
            InvalidName {
                received: &'static str,
                existing_names: Vec<&'static str>,
            },
            #[error("Failed to allocate a memory area with the specified size, although the total number of free bytes is enough")]
            AllocationFailed,
            #[error("Some faithe error: {0}")]
            Faithe(#[from] faithe::FaitheError),
        }

        pub struct MemoryRawAccess<'a> {
            name: Option<&'static str>,
            rel_address: usize,
            abs_address: usize,
            size: usize,

            controller: &'a MemoryController<'a>,
            process: Arc<Process>,
        }
        impl<'a> Debug for MemoryRawAccess<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("AccessBase")
                    .field("controller", &format!("id {:?}", self.controller as *const _))
                    .field("name", &self.name)
                    .field("relative_address", &self.rel_address)
                    .field("absolute_address", &self.abs_address)
                    .field("size", &self.size)
                    .field("process", &format!("id {:?}", self.process.id()))
                    .finish()
            }
        }
        impl<'a> traits::AccessBase<'a> for MemoryRawAccess<'a> {
            fn name(&self) -> Option<&'static str> {
                self.name
            }
            fn rel_address(&self) -> usize {
                self.rel_address
            }
            fn abs_address(&self) -> usize {
                self.abs_address
            }
            fn size(&self) -> usize {
                self.size
            }
            fn process(&self) -> Arc<Process> {
                self.process.clone()
            }
        }
        impl<'a> MemoryRawAccess<'a> {
            pub fn read<T>(&self, rel_address: usize) -> Result<T, Error> {
                self.check_permit_to_address::<T>(rel_address)?;
                let value = self.process.read(self.abs_address + rel_address)?;
                Ok(value)
            }
            pub fn read_buf<T>(
                &self,
                rel_address: usize,
                buf: impl AsMut<[u8]>,
            ) -> Result<usize, Error> {
                self.check_permit_to_address::<T>(rel_address)?;
                let bytes_read = self.process.read_buf(self.abs_address + rel_address, buf)?;
                Ok(bytes_read)
            }
            pub fn read_all(&self) -> Result<Vec<u8>, Error> {
                let mut buf = vec![0x0; self.size];
                let bytes_read = self.process.read_buf(self.abs_address, &mut buf)?;
                assert_eq!(bytes_read, self.size); // sanity check
                Ok(buf)
            }
            pub fn write<T>(&self, rel_address: usize, value: &T) -> Result<usize, Error> {
                self.check_permit_to_address::<T>(rel_address)?;
                let bytes_written = self.process.write(rel_address, value)?;
                Ok(bytes_written)
            }
            fn check_permit_to_address<T>(&self, rel_address: usize) -> Result<(), Error> {
                if rel_address + std::mem::size_of::<T>() > self.rel_address + self.size {
                    return Err(Error::InvalidAddress {
                        received: rel_address,
                        allowed_from_to: (self.rel_address, self.rel_address + self.size),
                    });
                }
                if rel_address >= self.rel_address && rel_address < self.rel_address + self.size {
                    Ok(())
                } else {
                    Err(Error::InvalidAddress {
                        received: rel_address,
                        allowed_from_to: (self.rel_address, self.rel_address + self.size),
                    })
                }
            }
        }
        impl<'a> traits::AutoImpl<'a> for MemoryRawAccess<'a> {}
        impl<'a> traits::RawIO<'a> for MemoryRawAccess<'a> {}

        pub struct MemoryCellAccess<'a, T> {
            name: Option<&'static str>,
            abs_address: usize,
            rel_address: usize,

            controller: &'a MemoryController<'a>,
            process: Arc<Process>,
            _marker: std::marker::PhantomData<T>,
        }
        impl<'a, T> Debug for MemoryCellAccess<'a, T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("AccessBase")
                    .field("controller", &format!("id {:?}", self.controller as *const _))
                    .field("name", &self.name)
                    .field("relative_address", &self.rel_address)
                    .field("absolute_address", &self.abs_address)
                    .field("size", &std::mem::size_of::<T>())
                    .field("process", &format!("id {:?}", self.process.id()))
                    .finish()
            }
        }
        impl<'a, T> traits::AccessBase<'a> for MemoryCellAccess<'a, T> {
            fn abs_address(&self) -> usize {
                self.abs_address
            }
            fn rel_address(&self) -> usize {
                self.rel_address
            }
            fn size(&self) -> usize {
                std::mem::size_of::<T>()
            }
            fn name(&self) -> Option<&'static str> {
                self.name
            }
            fn process(&self) -> Arc<Process> {
                self.process.clone()
            }
        }
        impl<'a, T> MemoryCellAccess<'a, T> {
            pub fn read(&self) -> Result<T, Error> {
                let value = self.process.read(self.abs_address)?;
                Ok(value)
            }
            pub fn write(&self, value: T) -> Result<usize, Error> {
                let bytes_written = self.process.write(self.abs_address, &value)?;
                Ok(bytes_written)
            }
        }
        impl<'a, T> traits::AutoImpl<'a> for MemoryCellAccess<'a, T> {}
        impl<'a, T> traits::CellIO<'a> for MemoryCellAccess<'a, T> {}

        pub struct MemoryController<'a> {
            region: MemoryRegion,
            rental_info: Mutex<Vec<Arc<dyn traits::AccessBase<'a>>>>,
        }
        impl<'a> MemoryController<'a> {
            pub fn new(region: MemoryRegion) -> Self {
                Self {
                    region,
                    rental_info: Mutex::new(Vec::new()),
                }
            }

            pub fn rent_memory<T: 'static>(
                &mut self,
                name: Option<&'static str>,
            ) -> Result<Arc<MemoryCellAccess<T>>, Error> {
                if name.is_some() {
                    self.name_collision_check(name.unwrap())?;
                }

                let size = std::mem::size_of::<T>();
                let rel_address = self.find_free_space(size)?;

                let access = Arc::new(MemoryCellAccess::<'a, T> {
                    name,
                    rel_address,
                    abs_address: self.region.address() + rel_address,
                    controller: self,
                    _marker: std::marker::PhantomData,
                    process: self.region.process(),
                });
                access.clear();
                trace!(
                    "Memory allocated by rental: {:?}",
                    &*access as &dyn traits::AccessBase
                );
                self.rental_info.lock().unwrap().push(access.clone());

                Ok(access)
            }

            pub fn rent_memory_for<T: 'static>(
                &mut self,
                value: T,
                name: Option<&'static str>,
            ) -> Result<Arc<MemoryCellAccess<T>>, Error> {
                let access = self.rent_memory(name)?;
                access.write(value)?;
                Ok(access)
            }

            pub fn rent_memory_raw(
                &mut self,
                size: usize,
                name: Option<&'static str>,
            ) -> Result<Arc<MemoryRawAccess>, Error> {
                if name.is_some() {
                    self.name_collision_check(name.unwrap())?;
                }
                let rel_address = self.find_free_space(size)?;

                let access = Arc::new(MemoryRawAccess::<'a> {
                    name,
                    rel_address,
                    abs_address: self.region.address() + rel_address,
                    size,
                    controller: self,
                    process: self.region.process(),
                });
                access.clear();
                trace!(
                    "Memory allocated by rental: {:?}",
                    &*access as &dyn traits::AccessBase
                );
                self.rental_info.lock().unwrap().push(access.clone());

                Ok(access)
            }

            pub fn release_memory_by_address(&mut self, address: usize) -> Result<(), Error> {
                self.dealloc_owner_free();
                let index = self
                    .get_rentals()
                    .iter()
                    .position(|rental| {
                        (rental.rel_address()..(rental.rel_address() + rental.size()))
                            .contains(&address)
                    })
                    .ok_or(Error::InvalidAddress {
                        received: address,
                        allowed_from_to: (
                            self.region.address(),
                            self.region.address() + self.region.size(),
                        ),
                    })?;

                self.release_memory_by_index(index);
                Ok(())
            }
 
            pub fn release_memory_by_name(&mut self, name: &'static str) -> Result<(), Error> {
                self.dealloc_owner_free();
                let index = self
                    .get_rentals()
                    .iter()
                    .position(|rental| rental.name() == Some(name))
                    .ok_or(Error::InvalidName {
                        received: name,
                        existing_names: {
                            let mut names = self
                                .get_rentals()
                                .iter()
                                .filter_map(|rental| rental.name())
                                .collect::<Vec<_>>();
                            names.sort();
                            names
                        },
                    })?;

                self.release_memory_by_index(index);
                Ok(())
            }

            pub fn calc_free_bytes(&self) -> usize {
                let mut bytes = self.region.size();
                for rental in self.get_rentals() {
                    bytes -= rental.size();
                }
                bytes
            }

            fn find_free_space(&self, size: usize) -> Result<usize, Error> {
                let free_bytes = self.calc_free_bytes();
                if size > free_bytes {
                    return Err(Error::MemoryRegionOverflow {
                        requested: size,
                        available: free_bytes,
                    });
                }

                let mut start_address = self.region.address();
                for rental in self.get_rentals().iter() {
                    let end_address = rental.rel_address() + rental.size();
                    if start_address + size <= rental.rel_address() || start_address >= end_address
                    {
                        break;
                    }
                    start_address = end_address;
                }

                if start_address + size > self.region.address() + self.region.size() {
                    Err(Error::AllocationFailed)
                } else {
                    Ok(start_address)
                }
            }

            fn name_collision_check(&self, name: &'static str) -> Result<(), Error> {
                if self
                    .get_rentals()
                    .iter()
                    .any(|rental| rental.name() == Some(name))
                {
                    Err(Error::DuplicateName)
                } else {
                    Ok(())
                }
            }

            /// # Panics
            ///
            /// Panics if `index` is out of bounds.
            fn release_memory_by_index(&mut self, index: usize) {
                let rental = self.rentals_vec_mut().remove(index);
                trace!("Memory deallocated by rental: {:?}", rental);
                rental.clear();
            }

            fn get_rentals(&self) -> Vec<Arc<dyn traits::AccessBase>> {
                self.dealloc_owner_free();
                let mut rentals = self.rental_info.lock().unwrap();
                let filtered = rentals
                    .iter()
                    .filter_map(|rental| {
                        let count = Arc::strong_count(rental);
                        if count > 1 {
                            Some(rental.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                *rentals = filtered.clone();
                filtered
            }

            fn dealloc_owner_free(&self) {
                let mut rentals = self.rental_info.lock().unwrap();
                let filtered = rentals
                    .iter()
                    .filter_map(|rental| {
                        let count = Arc::strong_count(rental);
                        if count > 1 {
                            Some(rental.clone())
                        } else {
                            rental.clear();
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                *rentals = filtered;
            }

            fn rentals_vec_mut(&mut self) -> &mut Vec<Arc<dyn traits::AccessBase>> {
                self.dealloc_owner_free();
                self.rental_info.get_mut().unwrap()
            }
        }
        impl<'a> Drop for MemoryController<'a> {
            fn drop(&mut self) {
                let len = self.rentals_vec_mut().len();
                for i in 0..len {
                    self.release_memory_by_index(i);
                }
            }
        }
    }

    use anyhow::anyhow;
    use std::{any::Any, sync::Arc};

    use crate::{
        assembly::hex_to_string,
        types::{debug, error, info, trace, warn, Address, AutoResult, UPtr},
    };
    use dynasmrt::{dynasm, x64::X64Relocation, DynasmApi};
    use faithe::{
        memory::MemoryProtection,
        process::Process,
        types::{
            allocation_types::{MEM_COMMIT, MEM_RESERVE},
            free_types::MEM_RELEASE,
        },
    };

    pub use memory_controller::MemoryController;
    pub use sized::InstructionSized;

    use self::memory_controller::{traits::CellIO, MemoryCellAccess, MemoryRawAccess};

    /// todo! переписать метод хранения данных используя новый AccessController
    /// Represents a handle for an injected code.
    ///
    /// `Drop` trait is implemented, the structure will safely revert the memory to its original state when `self` dropped.
    pub struct InjectHandle<'a> {
        original_code: InstructionSized,
        inject_address: UPtr,

        hook_code_region: Arc<MemoryRawAccess<'a>>,
        hook_data_regions: Vec<Arc<dyn CellIO>>,

        process: Arc<Process>,
    }
    impl<'a> InjectHandle<'a> {
        pub fn find_data_with_name(&self, name: &'static str) -> Option<Arc<dyn CellIO>> {
            self.hook_data_region1
                .iter()
                .find(|data| data.name() == Some(name))
                .map(|data| data.clone())
        }
    }
    impl Drop for InjectHandle {
        fn drop(&mut self) {
            self.process
                .write(self.inject_address, self.original_code.inner())
                .unwrap();
            // code_cave region will be dropped automatically
        }
    }

    /// Represents a memory region.
    ///
    /// `Drop` trait is implemented, so you do not need to manually free unused memory
    pub struct MemoryRegion {
        address: Address,
        size: usize,
        protection: MemoryProtection,
        process: Arc<Process>,
    }
    impl MemoryRegion {
        /// Allocates a memory region with protection `READ_WRITE_EXECUTE`.
        pub fn new_rwe_region(size: usize, process: Arc<Process>) -> Self {
            let region = Self::new_region(size, MemoryProtection::READ_WRITE_EXECUTE, process);
            trace!("Allocated memory for code at 0x{:X}", region.address());
            region
        }
        /// Allocates a memory region with protection `READ_WRITE`.
        pub fn new_rw_region(size: usize, process: Arc<Process>) -> Self {
            let region = Self::new_region(size, MemoryProtection::READ_WRITE, process);
            trace!("Allocated memory for data at 0x{:X}", region.address());
            region
        }
        fn new_region(size: usize, protection: MemoryProtection, process: Arc<Process>) -> Self {
            let alloc_address = process
                .allocate(0x0, size, MEM_RESERVE | MEM_COMMIT, protection)
                .map_err(|e| anyhow!("{} with size: {}", e, size))
                .unwrap();
            let win_region = process
                .query(alloc_address)
                .map_err(|e| {
                    anyhow!(
                        "{} with address: 0x{:X} and size: {}",
                        e,
                        alloc_address,
                        size
                    )
                })
                .unwrap();
            trace!("Allocated memory at region: {:?}", win_region);
            Self {
                address: alloc_address,
                size,
                protection,
                process,
            }
        }
        /// Changes the protection of self memory region.
        pub fn change_protection(&mut self, new_protection: MemoryProtection) {
            self.process
                .protect(self.address, self.size, new_protection)
                .unwrap();
            self.protection = new_protection;
        }
        /// Returns the address of the memory region.
        fn address(&self) -> Address {
            self.address
        }
        /// Returns the size of the memory region.
        fn size(&self) -> usize {
            self.size
        }
        /// Returns the protection of the memory region.
        fn protection(&self) -> MemoryProtection {
            self.protection
        }
        /// Returns the process associated with the memory region.
        fn process(&self) -> Arc<Process> {
            self.process.clone()
        }
        // #[cfg(test)]
        // pub fn test_new(address: Address, size: usize, proc_name: &str) -> Self {
        //     let process = Arc::new(
        //         Process::open_by_name(
        //             proc_name,
        //             false,
        //             faithe::types::access_rights::PROCESS_ALL_ACCESS,
        //         )
        //         .unwrap(),
        //     );
        //     Self::new_code_region(address, size, process)
        // }
    }

    impl Drop for MemoryRegion {
        /// Drops the memory region and frees the associated memory.
        fn drop(&mut self) {
            self.process.free(self.address, 0, MEM_RELEASE).unwrap();
        }
    }

    pub fn try_inject(
        inject_point: UPtr,
        original_code: InstructionSized,
        injectable_code: Vec<u8>,
        injectable_memory: Option<MemoryRegion>,
        process: Arc<Process>,
    ) -> AutoResult<InjectHandle> {
        let hook_code_region = MemoryRegion::new_rwe_region(1000, process.clone());

        let hook_code = get_code_cave(
            hook_code_region.address(),
            inject_point,
            injectable_code.clone(),
        );
        process.write(hook_code_region.address(), hook_code)?;

        let inject_code = get_jpm_inject_point(
            inject_point,
            hook_code_region.address(),
            original_code.inner().len() as u8,
        );
        process.write(inject_point, inject_code)?;

        Ok(InjectHandle {
            original_code,
            inject_address: inject_point,
            hook_code_region,
            hook_data_region1: injectable_memory,
            process,
        })
    }

    /// # Warning
    /// Original code length should be in the range of 5 to 8 bytes inclusive.
    ///
    /// Otherwise `panic!` will be called.
    fn get_jpm_inject_point(from: UPtr, to: UPtr, original_size: u8) -> Vec<u8> {
        assert!((5..=8).contains(&original_size));
        let mut ops: dynasmrt::VecAssembler<X64Relocation> = dynasmrt::VecAssembler::new(0);
        let offset = calc_offset(from, to, original_size);

        dynasm!(ops // jump to new_address
            ; .arch x64
            ; jmp offset as i32
        );

        let mut result = ops.finalize().unwrap();
        result.resize(original_size as usize, 0x90);

        assert_eq!(
            result.len(),
            original_size as usize,
            "from: 0x{:X} to: 0x{:X} raw:{}",
            from,
            to,
            hex_to_string(result)
        );
        result
    }

    fn get_code_cave(address: UPtr, return_addr: UPtr, code: Vec<u8>) -> Vec<u8> {
        let mut ops: dynasmrt::VecAssembler<X64Relocation> = dynasmrt::VecAssembler::new(address);

        ops.extend(&code);

        dynasm!(ops
            ; .arch x64
            ; jmp return_addr as i32
        );

        let result = ops.finalize().unwrap();
        assert_eq!(result.len(), code.len() + 5);
        result
    }

    fn calc_offset(from: UPtr, to: UPtr, original_size: u8) -> UPtr {
        to.overflowing_sub(from).0 + 1 - original_size as usize
    }

    #[cfg(test)]
    mod tests {
        use super::super::hex_to_string;
        use super::*;

        #[test]
        fn get_jmp_assembly_test() {
            assert_eq!(
                hex_to_string(get_jpm_inject_point(0x23D1787A38B, 0x23D17910000, 6)),
                "E9 70 5C 09 00 90".to_string()
            ); // short jmp
            assert_eq!(
                hex_to_string(get_jpm_inject_point(0x2737B9E95DB, 0x2737B870000, 6)),
                "E9 20 6A E8 FF 90".to_string()
            ); // short jmp
            assert_eq!(
                hex_to_string(get_jpm_inject_point(0x22EEAF7ABEB, 0x22EE8F40000, 6)),
                "E9 10 54 FC FD 90".to_string()
            ); // short jmp
               // todo: разобраться, влияет ли дальность прыжка на количество итоговых байт
               // assert_eq!(hex_to_string(get_jmp_assembly(0x24C7F00E55B, 0x65D47910000)), "FF 25 91 47 4D 02".to_string()); // long jmp
        }
    }
}

fn hex_to_string(vec: Vec<u8>) -> String {
    let mut buf = Vec::new();
    for i in &vec {
        buf.push(format!("{:02X}", i));
    }
    buf.join(" ")
}

/// # Warning
/// This function blocks the current thread in place using Tokio's `block_in_place` function.
/// Use with caution as blocking the thread can lead to performance issues and potential deadlocks.
pub fn do_async<F: core::future::Future>(future: F) -> F::Output {
    // Block the current thread in place using Tokio's `block_in_place` function.
    tokio::task::block_in_place(|| {
        // Use the Tokio runtime's handle to block on the given future.
        Handle::current().block_on(future)
    })
}

#[cfg(test)]
mod tests {
    use std::{borrow::Borrow, fmt::Pointer, mem::size_of, sync::Arc};

    use faithe::{
        process::Process,
        types::access_rights::{PROCESS_VM_OPERATION, PROCESS_VM_READ},
    };
    use tokio::{process::Command, time::sleep};

    use std::future::Future;

    use crate::assembly::inject::{memory_controller::Error, MemoryController, MemoryRegion};

    #[tokio::test]
    async fn _memory_controller() {
        let process = Arc::new(
            Process::open_by_name(
                "explorer.exe",
                false,
                PROCESS_VM_READ | PROCESS_VM_OPERATION,
            )
            .unwrap(),
        );
        println!("Process id: {:?}", process.id());
        let region = MemoryRegion::new_rw_region(10, process);
        let mut controller = MemoryController::new(region);

        type Type1 = u8;
        type Type2 = u16;
        type Type3 = i32;
        let type1_name = "Name for Type1";
        let type2_name = "Name for Type2";
        let type3_name = "Name for Type3";
        let test_find_name = "Name for Test";

        let access1 = controller.rent_memory::<Type1>(None).unwrap();

        {
            // Perform a read operation on a valid address
            println!("{:?}", access1);
            let result = access1.read().unwrap();
            assert_eq!(result, Type1::default());

            // Perform a write operation on a valid address
            let value1 = 20;
            let bytes_written = access1.write(value1).unwrap();
            assert_eq!(bytes_written, size_of::<Type1>());

            // Check that the value was written correctly
            let result = access1.read().unwrap();
            assert_eq!(result, value1);
        }

        {
            let _access = controller.rent_memory::<()>(Some(test_find_name)).unwrap();

            // Trying to remove this rental in controller by invalid name
            match controller.release_memory_by_name("invalid name blah-blah") {
                Ok(_) => panic!("Invalid name was used, but no error was returned"),
                Err(e) => assert!(matches!(e, Error::InvalidName { .. })),
            }

            // Trying to remove this rental in controller by valid name
            controller.release_memory_by_name(test_find_name).unwrap();

            let _must_dropped = controller.rent_memory::<()>(Some(test_find_name)).unwrap();
        }

        // trying to remove dropped rental
        match controller.release_memory_by_name(test_find_name) {
            Ok(_) => panic!("Dropped rental was used, but no error was returned"),
            Err(e) => assert!(matches!(e, Error::InvalidName { .. })),
        }

        todo!()
    }

    // #[tokio::test]
    // async fn test_read_invalid_address() {
    //     let region = MemoryRegion::new(/* initialize your memory region */);
    //     let controller = MemoryController::new(region).await;
    //     let access = MemoryAccess {
    //         rent: &RentalInfo {
    //             name: None,
    //             relative_address: 0,
    //             size: 100,
    //         },
    //         owner: Arc::downgrade(&controller),
    //     };

    //     // Perform a read operation on an invalid address
    //     let result: Result<u32, Error> = access.read(0x2000).await;

    //     // Assert that the read operation failed with an InvalidAddress error
    //     assert!(result.is_err());
    //     assert_eq!(result.unwrap_err(), Error::InvalidAddress);
    // }

    // #[tokio::test]
    // async fn test_write_valid_address() {
    //     let region = MemoryRegion::new(/* initialize your memory region */);
    //     let controller = MemoryController::new(region).await;
    //     let access = MemoryAccess {
    //         rent: &RentalInfo {
    //             name: None,
    //             relative_address: 0,
    //             size: 100,
    //         },
    //         owner: Arc::downgrade(&controller),
    //     };

    //     // Perform a write operation on a valid address
    //     let value: u32 = /* value to write */;
    //     let result: Result<usize, Error> = access.write(0x1000, &value).await;

    //     // Assert that the write operation was successful
    //     assert!(result.is_ok());
    //     assert_eq!(result.unwrap(), /* expected number of bytes written */);
    // }

    // #[tokio::test]
    // async fn test_write_invalid_address() {
    //     let region = MemoryRegion::new(/* initialize your memory region */);
    //     let controller = MemoryController::new(region).await;
    //     let access = MemoryAccess {
    //         rent: &RentalInfo {
    //             name: None,
    //             relative_address: 0,
    //             size: 100,
    //         },
    //         owner: Arc::downgrade(&controller),
    //     };

    //     // Perform a write operation on an invalid address
    //     let value: u32 = /* value to write */;
    //     let result: Result<usize, Error> = access.write(0x2000, &value).await;

    //     // Assert that the write operation failed with an InvalidAddress error
    //     assert!(result.is_err());
    //     assert_eq!(result.unwrap_err(), Error::InvalidAddress);
    // }
}
