mod inject {
    pub mod sized {
        /// Represents a one instruction sized vector.
        ///
        /// Ensures that the length of the `non-empty` vector does `not exceed 8 bytes`.
        pub struct InstructionSized(Vec<u8>);
        impl InstructionSized {
            pub fn new(vec: Vec<u8>) -> Self {
                assert!(!vec.is_empty() && vec.len() <= 8);
                Self(vec)
            }
            pub fn inner(&self) -> Vec<u8> {
                self.0.clone()
            }
        }
    }

    use crate::{
        assembly::hex_to_string,
        types::{Address, AutoResult, UPtr},
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

    pub use sized::InstructionSized;

    /// Represents a handle for an injected code.
    ///
    /// `Drop` trait is implemented, the structure will safely revert the memory to its original state when `self` dropped.
    pub struct InjectHandle<'a> {
        original_code: InstructionSized,
        inject_address: UPtr,

        hook_code_region: MemoryRegion<'a>,
        hook_data_region: Option<MemoryRegion<'a>>,

        process: &'a Process,
    }
    impl<'a> Drop for InjectHandle<'a> {
        fn drop(&mut self) {
            self.process
                .write(self.inject_address, self.original_code.inner())
                .unwrap();
        }
    }

    /// Represents a memory region.
    ///
    /// `Drop` trait is implemented, so you do not need to manually free unused memory
    pub struct MemoryRegion<'a> {
        address: Address,
        size: usize,
        protection: MemoryProtection,
        process: &'a Process,
    }
    impl<'a> MemoryRegion<'a> {
        /// Allocates a memory region with protection `READ_WRITE_EXECUTE`.
        pub fn new_code_region(address: Address, size: usize, process: &'a Process) -> Self {
            let address = process
                .allocate(
                    address,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    MemoryProtection::READ_WRITE_EXECUTE,
                )
                .unwrap();
            Self {
                address,
                size,
                protection: MemoryProtection::READ_WRITE_EXECUTE,
                process,
            }
        }
        /// Allocates a memory region with protection `READ_WRITE`.
        pub fn new_data_region(address: Address, size: usize, process: &'a Process) -> Self {
            let address = process
                .allocate(
                    address,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    MemoryProtection::READ_WRITE,
                )
                .unwrap();
            Self {
                address,
                size,
                protection: MemoryProtection::READ_WRITE,
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
        fn process(&self) -> &'a Process {
            self.process
        }
    }

    impl<'a> Drop for MemoryRegion<'a> {
        /// Drops the memory region and frees the associated memory.
        fn drop(&mut self) {
            self.process
                .free(self.address, self.size, MEM_RELEASE)
                .unwrap();
        }
    }

    pub fn try_inject<'a>(
        inject_point: UPtr,
        original_code: InstructionSized,
        injectable_code: Vec<u8>,
        injectable_memory: Option<MemoryRegion<'a>>,
        process: &'a Process,
    ) -> AutoResult<InjectHandle<'a>> {
        if original_code.inner().len() < 5 {
            panic!(
                "Original code length should be in the range of 5 to 8 bytes inclusive. Received code: {}",
                hex_to_string(original_code.inner())
            )
        }
        let hook_code_region = MemoryRegion::new_code_region(inject_point, 1000, process);

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
            hook_data_region: injectable_memory,
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
