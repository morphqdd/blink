use std::{fs, path::Path};

use goblin::{
    Object,
    elf::{Elf, sym::STB_GLOBAL},
};

use crate::linker::symbol::SymbolInfo;

mod symbol;

#[derive(Debug)]
pub struct Linker {
    symbol_table: Vec<symbol::SymbolInfo>,
    base_address: u64,
    text_data: Vec<u8>,
}

impl Linker {
    pub fn new() -> Self {
        Self {
            symbol_table: Vec::with_capacity(100),
            base_address: 0x400000,
            text_data: vec![],
        }
    }
    pub fn link<P: AsRef<Path>>(&mut self, objects: &[P]) -> anyhow::Result<()> {
        for path_to_obj in objects {
            let buffer = fs::read(path_to_obj)?;
            let obj = Object::parse(&buffer)?;

            match &obj {
                Object::Elf(elf) => {
                    self.add_elf(elf, &buffer)?;
                }
                _ => unimplemented!(),
            }
        }

        println!("{:?}", self);
        Ok(())
    }

    fn add_elf(&mut self, elf: &Elf, buf: &[u8]) -> anyhow::Result<()> {
        let mut text_shndx = None;
        for (i, sh) in elf.section_headers.iter().enumerate() {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                if name == ".text" {
                    text_shndx = Some(i);
                    break;
                }
            }
        }

        let text_shndx = text_shndx.ok_or(anyhow::anyhow!("Text section not found!!!"))?;
        let text_sh = &elf.section_headers[text_shndx];
        let text_offset = text_sh.sh_offset as usize;
        let text_size = text_sh.sh_size as usize;
        let text_data = &buf[text_offset..text_offset + text_size];

        let mut main_offset_in_section = None;
        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == "main" {
                    let sec_addr = text_sh.sh_addr as usize;
                    let val = sym.st_value as usize;
                    if sym.st_shndx == text_shndx {
                        main_offset_in_section = Some(val.saturating_sub(sec_addr));
                        break;
                    }
                }
            }
        }

        let main_off = main_offset_in_section
            .ok_or(anyhow::anyhow!("Symbol main not found in section .text"))?;
        // 3) Create a small _start stub that calls main and then invokes exit syscall
        // _start:
        // call main ; E8 <rel32>
        // mov rdi, rax ; 48 89 C7
        // mov eax, 60 ; B8 3C 00 00 00
        // syscall ; 0F 05
        // The call's relative displacement (rel32) will be patched later.
        let mut start_stub: Vec<u8> = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32
            0x48, 0x89, 0xC7, // mov rdi, rax
            0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60
            0x0F, 0x05,
        ]; // syscall

        let start_len = start_stub.len();

        // 4) Layout: for simplicity place the single PT_LOAD segment at file offset 0x1000
        let base_addr: u64 = 0x400000;
        let file_text_offset: u64 = 0x1000; // page-aligned file offset for the loaded segment
        let start_vaddr = base_addr + file_text_offset; // virtual address where our code will be loaded

        // Compute addresses for main and patch the call immediate
        let main_vaddr = start_vaddr + start_len as u64 + main_off as u64;
        let call_site_next = start_vaddr + 5; // call instruction is at offset 0, its end is +5
        let rel = (main_vaddr as i64) - (call_site_next as i64);
        let rel32 = rel as i32; // assume it fits (it will for small test programs)
        start_stub[1..5].copy_from_slice(&rel32.to_le_bytes());

        // 5) Concatenate final .text = start_stub + input object's .text
        let mut final_text: Vec<u8> = Vec::with_capacity(start_len + text_data.len());
        final_text.extend_from_slice(&start_stub);
        final_text.extend_from_slice(text_data);

        // 6) Build minimal ELF64 header + one PT_LOAD program header and write the file
        let mut out: Vec<u8> = Vec::new();

        let mut elf_header = [0u8; 16];
        elf_header[0] = 0x7F;
        elf_header[1] = b'E';
        elf_header[2] = b'L';
        elf_header[3] = b'F';
        elf_header[4] = 2; // ELFCLASS64
        elf_header[5] = 1; // ELFDATA2LSB
        elf_header[6] = 1; // EV_CURRENT
        out.extend_from_slice(&elf_header);

        Ok(())
    }

    // fn merge_sections(&mut self, elf: &Elf) -> goblin::error::Result<()> {
    //     if let Some(sh) = elf
    //         .section_headers
    //         .iter()
    //         .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".text"))
    //     {
    //         let (data, _) = elf.iter_note_sections;
    //         self.text_data.extend_from_slice(data);
    //     }
    //     Ok(())
    // }
}

#[cfg(test)]
mod tests {
    use crate::linker::Linker;

    #[test]
    fn load_simple_obj() {
        assert!(
            Linker::new()
                .link(&["test_assets/simple_prog/main.o"])
                .is_ok()
        )
    }
}
