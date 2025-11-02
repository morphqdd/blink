use std::{fs, path::Path};

use byteorder::{LittleEndian, WriteBytesExt};
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
            let buffer = fs::read(&path_to_obj)?;
            let obj = Object::parse(&buffer)?;

            match &obj {
                Object::Elf(elf) => {
                    let out = self.add_elf(elf, &buffer)?;
                    let path = path_to_obj
                        .as_ref()
                        .parent()
                        .ok_or(anyhow::anyhow!("Is a root of path already!"))?;
                    let name = path_to_obj
                        .as_ref()
                        .file_prefix()
                        .ok_or(anyhow::anyhow!("File prefix not found!"))?;
                    let out_path = path.join(&name);
                    fs::write(&out_path, &out)?;

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mut perm = fs::metadata(&out_path)?.permissions();
                        perm.set_mode(0o755);
                        fs::set_permissions(&out_path, perm)?;
                    }
                }
                _ => unimplemented!(),
            }
        }

        Ok(())
    }

    fn add_elf(&mut self, elf: &Elf, buf: &[u8]) -> anyhow::Result<Vec<u8>> {
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

        out.write_u16::<LittleEndian>(2)?; // e_type = ET_EXEC
        out.write_u16::<LittleEndian>(62)?; // e_machine = EM_X86_64
        out.write_u32::<LittleEndian>(1)?; // e_version
        out.write_u64::<LittleEndian>(start_vaddr)?; // e_entry
        out.write_u64::<LittleEndian>(64)?; // e_phoff (immediately after ELF header)
        out.write_u64::<LittleEndian>(0)?; // e_shoff (We don't write section headers)
        out.write_u32::<LittleEndian>(0)?; // e_flags 
        out.write_u16::<LittleEndian>(64)?; // e_ehsize 
        out.write_u16::<LittleEndian>(56)?; // e_phentsize 
        out.write_u16::<LittleEndian>(1)?; // e_phnum 
        out.write_u16::<LittleEndian>(0)?; // e_shentsize 
        out.write_u16::<LittleEndian>(0)?; // e_shnum 
        out.write_u16::<LittleEndian>(0)?; // e_shstrndx

        //Program header (one PT_LOAD)
        out.write_u32::<LittleEndian>(1)?; // p_type = PT_LOAD 
        out.write_u32::<LittleEndian>(5)?; // p_flags = PF_R | PF_X 
        out.write_u64::<LittleEndian>(file_text_offset)?; // p_offset in file 
        out.write_u64::<LittleEndian>(start_vaddr)?; // p_vaddr 
        out.write_u64::<LittleEndian>(start_vaddr)?; // p_paddr 
        out.write_u64::<LittleEndian>(final_text.len() as u64)?; // p_filesz 
        out.write_u64::<LittleEndian>(final_text.len() as u64)?; // p_memsz 
        out.write_u64::<LittleEndian>(0x1000)?; // p_align

        // Pad the file until file_text_offset (so that PT_LOAD p_offset points to this location)
        if out.len() as u64 > file_text_offset {
            return Err(anyhow::anyhow!(
                "Headers exceed chosen file_text_offset; choose larger offset"
            ));
        }
        out.resize(file_text_offset as usize, 0);

        // Append the final text segment
        out.extend_from_slice(&final_text);

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use tempfile::tempdir;

    use crate::linker::Linker;

    #[test]
    fn link_simple_obj() {
        let dir = tempdir().unwrap();
        let mut filename = String::new();
        rand::random_iter()
            .take(5)
            .into_iter()
            .for_each(|x: i32| filename.push_str(&x.to_string()));
        let c_path = dir.path().join(format!("{filename}.c"));
        let o_path = dir.path().join(format!("{filename}.o"));
        let bin_path = dir.path().join(format!("{filename}"));
        assert!(
            fs::write(
                &c_path,
                r"
                int main() {
                    return 20;
                }
            ",
            )
            .is_ok()
        );
        assert!(
            Command::new("gcc")
                .args([
                    "-c",
                    &c_path.to_string_lossy(),
                    "-o",
                    &o_path.to_string_lossy()
                ])
                .spawn()
                .is_ok()
        );
        assert!(Linker::new().link(&[&o_path]).is_ok());
        assert_eq!(Command::new(&bin_path).status().unwrap().code(), Some(20))
    }

    #[test]
    fn link_simple_obj_with_add_operation() {
        let dir = tempdir().unwrap();
        let mut filename = String::new();
        rand::random_iter()
            .take(5)
            .into_iter()
            .for_each(|x: i32| filename.push_str(&x.to_string()));
        let c_path = dir.path().join(format!("{filename}.c"));
        let o_path = dir.path().join(format!("{filename}.o"));
        let bin_path = dir.path().join(format!("{filename}"));
        assert!(
            fs::write(
                &c_path,
                r"
                int main() {
                    int a = 10;
                    int b = 15;
                    return a + b;
                }
            ",
            )
            .is_ok()
        );
        assert!(
            Command::new("gcc")
                .args([
                    "-c",
                    &c_path.to_string_lossy(),
                    "-o",
                    &o_path.to_string_lossy()
                ])
                .spawn()
                .is_ok()
        );
        assert!(Linker::new().link(&[&o_path]).is_ok());
        assert_eq!(Command::new(&bin_path).status().unwrap().code(), Some(25))
    }
}
