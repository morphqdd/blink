#[derive(Debug)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub section_index: usize,
    pub is_global: bool,
}
