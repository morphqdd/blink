use blink::linker::Linker;

fn main() -> anyhow::Result<()> {
    Linker::new().link_file("test_assets/simple_prog/main.o")
}
