use blink::linker::Linker;

fn main() -> anyhow::Result<()> {
    Linker::new().link(&["./test_assets/simple_prog/main.0"])
}
