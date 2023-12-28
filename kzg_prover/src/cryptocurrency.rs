#[derive(Debug, Clone)]
pub struct Cryptocurrency {
    pub name: String,
    pub chain: String,
}

impl Cryptocurrency {
    pub fn init_empty() -> Self {
        Cryptocurrency {
            name: String::new(),
            chain: String::new(),
        }
    }
}
