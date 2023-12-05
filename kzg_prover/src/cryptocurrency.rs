#[derive(Debug, Clone)]
pub struct Cryptocurrency {
    pub name: String,
    pub chain: String,
}

impl Cryptocurrency {
    pub fn init_empty() -> Self {
        Cryptocurrency {
            name: "".to_string(),
            chain: "".to_string(),
        }
    }
}
