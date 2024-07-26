#![feature(generic_const_exprs)]
pub mod apis;
pub mod tests;

use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub fn save_to_file<P: AsRef<Path>, T: Serialize>(path: P, data: &T) -> Result<(), Box<dyn Error>> {
    let serialized_data = serde_json::to_string(data)?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(serialized_data.as_bytes())?;
    Ok(())
}

pub fn load_from_file<P: AsRef<Path>, T: for<'de> Deserialize<'de>>(
    path: P,
) -> Result<T, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let deserialized_data = serde_json::from_str(&data)?;
    Ok(deserialized_data)
}
