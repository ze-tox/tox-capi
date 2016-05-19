extern crate cheddar;

use cheddar::Cheddar;


fn main() {
    Cheddar::new().expect("could not read manifest")
        .run_build("include/toxencryptsave.h");
}
