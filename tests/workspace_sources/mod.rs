//! The Rust sources of this workspace, for the tests that check a property of every file.

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

/// The directories whose sources are production or test code of this repository, the fuzz targets
/// included although they build as a workspace of their own.
const ROOTS: [&str; 4] = ["crates", "fuzz", "src", "tests"];

/// The workspace root.
pub fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every Rust source file of the workspace, skipping build output.
///
/// # Errors
///
/// Returns the I/O error of the first directory that cannot be read.
pub fn all() -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for directory in ROOTS {
        let directory = root().join(directory);
        if directory.is_dir() {
            collect(&directory, &mut files)?;
        }
    }

    Ok(files)
}

/// Every Rust source under a directory.
fn collect(directory: &Path, into: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, into)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path);
        }
    }

    Ok(())
}
