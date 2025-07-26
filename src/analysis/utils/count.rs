use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io;

pub fn count_lines(path: &str) -> io::Result<usize> {
    const CHUNK_SIZE: usize = 1024 * 1024 * 8;

    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let len = mmap.len();

    let chunks: Vec<&[u8]> = (0..len)
        .step_by(CHUNK_SIZE)
        .map(|start| {
            let end = (start + CHUNK_SIZE).min(len);
            &mmap[start..end]
        })
        .collect();

    let mut total = chunks
        .par_iter()
        .map(|chunk| bytecount::count(chunk, b'\n'))
        .sum();

    if len > 0 && mmap[len - 1] != b'\n' {
        total += 1;
    }

    Ok(total)
}
