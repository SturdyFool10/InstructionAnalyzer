use crate::analysis::collect::analyze_and_collect;
use crate::analysis::types::AnalysisOutput;
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

pub struct ExecutableProcessor {
    objdump_path: String,
    temp_dir: PathBuf,
}

impl ExecutableProcessor {
    pub fn new() -> io::Result<Self> {
        // Get objdump location from environment variable or use default
        let objdump_path = match env::var("OBJDUMP_LOCATION") {
            Ok(path) => path,
            Err(_) => {
                // Try to find objdump in PATH
                let default_path = if cfg!(target_os = "windows") {
                    "objdump.exe"
                } else {
                    "objdump"
                };

                // Test if the default path works
                match Command::new(default_path).arg("--version").output() {
                    Ok(_) => default_path.to_string(),
                    Err(e) => {
                        eprintln!("Error finding objdump: {}", e);
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            "objdump not found in PATH and OBJDUMP_LOCATION environment variable not set",
                        ));
                    }
                }
            }
        };

        // Create a temporary directory for objdump output files
        // Add process ID to avoid conflicts when multiple instances are running
        let temp_dir = env::temp_dir().join(format!("simd_analyzer_temp_{}", std::process::id()));
        if !temp_dir.exists() {
            fs::create_dir_all(&temp_dir)?;
        }

        Ok(Self {
            objdump_path,
            temp_dir,
        })
    }

    /// Check if a file is likely an executable
    pub fn is_executable(file_path: &str) -> bool {
        let path = Path::new(file_path);

        // Check extension for common executable formats
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if ["exe", "dll", "so", "dylib", "o", "obj", "a", "lib"].contains(&ext_str.as_str()) {
                return true;
            }
        }

        // If no extension, check file header (this is a basic implementation)
        if let Ok(mut file) = fs::File::open(path) {
            use std::io::Read;
            let mut buffer = [0; 4];
            if file.read_exact(&mut buffer).is_ok() {
                // Check for common executable headers
                // MZ header (Windows PE)
                if buffer[0] == 0x4D && buffer[1] == 0x5A {
                    return true;
                }

                // ELF header
                if buffer[0] == 0x7F && buffer[1] == 0x45 && buffer[2] == 0x4C && buffer[3] == 0x46
                {
                    return true;
                }

                // Mach-O header (macOS)
                if (buffer[0] == 0xFE
                    && buffer[1] == 0xED
                    && buffer[2] == 0xFA
                    && buffer[3] == 0xCE)
                    || (buffer[0] == 0xCE
                        && buffer[1] == 0xFA
                        && buffer[2] == 0xED
                        && buffer[3] == 0xFE)
                    || (buffer[0] == 0xCF
                        && buffer[1] == 0xFA
                        && buffer[2] == 0xED
                        && buffer[3] == 0xFE)
                    || (buffer[0] == 0xFE
                        && buffer[1] == 0xED
                        && buffer[2] == 0xFA
                        && buffer[3] == 0xCF)
                {
                    return true;
                }
            }
        }

        false
    }

    /// Process an executable file and return the assembly output path
    pub fn process_executable(&self, executable_path: &str) -> io::Result<String> {
        let path = Path::new(executable_path);
        let _file_name = path
            .file_name()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Invalid file path"))?
            .to_string_lossy();

        // Create a unique temporary file for the output
        // Include a sanitized version of the original filename for better identification
        let file_stem = Path::new(executable_path)
            .file_stem()
            .unwrap_or_else(|| std::ffi::OsStr::new("unknown"))
            .to_string_lossy()
            .replace(|c: char| !c.is_alphanumeric(), "_");

        let output_path = self.temp_dir.join(format!(
            "{}_asm_{:x}.txt",
            file_stem,
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));

        // Run objdump to disassemble the executable
        // Use flags similar to Rust's --emit-asm format
        // Run objdump to disassemble the executable
        let status = Command::new(&self.objdump_path)
            .arg("-d") // Disassemble
            .arg("--section=.text") // Only disassemble code sections
            .arg(executable_path)
            .stdout(std::fs::File::create(&output_path)?)
            .status()?;

        if !status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("objdump failed with status: {}", status),
            ));
        }

        Ok(output_path.to_string_lossy().to_string())
    }

    /// Process a list of executable files in parallel using rayon
    pub fn process_executables_parallel(
        &self,
        executable_paths: &[String],
    ) -> io::Result<Vec<(String, String)>> {
        let self_arc = Arc::new(self.clone());

        // Use rayon to process files in parallel
        let results: Vec<io::Result<(String, String)>> = executable_paths
            .par_iter()
            .map(|path| {
                let processor = Arc::clone(&self_arc);
                match processor.process_executable(path) {
                    Ok(asm_path) => Ok((path.clone(), asm_path)),
                    Err(e) => Err(Error::new(
                        ErrorKind::Other,
                        format!("Failed to process {}: {}", path, e),
                    )),
                }
            })
            .collect();

        // Filter out errors and return successful results
        let mut successful_results = Vec::new();
        for result in results {
            match result {
                Ok(path_pair) => successful_results.push(path_pair),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Ok(successful_results)
    }

    /// Analyze a list of executables and return analysis outputs
    pub fn analyze_executables(
        &self,
        executable_paths: &[String],
    ) -> io::Result<Vec<AnalysisOutput>> {
        let start = Instant::now();
        println!(
            "Processing {} executables with objdump at {}...",
            executable_paths.len(),
            self.objdump_path
        );

        // Process all executables in parallel
        let processed = self.process_executables_parallel(executable_paths)?;

        println!(
            "Successfully processed {} out of {} executables",
            processed.len(),
            executable_paths.len()
        );

        // Now analyze all the assembly files in parallel
        let analysis_results: Vec<io::Result<AnalysisOutput>> = processed
            .par_iter()
            .map(|(original_path, asm_path)| {
                match analyze_and_collect(asm_path) {
                    Ok((output, _set_blocks, _summary_lines)) => {
                        // Replace the file path in the output with the original executable path
                        let mut modified_output = output;
                        modified_output.file = original_path.clone();

                        // Print a message to show we're analyzing the original file
                        println!("Analyzing executable: {}", original_path);

                        Ok(modified_output)
                    }
                    Err(e) => Err(Error::new(
                        ErrorKind::Other,
                        format!("Failed to analyze {}: {}", original_path, e),
                    )),
                }
            })
            .collect();

        // Extract successful analyses
        let mut results = Vec::new();
        for result in analysis_results {
            match result {
                Ok(output) => results.push(output),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        let elapsed = start.elapsed();
        println!(
            "Analysis complete. Processed {} executables in {:.2}s",
            results.len(),
            elapsed.as_secs_f64()
        );

        Ok(results)
    }

    /// Clean up temporary files
    pub fn cleanup(&self) -> io::Result<()> {
        // Check if directory exists before attempting to remove it
        if self.temp_dir.exists() {
            // Attempt to remove temporary directory and all its contents
            match fs::remove_dir_all(&self.temp_dir) {
                Ok(_) => Ok(()),
                Err(e) => {
                    eprintln!("Warning: Failed to clean up temporary files: {}", e);
                    // Not returning the error as this is non-critical
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }
}

impl Clone for ExecutableProcessor {
    fn clone(&self) -> Self {
        Self {
            objdump_path: self.objdump_path.clone(),
            temp_dir: self.temp_dir.clone(),
        }
    }
}

impl Drop for ExecutableProcessor {
    fn drop(&mut self) {
        // Attempt to clean up temporary files when the processor is dropped
        // This helps ensure cleanup even if the program terminates unexpectedly
        let temp_dir = self.temp_dir.clone();
        thread::spawn(move || {
            // Wait a moment to ensure files aren't still in use
            thread::sleep(Duration::from_millis(100));
            if temp_dir.exists() {
                let _ = fs::remove_dir_all(&temp_dir);
            }
        });
    }
}
