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
    app_id: String,
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

        // Create a unique ID for this application instance - include PID for extra uniqueness
        let app_id = format!(
            "{:x}_pid{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            std::process::id()
        );

        // Try to create temp dir in current directory first
        let mut temp_dir = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(format!("simd_temp_{}", app_id));

        // If we can't use the current directory, fall back to system temp
        if fs::create_dir_all(&temp_dir).is_err() {
            temp_dir = env::temp_dir().join(format!("simd_analyzer_temp_{}", app_id));
            fs::create_dir_all(&temp_dir)?;
        }

        println!("Created temporary directory at: {}", temp_dir.display());

        // Create a marker file to help identify our temp folders
        let marker_path = temp_dir.join(".simd_analyzer_temp");
        fs::write(&marker_path, &app_id)?;

        // Register a cleanup handler for application exit
        Self::register_cleanup_handler(temp_dir.clone());

        Ok(Self {
            objdump_path,
            temp_dir,
            app_id,
        })
    }

    // Register a cleanup handler to be called when the application exits
    fn register_cleanup_handler(temp_dir: PathBuf) {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            // Clone the path for the handler
            let path_to_clean = temp_dir.clone();

            // Register handler for normal exit
            let _ = ctrlc::set_handler(move || {
                println!("Received interrupt signal, cleaning up...");
                let _ = fs::remove_dir_all(&path_to_clean);
                std::process::exit(0);
            });

            // Register an atexit handler
            std::thread::spawn(move || {
                // This thread will only exit when the process exits
                std::thread::park();
                let _ = fs::remove_dir_all(&temp_dir);
            });
        });
    }

    /// Check if a file is likely an executable
    pub fn is_executable(file_path: &str) -> bool {
        println!("Checking if file is executable: {}", file_path);
        let path = Path::new(file_path);

        // Check extension for common executable formats
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if ["exe", "dll", "so", "dylib", "o", "obj", "a", "lib"].contains(&ext_str.as_str()) {
                println!("Detected executable file: {}", file_path);
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
                    println!("Detected Windows PE executable by header: {}", file_path);
                    return true;
                }

                // ELF header
                if buffer[0] == 0x7F && buffer[1] == 0x45 && buffer[2] == 0x4C && buffer[3] == 0x46
                {
                    println!("Detected ELF executable by header: {}", file_path);
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
                    println!("Detected Mach-O executable by header: {}", file_path);
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

        // Create a unique but consistent temp path for this executable
        // Use file stem and a hash of the full path to avoid collisions
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Convert to absolute path to avoid issues with relative paths
        let abs_executable_path = std::path::Path::new(executable_path)
            .canonicalize()
            .unwrap_or_else(|_| std::path::Path::new(executable_path).to_path_buf());

        let mut hasher = DefaultHasher::new();
        abs_executable_path.display().to_string().hash(&mut hasher);
        let path_hash = hasher.finish();

        // Create the temp path
        // Create the output file - include app_id in the filename to avoid collisions
        // Sanitize the file_stem to avoid any path issues
        let sanitized_stem = file_stem
            .to_string()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>();

        let output_path = self
            .temp_dir
            .join(format!("asm_{}_{:x}.asm", sanitized_stem, path_hash));

        // Double check the temp directory exists
        if !self.temp_dir.exists() {
            std::fs::create_dir_all(&self.temp_dir)?;
        }

        println!("Using temporary directory: {}", self.temp_dir.display());

        // Add a symlink to the original file for easier tracking
        let symlink_info_path = self
            .temp_dir
            .join(format!("{}_source_{:x}.txt", sanitized_stem, path_hash));
        let _ = fs::write(symlink_info_path, executable_path);

        // Run objdump to disassemble the executable
        println!("Starting disassembly of: {}", executable_path);
        println!("Using objdump at: {}", self.objdump_path);
        println!("Output will be saved to: {}", output_path.display());

        // Use absolute path for the executable but avoid Windows extended path format (\\?\)
        let input_path = std::path::Path::new(executable_path);
        let abs_path_buf = if input_path.is_absolute() {
            input_path.to_path_buf()
        } else {
            // Make it absolute by joining with current directory
            let current_dir =
                std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            current_dir.join(input_path)
        };

        // Convert to string and ensure it doesn't have the \\?\ prefix
        let abs_path_str = abs_path_buf
            .to_string_lossy()
            .to_string()
            .replace(r"\\?\", "");

        println!("Using absolute path for executable: {}", abs_path_str);

        let mut cmd = Command::new(&self.objdump_path);
        cmd.arg("-d") // Disassemble
            .arg("--section=.text") // Only disassemble code sections
            .arg(abs_path_str)
            .stdout(std::fs::File::create(&output_path)?)
            .stderr(std::process::Stdio::inherit()); // Show errors to user

        println!("Running command: {:?}", cmd);
        let status = cmd.status()?;

        // Double check that the file was created
        if !output_path.exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "Disassembly file was not created at: {}",
                    output_path.display()
                ),
            ));
        }

        if !status.success() {
            println!("Disassembly failed for: {}", executable_path);
            return Err(Error::new(
                ErrorKind::Other,
                format!("objdump failed with status: {}", status),
            ));
        }

        println!("Successfully disassembled: {}", executable_path);
        // Return path as a normal string without any extended path format
        let output_path_str = output_path
            .to_string_lossy()
            .to_string()
            .replace(r"\\?\", "");

        Ok(output_path_str)
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
                    Ok(asm_path) => {
                        // Verify file exists and has content
                        let asm_path_obj = std::path::Path::new(&asm_path);

                        // Make absolutely sure the path is correct
                        println!("Checking disassembly file at: {}", asm_path_obj.display());

                        if !asm_path_obj.exists() {
                            return Err(Error::new(
                                ErrorKind::NotFound,
                                format!("Disassembly file not found at: {}", asm_path),
                            ));
                        }

                        let metadata = std::fs::metadata(&asm_path);
                        match metadata {
                            Ok(metadata) if metadata.len() > 0 => {
                                println!(
                                    "Found disassembly file: {} (size: {} bytes)",
                                    asm_path_obj.display(),
                                    metadata.len()
                                );

                                // Use the original path string directly
                                Ok((path.clone(), asm_path.clone()))
                            }
                            Ok(_) => Err(Error::new(
                                ErrorKind::Other,
                                format!("Disassembly produced empty output for {}", path),
                            )),
                            Err(e) => Err(Error::new(
                                ErrorKind::Other,
                                format!("Failed to access disassembly for {}: {}", path, e),
                            )),
                        }
                    }
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

        println!(
            "Starting parallel disassembly of {} executables...",
            executable_paths.len()
        );

        // Process all executables in parallel
        let processed = self.process_executables_parallel(executable_paths)?;

        println!(
            "Successfully disassembled {} out of {} executables",
            processed.len(),
            executable_paths.len()
        );

        // Wait a moment to ensure all files are fully written to disk
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Verify all disassembly files exist before starting analysis
        let mut verified_paths: Vec<(String, String)> = Vec::new();

        for (original_path, asm_path) in processed {
            let path = std::path::Path::new(&asm_path);

            // Try with direct file access
            match std::fs::File::open(&path) {
                Ok(_) => {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        println!(
                            "Verified disassembly file exists: {} (size: {} bytes)",
                            path.display(),
                            metadata.len()
                        );
                        // Only add files that actually exist and have content
                        if metadata.len() > 0 {
                            verified_paths.push((original_path, asm_path));
                        } else {
                            eprintln!("Warning: Disassembly file is empty: {}", path.display());
                        }
                    } else {
                        eprintln!("Warning: Could not get metadata for: {}", path.display());
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Disassembly file for {} cannot be opened at {}: {}",
                        original_path,
                        path.display(),
                        e
                    );
                }
            }
        }

        println!(
            "Beginning SIMD instruction analysis of {} disassembled executables...",
            verified_paths.len()
        );

        // Now analyze all the assembly files in parallel
        // Process serially to ensure we don't have file access conflicts
        let mut analysis_results = Vec::new();

        for (original_path, mut asm_path) in verified_paths {
            println!("Analyzing SIMD instructions in: {}", original_path);
            let path_hash = {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                original_path.hash(&mut hasher);
                hasher.finish()
            };

            // Use direct file access with the full path without any conversions
            println!("Reading disassembly from: {}", asm_path);

            // We'll copy the file to a new location before analyzing it to avoid any file access issues
            let copy_path = self
                .temp_dir
                .join(format!("analysis_copy_{}.asm", path_hash));
            match std::fs::copy(&asm_path, &copy_path) {
                Ok(bytes_copied) => {
                    println!(
                        "Copied {} bytes to temporary file: {}",
                        bytes_copied,
                        copy_path.display()
                    );
                    // Use the copied file for analysis
                    let copy_path_str = copy_path.to_string_lossy().to_string();
                    asm_path = copy_path_str;
                }
                Err(e) => {
                    eprintln!("Error copying disassembly file: {}", e);
                    continue;
                }
            }

            match analyze_and_collect(&asm_path) {
                Ok((output, _set_blocks, _summary_lines)) => {
                    // Replace the file path in the output with the original executable path
                    let mut modified_output = output;
                    modified_output.file = original_path.clone();

                    println!("Completed SIMD analysis of: {}", original_path);
                    analysis_results.push(Ok(modified_output));
                }
                Err(e) => {
                    eprintln!("Error analyzing {}: {}", original_path, e);
                    analysis_results.push(Err(Error::new(
                        ErrorKind::Other,
                        format!("Failed to analyze {}: {}", original_path, e),
                    )));
                }
            }
        }

        // Extract successful analyses
        // Extract successful analyses
        let mut results = Vec::new();
        for result in analysis_results {
            match result {
                Ok(output) => results.push(output),
                Err(e) => eprintln!("Analysis error: {}", e),
            }
        }

        let elapsed = start.elapsed();
        println!(
            "Analysis complete. Processed {} executables in {:.2}s",
            results.len(),
            elapsed.as_secs_f64()
        );
        println!("All executable analyses finished successfully");

        Ok(results)
    }

    /// Clean up temporary files
    pub fn cleanup(&self) -> io::Result<()> {
        // Check if directory exists before attempting to remove it
        if self.temp_dir.exists() {
            println!(
                "Cleaning up temporary files in: {}",
                self.temp_dir.display()
            );

            // List files before cleanup for debugging
            if let Ok(entries) = fs::read_dir(&self.temp_dir) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        println!("  Removing: {}", entry.path().display());
                        // Try to remove each file individually in case directory removal fails
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }

            // Attempt to remove temporary directory and all its contents
            match fs::remove_dir_all(&self.temp_dir) {
                Ok(_) => {
                    println!("Temporary files cleaned up successfully");
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Warning: Failed to clean up temporary directory: {}", e);

                    // Try an alternative approach - schedule deletion on process exit
                    if cfg!(target_os = "windows") {
                        // On Windows, we can use a special approach to delete on reboot
                        let temp_dir_str = self.temp_dir.to_string_lossy();
                        let _ = Command::new("cmd")
                            .args(&[
                                "/C",
                                "start",
                                "/b",
                                "cmd",
                                "/c",
                                &format!(
                                    "ping -n 5 127.0.0.1 > nul && rmdir /s /q \"{}\"",
                                    temp_dir_str
                                ),
                            ])
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .spawn();
                    }

                    // Not returning the error as this is non-critical
                    Ok(())
                }
            }
        } else {
            println!("No temporary files to clean up");
            Ok(())
        }
    }

    // Static method to clean up any orphaned temp directories from previous runs
    pub fn cleanup_orphaned_temps() -> io::Result<()> {
        println!("Checking for orphaned temporary directories...");

        // Try to find and clean up orphaned temp directories in the current directory
        if let Ok(current_dir) = std::env::current_dir() {
            Self::cleanup_temp_dirs_in(&current_dir)?;
        }

        // Also check the system temp directory
        if let Ok(sys_temp) = env::temp_dir().canonicalize() {
            Self::cleanup_temp_dirs_in(&sys_temp)?;
        }

        Ok(())
    }

    fn cleanup_temp_dirs_in(parent_dir: &Path) -> io::Result<()> {
        if let Ok(entries) = fs::read_dir(parent_dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir()
                    && path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| {
                            n.starts_with("simd_temp_") || n.starts_with("simd_analyzer_temp_")
                        })
                        .unwrap_or(false)
                {
                    // Check if it has our marker file
                    if path.join(".simd_analyzer_temp").exists() {
                        println!("Found orphaned temp directory: {}", path.display());
                        if let Err(e) = fs::remove_dir_all(&path) {
                            println!(
                                "Failed to remove orphaned directory {}: {}",
                                path.display(),
                                e
                            );
                        } else {
                            println!(
                                "Successfully removed orphaned directory: {}",
                                path.display()
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl Clone for ExecutableProcessor {
    fn clone(&self) -> Self {
        Self {
            objdump_path: self.objdump_path.clone(),
            temp_dir: self.temp_dir.clone(),
            app_id: self.app_id.clone(),
        }
    }
}

impl Drop for ExecutableProcessor {
    fn drop(&mut self) {
        // Attempt to clean up temporary files when the processor is dropped
        // This helps ensure cleanup even if the program terminates unexpectedly
        let temp_dir = self.temp_dir.clone();

        // Make a more serious effort to clean up
        if temp_dir.exists() {
            // Immediately try to clean up any files we can
            if let Ok(entries) = fs::read_dir(&temp_dir) {
                for entry in entries.filter_map(Result::ok) {
                    let _ = fs::remove_file(entry.path());
                }
            }

            // Try immediate directory removal
            let _ = fs::remove_dir_all(&temp_dir);

            // Also spawn a cleanup thread as a backup
            thread::spawn(move || {
                // Try multiple times with increasing delays
                for delay_ms in &[100, 500, 1000, 3000] {
                    thread::sleep(Duration::from_millis(*delay_ms));
                    if temp_dir.exists() {
                        // Try to clean up any remaining files first
                        if let Ok(entries) = fs::read_dir(&temp_dir) {
                            for entry in entries.filter_map(Result::ok) {
                                let _ = fs::remove_file(entry.path());
                            }
                        }
                        // Then try to remove the directory
                        if fs::remove_dir_all(&temp_dir).is_ok() {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                // If we still couldn't remove it, on Windows try the delayed deletion approach
                if cfg!(target_os = "windows") && temp_dir.exists() {
                    let temp_dir_str = temp_dir.to_string_lossy();
                    let _ = Command::new("cmd")
                        .args(&["/C", &format!("rmdir /s /q \"{}\"", temp_dir_str)])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                }
            });
        }
    }
}
