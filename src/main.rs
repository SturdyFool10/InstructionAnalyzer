pub mod analysis {
    pub mod collect;
    pub mod patterns;
    pub mod types;
    pub mod utils {
        pub mod count;
        pub mod format;
        pub mod print;
    }
}

// Global variable to track if we're in the process of cleaning up
static mut CLEANING_UP: bool = false;

use std::env;
use std::io::{self, Write};

use glob::glob;
use rayon::prelude::*;
use serde::Serialize;
use serde_json;
use std::collections::HashSet;
use toml;

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Pretty,
}

fn sanitize_path_for_toml(path: &str) -> String {
    path.replace(['/', '\\', ' ', '.', ':'], "_")
}
fn analyze_and_output(
    assembly_file_path: &str,
    output_format: OutputFormat,
    display_path: Option<&str>,
) -> std::io::Result<()> {
    use crate::analysis::collect::analyze_and_collect;
    use crate::analysis::utils::print::print_boxed_section;

    // Verify file exists before attempting to read it
    if !std::path::Path::new(assembly_file_path).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", assembly_file_path),
        ));
    }

    // Analyze silently without progress messages
    let (output, set_blocks, summary_lines) = analyze_and_collect(assembly_file_path)?;

    match output_format {
        OutputFormat::Pretty => {
            // Use the display path (original executable path) if provided, otherwise use the assembly path
            let display_file_path = display_path.unwrap_or(&output.file);

            // Prepare output content
            let mut all_lines: Vec<String> = Vec::new();
            let mut separator_indices: Vec<usize> = Vec::new();
            let mut line_count = 0;

            for (i, block) in set_blocks.iter().enumerate() {
                for line in block {
                    all_lines.push(line.clone());
                    line_count += 1;
                }
                if i != set_blocks.len() - 1 {
                    separator_indices.push(line_count - 1);
                }
            }

            if !set_blocks.is_empty() && !summary_lines.is_empty() {
                separator_indices.push(line_count - 1);
            }

            for line in &summary_lines {
                all_lines.push(line.clone());
                line_count += 1;
            }

            let final_lines: Vec<String> = all_lines
                .iter()
                .filter(|l| !l.is_empty())
                .cloned()
                .collect();

            // Only print the filename at the top of the output
            println!("\nResults for: {}", display_file_path);
            print_boxed_section(
                &final_lines,
                &separator_indices,
                Some("Instruction Extension Usage"),
            );
        }
    }
    Ok(())
}

use std::sync::atomic::{AtomicUsize, Ordering};

fn main() -> io::Result<()> {
    // Clean up any leftover temp directories
    let temp_pattern = std::env::temp_dir().join("simd_analyzer_temp_*");
    if let Ok(paths) = glob::glob(&temp_pattern.to_string_lossy()) {
        for path in paths.filter_map(Result::ok) {
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }

    use crate::analysis::collect::analyze_and_collect;
    use crate::analysis::types::AnalysisOutput;
    use crate::analysis::utils::print::print_instruction_sets;

    let args: Vec<String> = env::args().collect();

    if args.len() == 1
        || args
            .iter()
            .any(|a| a == "-h" || a == "--help" || a == "/?" || a == "-help" || a == "/help")
    {
        print_usage(&args[0]);
        return Ok(());
    }

    let mut input_files_set = HashSet::new();
    let mut output_mode = None;
    let mut output_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                output_mode = Some("json");
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].clone());
                    break;
                }
            }
            "--toml" => {
                output_mode = Some("toml");
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].clone());
                    break;
                }
            }
            arg => {
                // Wildcard expansion and deduplication
                if arg.contains('*') || arg.contains('?') || arg.contains('[') || arg.contains('{')
                {
                    match glob(arg) {
                        Ok(paths) => {
                            let mut found_any = false;
                            for entry in paths {
                                match entry {
                                    Ok(path) => {
                                        input_files_set.insert(path.display().to_string());
                                        found_any = true;
                                    }
                                    Err(e) => {
                                        eprintln!("Error with path from pattern {}: {}", arg, e)
                                    }
                                }
                            }
                            if !found_any {
                                eprintln!("Warning: Pattern '{}' didn't match any files", arg);
                            }
                        }
                        Err(e) => eprintln!("Invalid glob pattern '{}': {}", arg, e),
                    }
                } else {
                    input_files_set.insert(arg.to_string());
                }
                i += 1;
            }
        }
    }
    let mut input_files: Vec<String> = input_files_set.into_iter().collect();
    // Sort input files descending by size (largest first)
    input_files.sort_by(|a, b| {
        let a_size = std::fs::metadata(a).map(|m| m.len()).unwrap_or(0);
        let b_size = std::fs::metadata(b).map(|m| m.len()).unwrap_or(0);
        b_size.cmp(&a_size)
    });

    if args.iter().any(|a| a == "--info") {
        print_instruction_sets();
        return Ok(());
    }

    if input_files.is_empty() {
        println!(
            "Usage: instruction_extension_analyzer [file1 file2 ... | wildcards] [--json output.json | --toml output.toml]"
        );
        print_instruction_sets();
        return Ok(());
    }

    // Separate executable files from assembly files
    // Set up panic and termination handlers for cleanup
    use std::panic;
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        eprintln!("Error occurred: {}", panic_info);
        unsafe {
            CLEANING_UP = true;
        }
        default_hook(panic_info);
    }));

    println!("Scanning {} input files...", input_files.len());
    std::io::stdout().flush().ok();

    // Identify executables
    let mut assembly_files = Vec::new();
    let mut executable_files = Vec::new();

    for file in input_files {
        let path = std::path::Path::new(&file);
        if !path.exists() {
            eprintln!("Warning: File not found: {}", file);
            continue;
        }

        if path.extension().map_or(false, |ext| {
            ext == "exe" || ext == "dll" || ext == "so" || ext == "dylib" || ext == "o"
        }) {
            // Just collect executable files without verbose output
            executable_files.push(file);
        } else {
            assembly_files.push(file);
        }
    }

    println!(
        "Found {} assembly files, {} executable files",
        assembly_files.len(),
        executable_files.len()
    );

    // Register a termination handler to clean up temp files
    let temp_dir = std::env::temp_dir().join(format!("simd_analyzer_temp_{}", std::process::id()));
    let temp_dir_clone = temp_dir.clone();

    ctrlc::set_handler(move || {
        println!("Cleaning up and exiting...");
        if temp_dir_clone.exists() {
            let _ = std::fs::remove_dir_all(&temp_dir_clone);
        }
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    if let Some(mode) = output_mode {
        let out_path = output_path.expect("Output path required after --json/--toml");
        let mut results = Vec::new();

        // Process assembly files in parallel using rayon
        if !assembly_files.is_empty() {
            println!("Analyzing {} assembly files...", assembly_files.len());
            let assembly_results: Vec<AnalysisOutput> = assembly_files
                .par_iter()
                .filter_map(|file_path| match analyze_and_collect(file_path) {
                    Ok((output, _, _)) => Some(output),
                    Err(e) => {
                        eprintln!("Error analyzing {}: {}", file_path, e);
                        None
                    }
                })
                .collect();

            println!("Completed {} assembly files", assembly_results.len());
            results.extend(assembly_results);
        }

        // Process executable files using objdump
        if !executable_files.is_empty() {
            println!(
                "Processing {} executables with objdump...",
                executable_files.len()
            );
            // Initialize for executable processing
            // Create a temporary directory for objdump output
            let temp_dir =
                std::env::temp_dir().join(format!("simd_analyzer_temp_{}", std::process::id()));
            if !temp_dir.exists() {
                std::fs::create_dir_all(&temp_dir)?;
                // Temp directory created silently
            }

            // Get objdump location from environment variable
            let objdump_path = match std::env::var("OBJDUMP_LOCATION") {
                Ok(path) => path,
                Err(_) => if cfg!(target_os = "windows") {
                    "objdump.exe"
                } else {
                    "objdump"
                }
                .to_string(),
            };

            // Using objdump without verbose message

            // Process each executable
            let mut exec_results = Vec::new();

            for exe_path in &executable_files {
                // Process each executable with minimal output

                // Create a unique output file for this executable
                let file_name = std::path::Path::new(exe_path)
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("unknown"))
                    .to_string_lossy();

                let output_file = temp_dir.join(format!(
                    "{}_{}.asm",
                    file_name,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                ));

                // Run objdump
                // Disassembly happens silently
                let status = std::process::Command::new(&objdump_path)
                    .arg("-d")
                    .arg("--section=.text")
                    .arg(exe_path)
                    .stdout(std::fs::File::create(&output_file).unwrap_or_else(|_| {
                        eprintln!("Error creating output file");
                        std::process::exit(1);
                    }))
                    .status();

                match status {
                    Ok(exit_status) if exit_status.success() => {
                        // Successful disassembly

                        // Verify the output file exists and has content
                        match std::fs::metadata(&output_file) {
                            Ok(metadata) if metadata.len() > 0 => {
                                // Assembly generated

                                // Analyze the disassembly
                                match analyze_and_collect(&output_file.to_string_lossy()) {
                                    Ok((mut output, _, _)) => {
                                        // Replace the file path with the original executable path
                                        output.file = exe_path.clone();
                                        exec_results.push(output);
                                        // Analysis complete
                                    }
                                    Err(e) => eprintln!("Error analyzing {}: {}", exe_path, e),
                                }
                            }
                            _ => eprintln!(
                                "Error: Empty or missing disassembly file for {}",
                                exe_path
                            ),
                        }
                    }
                    Ok(_) => eprintln!("objdump failed for {}", exe_path),
                    Err(e) => eprintln!("Error running objdump: {}", e),
                }
            }

            // Add results to the main results list
            results.append(&mut exec_results);

            // Clean up temporary directory silently
            let _ = std::fs::remove_dir_all(temp_dir);
        }
        if mode == "json" {
            #[derive(Serialize)]
            struct JsonWrapper {
                analysis_results: Vec<AnalysisOutput>,
            }
            let json_wrapper = JsonWrapper {
                analysis_results: results,
            };
            let json = serde_json::to_string_pretty(&json_wrapper).unwrap();
            std::fs::write(&out_path, json).expect("Failed to write JSON output");
        } else if mode == "toml" {
            use std::collections::BTreeMap;
            #[derive(Serialize)]
            struct TomlMultiFile {
                #[serde(flatten)]
                files: BTreeMap<String, Vec<AnalysisOutput>>,
            }
            let mut files = BTreeMap::new();
            for result in results.into_iter() {
                let key = sanitize_path_for_toml(&result.file);
                files.entry(key).or_insert_with(Vec::new).push(result);
            }
            let toml_wrapper = TomlMultiFile { files };
            let toml = toml::to_string_pretty(&toml_wrapper).unwrap();
            let toml = toml.replace("}\n[", "}\n\n[");
            std::fs::write(&out_path, toml).expect("Failed to write TOML output");
        }
    } else {
        // Process assembly files in parallel using rayon
        if !assembly_files.is_empty() {
            println!("Analyzing {} assembly files...", assembly_files.len());
            let completed = AtomicUsize::new(0);
            let total = assembly_files.len();
            assembly_files.par_iter().for_each(|file_path| {
                match analyze_and_output(file_path, OutputFormat::Pretty, None) {
                    Ok(()) => {
                        let current = completed.fetch_add(1, Ordering::SeqCst) + 1;
                        if current % 5 == 0 || current == total {
                            println!("Completed {}/{} assembly files", current, total);
                        }
                    }
                    Err(e) => eprintln!("Error analyzing file {}: {}", file_path, e),
                }
            });
        }

        // Process executable files
        if !executable_files.is_empty() {
            println!("Processing {} executables...", executable_files.len());
            std::io::stdout().flush().ok();

            // Create a temporary directory for objdump output
            let temp_dir =
                std::env::temp_dir().join(format!("simd_analyzer_temp_{}", std::process::id()));
            if !temp_dir.exists() {
                std::fs::create_dir_all(&temp_dir)?;
            }

            // Get objdump location from environment variable
            let objdump_path = match std::env::var("OBJDUMP_LOCATION") {
                Ok(path) => path,
                Err(_) => if cfg!(target_os = "windows") {
                    "objdump.exe"
                } else {
                    "objdump"
                }
                .to_string(),
            };

            // Process each executable in parallel
            let completed = AtomicUsize::new(0);
            let total = executable_files.len();
            executable_files.par_iter().for_each(|exe_path| {
                // Create a unique output file for this executable
                let file_name = std::path::Path::new(exe_path)
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("unknown"))
                    .to_string_lossy();

                let output_file = temp_dir.join(format!(
                    "{}_{}.asm",
                    file_name,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                ));

                // Run objdump silently
                let status = std::process::Command::new(&objdump_path)
                    .arg("-d")
                    .arg("--section=.text")
                    .arg(exe_path)
                    .stdout(std::fs::File::create(&output_file).unwrap_or_else(|_| {
                        eprintln!("Error creating output file");
                        std::process::exit(1);
                    }))
                    .status();

                match status {
                    Ok(exit_status) if exit_status.success() => {
                        // Verify the output file exists and has content
                        match std::fs::metadata(&output_file) {
                            Ok(metadata) if metadata.len() > 0 => {
                                // Analyze the disassembly
                                match analyze_and_output(
                                    &output_file.to_string_lossy(),
                                    OutputFormat::Pretty,
                                    Some(exe_path),
                                ) {
                                    Ok(()) => {
                                        let current = completed.fetch_add(1, Ordering::SeqCst) + 1;
                                        if current % 5 == 0 || current == total {
                                            println!("Completed {}/{} executables", current, total);
                                        }
                                    }
                                    Err(e) => eprintln!("Error analyzing {}: {}", exe_path, e),
                                }
                            }
                            _ => eprintln!(
                                "Error: Empty or missing disassembly file for {}",
                                exe_path
                            ),
                        }
                    }
                    Ok(_) => eprintln!("objdump failed for {}", exe_path),
                    Err(e) => eprintln!("Error running objdump: {}", e),
                }
            });

            // Clean up temporary directory silently
            let _ = std::fs::remove_dir_all(temp_dir);
        }
    }

    Ok(())
}

fn print_usage(program: &str) {
    use colored::*;
    let exe = std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_else(|| program.into());
    println!(
        "{}",
        format!("SIMD Analyzer - Instruction Extension Usage Analyzer")
            .bold()
            .bright_cyan()
    );
    println!(
        "{}",
        format!("Usage: {} <assembly_file>... [options]", exe).bright_white()
    );
    println!();
    println!("{}", "Options:".bright_magenta());
    println!("  {}", "<assembly_file>...".bright_yellow());
    println!(
        "      One or more assembly files or executables to analyze. You can specify multiple files in a single call.",
    );
    println!("      Wildcards are supported (e.g., *.s, file?.asm, bin/[a-z]*.obj)",);
    println!(
        "      Executables (EXE, DLL, SO, etc.) will be automatically disassembled using objdump.",
    );
    println!("      Set OBJDUMP_LOCATION environment variable to specify objdump's path.",);
    println!(
        "  {}         Print this help message",
        "-h, --help, -help, /?, /help".bright_yellow()
    );
    println!(
        "  {}    Output results in JSON format to <output_file>",
        "--json <output_file>".bright_yellow()
    );
    println!(
        "  {}    Output results in TOML format to <output_file>",
        "--toml <output_file>".bright_yellow()
    );
    println!(
        "  {}   Print information about supported instruction sets",
        "--info".bright_yellow()
    );
    println!();
    println!("{}", "Example:".bright_magenta());
    println!(
        "  {} {} --json results.json",
        exe,
        "my_binary.s".bright_green()
    );
    println!(
        "  {} {} --toml results.toml",
        exe,
        "my_binary.s".bright_green()
    );
    println!(
        "  {} {} {}",
        exe,
        "*.s".bright_green(),
        "bin/*.asm".bright_green()
    );
    println!("  {} {} --info", exe, "my_binary.s".bright_green());
    println!();
    println!(
        "{}",
        "For more information, see the README or documentation.".bright_white()
    );
}
