pub mod analysis {
    pub mod collect;
    pub mod executable;
    pub mod patterns;
    pub mod types;
    pub mod utils {
        pub mod count;
        pub mod format;
        pub mod print;
    }
}

use std::env;
use std::io::{self};

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
    use crate::analysis::utils::format::format_number;
    use crate::analysis::utils::print::print_boxed_section;

    let (output, set_blocks, summary_lines) = analyze_and_collect(assembly_file_path)?;

    match output_format {
        OutputFormat::Pretty => {
            // Use the display path (original executable path) if provided, otherwise use the assembly path
            let display_file_path = display_path.unwrap_or(&output.file);
            println!(
                "Analyzed {} ({} lines) in {:.2} seconds (avg {} lines/sec)",
                display_file_path,
                format_number(output.total_lines),
                output.elapsed_secs,
                format_number(output.avg_lines_per_sec as usize)
            );
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
            print_boxed_section(
                &final_lines,
                &separator_indices,
                Some("Instruction Extension Usage"),
            );
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
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
    let (executable_files, assembly_files): (Vec<String>, Vec<String>) =
        input_files.into_iter().partition(|file| {
            use crate::analysis::executable::ExecutableProcessor;
            ExecutableProcessor::is_executable(file)
        });

    if let Some(mode) = output_mode {
        let out_path = output_path.expect("Output path required after --json/--toml");
        let mut results = Vec::new();

        // Process assembly files in parallel using rayon
        let assembly_results: Vec<AnalysisOutput> = assembly_files
            .par_iter()
            .filter_map(|file_path| match analyze_and_collect(file_path) {
                Ok((output, _, _)) => Some(output),
                Err(e) => {
                    eprintln!("Error analyzing assembly file {}: {}", file_path, e);
                    None
                }
            })
            .collect();

        results.extend(assembly_results);

        // Process executable files using objdump
        if !executable_files.is_empty() {
            use crate::analysis::executable::ExecutableProcessor;
            match ExecutableProcessor::new() {
                Ok(processor) => {
                    match processor.analyze_executables(&executable_files) {
                        Ok(mut exec_results) => results.append(&mut exec_results),
                        Err(e) => eprintln!("Error processing executables: {}", e),
                    }

                    // Clean up temp files
                    let _ = processor.cleanup();
                }
                Err(e) => eprintln!("Failed to initialize executable processor: {}", e),
            }
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
        assembly_files.par_iter().for_each(|file_path| {
            match analyze_and_output(file_path, OutputFormat::Pretty, None) {
                Ok(()) => {}
                Err(e) => eprintln!("Error analyzing assembly file {}: {}", file_path, e),
            }
        });

        // Process executable files
        if !executable_files.is_empty() {
            use crate::analysis::executable::ExecutableProcessor;
            match ExecutableProcessor::new() {
                Ok(processor) => {
                    // Process executables and get paths to assembly files
                    match processor.process_executables_parallel(&executable_files) {
                        Ok(processed_files) => {
                            // Process the assembly files in parallel using rayon
                            processed_files
                                .par_iter()
                                .for_each(|(original_path, asm_path)| {
                                    match analyze_and_output(
                                        &asm_path,
                                        OutputFormat::Pretty,
                                        Some(original_path),
                                    ) {
                                        Ok(()) => {}
                                        Err(e) => eprintln!(
                                            "Error analyzing executable {}: {}",
                                            original_path, e
                                        ),
                                    }
                                });
                        }
                        Err(e) => eprintln!("Error processing executables: {}", e),
                    }

                    // Clean up temp files
                    let _ = processor.cleanup();
                }
                Err(e) => eprintln!("Failed to initialize executable processor: {}", e),
            }
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
