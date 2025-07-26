use crate::analysis::patterns::get_instruction_patterns;
use crate::analysis::types::{AnalysisOutput, ExtensionSetResult, Occurrence};
use crate::analysis::utils::count::count_lines;
use crate::analysis::utils::format::format_number;
use memmap2::Mmap;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use terminal_size::{Width, terminal_size};

pub fn analyze_and_collect(
    assembly_file_path: &str,
) -> io::Result<(AnalysisOutput, Vec<Vec<String>>, Vec<String>)> {
    let instruction_patterns = get_instruction_patterns();

    let compiled_patterns: HashMap<String, Regex> = instruction_patterns
        .iter()
        .map(|(set_name, pattern)| {
            let regex = Regex::new(pattern).expect("Invalid merged regex pattern");
            (set_name.clone(), regex)
        })
        .collect();

    let mut instruction_counts: HashMap<String, usize> =
        compiled_patterns.keys().map(|k| (k.clone(), 0)).collect();
    let mut matched_instructions: HashMap<String, Vec<String>> = compiled_patterns
        .keys()
        .map(|k| (k.clone(), Vec::new()))
        .collect();

    let total_lines = count_lines(assembly_file_path)?;
    let file = File::open(assembly_file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let mmap_len = mmap.len();

    let start_time = Instant::now();

    let processed_lines = Arc::new(AtomicUsize::new(0));
    let processed_lines_progress = Arc::clone(&processed_lines);
    let progress_start_time = start_time.clone();

    let progress_handle = thread::spawn(move || {
        use colored::*;
        use std::io::{Write, stdout};
        let mut first = true;
        loop {
            let done = processed_lines_progress.load(Ordering::Relaxed);
            let elapsed = progress_start_time.elapsed().as_secs_f64();
            let lines_per_sec = if elapsed > 0.0 {
                done as f64 / elapsed
            } else {
                0.0
            };
            let percent = if total_lines > 0 {
                (done as f64 / total_lines as f64) * 100.0
            } else {
                100.0
            };
            let eta_secs = if lines_per_sec > 0.0 && done < total_lines {
                ((total_lines - done) as f64 / lines_per_sec).ceil() as u64
            } else {
                0
            };
            let (eta_h, eta_m, eta_s) = (eta_secs / 3600, (eta_secs % 3600) / 60, eta_secs % 60);

            let width = if let Some((Width(w), _)) = terminal_size() {
                w as usize
            } else {
                80
            };

            let mut colored_segments = Vec::new();
            colored_segments.push(format!("{}", format_number(done).bright_cyan()));
            colored_segments.push("/".dimmed().to_string());
            colored_segments.push(format!("{}", format_number(total_lines).bright_cyan()));
            colored_segments.push(" ".to_string());
            colored_segments.push("lines".bright_white().to_string());
            colored_segments.push(" (".dimmed().to_string());
            colored_segments.push(format!("{:.1}", percent).bright_yellow().to_string());
            colored_segments.push("%)".dimmed().to_string());
            colored_segments.push(" | ".dimmed().to_string());
            colored_segments.push(format!(
                "{}",
                format_number(lines_per_sec as usize).bright_cyan()
            ));
            colored_segments.push(" ".to_string());
            colored_segments.push("lines/sec".bright_white().to_string());
            colored_segments.push(" | ".dimmed().to_string());
            colored_segments.push("ETA".bright_white().to_string());
            colored_segments.push(" ".to_string());
            colored_segments.push(format!("{:02}", eta_h).bright_green().to_string());
            colored_segments.push(":".dimmed().to_string());
            colored_segments.push(format!("{:02}", eta_m).bright_green().to_string());
            colored_segments.push(":".dimmed().to_string());
            colored_segments.push(format!("{:02}", eta_s).bright_green().to_string());

            let numbers_line = colored_segments.join("");
            let numbers_line_stripped =
                String::from_utf8_lossy(&strip_ansi_escapes::strip(numbers_line.as_bytes()))
                    .to_string();

            let bar_max = if width > numbers_line_stripped.len() + 12 {
                width - numbers_line_stripped.len() - 2
            } else {
                10
            };
            let bar_width = bar_max.max(10).min(60);

            let filled = ((percent / 100.0) * bar_width as f64).floor() as usize;
            let bar = if filled == 0 {
                format!("[>{}]", " ".repeat(bar_width - 1).bright_black())
            } else if filled >= bar_width {
                format!("[{}]", "=".repeat(bar_width).bright_blue())
            } else {
                format!(
                    "[{}>{}]",
                    "=".repeat(filled).bright_blue(),
                    " ".repeat(bar_width - filled - 1).bright_black()
                )
            };

            let bar_line = format!("{}", bar);

            let pad_width = width;
            let numbers_line = format!("{:<pad_width$}", numbers_line, pad_width = pad_width);
            let bar_line = format!("{:<pad_width$}", bar_line, pad_width = pad_width);

            if first {
                print!("{}\n{}\r", numbers_line, bar_line);
                first = false;
            } else {
                print!("\x1b[1A\r{}\n{}\r", numbers_line, bar_line);
            }
            stdout().flush().ok();

            if done >= total_lines {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        println!();
    });

    const CHUNK_SIZE: usize = 1024 * 1024 * 8;
    let chunk_starts: Vec<usize> = (0..mmap_len).step_by(CHUNK_SIZE).collect();

    let chunk_ranges: Vec<(usize, usize)> = chunk_starts
        .iter()
        .zip(
            chunk_starts
                .iter()
                .skip(1)
                .chain(std::iter::once(&mmap_len)),
        )
        .map(|(&start, &end)| (start, end))
        .collect();

    let processed_lines = Arc::clone(&processed_lines);

    let results: Vec<(HashMap<String, usize>, HashMap<String, Vec<String>>)> = chunk_ranges
        .par_iter()
        .map(|&(start, end)| {
            let mut local_counts: HashMap<String, usize> = HashMap::new();
            let mut local_matches: HashMap<String, Vec<String>> = HashMap::new();

            let chunk = &mmap[start..end];
            let mut line_start = 0;
            for (i, &b) in chunk.iter().enumerate() {
                if b == b'\n' || i == chunk.len() - 1 {
                    let line_end = if b == b'\n' { i } else { i + 1 };
                    let line = match std::str::from_utf8(&chunk[line_start..line_end]) {
                        Ok(s) => s,
                        Err(_) => {
                            line_start = i + 1;
                            continue;
                        }
                    };

                    for (set_name, regex) in &compiled_patterns {
                        let matches: Vec<String> = regex
                            .find_iter(line)
                            .map(|m| m.as_str().to_string())
                            .collect();

                        if !matches.is_empty() {
                            *local_counts.entry(set_name.clone()).or_insert(0) += matches.len();
                            local_matches
                                .entry(set_name.clone())
                                .or_insert_with(Vec::new)
                                .extend(matches);
                        }
                    }

                    processed_lines.fetch_add(1, Ordering::Relaxed);
                    line_start = i + 1;
                }
            }

            (local_counts, local_matches)
        })
        .collect();

    processed_lines.store(total_lines, Ordering::Relaxed);
    progress_handle.join().ok();

    for (local_counts, local_matches) in results {
        for (set_name, count) in local_counts {
            *instruction_counts.get_mut(&set_name).unwrap() += count;
        }

        for (set_name, matches) in local_matches {
            matched_instructions
                .get_mut(&set_name)
                .unwrap()
                .extend(matches);
        }
    }

    let mut set_blocks: Vec<Vec<String>> = Vec::new();
    let mut total_instructions = 0;
    let mut sorted_sets: Vec<&String> = instruction_counts.keys().collect();
    sorted_sets.sort();

    for set_name in &sorted_sets {
        let count = instruction_counts[*set_name];
        if count > 0 {
            let mut block = Vec::new();
            let line = format!("{}: {} instructions found", set_name, format_number(count));
            block.push(line.clone());

            let mut instruction_frequency: BTreeMap<String, usize> = BTreeMap::new();
            for instr in &matched_instructions[*set_name] {
                *instruction_frequency.entry(instr.clone()).or_insert(0) += 1;
            }

            let mut common_instructions: Vec<(String, usize)> =
                instruction_frequency.into_iter().collect();
            common_instructions.sort_by(|a, b| b.1.cmp(&a.1));

            let common_instructions_str: Vec<String> = common_instructions
                .iter()
                .take(5)
                .map(|(instr, count)| format!("{} ({})", instr, format_number(*count)))
                .collect();

            let most_common_line = format!("  Most common: {}", common_instructions_str.join(", "));
            block.push(most_common_line.trim_end().to_string());

            set_blocks.push(block);

            total_instructions += count;
        }
    }

    let mut summary_lines = Vec::new();
    if total_instructions == 0 {
        summary_lines.push(String::from(
            "No instructions from recognized instruction extensions found in the assembly file.",
        ));
    } else {
        let percent = if total_lines > 0 {
            (total_instructions as f64 / total_lines as f64) * 100.0
        } else {
            0.0
        };
        summary_lines.push(format!(
            "Total Instructions from Instruction Extensions found: {} ({:.2}% of all lines)",
            format_number(total_instructions),
            percent
        ));
    }

    let elapsed_secs = start_time.elapsed().as_secs_f64();
    let avg_lines_per_sec = if elapsed_secs > 0.0 {
        total_lines as f64 / elapsed_secs
    } else {
        0.0
    };

    let mut extension_sets: Vec<ExtensionSetResult> = Vec::new();
    for set_name in &sorted_sets {
        let count = instruction_counts[*set_name];
        if count > 0 {
            let mut freq_map: BTreeMap<String, usize> = BTreeMap::new();
            for instr in &matched_instructions[*set_name] {
                *freq_map.entry(instr.clone()).or_insert(0) += 1;
            }
            let mut freq_vec: Vec<(String, usize)> = freq_map.into_iter().collect();
            freq_vec.sort_by(|a, b| b.1.cmp(&a.1));
            let occurrences = freq_vec
                .into_iter()
                .map(|(instruction, count)| Occurrence { instruction, count })
                .collect();
            extension_sets.push(ExtensionSetResult {
                extension: (*set_name).clone(),
                count,
                occurrences,
            });
        }
    }
    let percent = if total_lines > 0 {
        (total_instructions as f64 / total_lines as f64) * 100.0
    } else {
        0.0
    };
    let output = AnalysisOutput {
        file: assembly_file_path.to_string(),
        total_lines,
        elapsed_secs,
        avg_lines_per_sec,
        extension_instruction_total: total_instructions,
        extension_instruction_percent: percent,
        extension_sets,
    };

    Ok((output, set_blocks, summary_lines))
}
