use colored::*;
use strip_ansi_escapes;
use terminal_size::{Width, terminal_size};

fn colorize_line(line: &str, use_color: bool) -> String {
    if !use_color {
        return line.to_string();
    }

    if let Some(idx) = line.find("Most common:") {
        let mut result = String::new();
        result.push_str(&line[..idx]);
        result.push_str(&"Most common:".italic().bright_green().to_string());
        let rest = &line[idx + "Most common:".len()..];

        let mut segments = Vec::new();
        let mut chars = rest.trim_start().chars().peekable();
        while let Some(_) = chars.peek() {
            while let Some(&c) = chars.peek() {
                if c == ',' || c.is_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }
            let mut instr = String::new();
            while let Some(&c) = chars.peek() {
                if c == ' ' && chars.clone().nth(1) == Some('(') {
                    break;
                }
                if c == '(' {
                    break;
                }
                instr.push(c);
                chars.next();
            }
            instr = instr.trim().to_string();
            let mut paren = String::new();
            if let Some(&c) = chars.peek() {
                if c == '(' {
                    paren.push(' ');
                }
            }
            while let Some(&c) = chars.peek() {
                if c == '(' {
                    paren.push(c);
                    chars.next();
                    break;
                } else if c.is_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }
            let mut count = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() || c == ',' {
                    count.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            let mut close_paren = String::new();
            if let Some(&c) = chars.peek() {
                if c == ')' {
                    close_paren.push(c);
                    chars.next();
                }
            }
            let mut chunk = String::new();
            if !instr.is_empty() && !count.is_empty() {
                let instr_col = instr.bold().cyan().to_string();
                let paren_col = paren.white().to_string();
                let count_col = count.magenta().to_string();
                let close_paren_col = close_paren.white().to_string();
                chunk.push_str(&instr_col);
                chunk.push_str(&paren_col);
                chunk.push_str(&count_col);
                chunk.push_str(&close_paren_col);
                segments.push(chunk);
            }
            let mut comma_and_space = String::new();
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    comma_and_space.push(c);
                    chars.next();
                    if let Some(&' ') = chars.peek() {
                        comma_and_space.push(' ');
                        chars.next();
                    }
                    break;
                } else if c.is_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }
            if !comma_and_space.is_empty() && chars.peek().is_some() {
                segments.push(comma_and_space.to_string());
            }
        }
        let final_colored = segments.join("");
        result.push_str(&final_colored);
        return result;
    }

    if line.contains("Total Instructions") || line.contains("No instructions") {
        return line.bold().yellow().to_string();
    }

    if let Some(colon_idx) = line.find(':') {
        if line.contains("instructions found") {
            let ext = &line[..colon_idx].trim();
            let rest = line[colon_idx + 1..].trim();
            let mut result = String::new();
            result.push_str(&ext.bold().cyan().to_string());
            result.push_str(": ");
            let mut i = 0;
            let rest_bytes = rest.as_bytes();
            while i < rest.len() {
                if rest_bytes[i].is_ascii_digit() {
                    let start = i;
                    while i < rest.len()
                        && (rest_bytes[i].is_ascii_digit() || rest_bytes[i] == b',')
                    {
                        i += 1;
                    }
                    let num = &rest[start..i];
                    result.push_str(&num.magenta().to_string());
                } else if rest[i..].starts_with("instructions found") {
                    result.push_str(&"instructions found".blue().to_string());
                    i += "instructions found".len();
                } else {
                    let start = i;
                    while i < rest.len()
                        && !rest_bytes[i].is_ascii_digit()
                        && !rest[i..].starts_with("instructions found")
                    {
                        i += 1;
                    }
                    let other = &rest[start..i];
                    result.push_str(&other.bright_blue().to_string());
                }
            }
            return result;
        }
    }

    if let Some(idx) = line.find('-') {
        let (left, right) = line.split_at(idx);
        let ext = left.trim_end();
        let dash_and_desc = right;
        let mut result = String::new();
        result.push_str(&ext.bold().cyan().to_string());
        if let Some(dash_idx) = dash_and_desc.find('-') {
            result.push(' ');
            result.push_str(&"-".green().to_string());
            let desc = &dash_and_desc[dash_idx + 1..];
            result.push_str(&desc.bright_blue().to_string());
        } else {
            result.push_str(&dash_and_desc.bright_blue().to_string());
        }
        return result;
    }

    if line
        .chars()
        .all(|c| c.is_ascii_digit() || c.is_whitespace())
    {
        return line.magenta().to_string();
    }

    line.white().to_string()
}

pub fn print_boxed_section(lines: &[String], separator_indices: &[usize], title: Option<&str>) {
    let mut content_width = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    if let Some(title) = title {
        content_width = content_width.max(title.len());
    }
    content_width = content_width.max(40);

    let terminal_width = if let Some((Width(w), _)) = terminal_size() {
        w as usize
    } else {
        80
    };

    let box_width = content_width + 2;
    let use_box = terminal_width >= box_width;

    let use_color = atty::is(atty::Stream::Stdout);

    if use_box {
        if let Some(title) = title {
            let dash_total = box_width.saturating_sub(title.len());
            let left_dash = dash_total / 2;
            let right_dash = dash_total - left_dash;
            let border = format!(
                "+{:-<left$}{}{:->right$}+",
                "",
                &title.bold().yellow().to_string(),
                "",
                left = left_dash,
                right = right_dash
            );
            if use_color {
                println!("{}", border.white());
            } else {
                println!("{}", border);
            }
        } else {
            let border = format!("+{:-<width$}+", "", width = box_width);
            if use_color {
                println!("{}", border.white());
            } else {
                println!("{}", border);
            }
        }
        for (i, line) in lines.iter().enumerate() {
            let (left, right) = ("| ".to_string(), " |".to_string());
            let styled_content = colorize_line(line, use_color);
            let content_len =
                String::from_utf8_lossy(&strip_ansi_escapes::strip(styled_content.as_bytes()))
                    .len();
            let pad = if content_len < content_width {
                " ".repeat(content_width - content_len)
            } else {
                String::new()
            };
            if use_color {
                print!("{}", left.white());
                print!("{}{}", styled_content, pad);
                println!("{}", right.white());
            } else {
                println!("| {:<width$} |", line, width = content_width);
            }
            if separator_indices.contains(&i) {
                let sep = format!("+{:-<width$}+", "", width = box_width);
                if use_color {
                    println!("{}", sep.white());
                } else {
                    println!("{}", sep);
                }
            }
        }
        let border = format!("+{:-<width$}+", "", width = box_width);
        if use_color {
            println!("{}", border.white());
        } else {
            println!("{}", border);
        }
    } else {
        if let Some(title) = title {
            if use_color {
                println!("{}", title.bold().yellow());
                println!("{}", "-".repeat(content_width).white());
            } else {
                println!("{}", title);
                println!("{}", "-".repeat(content_width));
            }
        }
        for (i, line) in lines.iter().enumerate() {
            let styled_content = colorize_line(line, use_color);
            println!("{}", styled_content);
            if separator_indices.contains(&i) {
                let sep = "-".repeat(content_width);
                if use_color {
                    println!("{}", sep.white());
                } else {
                    println!("{}", sep);
                }
            }
        }
        let sep = "-".repeat(content_width);
        if use_color {
            println!("{}", sep.white());
        } else {
            println!("{}", sep);
        }
    }
}

pub fn print_instruction_sets() {
    let lines = vec![
        {
            let mut blocks = Vec::new();
            blocks.push("FPU           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "x87 Floating Point Unit instructions"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("VME           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Virtual Machine Extensions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("DE            ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Debugging Extensions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("PSE           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Page Size Extension".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("TSC           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Time Stamp Counter".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MSR           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Model Specific Registers".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("PAE           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Physical Address Extension".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MCE           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Machine Check Exception".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("CX8           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("CMPXCHG8B instruction".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("APIC          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Advanced Programmable Interrupt Controller"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SEP           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("SYSENTER/SYSEXIT support".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MTRR          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Memory Type Range Registers".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("PGE           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Page Global Enable".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MCA           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Machine Check Architecture".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("CMOV          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Conditional Move instructions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("PAT           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Page Attribute Table".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("CLFLUSH       ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Cache Line Flush".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MMX           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("MultiMedia eXtensions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("FXSR          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("FXSAVE/FXRSTOR instructions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SSE           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Streaming SIMD Extensions (128-bit floating-point)"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SSE2          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "128-bit integer & double-precision floating-point"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SSE3          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Horizontal operations within registers"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SSSE3         ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Supplemental SIMD integer instructions"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SSE4.1        ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "SSE4.1: Dot product, blending, etc."
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SSE4.2        ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "SSE4.2: String/text processing, CRC32"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SSE4A         ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "SSE4A: AMD-only SIMD instructions"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("PCLMULQDQ     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Carry-Less Multiplication Quadword"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-F      ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Foundation (512-bit ops, masks, blends, etc.)"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-CD     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("AVX-512 Conflict Detection".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-DQ     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("AVX-512 Double/Quad-word".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-BW     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("AVX-512 Byte/Word".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-VL     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Vector Length (128/256-bit)"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-ER     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Exponential & Reciprocal"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-IFMA   ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Integer Fused Multiply-Add"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-VBMI   ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Vector Byte Manipulation Instructions"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-VBMI2  ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Vector Byte Manipulation Instructions 2"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-PKU    ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Protection Keys for User-mode pages"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("XSAVE         ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("XSAVE/XRSTOR instructions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("OSXSAVE       ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("OS-Enabled XSAVE".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Advanced Vector Extensions (256-bit floating-point)"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("F16C          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "16-bit Floating-Point Conversion"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("RDRAND        ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Read Random Number".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("RDSEED        ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Read Random Seed".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("FSGSBASE      ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("FS/GS Base instructions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("BMI1          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Bit Manipulation Instruction Set 1"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("BMI2          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Bit Manipulation Instruction Set 2"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("HLE           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Hardware Lock Elision".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("RTM           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Restricted Transactional Memory".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SMEP          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Supervisor Mode Execution Protection"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SMAP          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Supervisor Mode Access Prevention"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("ERMS          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Enhanced REP MOVSB/STOSB".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("INVPCID       ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Invalidate Process-Context Identifier"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MPX           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Memory Protection Extensions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("ADX           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Multi-Precision Add-Carry Instruction Extensions"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("SHA           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("SHA Extensions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("CLFLUSHOPT    ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Cache Line Flush Optimized".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("CLWB          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Cache Line Write Back".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("PREFETCHWT1   ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Prefetch with Intent to Write".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("PREFETCHW     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Prefetch with Write Intent".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-F      ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Foundation (512-bit ops, masks, blends, etc.)"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-CD     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("AVX-512 Conflict Detection".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-DQ     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("AVX-512 Double/Quad-word".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-BW     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("AVX-512 Byte/Word".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-VL     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Vector Length (128/256-bit)"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-ER     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Exponential & Reciprocal"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-IFMA   ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Integer Fused Multiply-Add"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-VBMI   ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Vector Byte Manipulation Instructions"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-VBMI2  ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Vector Byte Manipulation Instructions 2"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX512-PKU    ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "AVX-512 Protection Keys for User-mode pages"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MOVDIR64B     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Move 64 Bytes as Direct Store".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MOVDIRI       ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Move as Direct Store Immediate".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("LZCNT         ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Leading Zero Count".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("MisalignSse   ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Misaligned SSE support".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("D3DNOWEXT     ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("3DNow! Extensions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("D3DNOW        ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("3DNow! instructions".bright_white().to_string());
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("AVX2          ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push(
                "Advanced Vector Extensions 2 (256-bit integer)"
                    .bright_white()
                    .to_string(),
            );
            blocks.join("")
        },
        {
            let mut blocks = Vec::new();
            blocks.push("FMA           ".bold().bright_blue().to_string());
            blocks.push(" : ".bright_black().to_string());
            blocks.push("Fused Multiply-Add".bright_white().to_string());
            blocks.join("")
        },
    ];
    print_boxed_section(&lines, &[], Some("Instruction Extension Set Information"));
}
