use serde::Serialize;
#[derive(Serialize, Clone)]
pub struct AnalysisOutput {
    pub file: String,
    pub total_lines: usize,
    pub elapsed_secs: f64,
    pub avg_lines_per_sec: f64,
    pub extension_instruction_total: usize,
    pub extension_instruction_percent: f64,
    pub extension_sets: Vec<ExtensionSetResult>,
}

#[derive(Serialize, Clone)]
pub struct ExtensionSetResult {
    pub extension: String,
    pub count: usize,
    pub occurrences: Vec<Occurrence>,
}

#[derive(Serialize, Clone)]
pub struct Occurrence {
    pub instruction: String,
    pub count: usize,
}
