pub fn format_number(num: usize) -> String {
    if num == 0 {
        return "0".to_string();
    }

    let mut result = String::new();
    let num_str = num.to_string();
    let len = num_str.len();

    for (i, c) in num_str.chars().enumerate() {
        result.push(c);
        if (len - i - 1) % 3 == 0 && i < len - 1 {
            result.push(',');
        }
    }

    result
}
