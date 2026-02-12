pub fn floor_char_boundary(s: &str, mut index: usize) -> usize {
    let len = s.len();
    if index >= len {
        return len;
    }

    while index > 0 && !s.is_char_boundary(index) {
        index -= 1;
    }

    index
}
