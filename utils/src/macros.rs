#[macro_export]
macro_rules! not_matches {
   ($expression:expr, $( $pattern:pat )|+ $( if $guard: expr )?) => {
        match $expression {
            $( $pattern )|+ $( if $guard )? => false,
            _ => true
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_not_matches_macro() {
        let foofoo = 'g';
        assert!(not_matches!(foofoo, 'a'..='f'));

        let barbar = Some(4);
        assert!(not_matches!(barbar, Some(x) if x < 2));
    }
}
