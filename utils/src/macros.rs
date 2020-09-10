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
    let foo = 'g';
    assert!(not_matches!(foo, 'a'..='f'));

    let bar = Some(4);
    assert!(not_matches!(bar, Some(x) if x < 2));
  }
}
