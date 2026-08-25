use pv::generator::{DEFAULT_LENGTH, GeneratedValueOptions, MAX_LENGTH, MIN_LENGTH, generate};

/// Verifies that generated-value options accept the supported range and default length.
#[test]
fn generated_value_options_validate_length_boundaries_and_default() {
    let defaults = GeneratedValueOptions::default();

    assert_eq!(defaults.length(), DEFAULT_LENGTH);
    assert_eq!(DEFAULT_LENGTH, 20);
    assert_eq!(MIN_LENGTH, 8);
    assert!(defaults.includes_numbers());
    assert!(!defaults.includes_symbols());
    assert!(GeneratedValueOptions::new(MIN_LENGTH, true, true).is_ok());
    assert!(GeneratedValueOptions::new(MAX_LENGTH, false, false).is_ok());
    assert!(GeneratedValueOptions::new(MIN_LENGTH - 1, true, true).is_err());
    assert!(GeneratedValueOptions::new(MAX_LENGTH + 1, true, true).is_err());
}

/// Verifies the Generated value allowlist and the guarantee for every enabled category.
#[test]
fn generated_values_respect_length_and_character_class_options() {
    /// The independent expected Symbol allowlist from the feature specification.
    const SYMBOLS: &str = "!@.-_*";

    for (length, include_numbers, include_symbols) in [
        (MIN_LENGTH, false, false),
        (DEFAULT_LENGTH, true, false),
        (MAX_LENGTH, false, true),
        (MAX_LENGTH, true, true),
    ] {
        let options = GeneratedValueOptions::new(length, include_numbers, include_symbols)
            .expect("the test length should be valid");
        let value = generate(options).expect("secure randomness should be available");
        let mut characters = value.chars();

        assert_eq!(value.chars().count(), length);
        assert!(value.chars().all(|character| {
            character.is_ascii_alphabetic()
                || (include_numbers && character.is_ascii_digit())
                || (include_symbols && SYMBOLS.contains(character))
        }));
        assert!(
            value
                .chars()
                .any(|character| character.is_ascii_alphabetic())
        );
        assert_eq!(
            value.chars().any(|character| character.is_ascii_digit()),
            include_numbers
        );
        assert_eq!(
            value.chars().any(|character| SYMBOLS.contains(character)),
            include_symbols
        );
        assert!(characters.all(|character| !character.is_whitespace()));
    }
}
