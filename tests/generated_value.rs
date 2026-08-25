use pv::generator::{DEFAULT_LENGTH, GeneratedValueOptions, MAX_LENGTH, MIN_LENGTH, generate};

/// Verifies that generated-value options accept the supported range and default length.
#[test]
fn generated_value_options_validate_length_boundaries_and_default() {
    let defaults = GeneratedValueOptions::default();

    assert_eq!(defaults.length(), DEFAULT_LENGTH);
    assert!(GeneratedValueOptions::new(MIN_LENGTH, true, true).is_ok());
    assert!(GeneratedValueOptions::new(MAX_LENGTH, false, false).is_ok());
    assert!(GeneratedValueOptions::new(MIN_LENGTH - 1, true, true).is_err());
    assert!(GeneratedValueOptions::new(MAX_LENGTH + 1, true, true).is_err());
}

/// Verifies that each enabled character class appears and disabled classes do not.
#[test]
fn generated_values_respect_length_and_character_class_options() {
    for (length, include_digits, include_punctuation) in [
        (MIN_LENGTH, false, false),
        (DEFAULT_LENGTH, true, false),
        (MAX_LENGTH, false, true),
        (MAX_LENGTH, true, true),
    ] {
        let options = GeneratedValueOptions::new(length, include_digits, include_punctuation)
            .expect("the test length should be valid");
        let value = generate(options).expect("secure randomness should be available");
        let mut characters = value.chars();

        assert_eq!(value.chars().count(), length);
        assert!(value.chars().all(|character| {
            character.is_ascii_alphabetic()
                || (include_digits && character.is_ascii_digit())
                || (include_punctuation && character.is_ascii_punctuation())
        }));
        assert!(
            value
                .chars()
                .any(|character| character.is_ascii_alphabetic())
        );
        assert_eq!(
            value.chars().any(|character| character.is_ascii_digit()),
            include_digits
        );
        assert_eq!(
            value
                .chars()
                .any(|character| character.is_ascii_punctuation()),
            include_punctuation
        );
        assert!(characters.all(|character| !character.is_whitespace()));
    }
}
