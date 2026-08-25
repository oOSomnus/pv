use rand::{TryRng, rngs::SysRng};
use thiserror::Error;

/// The shortest supported Generated value length.
pub const MIN_LENGTH: usize = 8;
/// The longest supported Generated value length.
pub const MAX_LENGTH: usize = 100;
/// The default Generated value length used when no length is entered.
pub const DEFAULT_LENGTH: usize = 20;

/// Errors returned while validating or generating a Generated value.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GeneratorError {
    /// The requested length is outside the inclusive supported range.
    #[error("generated value length must be between {MIN_LENGTH} and {MAX_LENGTH}, got {length}")]
    InvalidLength {
        /// The requested length that could not be accepted.
        length: usize,
    },

    /// The operating system could not provide cryptographically secure randomness.
    #[error("could not generate a random value: {0}")]
    Random(#[source] rand::rngs::SysError),
}

/// Configures the length and optional character classes for a Generated value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedValueOptions {
    /// The number of characters in the generated Value.
    length: usize,
    /// Whether decimal Numbers are included and guaranteed to appear.
    include_numbers: bool,
    /// Whether the supported Symbols are included and guaranteed to appear.
    include_symbols: bool,
}

impl Default for GeneratedValueOptions {
    /// Returns the default length with Numbers enabled and Symbols disabled.
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            include_numbers: true,
            include_symbols: false,
        }
    }
}

impl GeneratedValueOptions {
    /// Creates options after validating the inclusive supported length range.
    pub fn new(
        length: usize,
        include_numbers: bool,
        include_symbols: bool,
    ) -> Result<Self, GeneratorError> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
            return Err(GeneratorError::InvalidLength { length });
        }

        Ok(Self {
            length,
            include_numbers,
            include_symbols,
        })
    }

    /// Returns the configured Generated value length.
    pub const fn length(self) -> usize {
        self.length
    }

    /// Returns whether decimal Numbers are enabled.
    pub const fn includes_numbers(self) -> bool {
        self.include_numbers
    }

    /// Returns whether decimal Numbers are enabled.
    pub const fn includes_digits(self) -> bool {
        self.includes_numbers()
    }

    /// Returns whether the supported Symbols are enabled.
    pub const fn includes_symbols(self) -> bool {
        self.include_symbols
    }

    /// Returns whether the supported Symbols are enabled through the legacy punctuation name.
    pub const fn includes_punctuation(self) -> bool {
        self.includes_symbols()
    }
}

/// Generates a cryptographically secure ASCII value from the supplied options.
///
/// Every enabled character class contributes at least one character. The
/// operation returns [`GeneratorError::Random`] if the operating system cannot
/// provide entropy; the UTF-8 conversion is infallible because all source
/// character sets are ASCII.
pub fn generate(options: GeneratedValueOptions) -> Result<String, GeneratorError> {
    /// The ASCII letters available in every Generated value.
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    /// The decimal Numbers available when Number generation is enabled.
    const NUMBERS: &[u8] = b"0123456789";
    /// The exact Symbols available when Symbol generation is enabled.
    const SYMBOLS: &[u8] = b"!@.-_*";

    let mut rng = SysRng;
    let mut character_sets = vec![LETTERS];
    if options.include_numbers {
        character_sets.push(NUMBERS);
    }
    if options.include_symbols {
        character_sets.push(SYMBOLS);
    }

    let all_characters: Vec<u8> = character_sets
        .iter()
        .flat_map(|character_set| character_set.iter().copied())
        .collect();
    let mut value = Vec::with_capacity(options.length);

    for character_set in &character_sets {
        value.push(character_set[random_index(&mut rng, character_set.len())?]);
    }
    while value.len() < options.length {
        value.push(all_characters[random_index(&mut rng, all_characters.len())?]);
    }

    for index in (1..value.len()).rev() {
        let swap_index = random_index(&mut rng, index + 1)?;
        value.swap(index, swap_index);
    }

    Ok(String::from_utf8(value).expect("Generated value character sets are ASCII"))
}

/// Selects an unbiased random index below `upper_bound` using system entropy.
///
/// The caller must provide a non-zero `upper_bound`, which is guaranteed by
/// the non-empty character sets used by [`generate`]. The operation returns
/// [`GeneratorError::Random`] if the operating system cannot provide entropy.
fn random_index(rng: &mut SysRng, upper_bound: usize) -> Result<usize, GeneratorError> {
    let upper_bound = upper_bound as u64;
    let acceptance_limit = u64::MAX - (u64::MAX % upper_bound);

    loop {
        let random = rng.try_next_u64().map_err(GeneratorError::Random)?;
        if random < acceptance_limit {
            return Ok((random % upper_bound) as usize);
        }
    }
}
