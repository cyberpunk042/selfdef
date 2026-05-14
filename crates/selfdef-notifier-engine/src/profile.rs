//! Named escalation profiles — SDD-008 D-6b.
//!
//! A [`Profile`] is an operator-selected bundle of rung definitions
//! that the wake task drives a row through. v1 ships three built-in
//! profiles (`auto`, `aggressive`, `patient`) and parses a name
//! string out of the operator's `[notifier].profile` config knob.
//!
//! Each [`Rung`] today carries only an ack window. Per-rung channel
//! filtering (e.g. "ntfy at rung 0, escalate to Twilio at rung 1,
//! full WUPHF at rung 2") lands in a follow-up D-6c once
//! [`PayloadDispatcher`] grows a per-rung channel-set input.
//!
//! [`PayloadDispatcher`]: crate::PayloadDispatcher

/// One step in an escalation profile. Today it carries only an
/// ack window; future Ds may grow per-rung channel filtering,
/// DEFCON overrides, etc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rung {
    /// Seconds the wake task waits between firing this rung and
    /// advancing to the next. The operator's "ack window".
    pub ack_window_secs: i64,
}

impl Rung {
    /// Construct a rung with the given ack window in seconds.
    #[must_use]
    pub const fn new(ack_window_secs: i64) -> Self {
        Self { ack_window_secs }
    }
}

/// Named escalation profile. The wake task uses the profile's rung
/// count to decide when to close out, and each rung's ack window to
/// decide when to re-fire.
///
/// Rung indices match the persistence schema:
/// - `rung_index = 0` → initial attempt (fired by
///   [`PayloadDispatcher::submit`]). The 0th rung's ack window is
///   the initial deadline.
/// - `rung_index = 1..len` → retries fired by the wake task.
/// - After `rung_index >= len` the wake task closes the row.
///
/// [`PayloadDispatcher::submit`]: crate::PayloadDispatcher::submit
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Stable lowercase identifier (`"auto"` / `"aggressive"` /
    /// `"patient"` / operator-defined).
    pub name: String,
    /// Ordered rung sequence. **Must be non-empty** — a 0-rung
    /// profile would never fire.
    pub rungs: Vec<Rung>,
}

impl Profile {
    /// SDD-008 default profile. Two attempts (initial + one retry)
    /// with a 5-minute ack window between them. Preserves the
    /// hardcoded behaviour the wake task shipped with in D-5c, so
    /// operators who don't set `[notifier].profile` see no change.
    #[must_use]
    pub fn auto() -> Self {
        Self {
            name: "auto".into(),
            rungs: vec![Rung::new(300), Rung::new(300)],
        }
    }

    /// SDD-008 aggressive profile. Three attempts at 60s, 180s,
    /// 600s. Intended for "wake the on-call person" use cases
    /// where missed alerts are worse than a few extra pages.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            name: "aggressive".into(),
            rungs: vec![Rung::new(60), Rung::new(180), Rung::new(600)],
        }
    }

    /// SDD-008 patient profile. Four attempts at 10 / 30 / 60 / 120
    /// minutes. Intended for non-critical channels where multiple
    /// rapid retries would just be noise.
    #[must_use]
    pub fn patient() -> Self {
        Self {
            name: "patient".into(),
            rungs: vec![
                Rung::new(600),
                Rung::new(1_800),
                Rung::new(3_600),
                Rung::new(7_200),
            ],
        }
    }

    /// Parse the operator-facing string form (case-insensitive):
    /// `auto` | `aggressive` | `patient`. Returns `None` for
    /// unknown strings; callers log a warn and fall back to
    /// [`Self::auto`].
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::auto()),
            "aggressive" => Some(Self::aggressive()),
            "patient" => Some(Self::patient()),
            _ => None,
        }
    }

    /// Maximum reachable rung index. The wake task closes a row
    /// when `rung_index >= max_rung`. Always equals
    /// `rungs.len() as u32 - 1` for a non-empty profile (which
    /// invariant the constructors enforce).
    #[must_use]
    pub fn max_rung(&self) -> u32 {
        debug_assert!(!self.rungs.is_empty(), "empty profile");
        (self.rungs.len() as u32).saturating_sub(1)
    }

    /// Ack window for the rung at `index`, in seconds. Returns the
    /// last rung's window when `index >= rungs.len()` (clamp;
    /// shouldn't happen in normal flow, but defensive against off-
    /// by-one in callers).
    #[must_use]
    pub fn ack_window_for(&self, index: u32) -> i64 {
        let i = (index as usize).min(self.rungs.len().saturating_sub(1));
        self.rungs[i].ack_window_secs
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::auto()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_matches_d5c_defaults() {
        // The D-5c wake task hardcoded MAX_RUNG = 1 and a 5-min ack
        // window per rung. Profile::auto must reproduce that so
        // operators who don't opt in see zero behaviour change.
        let p = Profile::auto();
        assert_eq!(p.name, "auto");
        assert_eq!(p.max_rung(), 1, "auto has 2 attempts, max rung index 1");
        for i in 0..p.rungs.len() {
            assert_eq!(p.ack_window_for(i as u32), 300);
        }
    }

    #[test]
    fn aggressive_has_three_rungs() {
        let p = Profile::aggressive();
        assert_eq!(p.name, "aggressive");
        assert_eq!(p.max_rung(), 2);
        assert_eq!(p.ack_window_for(0), 60);
        assert_eq!(p.ack_window_for(1), 180);
        assert_eq!(p.ack_window_for(2), 600);
    }

    #[test]
    fn patient_has_four_rungs() {
        let p = Profile::patient();
        assert_eq!(p.name, "patient");
        assert_eq!(p.max_rung(), 3);
        assert_eq!(p.ack_window_for(0), 600);
        assert_eq!(p.ack_window_for(1), 1_800);
        assert_eq!(p.ack_window_for(2), 3_600);
        assert_eq!(p.ack_window_for(3), 7_200);
    }

    #[test]
    fn default_is_auto() {
        assert_eq!(Profile::default(), Profile::auto());
    }

    #[test]
    fn from_name_parses_known_strings_case_insensitive() {
        assert_eq!(Profile::from_name("auto"), Some(Profile::auto()));
        assert_eq!(Profile::from_name("AUTO"), Some(Profile::auto()));
        assert_eq!(Profile::from_name("Auto"), Some(Profile::auto()));
        assert_eq!(
            Profile::from_name("aggressive"),
            Some(Profile::aggressive())
        );
        assert_eq!(Profile::from_name("patient"), Some(Profile::patient()));
    }

    #[test]
    fn from_name_returns_none_for_unknown() {
        assert!(Profile::from_name("yolo").is_none());
        assert!(Profile::from_name("").is_none());
    }

    #[test]
    fn ack_window_for_clamps_past_max_rung() {
        let p = Profile::auto();
        // Out-of-range index returns the last rung's window —
        // defensive against wake-task off-by-one.
        assert_eq!(
            p.ack_window_for(99),
            p.rungs.last().unwrap().ack_window_secs
        );
    }
}
