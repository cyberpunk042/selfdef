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

/// One step in an escalation profile.
///
/// - `ack_window_secs` — how long the wake task waits for an ack
///   before advancing to the next rung.
/// - `channels` — SDD-008 D-6c: per-rung channel allow-list. Empty
///   = "fire every configured channel" (WUPHF). When non-empty,
///   only channels whose `name()` matches a string in this vec see
///   the payload at this rung.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rung {
    /// Seconds the wake task waits between firing this rung and
    /// advancing to the next. The operator's "ack window".
    pub ack_window_secs: i64,
    /// Per-rung channel allow-list. Empty = all channels (the
    /// pre-D-6c default; matches the WUPHF semantics from the
    /// charter).
    pub channels: Vec<String>,
}

impl Rung {
    /// Construct a rung with the given ack window and no channel
    /// filter (empty channels list = "fire all configured channels").
    #[must_use]
    pub const fn new(ack_window_secs: i64) -> Self {
        Self {
            ack_window_secs,
            channels: Vec::new(),
        }
    }

    /// SDD-008 D-6c: construct a rung that targets only the listed
    /// channels by name. Empty `channels` = all channels (use
    /// [`Self::new`] for that case).
    #[must_use]
    pub fn with_channels(ack_window_secs: i64, channels: Vec<String>) -> Self {
        Self {
            ack_window_secs,
            channels,
        }
    }

    /// Returns `true` when the channel name passes this rung's
    /// allow-list filter. Empty allow-list = accept every channel.
    #[must_use]
    pub fn allows_channel(&self, name: &str) -> bool {
        self.channels.is_empty() || self.channels.iter().any(|c| c == name)
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

    /// SDD-008 D-6c: construct an operator-defined custom profile
    /// from a name + a non-empty rung sequence. Refuses an empty
    /// rung list because a zero-rung profile would never fire.
    pub fn custom(name: impl Into<String>, rungs: Vec<Rung>) -> Result<Self, ProfileBuildError> {
        if rungs.is_empty() {
            return Err(ProfileBuildError::EmptyRungs);
        }
        Ok(Self {
            name: name.into(),
            rungs,
        })
    }

    /// Per-rung channel allow-list for the given rung index.
    /// Returns the empty slice (= "all channels") for indices past
    /// `max_rung`.
    #[must_use]
    pub fn channels_for(&self, index: u32) -> &[String] {
        let i = (index as usize).min(self.rungs.len().saturating_sub(1));
        &self.rungs[i].channels
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

/// SDD-008 D-6c: errors from [`Profile::custom`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileBuildError {
    #[error("custom profile must have at least one rung; got empty rung list")]
    EmptyRungs,
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

    // ---------------- SDD-008 D-6c: custom profiles ----------------

    #[test]
    fn rung_new_has_empty_channel_filter() {
        let r = Rung::new(300);
        assert!(r.channels.is_empty(), "Rung::new = WUPHF (no filter)");
        // Empty allow-list accepts every channel name.
        assert!(r.allows_channel("ntfy"));
        assert!(r.allows_channel("signal"));
        assert!(r.allows_channel("wall"));
    }

    #[test]
    fn rung_with_channels_filters_by_name() {
        let r = Rung::with_channels(60, vec!["ntfy".into(), "smtp".into()]);
        assert!(r.allows_channel("ntfy"));
        assert!(r.allows_channel("smtp"));
        assert!(!r.allows_channel("twilio"));
        assert!(!r.allows_channel("wall"));
    }

    #[test]
    fn custom_profile_with_rungs_succeeds() {
        let p = Profile::custom(
            "weekend-mode",
            vec![
                Rung::with_channels(1_800, vec!["ntfy".into()]),
                Rung::with_channels(3_600, vec!["signal".into()]),
                Rung::new(600), // WUPHF — empty allow-list
            ],
        )
        .expect("non-empty rungs must succeed");
        assert_eq!(p.name, "weekend-mode");
        assert_eq!(p.max_rung(), 2);
        assert_eq!(p.channels_for(0), &["ntfy".to_owned()]);
        assert_eq!(p.channels_for(1), &["signal".to_owned()]);
        assert!(
            p.channels_for(2).is_empty(),
            "rung 2 = WUPHF (all channels)"
        );
    }

    #[test]
    fn custom_profile_rejects_empty_rungs() {
        let err = Profile::custom("empty", vec![]).expect_err("empty must fail");
        assert_eq!(err, ProfileBuildError::EmptyRungs);
    }

    #[test]
    fn channels_for_clamps_past_max_rung() {
        let p = Profile::custom(
            "two-rung",
            vec![
                Rung::with_channels(60, vec!["a".into()]),
                Rung::with_channels(120, vec!["b".into()]),
            ],
        )
        .unwrap();
        // Out-of-range index returns the last rung's allow-list.
        assert_eq!(p.channels_for(99), &["b".to_owned()]);
    }

    #[test]
    fn built_in_profiles_have_empty_rung_filters() {
        // The pre-D-6c built-ins (auto/aggressive/patient) must
        // preserve the "fire all channels" behaviour — their rungs
        // all have empty channel allow-lists.
        for p in [Profile::auto(), Profile::aggressive(), Profile::patient()] {
            for (i, r) in p.rungs.iter().enumerate() {
                assert!(
                    r.channels.is_empty(),
                    "{}'s rung {} should have empty channel filter for backwards compat",
                    p.name,
                    i,
                );
            }
        }
    }
}
