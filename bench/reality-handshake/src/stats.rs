//! What a list of latencies is reported as.
//!
//! Percentiles here are nearest-rank on the sorted samples, not interpolated:
//! with a few hundred handshakes the honest statement is "this sample was the
//! slowest one in a hundred", and an interpolated p99 would be a fraction of a
//! sample that never happened. The rank is printed alongside the number so the
//! table cannot be read as more precise than it is.

/// A summary of one run of handshakes, all values in milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct Summary {
    pub count: usize,
    pub mean: f64,
    pub p50: f64,
    pub p99: f64,
    pub min: f64,
    pub max: f64,
}

impl Summary {
    pub fn of(mut millis: Vec<f64>) -> Self {
        assert!(!millis.is_empty(), "a summary needs at least one sample");
        millis.sort_by(|left, right| left.partial_cmp(right).expect("no NaN latencies"));
        let count = millis.len();
        let mean = millis.iter().sum::<f64>() / count as f64;
        Self {
            count,
            mean,
            p50: nearest_rank(&millis, 0.50),
            p99: nearest_rank(&millis, 0.99),
            min: millis[0],
            max: millis[count - 1],
        }
    }
}

/// The smallest sample at or above the `fraction`th rank.
fn nearest_rank(sorted: &[f64], fraction: f64) -> f64 {
    let rank = ((fraction * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// How far apart the largest and smallest value in a list are, as a fraction
/// of the smallest. Used to ask whether two runs were even comparable.
pub fn spread(values: &[f64]) -> f64 {
    let (Some(min), Some(max)) = (
        values.iter().cloned().reduce(f64::min),
        values.iter().cloned().reduce(f64::max),
    ) else {
        return 0.0;
    };
    if min <= 0.0 {
        return 0.0;
    }
    (max - min) / min
}
