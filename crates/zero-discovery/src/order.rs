//! The order in which candidates are tested.
//!
//! A feed lists servers in whatever order its scraper found them, which in
//! practice means long runs of one kind: two hundred WebSocket nodes behind
//! the same CDN, then a block of REALITY nodes. When a filtering change has
//! just broken one family, testing in feed order burns the whole time budget
//! on that family before reaching anything that works.
//!
//! So candidates are bucketed by [`LinkClass`], each bucket is shuffled (so
//! repeated discoveries do not all hammer the same first few servers), and the
//! buckets are interleaved round-robin. Whatever family currently survives is
//! reached within the first handful of tests.
//!
//! Within a bucket it is not enough to shuffle: a single popular worker
//! domain can still take half the bucket, and one filtering action against
//! that name kills every config behind it at once. So each bucket is also
//! spread across distinct wire names ([`wire_name`](crate::link::Candidate))
//! by round-robin before being handed to the class interleave.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::link::LinkClass;

/// Interleave `items` across classes, shuffled within each class.
///
/// The name-blind form of [`order_by_class_spread`]: every item lands in one
/// name group, so the result is exactly the class interleave over shuffled
/// buckets. Kept for callers that have no wire name to spread by.
pub fn order_by_class<T, R, F>(items: Vec<T>, class_of: F, rng: &mut R) -> Vec<T>
where
    R: Rng + ?Sized,
    F: Fn(&T) -> LinkClass,
{
    order_by_class_spread(items, class_of, |_| String::new(), rng)
}

/// Interleave `items` across classes, spreading each class across distinct
/// wire names as well.
///
/// `name_of` gives each item the name a censor would see (usually the TLS
/// server name; the empty string groups items with no distinctive name).
/// Within a class the items are grouped by name, both orders are shuffled,
/// and the names are interleaved round-robin — so the first several
/// candidates of a class come from different names whenever there are any
/// different names to take.
pub fn order_by_class_spread<T, R, F, N>(
    items: Vec<T>,
    class_of: F,
    name_of: N,
    rng: &mut R,
) -> Vec<T>
where
    R: Rng + ?Sized,
    F: Fn(&T) -> LinkClass,
    N: Fn(&T) -> String,
{
    let mut buckets: Vec<Vec<T>> = LinkClass::ALL.iter().map(|_| Vec::new()).collect();
    for item in items {
        let class = class_of(&item);
        let index = LinkClass::ALL
            .iter()
            .position(|candidate| *candidate == class)
            .unwrap_or(LinkClass::ALL.len() - 1);
        buckets[index].push(item);
    }
    let mut spread: Vec<Vec<T>> = Vec::with_capacity(buckets.len());
    for bucket in buckets {
        spread.push(spread_by_name(bucket, &name_of, rng));
    }
    let total: usize = spread.iter().map(Vec::len).sum();
    for bucket in &mut spread {
        bucket.reverse();
    }
    let mut ordered = Vec::with_capacity(total);
    while ordered.len() < total {
        for bucket in &mut spread {
            if let Some(item) = bucket.pop() {
                ordered.push(item);
            }
        }
    }
    ordered
}

/// One class's items, reordered so consecutive items come from different
/// wire names where possible. Names are visited round-robin; within a name
/// the items keep a shuffled order.
fn spread_by_name<T, R, N>(items: Vec<T>, name_of: &N, rng: &mut R) -> Vec<T>
where
    R: Rng + ?Sized,
    N: Fn(&T) -> String,
{
    // BTreeMap keeps name order deterministic so the result depends only on
    // the rng, not on hash seeds; each queue is shuffled individually.
    let mut by_name: std::collections::BTreeMap<String, std::collections::VecDeque<T>> =
        std::collections::BTreeMap::new();
    for item in items {
        let name = name_of(&item);
        by_name.entry(name).or_default().push_back(item);
    }
    let mut queues: Vec<std::collections::VecDeque<T>> = by_name.into_values().collect();
    for queue in &mut queues {
        let mut as_vec: Vec<T> = queue.drain(..).collect();
        as_vec.shuffle(rng);
        queue.extend(as_vec);
    }
    let total: usize = queues.iter().map(std::collections::VecDeque::len).sum();
    let mut out = Vec::with_capacity(total);
    while out.len() < total {
        for queue in &mut queues {
            if let Some(item) = queue.pop_front() {
                out.push(item);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn classes_are_interleaved_and_nothing_is_lost() {
        let mut items = Vec::new();
        for index in 0..10 {
            items.push((LinkClass::CdnTls, index));
        }
        for index in 0..3 {
            items.push((LinkClass::Reality, index));
        }
        items.push((LinkClass::XhttpExtra, 0));
        items.push((LinkClass::Other, 0));
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let ordered = order_by_class(items.clone(), |item| item.0, &mut rng);

        assert_eq!(ordered.len(), items.len());
        // The first round takes one from each class, in class order.
        let first: Vec<LinkClass> = ordered.iter().take(4).map(|item| item.0).collect();
        assert_eq!(first, LinkClass::ALL.to_vec());
        // Once the small classes run out the large one fills the tail.
        assert!(ordered[8..].iter().all(|item| item.0 == LinkClass::CdnTls));
        let mut sorted = ordered.clone();
        sorted.sort();
        let mut expected = items;
        expected.sort();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn order_within_a_class_is_shuffled() {
        let items: Vec<(LinkClass, u32)> = (0..50).map(|index| (LinkClass::Other, index)).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let ordered = order_by_class(items.clone(), |item| item.0, &mut rng);
        assert_ne!(
            ordered, items,
            "fifty items should not come back in feed order"
        );
    }

    #[test]
    fn an_empty_input_is_an_empty_order() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let ordered = order_by_class(Vec::<(LinkClass, u8)>::new(), |item| item.0, &mut rng);
        assert!(ordered.is_empty());
    }

    /// One worker name repeated many times must not run in a block at the
    /// front of its class: the first several items of the class come from
    /// different names.
    #[test]
    fn a_spread_batch_does_not_cluster_one_wire_name() {
        // 20 items under "worker.example" and 4 under three other names.
        let mut items: Vec<(LinkClass, &'static str, u32)> = Vec::new();
        for index in 0..20 {
            items.push((LinkClass::CdnTls, "worker.example", index));
        }
        for (index, name) in ["a.example", "b.example", "c.example"]
            .into_iter()
            .enumerate()
        {
            items.push((LinkClass::CdnTls, name, index as u32));
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let ordered = order_by_class_spread(
            items.clone(),
            |item| item.0,
            |item| item.1.to_string(),
            &mut rng,
        );
        assert_eq!(ordered.len(), items.len());
        // The four names interleave: among the first four items no name
        // appears twice, because every name still has an unvisited item.
        let first_four: Vec<&str> = ordered.iter().take(4).map(|item| item.1).collect();
        let mut unique = first_four.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 4, "first four items were {first_four:?}");
        // Nothing gained or lost.
        let mut sorted = ordered.clone();
        sorted.sort();
        let mut expected = items;
        expected.sort();
        assert_eq!(sorted, expected);
    }

    /// Items with no distinctive name (raw, no TLS) all share one key and
    /// keep their shuffled relative order — they do not crash the grouping.
    #[test]
    fn items_without_names_share_one_group() {
        let items: Vec<(LinkClass, &'static str, u32)> =
            (0..5).map(|index| (LinkClass::Other, "", index)).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let ordered = order_by_class_spread(
            items.clone(),
            |item| item.0,
            |item| item.1.to_string(),
            &mut rng,
        );
        assert_eq!(ordered.len(), items.len());
        let mut sorted = ordered.clone();
        sorted.sort();
        let mut expected = items;
        expected.sort();
        assert_eq!(sorted, expected);
    }
}
