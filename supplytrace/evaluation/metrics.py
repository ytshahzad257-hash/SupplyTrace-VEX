"""Evaluation metric helpers for local prioritization experiments."""

from __future__ import annotations

import math
from collections.abc import Sequence


def precision_recall_f1(true_positive: int, false_positive: int, false_negative: int) -> dict[str, float]:
    """Return precision, recall, and F1 for binary actionability decisions."""

    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def confusion_counts(labels: Sequence[bool], predictions: Sequence[bool]) -> dict[str, int]:
    """Count binary confusion-matrix cells for equal-length label and prediction sequences."""

    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have equal length")
    true_positive = sum(1 for label, prediction in zip(labels, predictions) if label and prediction)
    false_positive = sum(1 for label, prediction in zip(labels, predictions) if not label and prediction)
    false_negative = sum(1 for label, prediction in zip(labels, predictions) if label and not prediction)
    true_negative = sum(1 for label, prediction in zip(labels, predictions) if not label and not prediction)
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
    }


def classification_metrics(labels: Sequence[bool], predictions: Sequence[bool]) -> dict[str, float | int]:
    """Return confusion counts plus precision/recall/F1."""

    counts = confusion_counts(labels, predictions)
    prf = precision_recall_f1(
        counts["true_positive"],
        counts["false_positive"],
        counts["false_negative"],
    )
    return {**counts, **prf}


def false_positive_reduction(raw_false_positive: int, proposed_false_positive: int) -> float:
    """Measure how many false positives the proposed filter removes compared with raw scanner output."""

    if raw_false_positive <= 0:
        return 0.0
    reduction = (raw_false_positive - proposed_false_positive) / raw_false_positive
    return round(max(0.0, min(1.0, reduction)), 6)


def top_k_actionability(ranked_labels: Sequence[bool], k: int) -> dict[str, float | int]:
    """Return the actionable fraction in the first ``k`` ranked labeled items."""

    if k <= 0:
        raise ValueError("k must be positive")
    top = list(ranked_labels[:k])
    actionable = sum(1 for label in top if label)
    evaluated_count = len(top)
    value = actionable / evaluated_count if evaluated_count else 0.0
    return {
        "k": k,
        "evaluated_count": evaluated_count,
        "actionable_count": actionable,
        "topk_actionability": round(value, 6),
    }


def discounted_cumulative_gain(relevances: Sequence[float], k: int | None = None) -> float:
    """Compute DCG for a ranked sequence of non-negative relevance scores."""

    limit = len(relevances) if k is None else min(k, len(relevances))
    score = 0.0
    for rank, relevance in enumerate(relevances[:limit], start=1):
        if relevance <= 0:
            continue
        score += float(relevance) / math.log2(rank + 1)
    return score


def ndcg_at_k(relevances: Sequence[float | int | bool], k: int | None = None) -> float:
    """Compute normalized discounted cumulative gain for ranked binary or graded labels."""

    numeric = [float(item) for item in relevances]
    limit = len(numeric) if k is None else min(k, len(numeric))
    if limit == 0:
        return 0.0
    observed = discounted_cumulative_gain(numeric, limit)
    ideal = discounted_cumulative_gain(sorted(numeric, reverse=True), limit)
    return round(observed / ideal, 6) if ideal else 0.0


def mean_average_precision(ranked_labels: Sequence[bool]) -> float:
    """Compute average precision for a ranked binary relevance sequence."""

    positives = 0
    precision_sum = 0.0
    for index, label in enumerate(ranked_labels, start=1):
        if not label:
            continue
        positives += 1
        precision_sum += positives / index
    return round(precision_sum / positives, 6) if positives else 0.0


def scanner_overlap(scanner_sets: Sequence[set[str]]) -> dict[str, float | int]:
    """Summarize how often normalized findings contain evidence from multiple scanners."""

    finding_count = len(scanner_sets)
    multi_scanner_findings = sum(1 for scanners in scanner_sets if len(scanners) > 1)
    all_scanners = sorted({scanner for scanners in scanner_sets for scanner in scanners})
    possible_pairs = 0
    overlapping_pairs = 0
    for left_index, left in enumerate(all_scanners):
        for right in all_scanners[left_index + 1 :]:
            possible_pairs += 1
            if any(left in scanners and right in scanners for scanners in scanner_sets):
                overlapping_pairs += 1
    return {
        "finding_count": finding_count,
        "multi_scanner_findings": multi_scanner_findings,
        "scanner_overlap": round(multi_scanner_findings / finding_count, 6) if finding_count else 0.0,
        "scanner_pair_count": possible_pairs,
        "overlapping_pair_count": overlapping_pairs,
    }


def evidence_completeness_score(present_fields: int, expected_fields: int) -> float:
    """Return an evidence completeness fraction."""

    if expected_fields <= 0:
        return 0.0
    return round(max(0.0, min(1.0, present_fields / expected_fields)), 6)
