"""Workload split among team members with alphabetical Round-Robin (RF-07, Phase 5).

Sorts the changed binaries by key and assigns them in rotation to the people,
guaranteeing a fair and deterministic split. The coordinator uses these
assignments to generate one .zip per person.
"""

from __future__ import annotations

from typing import Any


def split_round_robin(
    changed: list[dict[str, Any]], people: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """Split `changed` among `people` with alphabetical Round-Robin.

    - Items are sorted by 'key' (or 'logical_name') so the split is
      deterministic and independent of the input order.
    - Item i is assigned to people[i % n].

    Returns {person: [items]} with one entry per person (it may be empty).
    """
    if not people:
        raise ValueError("at least one person is required for the split")

    ordered_people = sorted(people)
    assignments: dict[str, list[dict[str, Any]]] = {p: [] for p in ordered_people}

    def _key(item: dict[str, Any]) -> str:
        return item.get("key") or item.get("logical_name") or ""

    for i, item in enumerate(sorted(changed, key=_key)):
        assignments[ordered_people[i % len(ordered_people)]].append(item)

    return assignments


def balance_report(assignments: dict[str, list[Any]]) -> dict[str, int]:
    """Item count per person (to check that the split is balanced)."""
    return {person: len(items) for person, items in assignments.items()}
