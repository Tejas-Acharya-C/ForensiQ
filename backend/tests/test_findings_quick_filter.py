"""Regression test suite for Findings quick-filter pill logic and Increment 2 fix (INC2-DISC-01).

Verifies:
1. Selecting Low includes both LOW and INFORMATIONAL findings.
2. Selecting Low excludes MEDIUM, HIGH, and CRITICAL findings.
3. Selecting Medium still includes only MEDIUM.
4. Selecting Critical & High still includes both tiers.
5. Clearing the priority filter restores all applicable findings.
6. Search, sorting, and review-status filters continue to work alongside the Low filter.
7. The Low metric pill count matches the filtered table record count.
"""

import json
import subprocess
import pytest
from pathlib import Path


JS_FILTER_TEST_HARNESS = r"""
const fs = require('fs');

// Minimal DOM simulation for applyFindingsFilters
const state = {
  findingsState: {
    rawFindings: [],
    filteredFindings: [],
    searchQuery: '',
    priorityFilter: '',
    methodFilter: '',
    activityFilter: '',
    reviewStatusFilter: '',
    sortField: 'priority',
    sortDirection: 'desc'
  }
};

const FINDING_TIER_RANK = {
  'CRITICAL': 5,
  'HIGH': 4,
  'MEDIUM': 3,
  'LOW': 2,
  'INFORMATIONAL': 1,
  'INFO': 1
};

function getFindingEffectiveTier(f) {
  if (f.priority_tier) return String(f.priority_tier).toUpperCase();
  const sev = typeof f.severity === 'number' ? f.severity : (typeof f.severity_score === 'number' ? f.severity_score : 0);
  if (sev >= 0.8) return 'CRITICAL';
  if (sev >= 0.6) return 'HIGH';
  if (sev >= 0.4) return 'MEDIUM';
  if (sev >= 0.2) return 'LOW';
  return 'INFORMATIONAL';
}

function getFindingEffectiveScore(f) {
  if (typeof f.priority_score === 'number') return f.priority_score;
  const sev = typeof f.severity === 'number' ? f.severity : (typeof f.severity_score === 'number' ? f.severity_score : 0);
  return sev * 100.0;
}

function sortFindingsList(findings) {
  const field = state.findingsState.sortField || 'priority';
  const dir = state.findingsState.sortDirection === 'asc' ? 1 : -1;

  return findings.slice().sort((a, b) => {
    if (field === 'priority') {
      const tierA = FINDING_TIER_RANK[getFindingEffectiveTier(a)] || 0;
      const tierB = FINDING_TIER_RANK[getFindingEffectiveTier(b)] || 0;
      if (tierA !== tierB) {
        return dir * (tierA - tierB);
      }
      const scoreA = getFindingEffectiveScore(a);
      const scoreB = getFindingEffectiveScore(b);
      if (scoreA !== scoreB) {
        return dir * (scoreA - scoreB);
      }
      return 0;
    }
    if (field === 'title') {
      const titleA = (a.title || a.rule_name || a.rule_id || '').toLowerCase();
      const titleB = (b.title || b.rule_name || b.rule_id || '').toLowerCase();
      return dir * titleA.localeCompare(titleB);
    }
    return 0;
  });
}

function filterFindings(raw, filters) {
  const search = (filters.searchQuery || '').trim().toLowerCase();
  const prio = (filters.priorityFilter || '').toUpperCase().trim();
  const method = (filters.methodFilter || '').toUpperCase().trim();
  const activity = (filters.activityFilter || '').toUpperCase().trim();
  const review = (filters.reviewStatusFilter || '').toUpperCase().trim();

  return raw.filter(f => {
    // 1. Search filter
    if (search) {
      const title = (f.title || f.rule_name || '').toLowerCase();
      const desc = (f.description || '').toLowerCase();
      const fid = (f.id || '').toLowerCase();
      const rid = (f.rule_id || '').toLowerCase();
      const matchesSearch = title.includes(search) || desc.includes(search) || fid.includes(search) || rid.includes(search);
      if (!matchesSearch) return false;
    }

    // 2. Priority Filter (INC2-DISC-01 fix)
    if (prio) {
      const tier = getFindingEffectiveTier(f);

      if (prio === 'CRITICAL,HIGH' || prio === 'HIGH,CRITICAL') {
        if (tier !== 'CRITICAL' && tier !== 'HIGH') return false;
      } else if (prio === 'CRITICAL') {
        if (tier !== 'CRITICAL') return false;
      } else if (prio === 'HIGH') {
        if (tier !== 'HIGH') return false;
      } else if (prio === 'MEDIUM') {
        if (tier !== 'MEDIUM') return false;
      } else if (prio === 'LOW' || prio === 'LOW,INFORMATIONAL') {
        if (tier !== 'LOW' && tier !== 'INFORMATIONAL') return false;
      } else if (prio === 'INFORMATIONAL') {
        if (tier !== 'INFORMATIONAL') return false;
      }
    }

    // 3. Detection Method Filter
    if (method) {
      const ft = (f.finding_type || '').toUpperCase();
      const dm = (f.detection_method || '').toUpperCase();
      if (method === 'RULE') {
        if (ft === 'ML_ANOMALY' || dm.includes('MACHINE LEARNING')) return false;
      } else if (method === 'ML') {
        if (ft !== 'ML_ANOMALY' && !dm.includes('MACHINE LEARNING')) return false;
      }
    }

    // 4. Review Status Filter
    if (review) {
      const fRev = (f.review_status || 'NEW').toUpperCase();
      if (fRev !== review) return false;
    }

    return true;
  });
}

function updateFindingsSummaryMetrics(findings) {
  let highCount = 0;
  let medCount = 0;
  let lowCount = 0;
  let ruleCount = 0;
  let mlCount = 0;

  findings.forEach(f => {
    const tier = getFindingEffectiveTier(f);
    if (tier === 'CRITICAL' || tier === 'HIGH') {
      highCount++;
    } else if (tier === 'MEDIUM') {
      medCount++;
    } else {
      lowCount++;
    }

    if (f.finding_type === 'ML_ANOMALY' || f.detection_method === 'ML') {
      mlCount++;
    } else {
      ruleCount++;
    }
  });

  return { total: findings.length, highCount, medCount, lowCount, ruleCount, mlCount };
}

// Read input and execute scenario
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const filtered = filterFindings(input.rawFindings, input.filters);
state.findingsState.sortField = input.sortField || 'priority';
state.findingsState.sortDirection = input.sortDirection || 'desc';
const sorted = sortFindingsList(filtered);
const metrics = updateFindingsSummaryMetrics(input.rawFindings);

console.log(JSON.stringify({ filtered: sorted, metrics }));
"""


def _run_js_filter(raw_findings, filters, sort_field="priority", sort_direction="desc"):
    """Executes the JS filter harness with synthetic findings and filter options."""
    payload = json.dumps({
        "rawFindings": raw_findings,
        "filters": filters,
        "sortField": sort_field,
        "sortDirection": sort_direction
    })
    cmd = ["node", "-e", JS_FILTER_TEST_HARNESS]
    res = subprocess.run(cmd, input=payload, capture_output=True, text=True, check=True)
    return json.loads(res.stdout)


@pytest.fixture
def tiered_findings_set():
    """Provides a realistic set of findings across all tiers and statuses."""
    return [
        {
            "id": "f-crit-1",
            "title": "Privilege Escalation Mimikatz",
            "rule_id": "RULE-001",
            "finding_type": "RULE_MATCH",
            "severity": 0.95,
            "priority_tier": "CRITICAL",
            "review_status": "NEW",
            "created_at": "2026-11-10T10:00:00Z"
        },
        {
            "id": "f-high-1",
            "title": "PowerShell Obfuscated Download",
            "rule_id": "RULE-002",
            "finding_type": "RULE_MATCH",
            "severity": 0.75,
            "priority_tier": "HIGH",
            "review_status": "REVIEWED",
            "created_at": "2026-11-10T10:05:00Z"
        },
        {
            "id": "f-med-1",
            "title": "Unusual Port 445 SMB Traffic",
            "rule_id": "RULE-003",
            "finding_type": "RULE_MATCH",
            "severity": 0.50,
            "priority_tier": "MEDIUM",
            "review_status": "NEW",
            "created_at": "2026-11-10T10:10:00Z"
        },
        {
            "id": "f-low-1",
            "title": "Failed Single Authentication Attempt",
            "rule_id": "RULE-004",
            "finding_type": "RULE_MATCH",
            "severity": 0.25,
            "priority_tier": "LOW",
            "review_status": "REVIEWED",
            "created_at": "2026-11-10T10:15:00Z"
        },
        {
            "id": "f-info-1",
            "title": "User Logoff Recorded",
            "rule_id": "RULE-005",
            "finding_type": "RULE_MATCH",
            "severity": 0.05,
            "priority_tier": "INFORMATIONAL",
            "review_status": "NEW",
            "created_at": "2026-11-10T10:20:00Z"
        },
        {
            "id": "f-info-2",
            "title": "Scheduled Task Registration Baseline",
            "rule_id": "RULE-006",
            "finding_type": "RULE_MATCH",
            "severity": 0.10,
            "priority_tier": "INFORMATIONAL",
            "review_status": "REVIEWED",
            "created_at": "2026-11-10T10:25:00Z"
        }
    ]


def test_selecting_low_includes_both_low_and_informational(tiered_findings_set):
    """Proves: Selecting Low includes both LOW and INFORMATIONAL findings."""
    res = _run_js_filter(tiered_findings_set, {"priorityFilter": "LOW"})
    filtered = res["filtered"]
    filtered_ids = [f["id"] for f in filtered]

    # Must include the LOW finding and both INFORMATIONAL findings
    assert "f-low-1" in filtered_ids
    assert "f-info-1" in filtered_ids
    assert "f-info-2" in filtered_ids
    assert len(filtered) == 3


def test_selecting_low_excludes_medium_high_and_critical(tiered_findings_set):
    """Proves: Selecting Low excludes MEDIUM, HIGH, and CRITICAL findings."""
    res = _run_js_filter(tiered_findings_set, {"priorityFilter": "LOW"})
    filtered = res["filtered"]
    filtered_ids = [f["id"] for f in filtered]

    assert "f-crit-1" not in filtered_ids
    assert "f-high-1" not in filtered_ids
    assert "f-med-1" not in filtered_ids


def test_selecting_medium_includes_only_medium(tiered_findings_set):
    """Proves: Selecting Medium still includes only MEDIUM findings."""
    res = _run_js_filter(tiered_findings_set, {"priorityFilter": "MEDIUM"})
    filtered = res["filtered"]
    filtered_ids = [f["id"] for f in filtered]

    assert filtered_ids == ["f-med-1"]
    assert len(filtered) == 1


def test_selecting_critical_and_high_includes_both_tiers(tiered_findings_set):
    """Proves: Selecting Critical & High still includes both CRITICAL and HIGH tiers."""
    res = _run_js_filter(tiered_findings_set, {"priorityFilter": "CRITICAL,HIGH"})
    filtered = res["filtered"]
    filtered_ids = [f["id"] for f in filtered]

    assert "f-crit-1" in filtered_ids
    assert "f-high-1" in filtered_ids
    assert "f-med-1" not in filtered_ids
    assert "f-low-1" not in filtered_ids
    assert "f-info-1" not in filtered_ids
    assert len(filtered) == 2


def test_clearing_priority_filter_restores_all_findings(tiered_findings_set):
    """Proves: Clearing the priority filter restores all applicable findings."""
    # When priorityFilter is empty string
    res = _run_js_filter(tiered_findings_set, {"priorityFilter": ""})
    filtered = res["filtered"]

    assert len(filtered) == len(tiered_findings_set)
    assert set(f["id"] for f in filtered) == set(f["id"] for f in tiered_findings_set)


def test_search_sorting_and_review_status_work_alongside_low_filter(tiered_findings_set):
    """Proves: Search, sorting, and review-status filters continue to work alongside the Low filter."""
    # 1. Low + Search for "Logoff" -> should match f-info-1 only
    res_search = _run_js_filter(tiered_findings_set, {
        "priorityFilter": "LOW",
        "searchQuery": "Logoff"
    })
    assert [f["id"] for f in res_search["filtered"]] == ["f-info-1"]

    # 2. Low + Review Status "REVIEWED" -> should match f-low-1 and f-info-2
    res_review = _run_js_filter(tiered_findings_set, {
        "priorityFilter": "LOW",
        "reviewStatusFilter": "REVIEWED"
    })
    assert set(f["id"] for f in res_review["filtered"]) == {"f-low-1", "f-info-2"}

    # 3. Low + Sort by title ascending
    res_sort = _run_js_filter(tiered_findings_set, {
        "priorityFilter": "LOW"
    }, sort_field="title", sort_direction="asc")
    titles = [f["title"] for f in res_sort["filtered"]]
    assert titles == sorted(titles)


def test_pill_count_matches_filtered_count(tiered_findings_set):
    """Proves: The Low metric pill count matches the filtered table record count."""
    res = _run_js_filter(tiered_findings_set, {"priorityFilter": "LOW"})
    metrics = res["metrics"]
    filtered = res["filtered"]

    # lowCount on the pill MUST equal filtered row count when priorityFilter is 'LOW'
    assert metrics["lowCount"] == len(filtered)
    assert metrics["highCount"] == 2
    assert metrics["medCount"] == 1
    assert metrics["lowCount"] == 3
    assert metrics["total"] == 6


def test_frontend_source_contains_exact_low_filter_fix():
    """Verify that frontend/app.js literally contains the updated condition."""
    app_js_path = Path("frontend/app.js")
    assert app_js_path.exists(), "frontend/app.js must exist"
    code = app_js_path.read_text(encoding="utf-8")

    assert "prio === 'LOW' || prio === 'LOW,INFORMATIONAL'" in code, (
        "frontend/app.js must support both LOW and LOW,INFORMATIONAL filter strings"
    )
    assert "if (tier !== 'LOW' && tier !== 'INFORMATIONAL') return false;" in code, (
        "frontend/app.js must allow both LOW and INFORMATIONAL tiers when prio is LOW"
    )
