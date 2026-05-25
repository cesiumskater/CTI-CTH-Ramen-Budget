"""Tests for `ramen_cve.bucket_policy` — the leaf module that backs
Task 7's configurable bucket labels / thresholds.

Slice A scope: pure data only — `BucketSpec`, `BucketPolicy`,
`DEFAULT_BUCKET_POLICY`, `BucketPolicy.from_yaml`. No integration with
`bucket_and_suggest` or `write_markdown` yet (slices B / D).
"""
from __future__ import annotations

import pytest

from ramen_cve.bucket_policy import (
    BUCKET_IDS,
    DEFAULT_BUCKET_POLICY,
    KEV_BUCKET_ID,
    BucketPolicy,
    BucketSpec,
)
from ramen_cve.constants import (
    BUCKET_ACTIONS,
    DEFAULT_CVSS_THRESHOLD,
    DEFAULT_EPSS_THRESHOLD,
)

# ---------------------------------------------------------------------------
# Sanity: the leaf shape itself.
# ---------------------------------------------------------------------------


def test_bucket_ids_match_bucket_actions_keys():
    """The six reserved ids must agree with the existing constants table.

    A future hand-edit that adds a key to BUCKET_ACTIONS without bumping
    BUCKET_IDS would silently break `from_yaml` validation; lock that
    coupling here.
    """
    assert set(BUCKET_IDS) == set(BUCKET_ACTIONS.keys())


def test_kev_bucket_id_is_in_bucket_ids():
    assert KEV_BUCKET_ID in BUCKET_IDS


def test_bucket_spec_is_frozen():
    """BucketSpec must be immutable — slices B/D treat specs as values."""
    spec = BucketSpec(id="patch_now", label="L", action="A", order=1)
    with pytest.raises((AttributeError, TypeError)):
        spec.label = "x"  # type: ignore[misc]


def test_bucket_policy_is_frozen():
    with pytest.raises((AttributeError, TypeError)):
        DEFAULT_BUCKET_POLICY.default_cvss_threshold = 9.9  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DEFAULT_BUCKET_POLICY: must mirror today's hardcoded behaviour byte-for-byte.
# ---------------------------------------------------------------------------


def test_default_policy_thresholds_match_constants():
    assert DEFAULT_BUCKET_POLICY.default_cvss_threshold == DEFAULT_CVSS_THRESHOLD
    assert DEFAULT_BUCKET_POLICY.default_epss_threshold == DEFAULT_EPSS_THRESHOLD


def test_default_policy_carries_every_reserved_bucket():
    assert set(DEFAULT_BUCKET_POLICY.buckets.keys()) == set(BUCKET_IDS)


def test_default_policy_actions_match_constants_table():
    """Each bucket's action prose must equal today's BUCKET_ACTIONS entry."""
    for bid in BUCKET_IDS:
        assert DEFAULT_BUCKET_POLICY.action(bid) == BUCKET_ACTIONS[bid]


def test_default_policy_display_order_matches_markdown_order():
    """display_order() must mirror output.markdown.BUCKET_ORDER exactly.

    A reordering here would shift the Markdown report's section sequence
    — the byte-oracle would catch it later, but lock the contract now.
    """
    from ramen_cve.output.markdown import BUCKET_ORDER as MARKDOWN_ORDER

    assert DEFAULT_BUCKET_POLICY.display_order() == list(MARKDOWN_ORDER)


def test_default_policy_labels_match_markdown_display():
    """spec.label per bucket must equal today's BUCKET_DISPLAY entry."""
    from ramen_cve.output.markdown import BUCKET_DISPLAY as MARKDOWN_DISPLAY

    for bid in BUCKET_IDS:
        assert DEFAULT_BUCKET_POLICY.label(bid) == MARKDOWN_DISPLAY[bid]


def test_default_policy_has_no_per_bucket_threshold_overrides():
    """v0 default behaviour uses one shared threshold pair, not per-bucket."""
    for bid in BUCKET_IDS:
        spec = DEFAULT_BUCKET_POLICY.spec(bid)
        assert spec.cvss_threshold is None
        assert spec.epss_threshold is None


def test_threshold_fallback_returns_policy_default_when_spec_unset():
    """`cvss_threshold_for` / `epss_threshold_for` fall back to the policy default."""
    assert DEFAULT_BUCKET_POLICY.cvss_threshold_for("patch_now") == DEFAULT_CVSS_THRESHOLD
    assert DEFAULT_BUCKET_POLICY.epss_threshold_for("patch_now") == DEFAULT_EPSS_THRESHOLD


# ---------------------------------------------------------------------------
# BucketPolicy.from_yaml — the YAML-merge contract.
# ---------------------------------------------------------------------------


def test_from_yaml_none_returns_default_policy_identity():
    """An absent `buckets:` block must produce the literal default singleton."""
    assert BucketPolicy.from_yaml(None) is DEFAULT_BUCKET_POLICY


def test_from_yaml_empty_dict_returns_default_policy_identity():
    """An empty `buckets:` block is "nothing overridden" — same as missing."""
    assert BucketPolicy.from_yaml({}) is DEFAULT_BUCKET_POLICY


def test_from_yaml_overrides_one_bucket_label_keeps_others_default():
    """Partial overrides must merge over the default — untouched buckets unchanged."""
    policy = BucketPolicy.from_yaml({"patch_now": {"label": "URGENT"}})

    # Overridden bucket picks up the new label, keeps default action/order.
    spec = policy.spec("patch_now")
    assert spec.label == "URGENT"
    assert spec.action == BUCKET_ACTIONS["patch_now"]
    assert spec.order == DEFAULT_BUCKET_POLICY.spec("patch_now").order

    # Untouched buckets identical to default.
    for bid in BUCKET_IDS:
        if bid == "patch_now":
            continue
        assert policy.spec(bid) == DEFAULT_BUCKET_POLICY.spec(bid)


def test_from_yaml_overrides_per_bucket_thresholds():
    """A YAML override of cvss_threshold/epss_threshold must reach the spec."""
    policy = BucketPolicy.from_yaml({
        "patch_now": {"cvss_threshold": 8.5, "epss_threshold": 0.20}
    })

    assert policy.cvss_threshold_for("patch_now") == 8.5
    assert policy.epss_threshold_for("patch_now") == 0.20
    # Other buckets still use the policy default.
    assert policy.cvss_threshold_for("watch_closely") == DEFAULT_CVSS_THRESHOLD
    assert policy.epss_threshold_for("watch_closely") == DEFAULT_EPSS_THRESHOLD


def test_from_yaml_overrides_action_text_and_order():
    policy = BucketPolicy.from_yaml({
        "watch_closely": {"action": "Custom action prose.", "order": 99},
    })
    spec = policy.spec("watch_closely")
    assert spec.action == "Custom action prose."
    assert spec.order == 99

    # The reordering propagates to display_order().
    assert policy.display_order()[-1] == "watch_closely"


def test_from_yaml_unknown_bucket_id_raises():
    """A typo'd bucket id must fail loudly — silent no-op is a foot-gun."""
    with pytest.raises(ValueError, match="Unknown bucket id"):
        BucketPolicy.from_yaml({"patch_immediately": {"label": "X"}})


def test_from_yaml_non_mapping_top_level_raises():
    with pytest.raises(ValueError, match="must be a YAML mapping"):
        BucketPolicy.from_yaml(["patch_now"])  # type: ignore[arg-type]


def test_from_yaml_non_mapping_bucket_entry_raises():
    with pytest.raises(ValueError, match=r"buckets\.patch_now must be a YAML mapping"):
        BucketPolicy.from_yaml({"patch_now": "URGENT"})


def test_from_yaml_can_override_kev_metadata_but_id_stays_reserved():
    """KEV bucket label/action are configurable; the bucket id itself is not.

    Slice B will enforce the rule that KEV records *always* land in the
    KEV bucket (kev_listed precedence) regardless of label customisation.
    """
    policy = BucketPolicy.from_yaml({
        KEV_BUCKET_ID: {"label": "KEV — EMERGENCY", "action": "Drop everything."}
    })
    assert policy.label(KEV_BUCKET_ID) == "KEV — EMERGENCY"
    assert policy.action(KEV_BUCKET_ID) == "Drop everything."


def test_from_yaml_coerces_yaml_numeric_strings_to_float():
    """YAML can emit '0.15' as a string in edge cases; from_yaml must coerce."""
    policy = BucketPolicy.from_yaml({
        "patch_now": {"cvss_threshold": "8.5", "epss_threshold": "0.15"}
    })
    assert policy.cvss_threshold_for("patch_now") == 8.5
    assert policy.epss_threshold_for("patch_now") == 0.15


def test_from_yaml_blank_threshold_collapses_to_none_override():
    """An empty-string threshold means 'no override' (fall back to default)."""
    policy = BucketPolicy.from_yaml({"patch_now": {"cvss_threshold": ""}})
    assert policy.cvss_threshold_for("patch_now") == DEFAULT_CVSS_THRESHOLD


def test_from_yaml_returns_a_bucket_policy_instance():
    """Light type-check guard for downstream `isinstance` uses."""
    policy = BucketPolicy.from_yaml({"patch_now": {"label": "X"}})
    assert isinstance(policy, BucketPolicy)
    for spec in policy.buckets.values():
        assert isinstance(spec, BucketSpec)


# ---------------------------------------------------------------------------
# Slice B — bucket_and_suggest(policy=…) backward-compat path.
# ---------------------------------------------------------------------------


def _enriched(*, cvss, epss, kev=False):
    """Build a minimal EnrichedCve for the policy-routing tests."""
    from datetime import date

    from ramen_cve.models import EnrichedCve

    return EnrichedCve(
        cve_id="CVE-2024-9001",
        source="t",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=cvss,
        epss_score=epss,
        kev_listed=kev,
    )


def test_bucket_and_suggest_default_call_uses_default_policy_actions():
    """Calling with no policy → DEFAULT_BUCKET_POLICY actions land verbatim."""
    from ramen_cve.analyze import bucket_and_suggest

    rec = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([rec])
    assert rec.bucket == "patch_now"
    assert rec.suggested_action == DEFAULT_BUCKET_POLICY.action("patch_now")


def test_bucket_and_suggest_explicit_default_policy_is_identity():
    """Passing `policy=DEFAULT_BUCKET_POLICY` matches the policy=None call."""
    from ramen_cve.analyze import bucket_and_suggest

    a = _enriched(cvss=9.0, epss=0.5)
    b = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([a])
    bucket_and_suggest([b], policy=DEFAULT_BUCKET_POLICY)
    assert a.bucket == b.bucket == "patch_now"
    assert a.suggested_action == b.suggested_action


def test_bucket_and_suggest_legacy_threshold_args_still_steer_decision_tree():
    """Legacy `cvss_thr`/`epss_thr` args (policy=None path) must still work."""
    from ramen_cve.analyze import bucket_and_suggest

    # 5.0/0.05 is "deprioritize" under defaults (cvss 7, epss 0.10) but
    # "patch_now" under tighter thresholds.
    rec = _enriched(cvss=5.0, epss=0.05)
    bucket_and_suggest([rec], cvss_thr=4.0, epss_thr=0.04)
    assert rec.bucket == "patch_now"


def test_bucket_and_suggest_per_bucket_patch_now_thresholds_drive_pivot():
    """A YAML override of patch_now.cvss/epss_threshold must steer the tree."""
    from ramen_cve.analyze import bucket_and_suggest

    policy = BucketPolicy.from_yaml({
        "patch_now": {"cvss_threshold": 8.0, "epss_threshold": 0.20}
    })

    # CVSS 9.0 / EPSS 0.5 still qualifies as patch_now under the stricter pivot.
    rec_high = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([rec_high], policy=policy)
    assert rec_high.bucket == "patch_now"

    # CVSS 7.5 / EPSS 0.5 is "watch_closely" now (CVSS below the 8.0 pivot,
    # EPSS above the 0.20 pivot) — would have been patch_now under defaults.
    rec_borderline = _enriched(cvss=7.5, epss=0.5)
    bucket_and_suggest([rec_borderline], policy=policy)
    assert rec_borderline.bucket == "watch_closely"


def test_bucket_and_suggest_policy_action_text_overrides_default():
    """Per-bucket `action` from YAML must reach `rec.suggested_action`."""
    from ramen_cve.analyze import bucket_and_suggest

    policy = BucketPolicy.from_yaml({
        "patch_now": {"action": "Patch within 24 hours per security policy."}
    })
    rec = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([rec], policy=policy)
    assert rec.bucket == "patch_now"
    assert rec.suggested_action == "Patch within 24 hours per security policy."


def test_bucket_and_suggest_kev_always_wins_under_custom_policy():
    """KEV precedence is non-configurable — a relabelled KEV bucket still wins."""
    from ramen_cve.analyze import bucket_and_suggest

    policy = BucketPolicy.from_yaml({
        KEV_BUCKET_ID: {"label": "KEV — EMERGENCY", "action": "Drop everything."}
    })
    rec = _enriched(cvss=1.0, epss=0.01, kev=True)
    bucket_and_suggest([rec], policy=policy)
    assert rec.bucket == KEV_BUCKET_ID
    assert rec.suggested_action == "Drop everything."


def test_bucket_and_suggest_legacy_args_ignored_when_policy_supplied():
    """When `policy` is passed, the legacy `cvss_thr`/`epss_thr` args are ignored."""
    from ramen_cve.analyze import bucket_and_suggest

    policy = BucketPolicy.from_yaml({
        "patch_now": {"cvss_threshold": 8.0, "epss_threshold": 0.20}
    })
    # If the legacy args were honoured, the policy=None branch would
    # produce a wider net and this would be patch_now. With policy
    # supplied, the pivot is 8.0/0.20 and this record is deprioritized.
    rec = _enriched(cvss=4.5, epss=0.05)
    bucket_and_suggest([rec], cvss_thr=4.0, epss_thr=0.04, policy=policy)
    assert rec.bucket == "deprioritize"


def test_bucket_and_suggest_unknown_when_score_missing_under_custom_policy():
    """Missing CVSS/EPSS still routes to `unknown` regardless of policy."""
    from ramen_cve.analyze import bucket_and_suggest

    policy = BucketPolicy.from_yaml({
        "patch_now": {"cvss_threshold": 8.0, "epss_threshold": 0.20},
        "unknown": {"action": "Triage manually within 1 business day."},
    })
    rec = _enriched(cvss=None, epss=0.5)
    bucket_and_suggest([rec], policy=policy)
    assert rec.bucket == "unknown"
    assert rec.suggested_action == "Triage manually within 1 business day."


# ---------------------------------------------------------------------------
# Slice C — apply_yaml_config(buckets=…) integration.
# ---------------------------------------------------------------------------


def _bare_args():
    """Build a minimal argparse.Namespace `apply_yaml_config` accepts."""
    import argparse

    return argparse.Namespace(
        subcommand=None, out_dir=None, basename=None, format=None,
        cvss_threshold=None, epss_threshold=None, no_cache=False,
        quiet=False, verbose=False, dispatch=False, digest=False,
        no_exploit_lookup=False, no_enrich_iocs=False, sector=None,
        ioc_confidence_floor=None, start=None, end=None, date_mode=None,
        path=None, url=None, cves=None, taxii_url=None,
        taxii_collection=None, inventory=None, allow_tlp_red=False,
    )


def test_apply_yaml_config_no_buckets_block_leaves_namespace_untouched():
    """A config without `buckets:` must not stamp a `bucket_policy` attr."""
    from ramen_cve import apply_yaml_config

    args = _bare_args()
    apply_yaml_config(args, {"subcommand": "opml"})
    assert getattr(args, "bucket_policy", None) is None


def test_apply_yaml_config_empty_buckets_block_yields_default_policy():
    """`buckets: {}` is interpreted as 'all defaults' → the default singleton."""
    from ramen_cve import apply_yaml_config

    args = _bare_args()
    apply_yaml_config(args, {"buckets": {}})
    assert args.bucket_policy is DEFAULT_BUCKET_POLICY


def test_apply_yaml_config_populated_buckets_block_reaches_namespace():
    """Per-bucket overrides reach `args.bucket_policy` as a real `BucketPolicy`."""
    from ramen_cve import apply_yaml_config

    args = _bare_args()
    apply_yaml_config(args, {
        "buckets": {
            "patch_now": {
                "label": "Critical - Patch Now",
                "cvss_threshold": 8.0,
                "epss_threshold": 0.15,
                "action": "Patch within 24 hours",
                "order": 1,
            },
        },
    })
    assert isinstance(args.bucket_policy, BucketPolicy)
    spec = args.bucket_policy.spec("patch_now")
    assert spec.label == "Critical - Patch Now"
    assert spec.action == "Patch within 24 hours"
    assert spec.cvss_threshold == 8.0
    assert spec.epss_threshold == 0.15
    assert spec.order == 1
    # Untouched buckets remain at default.
    assert args.bucket_policy.spec("watch_closely") == DEFAULT_BUCKET_POLICY.spec("watch_closely")


def test_apply_yaml_config_cli_set_bucket_policy_is_preserved():
    """A pre-set `bucket_policy` on args is preserved — same heuristic as other CLI-wins keys."""
    from ramen_cve import apply_yaml_config

    args = _bare_args()
    cli_policy = BucketPolicy.from_yaml({"patch_now": {"label": "CLI-WINS"}})
    args.bucket_policy = cli_policy

    apply_yaml_config(args, {"buckets": {"patch_now": {"label": "YAML-LOSES"}}})
    assert args.bucket_policy is cli_policy
    assert args.bucket_policy.label("patch_now") == "CLI-WINS"


def test_apply_yaml_config_buckets_block_unknown_id_raises():
    """A typo in a bucket id surfaces from `apply_yaml_config` as ValueError."""
    from ramen_cve import apply_yaml_config

    args = _bare_args()
    with pytest.raises(ValueError, match="Unknown bucket id"):
        apply_yaml_config(args, {"buckets": {"patch_immediately": {"label": "X"}}})


def test_apply_yaml_config_buckets_threaded_through_decision_tree():
    """End-to-end: YAML → apply → bucket_and_suggest(policy=args.bucket_policy)."""
    from ramen_cve import apply_yaml_config
    from ramen_cve.analyze import bucket_and_suggest

    args = _bare_args()
    apply_yaml_config(args, {
        "buckets": {
            "patch_now": {
                "cvss_threshold": 8.0,
                "epss_threshold": 0.20,
                "action": "Emergency patch protocol engaged.",
            }
        }
    })
    rec = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([rec], policy=args.bucket_policy)
    assert rec.bucket == "patch_now"
    assert rec.suggested_action == "Emergency patch protocol engaged."


# ---------------------------------------------------------------------------
# Slice D — write_markdown(policy=…) consumption.
# ---------------------------------------------------------------------------


def _md_run_metadata():
    """Minimal run_metadata dict accepted by write_markdown."""
    return {
        "version": "test-0",
        "command": "test",
        "args": "",
        "cvss_threshold": 7.0,
        "epss_threshold": 0.10,
    }


def test_write_markdown_default_policy_produces_pre_task7_section_labels(tmp_path):
    """policy=None must produce the same section headings as today."""
    from ramen_cve.analyze import bucket_and_suggest
    from ramen_cve.output.markdown import write_markdown

    rec = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([rec])
    md_path = tmp_path / "out.md"
    write_markdown([rec], md_path, _md_run_metadata())
    body = md_path.read_text(encoding="utf-8")
    assert "## Patch Now" in body  # default BUCKET_DISPLAY label
    assert "## Critical - Patch Now" not in body  # not the custom label


def test_write_markdown_custom_policy_changes_section_heading_and_summary(tmp_path):
    """A `buckets.patch_now.label` override must propagate to ## heading + summary table."""
    from ramen_cve.analyze import bucket_and_suggest
    from ramen_cve.output.markdown import write_markdown

    policy = BucketPolicy.from_yaml({
        "patch_now": {"label": "Critical - Patch Now",
                      "action": "Patch within 24 hours per security policy."}
    })
    rec = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([rec], policy=policy)

    md_path = tmp_path / "out.md"
    write_markdown([rec], md_path, _md_run_metadata(), policy=policy)
    body = md_path.read_text(encoding="utf-8")

    # The section heading uses the custom label.
    assert "## Critical - Patch Now" in body
    assert "## Patch Now\n" not in body  # the default-label heading is gone

    # The per-record Action line uses the custom action prose.
    assert "Patch within 24 hours per security policy." in body

    # The summary table row uses the custom label.
    assert "| Critical - Patch Now | 1 |" in body


def test_write_markdown_custom_policy_reorders_sections(tmp_path):
    """An `order` override on `unknown` must reshuffle the section sequence."""
    from ramen_cve.analyze import bucket_and_suggest
    from ramen_cve.output.markdown import write_markdown

    # Pull `unknown` to the front by giving it the lowest order.
    policy = BucketPolicy.from_yaml({
        "unknown": {"order": -1},
    })

    a = _enriched(cvss=None, epss=0.5)  # → unknown
    b = _enriched(cvss=9.0, epss=0.5)   # → patch_now
    bucket_and_suggest([a, b], policy=policy)

    md_path = tmp_path / "out.md"
    write_markdown([a, b], md_path, _md_run_metadata(), policy=policy)
    body = md_path.read_text(encoding="utf-8")

    unknown_pos = body.find("## Unknown / Insufficient Data")
    patch_now_pos = body.find("## Patch Now")
    assert unknown_pos > 0 and patch_now_pos > 0
    assert unknown_pos < patch_now_pos


def test_write_markdown_threads_through_pipeline_output(tmp_path):
    """End-to-end via pipeline._output: args.bucket_policy reaches the MD file."""
    import argparse

    from ramen_cve.analyze import bucket_and_suggest
    from ramen_cve.pipeline import _output

    policy = BucketPolicy.from_yaml({
        "patch_now": {"label": "URGENT-PATCH"}
    })
    rec = _enriched(cvss=9.0, epss=0.5)
    bucket_and_suggest([rec], policy=policy)

    args = argparse.Namespace(
        out_dir=tmp_path, basename="test", format="md",
        allow_tlp_red=False, bucket_policy=policy,
    )
    metadata = _md_run_metadata()
    paths = _output([rec], args, metadata)
    md_text = paths["md"].read_text(encoding="utf-8")
    assert "## URGENT-PATCH" in md_text
