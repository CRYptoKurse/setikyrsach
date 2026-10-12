import copy
import unittest

from overlay.study import validate_run


def accepted_result() -> dict:
    return {
        "config": {
            "node_count": 12,
            "bucket_size": 3,
            "operationally_converged": True,
            "profile": {"required_relays": 2},
        },
        "node_tables": [{"total_contacts": 8, "bucket_sizes": [1] * 8 + [0] * 248} for _ in range(12)],
        "lookups": [{"target_absent_before": True, "used_intermediate": True, "target_found": True}
                    for _ in range(30)],
        "lookup_candidate_failure": {"failure_observed": True, "target_found": True},
        "bootstrap_failure": {"lookup_target_found": True, "find_value_succeeded": True},
        "storage_failure_injections": [{"replica_count_before_failure": 3, "recovered": True}
                                       for _ in range(5)],
        "messages": [{"delivered": True, "relay_ids": ["a", "b"]} for _ in range(30)],
        "relay_failure_injections": [{"first_attempt_failed": True, "recovered": True,
                                      "replacement_relay_ids": ["b", "c"], "failed_relay_id": "a"}
                                     for _ in range(5)],
    }


class StudyValidationTests(unittest.TestCase):
    def test_accepts_complete_simplified_profile(self):
        self.assertTrue(all(validate_run(accepted_result()).values()))

    def test_rejects_lookup_that_skips_intermediate_node(self):
        result = copy.deepcopy(accepted_result())
        result["lookups"][0]["used_intermediate"] = False
        self.assertFalse(validate_run(result)["30_absent_target_lookups_via_intermediary"])

    def test_rejects_degenerate_routing_tables(self):
        result = accepted_result()
        for node in result["node_tables"]:
            node["total_contacts"] = 11
        self.assertFalse(validate_run(result)["non_degenerate_bounded_dht"])


if __name__ == "__main__":
    unittest.main()