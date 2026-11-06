"""Guard fixtures verify evidence rejection, not application/native behavior."""
import copy
import unittest

import validate_agent_read_components as original
import validate_agent_exposure_components as exposure


def synthetic(roster):
    events = []
    for package, names in roster.items():
        events.append({'Package': package, 'Action': 'start'})
        ordered = sorted(names, key=lambda name: (name.count('/'), name))
        for name in ordered:
            events.append({'Package': package, 'Test': name, 'Action': 'run'})
        for name in reversed(ordered):
            events.append({'Package': package, 'Test': name, 'Action': 'pass'})
        events.append({'Package': package, 'Action': 'pass'})
    return events


class ExposureEvidenceContractTests(unittest.TestCase):
    def test_complete_new_76_fixture_is_validator_only_and_old_76_cannot_substitute(self):
        expected, paths = exposure.load_contract()
        self.assertEqual(set(expected), exposure.PACKAGES)
        self.assertTrue(exposure.GUARDS.issubset(paths))
        self.assertEqual(original.validate_events(synthetic(expected), 0, expected),
                         {'classification': 'component-only', 'packages': 4, 'named_passes': 76})
        with self.assertRaises(original.EvidenceRejected):
            original.validate_events(synthetic(original.EXPECTED), 0, expected)
        self.assertEqual(original.validate_events(synthetic(original.EXPECTED), 0)['named_passes'], 76)
        self.assertNotEqual(expected, original.EXPECTED)

    def test_partial_setup_skip_duplicate_and_foreign_results_cannot_pass(self):
        expected, _ = exposure.load_contract()
        events = synthetic(expected)
        for status in [1, -1, True, None]:
            with self.subTest(status=status), self.assertRaises(original.EvidenceRejected):
                original.validate_events(events, status, expected)
        partial = {package: names for package, names in expected.items() if package.endswith('/migrations')}
        invalid = [[], synthetic(partial), events[:-1], events + [events[-1]],
                   events + [{'Package': 'foreign', 'Action': 'pass'}]]
        for action in ['skip', 'fail', 'unknown']:
            bad = copy.deepcopy(events)
            bad[2]['Action'] = action
            invalid.append(bad)
        bad = copy.deepcopy(events)
        bad[1]['Test'] += '_foreign'
        invalid.append(bad)
        for index, bad in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(original.EvidenceRejected):
                original.validate_events(bad, 0, expected)


if __name__ == '__main__':
    unittest.main()
