"""Synthetic fixtures test STRICT REJECTION only; no application/native pass evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import validate_agent_read_components as engine
import validate_sensor_node_coverage_components as coverage

# Sanitized closed metadata fields copied from actual root zero-named OPA setup
# trace api-runtime-cli-final-compile-attempt.jsonl; fixed package failure Output
# retained so rejection reaches real failed/build state, not missing Output.
ACTUAL_ZERO_NAMED_API = [{'Action': 'start', 'Package': 'github.com/zasp-ai/zasp-sec/services/platform/apiserver'}, {'Action': 'output', 'Package': 'github.com/zasp-ai/zasp-sec/services/platform/apiserver', 'Output': 'FAIL\tgithub.com/zasp-ai/zasp-sec/services/platform/apiserver [setup failed]\n'}, {'Action': 'fail', 'Package': 'github.com/zasp-ai/zasp-sec/services/platform/apiserver', 'FailedBuild': 'github.com/open-policy-agent/opa/v1/rego'}]

def synthetic(roster):
 events=[]
 for package,names in roster.items():
  events.append({'Package':package,'Action':'start'})
  ordered=sorted(names,key=lambda n:(n.count('/'),n))
  for name in ordered: events.append({'Package':package,'Test':name,'Action':'run'})
  for name in reversed(ordered): events.append({'Package':package,'Test':name,'Action':'pass'})
  events.append({'Package':package,'Action':'pass'})
 return events

class SensorCoverageComponentEvidenceTests(unittest.TestCase):
 def test_exact152_synthetic_fixture_is_guard_only(self):
  expected,required=coverage.load_contract()
  self.assertEqual(len(expected),10)
  self.assertEqual(sum('/' not in n for names in expected.values() for n in names),28)
  self.assertTrue(coverage.GUARDS.issubset(required))
  self.assertEqual(engine.validate_events(synthetic(expected),0,expected),{'classification':'component-only','packages':10,'named_passes':152})
 def test_actual_zero_named_setup_trace_and_partial_package_rejected(self):
  expected,_=coverage.load_contract()
  for status in [0,1]:
   with self.subTest(status=status),self.assertRaises(engine.EvidenceRejected):engine.validate_events(ACTUAL_ZERO_NAMED_API,status,expected)
  with self.assertRaises(engine.EvidenceRejected):engine.validate_events(synthetic({p:n for p,n in expected.items() if p.endswith('/migrations')}),0,expected)
 def test_nonzero_unknown_skip_duplicate_foreign_missing_never_pass(self):
  expected,_=coverage.load_contract();events=synthetic(expected)
  for status in [1,-1,True,None]:
   with self.subTest(status=status),self.assertRaises(engine.EvidenceRejected):engine.validate_events(events,status,expected)
  variants=[[],events[:-1],events+[events[-1]],events+[{'Package':'foreign','Action':'pass'}]]
  for action in ['skip','fail','unknown']:
   bad=copy.deepcopy(events);bad[2]['Action']=action;variants.append(bad)
  bad=copy.deepcopy(events);bad[1]['Test']+='_foreign';variants.append(bad)
  for i,bad in enumerate(variants):
   with self.subTest(i=i),self.assertRaises(engine.EvidenceRejected):engine.validate_events(bad,0,expected)
 def test_ancestor_or_start_or_pass_reordering_rejected(self):
  expected,_=coverage.load_contract();events=synthetic(expected)
  bad=copy.deepcopy(events)
  child=next(i for i,event in enumerate(bad) if event.get('Action')=='run' and '/' in event.get('Test',''))
  bad[1],bad[child]=bad[child],bad[1]
  with self.assertRaises(engine.EvidenceRejected):engine.validate_events(bad,0,expected)
  bad=copy.deepcopy(events);bad.insert(2,copy.deepcopy(bad[1]))
  with self.assertRaises(engine.EvidenceRejected):engine.validate_events(bad,0,expected)
 def test_old_agent_roster_cannot_substitute(self):
  expected,_=coverage.load_contract()
  with self.assertRaises(engine.EvidenceRejected):engine.validate_events(synthetic(engine.EXPECTED),0,expected)
 def test_fixed_contract_names_modules_and_ancestors_cannot_drift(self):
  spec=json.loads(coverage.ROSTER.read_text())
  variants=[]
  bad=copy.deepcopy(spec);bad['packages'][0]['expected_names'][0]+='_foreign';variants.append(bad)
  bad=copy.deepcopy(spec);bad['packages'][0]['module']='services/event-ingest';variants.append(bad)
  bad=copy.deepcopy(spec);bad['required_source_paths'].remove('scripts/validate_agent_read_components.py');variants.append(bad)
  bad=copy.deepcopy(spec);bad['packages'][0]['expected_names'].append(bad['packages'][0]['expected_names'][0]);variants.append(bad)
  for i,bad in enumerate(variants):
   with self.subTest(i=i),tempfile.TemporaryDirectory() as directory:
    path=Path(directory)/'roster.json';path.write_text(json.dumps(bad))
    with patch.object(coverage,'ROSTER',path),self.assertRaises(engine.EvidenceRejected):coverage.load_contract()

if __name__ == '__main__': unittest.main()
