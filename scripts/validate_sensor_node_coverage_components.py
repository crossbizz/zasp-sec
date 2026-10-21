#!/usr/bin/env python3
"""Require exact retained node-coverage COMPONENT results, never native/deployed proof."""
import argparse
import json
from pathlib import Path
import re
import sys
from validate_agent_read_components import EvidenceRejected, check_sources, decode_json, load_events, validate_events

ROOT = Path(__file__).resolve().parent.parent
ROSTER = ROOT / '.github/sensor-node-coverage-component-roster.json'
HEADS = {'github.com/zasp-ai/zasp-sec/services/platform/apiserver': ['TestSensorNodeCoverageRepresentationAdmission', 'TestSensorNodeCoverageCurrentRepositoryAndStatement', 'TestSensorNodeCoverageStrictReadDTO', 'TestSensorNodeCoverageMountedHandlerSelectsExactRead'], 'github.com/zasp-ai/zasp-sec/services/platform/agentsec-api': ['TestSensorNodeCoverageRuntimeExplicitCompiledPin'], 'github.com/zasp-ai/zasp-sec/services/platform/agentsec-migrate': ['TestSensorNodeCoverageMigrationDispatchAndConfirmation', 'TestSensorNodeCoverageCLIInputsAndChecksums'], 'github.com/zasp-ai/zasp-sec/services/platform/migrations': ['TestSensorNodeCoverageInstallerClosedAdmission', 'TestSensorNodeCoverageCompilerIdentity'], 'github.com/zasp-ai/zasp-sec/services/platform/runtimeevent': ['TestCurrentRuntimeIngestRoutesSemanticAndPreciseSources', 'TestCurrentRuntimeIntakeIdentityDoesNotReplaceHealth'], 'github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire': ['TestRetainedCoverageWireFullInventoryAndOriginalTimes', 'TestRetainedCoverageWireStructuralExpiryAndIncompleteInventory', 'TestRetainedCoverageWireClosedNestedContract', 'TestRetainedCoverageWireReceiptDispositionsAreExact', 'TestRetainedCoverageWireExistingReportCompatibility'], 'github.com/zasp-ai/zasp-sec/services/platform/sensor': ['TestPrivateNodeCoverageHeartbeatAdmissionAndReceipt'], 'github.com/zasp-ai/zasp-sec/services/platform/sensoradapter': ['TestProductionClientRetainedHeartbeatExactWireAndReceipt'], 'github.com/zasp-ai/zasp-sec/services/event-ingest': ['TestNodeCoverageRetentionConfigRefusesImplicitAuthority', 'TestProductionNodeCoverageComposedCommitBoundary', 'TestProductionNodeCoverageSamePoolTransaction'], 'github.com/zasp-ai/zasp-sec/services/sensor-agent': ['TestRetainedCoordinatorPreparesFullCapacityWithoutLegacyAnnotation', 'TestRetainedCoordinatorResolvesExactPendingWithoutFreshObservation', 'TestRetainedCoordinatorRefusesIncompleteOptInConfiguration', 'TestRetainedCoordinatorStorageCustodyAndEpoch', 'TestRetainedCoordinatorAbortsUnsentPrepareWithoutEpochReuse', 'TestRetainedCoordinatorStateCASDoesNotEraseSealedPending', 'TestRetainedCoordinatorRequiresExactSensorReceipt']}
GUARDS = {
 'scripts/validate_agent_read_components.py',
 'scripts/validate_sensor_node_coverage_components.py',
 'scripts/validate_sensor_node_coverage_components_test.py',
 '.github/sensor-node-coverage-component-roster.json',
 '.github/workflows/sensor-node-coverage-components.yml',
}

def load_contract():
 with ROSTER.open('rb') as stream:
  raw = stream.read(1024 * 1024 + 1)
 if len(raw) > 1024 * 1024:
  raise EvidenceRejected('oversized fixed roster')
 spec = decode_json(raw)
 if not isinstance(spec, dict) or set(spec) != {'schema','expected_total_named','expected_top_heads','packages','required_source_paths'} or spec['schema'] != 'zasp-sensor-node-coverage-components-v1' or type(spec['expected_total_named']) is not int or spec['expected_total_named'] != 152 or type(spec['expected_top_heads']) is not int or spec['expected_top_heads'] != 28 or not isinstance(spec['packages'],list):
  raise EvidenceRejected('unexpected fixed component contract')
 expected = {}
 for entry in spec['packages']:
  if not isinstance(entry,dict) or set(entry) != {'package','module','relative_package','run_regex','expected_names'}:
   raise EvidenceRejected('invalid package contract')
  package,names = entry['package'],entry['expected_names']
  if package not in HEADS or package in expected or not isinstance(names,list) or not names or len(set(names)) != len(names) or any(not isinstance(n,str) or re.fullmatch(r'Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_#.-]+)*',n) is None for n in names):
   raise EvidenceRejected('invalid package/named roster')
  platform = '/services/platform/' in package
  module = 'services/platform' if platform else 'services/'+package.rsplit('/',1)[-1]
  relative = './'+package.rsplit('/',1)[-1] if platform else '.'
  heads = [n for n in names if '/' not in n]
  if entry['module'] != module or entry['relative_package'] != relative or heads != HEADS[package] or entry['run_regex'] != '^('+'|'.join(heads)+')$':
   raise EvidenceRejected('module/selector differs from exact source heads')
  for name in names:
   pieces = name.split('/')
   if any('/'.join(pieces[:n]) not in names for n in range(1,len(pieces))):
    raise EvidenceRejected('missing named ancestor')
  expected[package] = names
 if set(expected) != set(HEADS) or sum(map(len,expected.values())) != 152:
  raise EvidenceRejected('incomplete fixed component roster')
 paths = spec['required_source_paths']
 if not isinstance(paths,list) or not paths or any(not isinstance(p,str) or Path(p).is_absolute() or '..' in Path(p).parts or Path(p).as_posix()!=p for p in paths) or len(set(paths)) != len(paths) or not GUARDS.issubset(paths):
  raise EvidenceRejected('invalid required source closure')
 return expected, frozenset(paths)

def main():
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument('evidence',nargs='?')
 parser.add_argument('--go-exit-code',type=int)
 parser.add_argument('--check-sources')
 args = parser.parse_args()
 try:
  expected,required = load_contract()
  custody = check_sources(ROOT,args.check_sources or ROOT/'.github/connector-native-compile-source-pins.json',required)
  if args.check_sources:
   if args.evidence is not None or args.go_exit_code is not None:
    raise EvidenceRejected('mixed invocation')
   result = custody
  else:
   if args.evidence is None or args.go_exit_code is None:
    raise EvidenceRejected('missing actual execution status')
   result = validate_events(load_events(args.evidence),args.go_exit_code,expected)
  print(json.dumps(result,sort_keys=True))
 except (EvidenceRejected,OSError,TypeError,KeyError,ValueError,re.error):
  print('Sensor node coverage COMPONENT evidence rejected',file=sys.stderr)
  return 1
 return 0

if __name__ == '__main__':
 sys.exit(main())
