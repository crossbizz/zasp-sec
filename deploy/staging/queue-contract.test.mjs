import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// Offline source-contract checks, not a Terraform plan or provider-default proof.
const main = await readFile(new URL("./main.tf", import.meta.url), "utf8");
const outputs = await readFile(new URL("./outputs.tf", import.meta.url), "utf8");
const originalQueues = {
  background: { visibility: 300, max_receive: 5, schema: "agentsec.background.v1" },
  "runtime-events": { visibility: 120, max_receive: 5, schema: "agentsec.runtime-events.v1" },
  tests: { visibility: 900, max_receive: 5, schema: "agentsec.tests.v1" },
};

function queueContract(source) {
  const body = source.match(/^ {2}queue_contract = \{\n([\s\S]*?)^ {2}\}/m)?.[1];
  assert.ok(body, "staging must define its queue contract");
  return Object.fromEntries([...body.matchAll(/^\s*"?([\w-]+)"?\s*=\s*\{\s*visibility\s*=\s*(\d+),\s*max_receive\s*=\s*(\d+),\s*schema\s*=\s*"([^"]+)"\s*\}/gm)]
    .map(([, key, visibility, maxReceive, schema]) => [key, { visibility: Number(visibility), max_receive: Number(maxReceive), schema }]));
}

function block(source, header) {
  const start = source.indexOf(`${header} {\n`);
  assert.notEqual(start, -1, `missing ${header}`);
  const end = source.indexOf("\n}", start);
  assert.notEqual(end, -1, `unterminated ${header}`);
  return source.slice(start, end + 2);
}

function assertOriginalQueues(source) {
  const queues = queueContract(source);
  for (const [key, settings] of Object.entries(originalQueues)) {
    assert.deepEqual(queues[key], settings, `original ${key} queue must use its canonical contract`);
  }
}

// Evaluate only the narrow conditional form used for these optional attributes.
// This is a source-contract projection, not Terraform expression evaluation.
function scopedAttribute(resource, attribute, key) {
  const expression = resource.match(new RegExp(`^\\s*${attribute}\\s*=\\s*(.+)$`, "m"))?.[1];
  assert.ok(expression, `missing explicit ${attribute}`);
  const conditional = expression.match(/^contains\((\[[^\]]*\]),\s*each\.key\)\s*\?\s*(\d+)\s*:\s*(null|\d+)$/);
  assert.ok(conditional, `unsupported ${attribute} expression: ${expression}`);
  const keys = JSON.parse(conditional[1]);
  return keys.includes(key) ? Number(conditional[2]) : conditional[3] === "null" ? null : Number(conditional[3]);
}

function assertScopedAttribute(source, resourceName, attribute, value) {
  const resource = block(source, `resource "aws_sqs_queue" "${resourceName}"`);
  for (const key of Object.keys(queueContract(source))) {
    assert.equal(scopedAttribute(resource, attribute, key), key in originalQueues ? value : null,
      `${resourceName}.${attribute} for ${key} must preserve the original-only scope`);
  }
}

// Removing a setting, changing its value, or changing either scope branch must fail.
for (const [resourceName, attribute, value] of [
  ["dead_letter", "receive_wait_time_seconds", 20],
  ["dead_letter", "max_message_size", 262144],
  ["dead_letter", "delay_seconds", 0],
  ["work", "delay_seconds", 0],
]) {
  test(`${resourceName}.${attribute} pins the canonical value only for the original queues`, () => {
    assertScopedAttribute(main, resourceName, attribute, value);
  });

  test(`${resourceName}.${attribute} guard rejects missing, changed and over-scoped settings`, () => {
    assertScopedAttribute(main, resourceName, attribute, value);
    const resource = block(main, `resource "aws_sqs_queue" "${resourceName}"`);
    const line = resource.match(new RegExp(`^\\s*${attribute}\\s*=.+$`, "m"))[0];
    const mutations = [
      "",
      line.replace(/\?\s*\d+/, `? ${value + 1}`),
      line.replace('"tests"', '"not-an-original"'),
      line.replace('"tests"', '"tests", "red-team-tests"'),
      line.replace(/:\s*null$/, ": 0"),
    ];
    for (const changedLine of mutations) {
      assert.notEqual(changedLine, line, "negative control must change the attribute");
      const changed = main.replace(resource, resource.replace(line, changedLine));
      assert.throws(() => assertScopedAttribute(changed, resourceName, attribute, value), assert.AssertionError);
    }
  });
}

function assertSharedResources(source, outputSource) {
  const work = block(source, 'resource "aws_sqs_queue" "work"');
  const deadLetter = block(source, 'resource "aws_sqs_queue" "dead_letter"');
  const allow = block(source, 'resource "aws_sqs_queue_redrive_allow_policy" "dead_letter"');
  for (const resource of [work, deadLetter, allow]) assert.match(resource, /for_each\s*=\s*local\.queue_contract/);
  for (const resource of [work, deadLetter]) {
    assert.match(resource, /kms_master_key_id\s*=\s*each\.key == "red-team-tests" \? aws_kms_key\.red_team\.arn : each\.key == "attack-lab-jobs" \? aws_kms_key\.attack_lab\.arn : aws_kms_key\.staging\.arn/);
    assert.match(resource, /tags\s*=\s*\{ Schema = each\.value\.schema \}/);
  }
  assert.match(work, /name\s*=\s*"agentsec-\$\{each\.key\}"/);
  assert.match(work, /message_retention_seconds\s*=\s*345600\b/);
  assert.match(work, /visibility_timeout_seconds\s*=\s*each\.value\.visibility/);
  assert.match(work, /receive_wait_time_seconds\s*=\s*20\b/);
  assert.match(work, /max_message_size\s*=\s*262144\b/);
  assert.match(work, /deadLetterTargetArn\s*=\s*aws_sqs_queue\.dead_letter\[each\.key\]\.arn/);
  assert.match(work, /maxReceiveCount\s*=\s*each\.value\.max_receive/);
  assert.match(deadLetter, /name\s*=\s*"agentsec-\$\{each\.key\}-dlq"/);
  assert.match(deadLetter, /message_retention_seconds\s*=\s*1209600\b/);
  assert.match(deadLetter, /visibility_timeout_seconds\s*=\s*30\b/);
  assert.match(allow, /queue_url\s*=\s*aws_sqs_queue\.dead_letter\[each\.key\]\.id/);
  assert.match(allow, /redrivePermission\s*=\s*"byQueue"/);
  assert.match(allow, /sourceQueueArns\s*=\s*\[aws_sqs_queue\.work\[each\.key\]\.arn\]/);
  assert.match(block(outputSource, 'output "queue_urls"'), /value\s*=\s*\{ for key, queue in aws_sqs_queue\.work : key => queue\.id \}/);
  assert.match(block(outputSource, 'output "dead_letter_queue_urls"'), /value\s*=\s*\{ for key, queue in aws_sqs_queue\.dead_letter : key => queue\.id \}/);
}

test("staging retains all three original queue contracts independently of Red Team", () => {
  assertOriginalQueues(main);
  const queues = queueContract(main);
  assert.deepEqual(Object.fromEntries(Object.entries(queues).filter(([key]) => !(key in originalQueues))), {
    "discovery-jobs": { visibility: 30, max_receive: 5, schema: "agentsec.discovery-jobs.v1" },
    "red-team-tests": { visibility: 900, max_receive: 5, schema: "agentsec.red-team-tests.v1" },
    "attack-lab-jobs": { visibility: 60, max_receive: 5, schema: "agentsec.attack-lab-jobs.v1" },
    "recovery-backup-jobs": { visibility: 30, max_receive: 100, schema: "agentsec.recovery-backup-jobs.v1" },
    "recovery-restore-jobs": { visibility: 30, max_receive: 100, schema: "agentsec.recovery-restore-jobs.v1" },
    "audit-exports": { visibility: 300, max_receive: 20, schema: "agentsec.audit-exports.v1" },
  });
});

test("shared staging resources bind each queue to its encrypted DLQ and output", () => {
  assertSharedResources(main, outputs);
});

test("Red Team consumer authority stays on its separate queue", () => {
  const policy = block(main, 'resource "aws_iam_role_policy" "red_team"');
  assert.equal([...policy.matchAll(/aws_sqs_queue\.work\["red-team-tests"\]\.arn/g)].length, 4);
  assert.doesNotMatch(policy, /aws_sqs_queue\.work\["tests"\]|sqs:\*|Resource\s*=\s*aws_sqs_queue\.work\s/);
  for (const action of ["SendMessage", "GetQueueAttributes", "ReceiveMessage", "DeleteMessage", "ChangeMessageVisibility"]) {
    assert.ok(policy.includes(`"sqs:${action}"`));
  }
  assert.match(block(outputs, 'output "red_team_release_authority"'), /queue_url\s*=\s*aws_sqs_queue\.work\["red-team-tests"\]\.id/);
});

test("original queue guard rejects missing tests and changed schema or delivery settings", () => {
  // Hand-written fixture proves each negative control independently of main.tf.
  const fixture = `  queue_contract = {
    background = { visibility = 300, max_receive = 5, schema = "agentsec.background.v1" }
    runtime-events = { visibility = 120, max_receive = 5, schema = "agentsec.runtime-events.v1" }
    tests = { visibility = 900, max_receive = 5, schema = "agentsec.tests.v1" }
  }`;
  assertOriginalQueues(fixture);
  for (const changed of [
    fixture.replace(/^ {4}tests.*\n/m, ""),
    fixture.replace("visibility = 900", "visibility = 30"),
    fixture.replace('max_receive = 5, schema = "agentsec.tests.v1"', 'max_receive = 20, schema = "agentsec.tests.v1"'),
    fixture.replace("agentsec.tests.v1", "agentsec.red-team-tests.v1"),
  ]) assert.throws(() => assertOriginalQueues(changed), /original tests queue/);
});

test("shared-resource guard rejects crossed DLQs, redrive widening and missing output membership", () => {
  assertSharedResources(main, outputs);
  for (const [changedMain, changedOutputs] of [
    [main.replace("deadLetterTargetArn = aws_sqs_queue.dead_letter[each.key].arn", 'deadLetterTargetArn = aws_sqs_queue.dead_letter["red-team-tests"].arn'), outputs],
    [main.replace('redrivePermission = "byQueue"', 'redrivePermission = "allowAll"'), outputs],
    [main, outputs.replace("for key, queue in aws_sqs_queue.work : key => queue.id", 'for key, queue in aws_sqs_queue.work : key => queue.id if key != "tests"')],
  ]) assert.throws(() => assertSharedResources(changedMain, changedOutputs), assert.AssertionError);
});
