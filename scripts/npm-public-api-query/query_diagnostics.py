"""Closed diagnostic vocabulary shared by evidence producers and summaries."""

REASONS = {
    'cancel/deadline': 'owner_deadline_or_cancel',
    'filesystem floor': 'filesystem_floor',
    'memory floor': 'memory_floor',
    'memory observer normal join refusal': 'memory_observer_refused',
    'memory observer shape refusal': 'memory_observer_shape',
    'memory observer timeout': 'memory_observer_timeout',
    'memory observer binding refusal': 'memory_binding_refused',
    'input source/tool refusal': 'source_tool_changed',
    'source/tool postcondition refusal': 'source_tool_changed',
    'public query request deadline': 'request_deadline',
    'public query byte cap': 'response_byte_limit',
    'public query aggregate cap': 'response_byte_limit',
    'public query request bound': 'request_limit',
    'public query upstream refusal': 'upstream_refused',
    'public query HTTP grammar': 'http_grammar',
    'public query HTTP status grammar': 'http_status_grammar',
    'public query HTTP header grammar': 'http_header_grammar',
    'owned public query cleanup refusal': 'cleanup_refused',
    'session_observation_deadline': 'cleanup_deadline',
    'proc_identity_unknown': 'process_identity_unverified',
    'proc_metadata_cap': 'process_metadata_limit',
    'owned_session_identity_unknown': 'process_identity_unverified',
    'pre_signal_identity_unknown': 'signal_identity_unverified',
    'pre_reap_identity_unknown': 'reap_identity_unverified',
    'owned_child_reap_unknown': 'reap_unverified',
    'subreaper restore refused': 'subreaper_restore',
}
CODES = frozenset(REASONS.values()) | {'unexpected', 'component_refused', 'child_timeout', 'os_error'}
PHASES = frozenset({'bootstrap', 'snapshot_before', 'public_lock_traversal', 'start_child',
                   'read_response', 'join_child', 'cleanup_child', 'parse_http',
                   'validate_page', 'snapshot_after', 'final_guard'})


def failure_code(error):
    # Never include an exception message, HTTP header or response in a notice.
    if isinstance(error, RuntimeError) and len(error.args) == 1 and isinstance(error.args[0], str):
        return REASONS.get(error.args[0], 'unexpected')
    if type(error).__name__ == 'TimeoutExpired':
        return 'child_timeout'
    if type(error).__name__ == 'Refused':
        return 'component_refused'
    return 'os_error' if isinstance(error, OSError) else 'unexpected'
