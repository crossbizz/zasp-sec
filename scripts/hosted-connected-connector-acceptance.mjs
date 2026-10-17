import assert from 'node:assert/strict';
import { selectConnectorAcceptanceGroup, validateConnectorAcceptanceTrace, parseConnectorNativeObservation, describeConnectorAcceptanceTraceFailure, describeConnectorAcceptanceTraceEvent } from './connector-acceptance-groups.mjs';
const selectedGroup = selectConnectorAcceptanceGroup(process.argv.slice(2));
const selectedGroupName = process.argv[2];
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, chmod, lstat, statfs, stat, readdir, symlink, realpath, rename } from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { observeHostedMemory } from './hosted-memory-observation.mjs';
import {openSync,writeSync,fsyncSync,closeSync,constants} from 'node:fs';
import { captureStart, observeOwnedListener } from './owned-listener.mjs';
import { spawnOwnedCommand } from './owned-command.mjs';
import { loadOfficialHeldTool, spawnHeldTool, closeHeldTool, verifyHeldTool } from './official-held-tools.mjs';

// Connected application acceptance using original signed native admissions. No production credentials, fleet admission or deployment proof.
const image = 'postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba';
const pins = {
  "services/platform/apiserver/security_agent_temporal_ownership_postgres_test.go": "bb7df4a074825f91c29970ef2fed9c4d363f5dcdcbb82e03e5cbc5c3070df78d",
  "services/platform/apiserver/security_agent_temporal_executor_postgres_test.go": "c2ef8641fe329f9f50dba2f9c0e35766c82832966153d86e54b56c41d5bb531b",
  "services/platform/apiserver/authorization_worker_ordered_provider_evidence_test.go": "f1f1f4d26aa6c03a0955e87cc35ca29ec860430abfc5c5c343f81e7eff39a843",
  "services/platform/apiserver/approval_projection_visibility_test.go": "b8f964ffe558539a52e1fca5c97cac4f7add6e366b18a88f0e6682e72def526b",
  "services/platform/agentsec-api/bounded_parallel_readiness_test.go": "4a82a77cf64184177b7f7bde1ee56d736e5d9bd6624b7174e9f45e9a48043951",
  "services/platform/apiserver/authorization_readiness.go": "ad1a94117de4e63b9c7ef15faf4c4744e6a6675b44ad6da1d7991cb63fcb683a",
  "services/platform/apiserver/current_authorization_health_probe_test.go": "09361c7c963d5f3d508b9c534d92c5b7d6bcf2f19c4c46b8413088c0b974c593",
  "services/platform/apiserver/current_authorization_health_probe.go": "3bed74745ef1056405965605ea6c45b949e842bf29065e8665e7900ec3cd8a66",
  "services/platform/connectormaintenancecutover/coordinator_test.go": "26ce6254da116eb381365e2c90ae97e4c7366d829168e5a55438b40dc8ba9a90",
  "services/platform/apiserver/connector_maintenance_catalog_diagnostic_test.go": "3a0a5a0dc9c6fa4d74cae94d06ddfd470473a2d07dd0d673d1d9c62359a3a426",
  "services/platform/apiserver/connector_maintenance_callback_restart_postgres_test.go": "fe1f04ee8d9d6c78814a05df0fb976f4aedd5f1667e648c5342fbc14ea1d46bf",
  "services/platform/apiserver/connector_maintenance_callback_recovery_test.go": "18274be7f5b461c1fe3447db1b8d6761428f41955250313e8ed8ea346a1fe18f",
  "services/platform/apiserver/connector_maintenance_callback_recovery_database.go": "a9330f0ece5e4349f9a3252a5b44f5409340130b125763dab6cefe49aaa89b6a",
  "services/platform/apiserver/connector_maintenance_callback_recovery.go": "78ab4d746bf9d76d65f5113df17865fed91ba0ebdd7c55d4ba023612533d1b75",
  "services/platform/agentsec-api/connector_callback_runtime.go": "69c0fe154628058709eaf886369e3aa92aee8a9526a1bebda091ad8147c6cd95",
  "services/platform/agentsec-api/connector_maintenance_runtime.go": "8f7207d81d37dcceb02dcfd55975eefe407cebca06eaf7b99a6bd9eb555d5dc3",
  "services/platform/agentsec-api/production_runtime.go": "c86f511a99526afa09755b8cbae81db193aa99a3c81a5a17167b3846f8bf7f67",
  "services/platform/agentsec-api/runtime.go": "d7a13b4e17461b2598c419cd3f1176cd268ee64373e4183735b380f17977febd",
  "services/platform/agentsec-worker/authorization_worker_runtime.go": "9616068ff5d9121bbe8f4c017b1580a99898dbb90ee8b538f4ec7f4a47bfc5e2",
  "services/platform/apiserver/connector_enqueue_provenance_postgres_test.go": "d6039cfa0d1673a5cf29e68e209b73c2cb6aeefd715e4d7805d3690b8ab0afde",
  "services/platform/apiserver/connector_handler.go": "e8a28640de67507a0676a882cc627bc20910d4fc55c606b08c9bc6663de76eb0",
  "services/platform/apiserver/connector_maintenance_callback_database.go": "68daa6030d5ad5e51dbcd95c5c7d3a77160dc74bafea1a986049b937bf787efc",
  "services/platform/apiserver/connector_maintenance_callback_resolver.go": "995c5238f7e4fa4a58a5d35218234600beaec374f67bb36f5a363a77357c7585",
  "services/platform/apiserver/connector_maintenance_enqueue_database.go": "df803820e44feadcbe41f4778cd50ee20edbfa1847fb82d0d9abcc39f3a962ac",
  "services/platform/apiserver/connector_maintenance_enqueue_postgres_test.go": "76da1cc4969e8ad84f3f61410e2be98e6ecc48facf1e42ec10b82ab66d93628e",
  "services/platform/apiserver/connector_maintenance_repository.go": "12ae3d8d18cda869818522852509340687372558fbbfb3ff1826171008d2b119",
  "services/platform/apiserver/connector_reconciler.go": "3170126141cde2be045e2a04727a1c9658a0100cfd610ea45ea3a7c5d359689d",
  "services/platform/authorization/connector_maintenance_projection.go": "e9189565c21f4d16c3f06c3cf89b35e57b1cef5e5bb51b1ff49da02349dcd7b8",
  "services/platform/authorization/worker_current_maintenance.go": "77e382687cc15c54bd3065a10caeb607921c7ee89f3f6ad373c8d645c01d9246",
  "services/platform/cmd/zasp-authorization-reconcile/main.go": "bdaa8815eb14bf35e19d4a5e76764f623ce0277c9d04ebfbfc9f120dba244a6d",
  "services/platform/connectormaintenance/authority.go": "6165e9fc541c82439e4cb5cad6f71c91d6507cd49d3b70e526ea57354db8898a",
  "services/platform/connectormaintenance/executor.go": "8ed045a49c94dd100633e3837d0236f0124d6fcb5e88dc818fd107c30e01d598",
  "services/platform/connectormaintenancecutover/coordinator.go": "d2867a6154c9df7b00a6e575d08cdcf33e6e7bf1d71b493baa7428334af286fe",
  "services/platform/connectormaintenancecutover/fga.go": "d3b9b4bea7f707e802c11e62c3e331477a3ff23a5f8d2049125155fd9e2bcb46",
  "services/platform/connectormaintenancecutover/model.json": "329f49e1f2effecbe1a0e9caf6c89be939b1e36e034155d74977bfc82c73cc2c",
  "services/platform/connectormaintenancecutover/process_linux.go": "6096f7c304818c7e6ebc31d3940bacf75932b9f2971c8c529316ebee92cede54",
  "services/platform/connectormaintenancecutover/raw_model.go": "4a5732177b025ec3e7306dd1186c2c358d59a3b7df235e53e12f34384ecc6d3e",
  "services/platform/connectormaintenancecutover/sql.go": "baaa4fe83a4689b053387fc7a8a3abe34d6130384d4197e244aab1c21f5a20b8",
  "services/platform/migrations/production_connector_enqueue_provenance.go": "793b230a8572fbfbed2a4702e1513bfa90afac596a8d0707ae047bbdf8bacc36",
  "services/platform/migrations/production_connector_maintenance.go": "18b0989e395e85f18a78f5f51aee06eb1f969fba79a66650754bfc3858d055cd",
  "services/platform/migrations/sql/connector_enqueue_provenance.sql": "32b3f8cbe175b5256ff4542cdff044d6d060e0240d24632bf3d057f3553a5c13",
  "services/platform/migrations/sql/connector_maintenance_profile.sql": "9b6d105e1f69f46719d001cd80c3e540a8fabbf00b364cf0281857575d2c5bf7",
  "services/platform/runtimeservices/config.go": "5cd087e846c9106c07c0734f06937e727c25fb04887dbfdf8d78da4c70e48731",
  "services/platform/migrations/production_approval_maintenance_profile.go": "2e98fa960c2e7b42b2a6a343b4ff47059c0d23fac83dbed887d2868f1b9c99f3",
  "services/platform/migrations/production_approval_maintenance_successor.go": "6817964c5c0dfcabe7ea9f65caf5b7840f6d9e4d29a1ec39b00e1b03b0fa6eca",
  "services/platform/migrations/production_approval_maintenance_profile_test.go": "5592e136c7578bac21bf698c675762b28b68b46a37b1d2ed7670e2d707150a6a",
  "services/platform/apiserver/connector_maintenance_callback_execution_test.go": "aeed97eabbf32cb8f2af66d8b4ca37ceeeb6d6a4ad6dcc9e4f4961f198bdff2d",
  "services/platform/apiserver/connector_maintenance_lifecycle_postgres_test.go": "345c365921cdc9281ec767e00fd3e934f31fa4badb393f4a6b6e5793bd544e2d",
  "services/platform/apiserver/connector_maintenance_lifecycle_helpers_test.go": "17e25679f365e81f0450cfa2c9c5a23250afeb43f47f8577e34ed8de77029bc3",
  "services/platform/agentsec-api/compliance_browser_process_test.go": "ce30c1b24c754ee92be7cbc8c3fb82182b5416609b87aa0763aa7edf805e7aef",
  "scripts/browser-command-failure.mjs": "04cac4762fed7431263b7b01fdd9a562efcb57125da453d3e49c842f3eb03407",
  "services/platform/apiserver/production.go": "ca69d1bf4f7d6d0a94c68529f117a55d6e786aba437b9c55a0ee42c9af117c3c",
  "services/platform/apiserver/connector_maintenance_pkce_recovery_test.go": "87e4d51d94e1d3176c14dce23a9215b5379aec8399a0cdd87ef5616fef240a1e",
  "services/platform/apiserver/connector_maintenance_recovery_decode_test.go": "08ad69924af72241a35c146e371c2a2ec955a25a8af16cfee81537073335c8f1",
  "services/platform/agentsec-api/authorization_runtime_readiness.go": "7999316f721e079c16656412eb594e460ca154f6f78a5cee5a1d894bf000ae21",
  "services/platform/agentsec-api/authorization_runtime_readiness_test.go": "d5900ebdd4e1a9663dceddd61b08e18b24ad540b385b1b1357122e797984e417",
  "scripts/browser-command-failure.test.mjs": "9058178b89b07a810e50c8b098800c4072879a95a9ac7a686d6ce40032735f29",
  "services/platform/connectormaintenancecutover/readback_defaults.json": "d4c42d89fa77b89513e732b6d5bdd206c808111096307d38784cc6f1ba639835",
  "services/platform/connectormaintenancecutover/readback_test.go": "e4970d8ef25f042e9948abb5cbb0557c32988a50bd80b3bcddd6c8f74a8da23a",
  "services/platform/agentsec-migrate/main.go": "dde3d2f6b26b89ecda800915c3e9a27a7db2e39f6f224033d62d1b07e57ad773",
  "services/platform/agentsec-migrate/maintenance_profile_commands_test.go": "8745c207020f6b8cf7992aed8a00e518f61869568a50f9bfcebb19f8e004ae22",
  "services/platform/agentsec-worker/authorization_worker_activation_config_test.go": "3b66404d7740592ad2c42e6491861e26f11788b3b6be0b7e68cbe9a6c20bca23",
  "services/platform/apiserver/approval_activation_postgres_test.go": "4a40ff1c879cd4c1af951ba8bc812d0d9ea81a360c856fcde4235b63581ae6e5",
  "services/platform/authorization/worker.go": "6693ec0a0aae3b18a0db4ebbaf3f5b80d7c2c54be8983b918e29ec4936554ac2",
  "services/platform/authorization/worker_approval_activation_test.go": "15e44850678ba5b9b385023555fcc501eca600c53c1f912dbf799841387d7b0b",
  "services/platform/authorization/worker_approval_origin.go": "6f83d9f2998fdf8d94beb69e3c4c15fe11037a8bb386303a831f5f1dfee8a69f",
  "services/platform/cmd/zasp-authorization-reconcile/hold_test.go": "07465bbdeb1bcb66a865f855279fe1b764063aba0f17bbcdfecb5726eef9ffe6",
  "services/platform/cmd/zasp-controlled-maintenance-cutover/main.go": "90a0e4a39acaf006571f2a3a610bf1b8b4881c39645fbea10cb5c81290eea5e8",
  "services/platform/cmd/zasp-controlled-maintenance-cutover/main_test.go": "a8e1b3d97076b74daa29f60e117b9ca0f370bcd627d9819152b418c992e8da74",
  "services/platform/cmd/zasp-maintenance-register/main.go": "f2f2ac05671b7738f3c12b1206e7865cff514606189da3a82c888732acd60fc9",
  "services/platform/cmd/zasp-maintenance-register/main_test.go": "5ae1660fd2e5de9961c459d619cf291ae6d730896d9126c2074f68ed2c8069c0",
  "services/platform/connectormaintenancecutover/combined.go": "b841c26caee24f7948d43ec72b1b2d2dc53ce0661845af73a9f417ae93091f84",
  "services/platform/migrations/production_approval_activation_profile.go": "a770b962f1c3f3622a368d32d19f865231f458a1c36d2db764056fb60f6faea2",
  "services/platform/migrations/production_approval_activation_profile_test.go": "4d1c29736e796e8e9deecd7845a0ad6ba2e3948043427e2cc88c57b32fdfdf16",
  "services/platform/migrations/sql/approval_activation_profile.sql": "f256e35509c6573b85fda9babb8e5d87641927c5246d5d1408f98a0159cd139d",
  "services/platform/runtimeservices/approval_activation_config_test.go": "d288ebc83684b8d49bdfab4fabb30bf4e65dc530f327ea06e205c415bd7195df",
  "services/platform/apiserver/approval_activation_flow_test.go": "80caab8829ae1e4eae077562437f36b75341dd83cb9b98765b608308f78a0c5a",
  "services/platform/apiserver/connector_preparation_stage_test.go": "338c9d4717d2c505f3af9d153d3dfcd58a4027a98c7232e0daa4316bfd466e37",
  "services/platform/agentsec-api/approval_maintenance_runtime.go": "6ef7c41f56c46ab93460471e7c7f4cb92db3b6b68e9aebd9d68ea3129de96039",
  "services/platform/agentsec-api/approval_settlement_runtime_selection_test.go": "c241cfeb1a0024787ca1b8d620fea2c17cb28eceeb9761db0f22a5d431980d42",
  "services/platform/approvalmaintenance/executor.go": "f165e9528741feb99d18abab61eb739ee1efac8687f6a3d3a402ba50b4631e8f",
  "services/platform/approvalmaintenance/settlement_audit_executor_test.go": "2bf91ce4d0c27c14bb67ff9293a50728b28d7e45923a09c600ea17cb784d0b3f",
  "services/platform/migrations/production_approval_settlement_audit_profile.go": "48cf793e911b7766da1de15b01ee741c6c6cb1e800654fcd5d495d156886f7d1",
  "services/platform/migrations/production_approval_settlement_audit_profile_test.go": "868232f1bce320c00d360d5b023628b22e385dcfe7345e83755d04a656569434",
  "services/platform/migrations/sql/approval_settlement_audit_profile.sql": "5d32526a3e1029c031193e689186b3892535f98e1a882e2a2f46d7f11f4361c2",
  "services/platform/apiserver/approval_maintenance_genuine_test74_postgres_test.go": "77293329f990aafb033e634603742afd0578dd0fec7d3c42127ce35cd77d1075",
  "services/platform/apiserver/approval_activation_family_flow_test.go": "95272945e897f76c0d73b7722aa6fde436aff342b18e5109c2073206af709156",
  "services/platform/apiserver/approval_activation_family_runtime_test.go": "fff68ca1b09942be107df4b1b5345277aa9d0a96a7a2325ff76684289c46e12a",
  "services/platform/apiserver/approval_activation_ordered_progress_test.go": "d4046a280bbe47b705f5851ac656a63c20fe46031c80b264fdd9678b36ec825a",
  "services/platform/apiserver/approval_activation_future_family_test.go": "baf589a10beee3b81ee430757a81adb06ab255be992f7cd75bb1896c3c265158",
  "services/platform/apiserver/approval_activation_overflow_test.go": "16b8a4826129804e73d6292eaa3778068ff7946f96ae303b7bd4070da28c6eea",
  "services/platform/apiserver/approval_maintenance_genuine_progress_postgres_test.go": "a25253c3d04a09e0a0186e6c989c8b787fad2df5103e2c592b6d3c67c37e0321",
  "services/platform/apiserver/connector_maintenance_failure_observation_test.go": "38e59d1e256423bda47285786edcd4ecbb1f95fb32a85153559e9ce65aabb36f",
  "services/platform/apiserver/approval_activation_failure_observation_test.go": "d521fb9a290f1969ea355e5d95632f6777132a21f86eade1f18a5db1b47d7d18",
  "services/platform/agentsec-api/optional_egress_runtime.go": "dd4b48563471cc2212c2e8b51f0d1198b88d47f372f28600781cfaefadccded3",
  "services/platform/agentsec-api/optional_egress_runtime_test.go": "1e9c282fd6f335ca00334bb6ffbc28f558bded72bf88b7038d657b8a62ebbb86",
  "services/platform/agentsec-api/runtime_dependency_diagnostic.go": "303056dd017b53b1c0bd1774e6d118e8a9fde47513983256df7979f492636324",
  "services/platform/agentsec-migrate/optional_egress_profile.go": "b78c812311dc45a42553d6090716b66275780a6c3934c5f2145f4d36a6ad5502",
  "services/platform/agentsec-migrate/optional_egress_profile_test.go": "811f477dbce598a8f4d16ef81e92cea7145244aca605f9a64090b0eafaa3ecec",
  "services/platform/agentsec-worker/authorization_worker_planning.go": "3480905f7b56c920fc3366e9546e44c242f819ebf58f0b24ebb8d8c60d190a6a",
  "services/platform/agentsec-worker/authorization_worker_planning_test.go": "8c3f41fac6a52982949d2ca1afea843f4002f96c805e696689d30c84f30859ad",
  "services/platform/agentsec-worker/optional_egress_planner.go": "0eb9101e9958790c376758d67e3ba4943dc358b775c4739fa4bc637e9de9e40f",
  "services/platform/agentsec-worker/optional_egress_planner_test.go": "3f88a30f553f9aabbaa284c29635a30c46aef5740192c7e78dcc5d895ed451e7",
  "services/platform/agentsec-worker/production_runtime.go": "3335b5125a5cc3fd580f29f1e67a4f46d1b4fdbc7ce1a96af263fbf1d0bfa15f",
  "services/platform/agentsec-worker/runtime_config.go": "4da28406ab0718b2b90ae513a90a6c9ae579f80777b4b46b7e606a257e8532c7",
  "services/platform/agentsec-worker/security_agent_budget_runtime_test.go": "e3b42627461ae92001bb5722ae5e1d4667975b0abc60ce26656450532949a4cc",
  "services/platform/agentsec-worker/security_agent_cost_policy_test.go": "b732a55b18ffdab94e6f5f70603cdcedb14d8facd835d16535aef6cb9dc737b3",
  "services/platform/agentsec-worker/security_agent_legacy_pricing_test.go": "995d56ee087e1b4e52fba7a2be2ca837350189fb855503e7ed3d04e1f6fa6de3",
  "services/platform/agentsec-worker/security_agent_multistep_planning.go": "bcee626443ec32fbef11f61908f464d808bc51d7f7984c82212503dca7b955bd",
  "services/platform/agentsec-worker/security_agent_multistep_planning_test.go": "19a83875a06f7e97c32398019748c625ac7d2e4d63aa1ff944f97c9f3674e205",
  "services/platform/agentsec-worker/security_agent_planner.go": "d8ac241a38cfed3dcd0702ef6fe8531213d56a58652e387fbbe97551812b00a7",
  "services/platform/agentsec-worker/security_agent_prepared_plan_test.go": "5accde7f0e261f7c8cc8b406e40f3712d9c47118ffac9dc1ed4931dbdd315209",
  "services/platform/agentsec-worker/security_agent_temporal_planning.go": "ad6e46ffe51b0412d1a159061a761a9bd06e8cc791e98392eedc9e000032561d",
  "services/platform/agentsec-worker/security_agent_temporal_product.go": "511c9155fcd7a8aa8651f007ab030471a9fb6eb744f58fb735f6cf199054c880",
  "services/platform/agentsec-worker/security_agent_temporal_runtime.go": "a9731e695a888f1533852e30416bbc60bdee7053768739238e21283a175fc217",
  "services/platform/apiserver/authorization_integration_mutations_postgres_test.go": "5e4beb04b2409ad9b11b89c017ada5e2eccffd78a87bdd5692d40670f12a2ba0",
  "services/platform/apiserver/authorization_projection_fga_test.go": "38dd0f185d3b63390ae46208417fa56758a3764ef8fe0024b1b7190491f49782",
  "services/platform/apiserver/authorization_targets.go": "badfabbcff13b4f6f0e7b9bc354dd8f7cc9135d09d824980392bc962fc4fb2c9",
  "services/platform/apiserver/composition.go": "395e53a86fe27554008fa3c90be302a9f5f0ff3146c8b14bb1c9a60c5d752932",
  "services/platform/apiserver/composition_test.go": "2541f7646a2b15e29d7438675eb2bd8d857b560240d13b63d52c6133188a347f",
  "services/platform/apiserver/optional_egress_handler.go": "cac826d2e545ae6c198c1f9aba191429fdf55e7cda0fc4938a6cfd3c0206d97d",
  "services/platform/apiserver/optional_egress_handler_test.go": "40f8920127b0f6f441ce65d1679f6bb7bd6a82f4c79ff0fbad80dfefcde10911",
  "services/platform/apiserver/optional_egress_native_postgres_test.go": "c89f66eeff0634cde1396a8cba46067ea322822d1613007dc5c79109ce7b84d6",
  "services/platform/apiserver/optional_egress_repository.go": "b69bca265a600b1f1b47f680b4e50cccb0889a38498fd3bddce8259048af795c",
  "services/platform/apiserver/optional_egress_repository_test.go": "9dbf6142153eddd2bd472e918a7638e8649a0afa2048798291b6d6b6e0e544d5",
  "services/platform/authorization/identity_attestation.go": "71d040a8b9b961745bdf0abc9b6902b45756c2da0c54b84fd0d3f1b04650fbb7",
  "services/platform/authorization/openfga.go": "0b67ec3f77bc70cd355538a387a994755ae2e34c5675f3c473075d29d09774a3",
  "services/platform/authorization/operations.json": "335f51b588ebdb8f13e8d99272782fd34124e9538a5bdaaa71348c8e6f7c23ba",
  "services/platform/authorization/projection.go": "a375a4b3cb3851c286eb5f8053860328dc6d0f435950b8d16467bc375218b304",
  "services/platform/authorization/projection_openfga.go": "88c87c8df427966f140e69ef737de9dfea6c769ac31e512e8815276f82651481",
  "services/platform/authorization/worker_optional_egress.go": "f95fb17a333cf4ba13b92b12288003b09a672b029e93cf3efebe6433229e7de9",
  "services/platform/authorization/worker_optional_egress_test.go": "12a26769e2dc0e347b66a632563c4be5d1fb4a4346a5744a7b08a1aa97c7d69e",
  "services/platform/authorization/worker_ordered.go": "75fd29bf8f2baebbfec169876ea89fd16a3045c5f7b728146fa831c82b95761b",
  "services/platform/authorization/worker_ordered_prepare.go": "8db68748a7dc69efcaba4584a72ecdd84788d68f1a35c84bfe8fa99688c23833",
  "services/platform/authorization/worker_ordered_signing.go": "cc0f7ea3eb9326e5c7425b3047235846c49cfbec169072249c43c7337127529f",
  "services/platform/migrations/production_authorization_runtime_profile.go": "2e1505d973f621b97081cef217fa0f7f56f3d501ba77a15228a7b9bfb50a6c70",
  "services/platform/migrations/production_authorization_worker_audit_profile.go": "82e305184878089e91dfd39d5a8b70216a2a23fc302cbdbfaae8f512510a541d",
  "services/platform/migrations/production_authorization_worker_profile.go": "84944f2610080b581102b3cc1cc649c42af394acccb3d8ae3f7bc38eb40165f3",
  "services/platform/migrations/production_optional_egress_profile.go": "1fbc36a8d55e2734deda4a4110c9b997c09a49c02c4c022b44e5cbafc6b237d0",
  "services/platform/migrations/production_optional_egress_profile_test.go": "fd16b29786485429910097ea8fab567b03d0be252725d709376b04b41ab77ab8",
  "services/platform/migrations/production_temporal_finding_response.go": "02149437927657c7d54c856093f7831d92263e8ed458d4d9a45f745d30229590",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.accounting.sql": "e071cee3ea0a7d87cfff2386272f485c0e1bbe98ac18cc0b5ea0f68c5ecdad9e",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.admission.sql": "c0e37bef70540aa8df5f580573a32d60340876bb9a919ba3a75da135b7d4c499",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.approval.sql": "bff85b2d01a14cc0e110fb902ff403e0acca2cf465c13421e4f28e38e6cb0fd1",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.control.sql": "924723fc50472fad4f11ca8d07eb16956fbad39895010decfcd30f4b38c94f66",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.decisions.sql": "9f14db2ea3be8c979082ab77c0b53d9ed1d3fb37a4d0f59f0f1fd8db61d827bb",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.delivery.sql": "1f01706578d04062a10db08b12a9e5dfee64420bdfa9caa252763f9811fc911d",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.effect.sql": "34c0f9b5c012054068ec59b53d33ee5fdf9644dc15c4c24b3d85a2732e6c675a",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.human.sql": "8c6c18afba5d45450512ef3043b553ce2ae1ddf98bcb06977f6b5a4222989d5a",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.omitted.sql": "763e76a276ced6dffb04c3e77ff8a2b97d33f2b0a0c21c5de9f35ed05e77f1bd",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.planning.sql": "9927f2a72fdabeb671f3f1af99a9021be3df1d7c7a9bb94c2c7c7a07b52d6a2c",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.reads.sql": "86ee2dbdec29b1da05c0bc1b550c20085da9c64df3b7ca34ee0cb8ccd499c5e1",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.retained.sql": "98dd199b48c7cd8db7b7fc5f8a6b8928bdd669fc48b3e1884c8c770d6974c267",
  "services/platform/migrations/sql/0078_production_temporal_finding_response.up.sql": "40d02f7691da348d87f96c24d56ec6805fdd327c4dfd8a2554f451af0e268e56",
  "services/platform/migrations/sql/0080_authorization_runtime_profile.sql": "21ffeea2a10235bca9f765f987fc60769d7c5de29346734276b444ec93363c7f",
  "services/platform/migrations/sql/0080_authorization_runtime_projection.sql": "7323ffb9a40ec35dec337ef3c949eaca8706e2098455c50e9ab3dbf59a519817",
  "services/platform/migrations/sql/0080_authorization_worker_audit_readiness_graph.sql": "013deafb134671e69656f9a6430923cb5ba6d4d049a44c64c67e3104b80fd5de",
  "services/platform/migrations/sql/0080_authorization_worker_gateway_writers.sql": "5ce0934637fddd422c5c01f3d8e7e44737ac106cd013fc97649955e710228901",
  "services/platform/migrations/sql/0080_authorization_worker_planner_portability.sql": "3434767e4f475774264f264a401341ad11a3787af6df3f65c4a6951b0d621e10",
  "services/platform/migrations/sql/0080_authorization_worker_planning.sql": "189fe98490de3964d2c7be7e96b1e697d16ae03087c6134c1e3331689cf2a336",
  "services/platform/migrations/sql/0080_authorization_worker_profile.sql": "785c03177c693ebdf0d00a259ae4bbebc90a27ce3c855f37306744561a1965c4",
  "services/platform/migrations/sql/0080_authorization_worker_sources.sql": "723d9025b3f87960c381798dfe111781570b41ce3eed52c507a6106ad1cf01d9",
  "services/platform/migrations/sql/0080_authorization_worker_test_activation.sql": "847769a276c380af9bfc5d77bbe54df7fbf1c9b7a8ca073a840d317f9b2c52f4",
  "services/platform/migrations/sql/0080_authorization_worker_test_adapter.sql": "93a3072f0954f9d3b86dbf2531b5fdaf12b4b7ee711ec0ad61c582e8c95e7188",
  "services/platform/migrations/sql/0080_authorization_worker_test_catalog.sql": "4932e318bd726e9faf76c17c04e8b0985ced024e78e35d82b715b15f5fd538b0",
  "services/platform/migrations/sql/0080_authorization_worker_test_completion.sql": "08cdf1f006d2952ba9bf99fa7f89ca4a83de8f0957bc37581a37dc765040c5a1",
  "services/platform/migrations/sql/0080_authorization_worker_test_effects.sql": "e2ac1067fbe3a0eeb0f8b3ef4292c5798e4c5683bf19b8fbe3509741879e0ec3",
  "services/platform/migrations/sql/0080_authorization_worker_test_lifecycle.sql": "7237289ceecdfb83bd89943cb9d0a1274fc4e642eeced3c9f85ca567ce51b075",
  "services/platform/migrations/sql/0080_authorization_worker_test_receipt.sql": "46fa16499b1f56a0fb331a31eaf6e61bb05c369afda9e3195141f8ac42cd0ea4",
  "services/platform/migrations/sql/0080_authorization_worker_test_settlement.sql": "bac27a50f5fb08866ce41de6fdfe5ffe797dcc608a2b5f41d5c32dfc033968d6",
  "services/platform/migrations/sql/0080_authorization_worker_tests.sql": "1ee865175b94bea8ece71a76ff64e7f2a1e17bcb3468802f16d1087aba015888",
  "services/platform/migrations/sql/optional_egress_profile.sql": "887f93fc0d986ee649cd9fb48d5016142a89e539c1df0f5b3c7aedd2d5865b31",
  "services/platform/optionalegress/contract.go": "7fe6129dc9d26a5f06585670827300083da32ebe6c2fdfc39800523dc8f1543b",
  "services/platform/optionalegress/optionalegress_test.go": "144f608aa630180ff17766d4dd4046e4a2d5b510518d6367c43d8617fd24654f",
  "services/platform/optionalegress/prepare.go": "fbad196e2896299d408e4f6b53a7ad476e8a1cdab4c20ecf5e2ef7fd65238048",
  "services/platform/optionalegress/service.go": "bf52b87033c002e105432e3220cb80f375855d1868fc588ea1c887f8877588de",
  "services/platform/optionalegress/socket_flow_test.go": "16d441ba697cc3baa979e71ff6a07b9b3ec2dc496e44f76b260b9d2b21251872",
  "services/platform/optionalegress/transport.go": "78f915fdff74c5b57f33621af11e6b5996e5ee8d56c762d8d7753e157ca02c3e",
  "services/platform/apiserver/approval_maintenance_genuine_enqueue_postgres_test.go": "376c63e3b498569d5287f0ebeeaa956de8e62ee25216a3ec8bb55b27a4ec2995",
  "services/platform/apiserver/authorization_worker_planning_proof_postgres_test.go": "05d5049ad6854c19eaede77eb60b4aa628d26710bdde8fdb56f7dd8de358c743",
  "deploy/production/authorization-temporal-resources.mjs": "ecc112b8fd0fad16830cc1c32d535776244382a11416158fc8d5aedd2c1a4401",
  "deploy/production/release-contract.mjs": "cb519e962ad32317770fde21a5921837df9f2606833a7b169a4834b4b1b99a0a",
  "deploy/production/release-contract.test.mjs": "47623043760755736745ada4882ba3c34b875ae67401d187c8cc153d8a21b7ba",
  "deploy/production/session-search-rollout.mjs": "a1690c1d62442cc26290d391db3b77f6665dc7c7e3c06de5220ff8f469b16398",
  "deploy/staging/main.tf": "454558b65382c7da5406d4218ef8aec136c819d969e52473e294286d228bada6",
  "deploy/staging/product/templates/runtime.yaml": "6926dd10221a467cea24f144c26b8b94c42d8fd73253aa6d8ad09fb5d23cec39",
  "deploy/staging/product/templates/workloads.yaml": "9906d87085fe2ccfb4ceb45481a66c27270616d6cde86c8530e3cf0456f40806",
  "deploy/staging/product/values.yaml": "a58060e2f3630ae1ed6bc47cef9fa181ced7d5b7a443e10fa0c17240001fc3ae",
  "services/platform/agentsec-api/policy_production.go": "c0b706a39ec81580f1a0a9d998fd2e2d8320079b78abc53485323ade5dc2a580",
  "services/platform/agentsec-worker/runtime_archive_production.go": "681f46325c50fd99dab5ba74a9a188cd5ec4fb02acedc67ecab650f18245b6f6",
  "services/platform/agentsec-worker/runtime_index.go": "ed86801896ce60afee2d76582cf70c04e1f7aed6e2cd7dc93571b88d907064c7",
  "services/platform/agentsec-worker/runtime_index_production.go": "f359846552f184a4a0c7b46ed7d58175ee820cfc601a0877b236d5d13010db69",
  "services/platform/agentsec-worker/runtime_session_search_current.go": "089cfd19a87014e9f279c38a141ceb277ef49cdad472253a7d3b8109760eadf9",
  "services/platform/agentsec-worker/runtime_session_search_processor.go": "1e43b3f80b761e11bfb2f7e87d2e8d93c5a43de08def236c374b7cad60299886",
  "services/platform/apiserver/administration_repository.go": "351d1910c34eb5f408dea662ea497e41268833a86c1132f63e27a8c4ffbb4064",
  "services/platform/apiserver/authorization_statement.go": "c6db59f33ca7791b62c4656ac91b93bc7a1e92016906aa485494b6b191786a38",
  "services/platform/apiserver/repository.go": "11df6d30db58f6b012b350b69d8d36fc43071f3e20f2065d75feef3e2163174e",
  "services/platform/policy/opensearchhistory/driver.go": "69269c4c7426619d6b700f913d98ab03b7afa4b4cfd91f490ec429de6b4c2c53",
  "services/platform/runtimeindex/opensearchdriver/session_index.go": "0a0b9aaad0c11b201e45612463e8fdcb3ab23ddf0dd7410ae94517f9a778f277",
  "services/platform/runtimeindex/opensearchdriver/session_selection.go": "72b8fa3b2f7df629838e50539ef3e517784ccfec1c7af3f105a010defce514d4",
  "services/platform/runtimeindex/opensearchdriver/session_visibility.go": "24eabed6e3062f6904a289a4037fc946eaa891165436be3f8871203fe19a10c8",
  "services/platform/runtimeindex/opensearchdriver/session_write.go": "a0bc662748d033e5d36a35e83a592601aee64a4774459572669d00688010a1de",
  "services/platform/runtimeindex/opensearchdriver/session_write_test.go": "74cead417dc4c086ecfd0c2ccfe47bd6e989bf5392cd4be3186470d541667fe2",
  "services/platform/runtimeindex/store.go": "ea669383ff34760f0c0f054032502493c1d463af9a15a7443a81cf42c8a709c3",
  "deploy/production/retention-profile.mjs": "806a0ba86ff1a7a9ce4c204f78cee0e4381df125bd3a0c93ed981cf4c1618a77",
  "deploy/production/retention-profile.test.mjs": "d389d0f42f72435e805579f38be4420e2198443903a90341c204f984f3ef7efe",
  "deploy/staging/product/templates/_retention.tpl": "0a3e3f0009a732ccda39c757a327a3b0aa2e2b4cdd1b674da3cc9b07c44411c4",
  "deploy/staging/product/templates/retention.yaml": "eeb23c1bd699e6a722732f7cfdbbc2bf9482fc1aaa585c601af4457883424a87",
  "services/platform/agentsec-migrate/retention_profile.go": "c87d5f5435965e6cff736bd1af868b8bac885d0fdd42a91e6ce816621bf9e0a5",
  "services/platform/agentsec-migrate/retention_profile_test.go": "057e0b9f29c8d53983677911ac03531712147e4c4b773759061264a6eff0e511",
  "services/platform/agentsec-worker/retention_cleanup.go": "a92cad6ae94582769da5a0996f42778705b8045c71604e3d9151deafed1a1dd3",
  "services/platform/agentsec-worker/retention_cleanup_test.go": "b506eab7ccf87890f490ba041ef7df46c3decd1a882706fbdde81b6e386602df",
  "services/platform/agentsec-worker/retention_runtime.go": "1348cc43852aa513c0d4cf1107fc1f5ed2cb9d5e5b39a6b9cacfc72c4962dbe2",
  "services/platform/agentsec-worker/retention_runtime_index.go": "7384e6c55773c66b726c5bc3a8033e4afb17b8d6d060264b051a25c7404c5d30",
  "services/platform/agentsec-worker/retention_runtime_index_test.go": "a4297c435ad5289407c8cac30ef9e3500ca468df610a4c9114ee817a6daed220",
  "services/platform/agentsec-worker/retention_runtime_pipeline.go": "8f082cc91b4f3662bce15c6d329a3d0115b7fb2548c421724b4906d596caf473",
  "services/platform/agentsec-worker/retention_runtime_pipeline_test.go": "bcb23131853a42529fb8f2ebaddc4e8e249ef56ece08c35b5ca8837d28b006d7",
  "services/platform/agentsec-worker/retention_runtime_test.go": "9ca5fc072a064eca78b31f88c9ed1ba6ec51102d21e19332b74b89e53ee51f95",
  "services/platform/apiserver/retention_native_postgres_test.go": "598976d7d8f237df54475194016086de7e716490bb535fd7587f31b71e7eb31b",
  "services/platform/apiserver/retention_visibility_repository.go": "449c1f96279e09ccf2b991c8ac53b88f8d2036346c1bc7cbf62714a453fb1158",
  "services/platform/apiserver/retention_visibility_repository_test.go": "2bd71717380acb8aa44cebcac6f15c76a0f80d585e89f1fa3da69eb83ff6dc88",
  "services/platform/apiserver/runtime_session_retention_search.go": "8b00d55286c8094e324a1557739e02d1b77a51c465f73bb8779ed9768749588c",
  "services/platform/apiserver/runtime_session_retention_search_test.go": "a011cc495726e70df6fba6402362a567088cca1cd550034ed673670f14df7842",
  "services/platform/migrations/production_retention_profile.go": "71fc7c9827d610ac61f1e1c92c89a25a16a5167eeb033f5a20f32c2172cf6f0f",
  "services/platform/migrations/production_retention_profile_test.go": "2dd97aa23aa4c4d9c7ae7bb5a1f3a727484e55c03ec806f5724bc35b01992903",
  "services/platform/migrations/sql/retention_cleanup.sql": "302cdd7c0421df3b75c178f5a16d203e11abef893b902715186fb9409b09cef2",
  "services/platform/migrations/sql/retention_index.sql": "f0f58105f9b1aba2965cc5cca9a603f647bb1e09ef41685a77650edc355aa250",
  "services/platform/migrations/sql/retention_partition.sql": "3edbcd31f2aa5b0dbf246f5fda5496a7ab9a0c21b8d4272ea3b1a461928a75bf",
  "services/platform/migrations/sql/retention_profile.sql": "30f3d887d63f13cd6b2245a90cd9b2f7a6957349d696e4f37c5866ba81521693",
  "services/platform/migrations/sql/retention_successor.sql": "0b2327a86b5a58b132aaf8d23dbbef8d0ba5a76c0c7ca53ae159f1d625c29ff2",
  "services/platform/orchestration/retention_activities.go": "1feae2d7592d9649cb215879900ede4828b07f4825dd9249d055d99e3ae96a11",
  "services/platform/orchestration/retention_schedule.go": "54ad05917914b59fe241bfc9933af60373b84116b851ed558ab35b1e61e510c1",
  "services/platform/orchestration/retention_schedule_test.go": "2122381d1f1eade714b21e0c29f19cbb1eac5395e7d6090f3225fcfeb3981e27",
  "services/platform/orchestration/retention_workflow.go": "09fd8238291880a5b555b46a697dfb30cc1b752be5ea76a6472cdef1c5b2d080",
  "services/platform/orchestration/retention_workflow_test.go": "092606b7ed1a21979d810058048d7754be89351fb61eda617f2e47c94103e724",
  "services/platform/policy/opensearchhistory/retention.go": "c764bc7c6829000d4508b007a7d69ba4c7256169f3cd31830e7c770ae8a27c41",
  "services/platform/policy/opensearchhistory/retention_test.go": "3ec4bac2e3d5d180cd52ae0ee2feed432b07d605af43d5427c66926103efbd2f",
  "services/platform/runtimeevent/production_retention_profile.go": "9d003cd466f5884ef6baf5386d1acbe188e0988cfb2207b8d74d26829220aecb",
  "services/platform/runtimeevent/production_retention_profile_test.go": "467a0e0ca931a7daa63a40b26cb366b4d51c2fe7e42178b979fc0b89acbff6dd",
  "services/platform/runtimeindex/opensearchdriver/retention_purge.go": "727616a15e5582c0faaa7da1accd46e7ac10e080bc7c24debf7454cd81e2a089",
  "services/platform/runtimeindex/opensearchdriver/retention_purge_test.go": "3b3a5665152109a06e0fc0222cd7b1f9319d32f2f84b943e6621fd0a88409761",
  "services/platform/runtimeindex/opensearchdriver/session_retention_test.go": "1bc0d5f9fb159b2ae02fd970235db64e6aacfd1387ed509dc34dfc7db5468814",
  "services/platform/runtimeindex/retained_write.go": "0718b8600b864434348e8b0d6c237dff0da76e735206b0a76d15061877d696ba",
  "services/platform/runtimeindex/retained_write_test.go": "60512025b10a64dd5e6fdd9dc540ecc633bd49bff2ad611378ce706ec53e506f",
  "services/platform/runtimeindex/retention_visibility.go": "e567a6c1152d42369d600f6661bddd4955cfb46de9cd257a6a194d5dab9a1d16",
  "services/platform/runtimeindex/retention_visibility_test.go": "5a48fb90abeda10b1fa0aa8a4d0ce6bfa9e44830dff9159f8cf9e03b01ffabcb",
  "services/platform/runtimeevent/production_pipeline_repository.go": "c8e6de17dc5bc08fbccfef6cb41aa90b842af3f126a0adce7cd02d170ba85d44",
  "services/platform/runtimeevent/production_current_profile.go": "2a9cb8fed5d5d85cd90907368f4a0e1c37c1a5eb4fb81060781dc1e1204fbfe1",
  "services/platform/runtimeevent/production_ingest.go": "87ea54a5eb967beb284e766999e18ecd5f5e23704a3d41e4a8404039f301e1d9",
  "services/platform/runtimeevent/production_session_routing.go": "6ec55c6432d740e6b6d11fccf61da10f6e2f35085381216ed16ad56f64df738f",
  "services/platform/runtimeevent/production_precise_ingest_repository.go": "83ff28136f956958fc37634d90f458a91c7a84be2a4b8050fd4dd8b46c910220",
  "services/platform/runtimeevent/production_precise_completion.go": "42fb0f6e260a3dcaf18db8a203a403c89d66dfce7aa9a361cd15541db25152de",
  "services/platform/runtimeevent/stage_receipt.go": "c37fa9cf2879e967055e24f714f7fe04292eb77fe136a840ab5e7cbfdcf24389",
  "services/platform/runtimeevent/runtimeevent.go": "73f0cbf966b9013c6ad530011e25dd22849a0561e7280a84f6bdf9b7e940f0fe",
  "services/platform/runtimeprojection/projector.go": "7ef4ab496fe2709a2857a8686ca71023bd8d8507712b339e5beca8e199d61331",
  "services/platform/runtimeprojection/receipt.go": "e5b479e26c0838facf3dbed9874d37d025ab57a35c876ab21a2faaf2428926fc",
  "services/platform/runtimeprojection/precise.go": "8aec42b0bb97385173fb38245022b1f067789f302b69715312e22523cb064c9b",
  "services/platform/runtimeprojection/precise_receipt.go": "f5197024404435c49cbd0bb9f9b8d743c92f81326df7bdcc5ec2e53ce809c923",
  "services/platform/runtimecorrelation/correlator.go": "cb231788fc8d78abd65786e49ac4cda5c6eb7d6cda37e6de1d462e540f86196a",
  "services/platform/runtimecorrelation/frozen_correlator.go": "7768bb0249401723864525b541d66452af5b1912ff5aaf78371d310a749fb474",
  "services/platform/runtimecorrelation/sandbox_correlator.go": "b8b7797e883be279222202e98babd2b499e895b01596d6757fda4a81ecab3e6f",
  "services/platform/runtimecorrelation/precise_correlator.go": "56092177e3f1360c1f2637c9e8387397dc8d07710a67b319f029a160eb8d613d",
  "services/platform/runtimecorrelation/receipt.go": "b7cde1f8214aea44987f82fd9d102ca59350493d0ec689d4deaef9d8b53f00e4",
  "services/platform/runtimecorrelation/precise_receipt.go": "570338804246db5ca56bf2f173907e808ef386eb3a181e0587ec7536b993e687",
  "services/platform/runtimeindex/precise.go": "b42d4bcc1d41aca1e9bced0db6eb1c025306493846d2dac970ff5b19577978e3",
  "services/platform/runtimeindex/opensearchdriver/driver.go": "8bdfa5d468eea7990d3a195bcd990d68a332516d052fa0a6ffc92fc33bc396f6",
  "services/platform/runtimeindex/opensearchdriver/schema.go": "9d339e06869053bbe3ef840916ca74da540849df18afc55b1ea84cd28fc67e2c",
  "services/platform/runtimeindex/opensearchdriver/session_precise.go": "5327bc0025ec7980775d71375b5521dc1c0e1d594599c6166ca0e936df86358d",
  "services/platform/sessionsearch/query.go": "da6e5c69c7c187488ebb185550da9351545f574bc5f50ddef540dafe54f4c454",
  "services/platform/sessionsearch/document.go": "a86aa554799074f8af1cb820f19ab2f87d4c26250cb4caf6410a832f731ef18b",
  "services/platform/sessionsearch/precise.go": "8aae642d61bbde3a3377fb704c57c9825b03304ab232559629e4dc42f23e18f9",
  "services/platform/orchestration/schedules.go": "cf9acb3d1eb77cf99519a62a652f22a6bf25cb18d2e923835b3f4666346b7d95",
  "services/platform/orchestration/contracts.go": "1c6a7dece3b90229359ef2eacd0a142620bee52ccf2c1dfe5c3a9b0d95332b7a",
  "services/platform/orchestration/temporal_client.go": "197d48f9ddd8fe3f362c3bb973a091633a716ef451daeb11c666abf37860f8ee",
  "services/platform/runtimepostgres/config.go": "846368d7910d6aade67c9a952ce70da2e0aaa5c302f72b189acf36e48e14bc8c",
  "services/platform/runtimeservices/clients.go": "e1c9f3006ae7f7f36baa1e50c6a931d27e92d7c5b9515188c98be7ae9702c2c3",
  "services/platform/sensoradapter/adapter.go": "2e0bbd159185eb9154b3d60111109c7549dc92caed83c9b6d0ac870b8b1942f1",
  "services/platform/sensoradapter/envelope.go": "943bc1d396365a95907c0ae2b4ba06b487751b41c5fee5a14d669aa67a7dfb34",
  "services/platform/sensoradapter/precise_envelope.go": "dcd33cc15e8ab9810a1d5b759f8f7a63d84a885d41a6c2f28db1c05bc00f6fce",
  "services/platform/sensoradapter/precise_record.go": "150f9ec34579e9a50a05f414c69b8852052e0587db023d6a92a00737a89bf2f4",
  "services/platform/migrations/production_authorization_worker_runtime.go": "3f93b8bd2ae8b08e61eaf9ffccb0694d559b93f81b03e03df3d1cbe2faa874ab",
  "services/platform/apiserver/audit_export_http_size_lifetime_test.go": "5a1158b3aa7fc62e0816e2059111157bbde5369083ff200764594dddabe9dfc6",
  "services/platform/apiserver/authorization_attestation_test.go": "6945a14ea82af2d8a9f071cce012973a8f5b018c9217b365af61e046bca37e17",
  "services/platform/apiserver/authorization_enforcement_postgres_test.go": "43e63a05a4a43dc2b0f9537891f3ebbb667ff8571fda791d0d7208734a4e3884",
  "services/platform/apiserver/connector_authorization_postgres_test.go": "b55e132588ccd6fec463344030f2257562431d3853b161729ae48a535dbd6051",
  "services/platform/apiserver/discovery_execution_postgres_test.go": "bad0889aa110b6b2924a61f63f1c4b58281afa4e8c5f16270a56b772644cdfbb",
  "services/platform/apiserver/discovery_postgres_test.go": "923d4816734f8dd136b7597c114c27e7aba67371fe640fa1561c67bed9453b5e",
  "services/platform/apiserver/inventory_cutover_postgres_test.go": "d6c483494897220a3923becea99fb76f18fa7f67b6d69f7c7eb2adb4dd97f01e",
  "services/platform/apiserver/middleware_test.go": "a2a1a979e9364056f2efdaf7f4d849f73ab4c977244376e85319741e5b39a220",
  "services/platform/apiserver/reference_authorization_postgres_test.go": "3e063d77fbb85d40673cc683e5efb2acc55fdd884605913c462aa360c211109c",
  "services/platform/apiserver/runtime_data_plane_postgres_test.go": "67be7e13317379c4f51c3a37db649d509141f02f496b7fe99826ce281007780d",
  "services/platform/apiserver/runtime_sandbox_candidate_postgres_test.go": "cb1f0862ce4b1df4fe1d198f3f2c2bd0ce44017b42c30bec01a369dc72d78e48",
  "services/platform/apiserver/runtime_sessions_postgres_test.go": "359a5aa7338fda86269ff527467453c0d46769784578302c6e89140f4848b418",
  "services/platform/apiserver/security_agent_temporal_automatic_sources_postgres_test.go": "d17e31da8e66cffd2eb15d13496a3f800438e1f6e23d880520b068451f6930ac",
  "services/platform/connectormaintenance/compiled_pin_freshness_test.go": "16fd332bc993cb575ecc60cf4d416b4b488afac8ad24a60acd88aa6839a1944d"
};
const roster = selectedGroup.names;
const helperPins={
  "scripts/connector-acceptance-groups.test.mjs": "a1622a9417e9fe4d62c2aed82bcf5f7f3e11dce841d802bf005b29d54405d388",
  "scripts/connector-acceptance-groups.mjs": "35d642c4a4fa0b95d027940d40ceab73116f03b38dc4c0fa6a29982d88e49b61",
  "docs/internal/evidence/cloud-2026-10-07/native-service-readiness/openfga/09-pg-non-glibc-libs-manifest.json": "96642e82997ffd2caf2893a5ecc0116ad2aef6e982df2d929f3efda4e04f3474",
  "services/platform/apiserver/authorization_integration_mutations_postgres_test.go": "5e4beb04b2409ad9b11b89c017ada5e2eccffd78a87bdd5692d40670f12a2ba0",
  "scripts/hosted-memory-observation.mjs": "70c2ae837d040be4756842e4016acbc4eebd6bae3d8c992aba2a80e2a097ba75",
  "scripts/owned-command.mjs": "50b5481d008546a713ac730cb933108be66b2f08226ced8bc47deaea14e95ec8",
  "scripts/owned-fixed-fd-command.mjs": "15c38bd9d627124b7d81e5fe9b96dd3c4af8757b33f2204a9dce4b86e93e5693",
  "scripts/official-held-tools.mjs": "451dad7212561fc02e1f5b03280672c9d900a5ac644a665c022deafa9f72dfdd",
  "scripts/owned-listener.mjs": "3e5a4357fb53a412d0c38ab608c49543cf1bf74b2bb624022791a8bb6d1a43de",
  "services/platform/apiserver/postgres_integration_test.go": "0d908c53cdea021e4c60adc412a04d631fd58c0b0544e7cce723884ea4002a42",
  "services/platform/apiserver/approval_maintenance_owned_fga_test.go": "e505c27d07bde5948d7ec4f4612ffc28ccb2b68f37bebc842e91cec0d5066647"
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const root=process.cwd();const selfSHA256=hash(await readFile(new URL(import.meta.url)));
assert.equal(process.version,'v22.23.1');
assert.ok(path.isAbsolute(process.env.RUNNER_TEMP??''));
const out=await mkdtemp(path.join(process.env.RUNNER_TEMP,'connector-authenticated-enqueue-'));
const end=performance.now()+1500_000;
let tokenForRedaction='', canceled=false, finished=false, refused=false, container, tool, fga, fgaPort, grpcPort, fgaStart;
const owners=new Set();let phase='source-admission';
const receipt={scope:'connected native enqueue, controlled one-writer cutover, execution, PKCE restart recovery, revocation, callback cleanup and settlement; component integration only',completed:false,activationScope:'owned-one-writer-fixture-only',deployedActivation:false,production:false,acceptanceGroup:selectedGroupName,testPins:pins,helperPins,selfSHA256,pgImage:image,commands:[],authStatuses:[],normalCleanup:false};
function lateRefusal(reason){let fd;try{fd=openSync(path.join(out,'late-refusal.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);const bytes=Buffer.from(JSON.stringify({completed:false,reason})+'\n');let offset=0;while(offset<bytes.length){const written=writeSync(fd,bytes,offset,bytes.length-offset);assert.ok(written>0);offset+=written;}fsyncSync(fd);closeSync(fd);fd=undefined;const directory=openSync(out,constants.O_RDONLY|constants.O_DIRECTORY);try{fsyncSync(directory);}finally{closeSync(directory);}}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}finally{if(fd!==undefined)try{closeSync(fd);}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}}}
function signal(){canceled=true; if(finished){lateRefusal('late-signal');process.exit(1);} for(const owner of owners)void owner.stop().catch(()=>{refused=true;});}
process.on('SIGTERM',signal);process.on('SIGINT',signal);
function failureClass(error){return ['ENOENT','EACCES','EPERM','ENOSPC','ETIMEDOUT','ECONNREFUSED','ERR_ASSERTION'].includes(error?.code)?error.code:'other-refusal';}
function guard(){assert.ok(!canceled&&!refused&&performance.now()<end,'owned integration refused');}
async function floors(){
 const values={workspaceFreeBytes:null,scratchFreeBytes:null,memoryHeadroomBytes:null};let step='workspace-statfs';
 try{
  for(const [dir,min,key]of [[root,1500000000,'workspaceFreeBytes'],[out,100000000,'scratchFreeBytes']]){step=key==='workspaceFreeBytes'?'workspace-statfs':'scratch-statfs';const v=await statfs(dir);values[key]=v.bavail*v.bsize;step=key==='workspaceFreeBytes'?'workspace-floor':'scratch-floor';assert.ok(values[key]>=min);}
  step='portable-memory-observation';const observation=await observeHostedMemory();const available=observation.availableBytes;receipt.memoryObservationBasis=observation.basis;receipt.memoryObservation={hostAvailableBytes:observation.hostAvailableBytes,finiteAncestorLimits:observation.finiteAncestorLimits,visibleGroupsObserved:observation.visibleGroupsObserved};
  values.memoryHeadroomBytes=available;step='memory-floor';assert.ok(available>=268435456);receipt.resourceSnapshot=values;
 }catch(error){receipt.resourceSnapshot=values;receipt.resourceRefusal={step,class:failureClass(error)};throw error;}
}
let sampling, samplingStopped=false;const sampler=setInterval(()=>{if(samplingStopped||sampling)return;sampling=floors().catch(()=>{refused=true;for(const owner of owners)void owner.stop().catch(()=>{});}).finally(()=>{sampling=undefined;});},250);const aggregateTimer=setTimeout(()=>{refused=true;for(const owner of owners)void owner.stop().catch(()=>{});},1500_000);
const closed={PATH:process.env.PATH,LANG:'C.UTF-8',HOME:path.join(out,'home'),TMPDIR:out,GOENV:'off',GOWORK:'off',GOTOOLCHAIN:'local',GOFLAGS:'',GOPRIVATE:'',GONOPROXY:'',GONOSUMDB:'',GOSUMDB:'sum.golang.org',GOPROXY:'https://proxy.golang.org',GOCACHE:path.join(out,'go-cache'),GOMODCACHE:path.join(out,'module-cache'),GOMEMLIMIT:'256MiB',GOGC:'20',GOMAXPROCS:'2',PGOPTIONS:'-c jit=off'};
for(const key of ['HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy','SSL_CERT_FILE','CURL_CA_BUNDLE'])if(typeof process.env[key]==='string')closed[key]=process.env[key];
function postgresFailureCategories(output){const categories=[['initdb:','initdb-command-refused'],['postgres did not become ready:','server-readiness-refused'],['error while loading shared libraries:','child-shared-library-loader'],['cannot be run as root','root-user-refused'],['Permission denied','filesystem-permission-refused'],['permission denied','filesystem-permission-refused'],['could not access directory','required-directory-unavailable'],['No such file or directory','required-file-unavailable'],['does not belong to PostgreSQL','share-file-version-refused'],['is not the same version as initdb','backend-version-refused'],['could not execute command','backend-exec-refused'],['GLIBC_PRIVATE','glibc-private-linkage-refused'],['invalid locale','locale-refused'],['could not load library','postgres-extension-library-refused'],['owned PostgreSQL cleanup failed:','owned-pg-cleanup-refused'],['not the same version as initdb','backend-version-refused'],['symbol lookup error','child-symbol-lookup-refused'],['GLIBC_','glibc-symbol-version-observed'],['not found in the same directory','backend-sibling-unavailable']];const labels=[];for(const [pattern,label]of categories)if(output.includes(pattern)&&!labels.includes(label))labels.push(label);return labels;}
function initdbDiagnostic(stderr){
 // Only the pinned tool's pre-credential local error lines; never FGA/API output.
 assert.equal(tokenForRedaction,'');
 const lines=stderr.split(/\r?\n/).filter(line=>line.startsWith('initdb:')).slice(0,4);
 for(let line of lines){line=line.replaceAll(out,'[owned-runtime]');for(const key of ['HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy'])if(typeof closed[key]==='string'&&closed[key])line=line.replaceAll(closed[key],'[redacted-env]');line=line.slice(0,512).replaceAll('%','%25').replaceAll('\r','%0D').replaceAll('\n','%0A');console.log('::notice title=Owned initdb diagnostic::'+line);}
}
function nativeDiagnostic(result,timed){
 const allowed=roster;const diagnostic={status:Number.isInteger(result.status)?result.status:null,signal:['SIGTERM','SIGKILL','SIGINT','SIGABRT','SIGSEGV'].includes(result.signal)?result.signal:null,timed,outputLimitExceeded:result.outputLimitExceeded,counts:{run:0,pass:0,fail:0,skip:0},failedCases:[],locations:[],jsonMalformed:false,fixtureStages:[],sqlStates:[],canonicalVersions:[],fixtureErrorCategory:null,postgresCategories:[],migrationDiagnostics:[],rollbackDiagnostic:null,catalogDiagnostic:null,catalogKinds:[],cutoverPrepareStages:[],cutoverActivationStages:[],preparationStages:[],leaseObservations:[],approvalPayloadObservations:[]};
 const fixedStages=["postgres-start", "postgres-connect", "canonical-install", "fixture-data", "projection-pool", "owned-fga-model", "tuple-writer", "fga-checker", "projection-configure", "projection-reconcile", "registered-api-connect", "registered-api-role", "database-current-authority", "browser-authentication", "token-authentication", "authorization-resolver", "connector-registry", "reference-registry", "workflow-handler", "router", "canonical-cutover", "data-plane-roles", "data-plane-principals", "current-authorization-modules", "execution-roles", "execution-principals", "temporal-authorization-modules", "current-authorization-replay", "verifier-registration"];const locations=new Set();for(const line of result.stdout.split('\n').filter(Boolean)){let row;try{row=JSON.parse(line);}catch{diagnostic.jsonMalformed=true;continue;}if(allowed.includes(row.Test)&&['run','pass','fail','skip'].includes(row.Action)){diagnostic.counts[row.Action]++;if(row.Action==='fail')diagnostic.failedCases.push(row.Test);}if(typeof row.Output==='string'){
 const observed=parseConnectorNativeObservation(row.Output);if(observed?.kind==='catalog-summary'&&diagnostic.catalogDiagnostic===null)diagnostic.catalogDiagnostic=observed.value;else if(observed?.kind==='catalog-object'&&diagnostic.catalogKinds.length<9&&!diagnostic.catalogKinds.some(value=>value.kind===observed.value.kind))diagnostic.catalogKinds.push(observed.value);else if(observed?.kind==='cutover'&&diagnostic.cutoverPrepareStages.length<4&&!diagnostic.cutoverPrepareStages.includes(observed.stage))diagnostic.cutoverPrepareStages.push(observed.stage);else if(observed?.kind==='activation'&&diagnostic.cutoverActivationStages.length<4&&!diagnostic.cutoverActivationStages.includes(observed.stage))diagnostic.cutoverActivationStages.push(observed.stage);else if(observed?.kind==='preparation'&&diagnostic.preparationStages.length<4&&!diagnostic.preparationStages.includes(observed.stage))diagnostic.preparationStages.push(observed.stage);else if(observed?.kind==='lease'&&diagnostic.leaseObservations.length<8)diagnostic.leaseObservations.push(observed.value);else if(observed?.kind==='approval-payload'&&diagnostic.approvalPayloadObservations.length<4)diagnostic.approvalPayloadObservations.push(observed.value);


 for(const label of postgresFailureCategories(row.Output))if(!diagnostic.postgresCategories.includes(label))diagnostic.postgresCategories.push(label);

 for(const match of row.Output.matchAll(/connector migration phase=(worker-profile|approval-profile|connector-profile|oauth-competing-attempt|oauth-first-attempt) statement=(oauth-admission|private-query|approval-definitions|connector-definitions|capture-definitions|namespace-bootstrap|organization-reference|registration-insert|authority-selection) SQLSTATE=([0-9A-Z]{5}) target=(unknown|zasp_organizations|zasp_security_agent_approval_notifications|zasp_authorization80_worker|zasp_authorization80_temporal|zasp_temporal78|zasp_approval_maintenance|zasp_connector_provenance|zasp_connector_maintenance|zasp_discovery_authority|registration) position=([0-9]{1,7}) reason=(unknown|attestation|fence|scope|oauth-catalog|oauth-registration|oauth-fingerprint|oauth-provenance|oauth-principal|oauth-source|cleanup-source|oauth-expired|task-purpose|task-source|task-witness)(?:\s|$)/g))if(diagnostic.migrationDiagnostics.length<16&&Number(match[5])<=2000000)diagnostic.migrationDiagnostics.push({phase:match[1],statement:match[2],sqlState:match[3],target:match[4],position:Number(match[5]),reason:match[6]});
 for(const match of row.Output.matchAll(/connector fixture stage=([a-z-]+)/g))if(fixedStages.includes(match[1])&&diagnostic.fixtureStages.length<32)diagnostic.fixtureStages.push(match[1]);
 for(const match of row.Output.matchAll(/connector fixture SQLSTATE=([0-9A-Z]{5})(?:\s|$)/g))if(diagnostic.sqlStates.length<16)diagnostic.sqlStates.push(match[1]);
 for(const match of row.Output.matchAll(/failed after canonical version ([0-9]{1,4})(?:\s|$)/g))if(diagnostic.canonicalVersions.length<16)diagnostic.canonicalVersions.push(Number(match[1]));
 if(row.Output.includes('connector rollback result=admitted'))diagnostic.rollbackDiagnostic='admitted';else if(row.Output.includes('connector rollback result=non-postgres-error'))diagnostic.rollbackDiagnostic='non-postgres-error';
 if(row.Output.includes('connector fixture errorCategory=non-postgres-or-unclassified'))diagnostic.fixtureErrorCategory='non-postgres-or-unclassified';
 for(const match of row.Output.matchAll(/(?:retention_native_postgres_test|optional_egress_native_postgres_test|approval_maintenance_genuine_enqueue_postgres_test|authorization_worker_planning_proof_postgres_test|approval_activation_postgres_test|approval_activation_flow_test|approval_activation_family_flow_test|approval_activation_family_runtime_test|approval_activation_ordered_progress_test|approval_activation_future_family_test|approval_activation_overflow_test|connector_maintenance_failure_observation_test|connector_maintenance_callback_restart_postgres_test|connector_maintenance_catalog_diagnostic_test|connector_maintenance_pkce_recovery_test|connector_maintenance_lifecycle_postgres_test|connector_maintenance_lifecycle_helpers_test|connector_maintenance_enqueue_postgres_test|connector_enqueue_provenance_postgres_test|authorization_integration_mutations_postgres_test|authorization_projection_fga_test|approval_maintenance_owned_fga_test|approval_maintenance_genuine_test74_postgres_test|approval_maintenance_genuine_progress_postgres_test|authorization_worker_ordered_planning_postgres_test|authorization_worker_ordered_policy_postgres_test|authorization_worker_ordered_policy_flow_test|security_agent_temporal_test_executor_postgres_test|security_agent_temporal_executor_postgres_test|security_agent_multistep_dependencies_test|temporal_finding_response_postgres_test|postgres_integration_test)\.go:[0-9]{1,6}:/g))locations.add(match[0].slice(0,-1));}
}
 diagnostic.locations=[...locations].slice(0,16);diagnostic.failedCases=diagnostic.failedCases.slice(0,10);receipt.nativeDiagnostic=diagnostic;
 const scalar=n=>Number.isInteger(n)?String(n):'unobserved';console.log('::notice title=Connector native command outcome::status='+scalar(diagnostic.status)+'; timed='+String(timed)+'; signal='+(diagnostic.signal??'none')+'; cap='+String(diagnostic.outputLimitExceeded)+'; namedRUN='+diagnostic.counts.run+'; namedPASS='+diagnostic.counts.pass+'; namedFAIL='+diagnostic.counts.fail+'; namedSKIP='+diagnostic.counts.skip+'; failedCases='+diagnostic.failedCases.join(',')+'; sourceLocations='+diagnostic.locations.join(',')+'; postgresCategories='+diagnostic.postgresCategories.join(',')+'; fixtureStages='+diagnostic.fixtureStages.join(',')+'; SQLSTATE='+diagnostic.sqlStates.join(',')+'; canonicalVersions='+diagnostic.canonicalVersions.join(',')+'; fixtureErrorCategory='+(diagnostic.fixtureErrorCategory??'none')+'; rollbackDiagnostic='+(diagnostic.rollbackDiagnostic??'none')+'; migrationDiagnostics='+JSON.stringify(diagnostic.migrationDiagnostics)+'; catalogDiagnostic='+JSON.stringify(diagnostic.catalogDiagnostic)+'; catalogKinds='+JSON.stringify(diagnostic.catalogKinds)+'; cutoverPrepareStages='+diagnostic.cutoverPrepareStages.join(',')+'; cutoverActivationStages='+diagnostic.cutoverActivationStages.join(',')+'; preparationStages='+diagnostic.preparationStages.join(',')+'; leaseObservations='+JSON.stringify(diagnostic.leaseObservations)+'; approvalPayloadObservations='+JSON.stringify(diagnostic.approvalPayloadObservations)+'; JSONMalformed='+String(diagnostic.jsonMalformed)+'. No deployment readiness established.');
}
async function run(exe,args,seconds=60,env=closed,cleanup=false){if(!cleanup){guard();await floors();guard();}const owner=spawnOwnedCommand(exe,args,{cwd:root,env,maxOutputBytes:8*1024*1024});owners.add(owner);let timed=false;const timer=setTimeout(()=>{timed=true;void owner.stop().catch(()=>{refused=true;});},cleanup?seconds*1000:Math.min(seconds*1000,end-performance.now()));let result;
 try{result=await owner.completed;receipt.commands.push({command:exe==='docker'?'docker':path.basename(exe),status:result.status,signal:result.signal,outputLimitExceeded:result.outputLimitExceeded,stdoutBytes:Buffer.byteLength(result.stdout),stderrBytes:Buffer.byteLength(result.stderr),stdoutSHA256:hash(result.stdout),stderrSHA256:hash(result.stderr)});if(exe==='go'&&args[0]==='test')nativeDiagnostic(result,timed);if(['owned-initdb-tool-smoke','owned-raw-postgres-version-probe'].includes(phase)){const observation={status:result.status,signal:result.signal,timed,outputLimitExceeded:result.outputLimitExceeded,categories:postgresFailureCategories(result.stdout+'\n'+result.stderr),stdoutBytes:Buffer.byteLength(result.stdout),stderrBytes:Buffer.byteLength(result.stderr)};if(phase==='owned-initdb-tool-smoke')receipt.initdbToolSmoke=observation;else receipt.rawPostgresVersionProbe=observation;console.log('::notice title=Owned PostgreSQL prerequisite::phase='+phase+'; status='+String(result.status)+'; timed='+String(timed)+'; signal='+(result.signal??'none')+'; cap='+String(result.outputLimitExceeded)+'; categories='+observation.categories.join(',')+'. Tool compatibility only; no product test or deployment acceptance.');}if(phase==='owned-initdb-tool-smoke'&&result.status!==0)initdbDiagnostic(result.stderr);assert.ok(!timed&&(cleanup||!canceled)&&result.status===0&&!result.signal&&!result.outputLimitExceeded,'owned command refused');if(!cleanup)guard();return result;}
 finally{clearTimeout(timer);await owner.stop();owners.delete(owner);}
}
async function port(){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const value=server.address().port;await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));return value;}
async function absent(pid){try{process.kill(pid,0);return false;}catch(error){assert.equal(error.code,'ESRCH');return true;}}
async function sessionEmpty(sid){const names=(await readdir('/proc')).filter(name=>/^[0-9]+$/.test(name));assert.ok(names.length<=8192);for(const name of names){let row;try{row=await readFile('/proc/'+name+'/stat','utf8');}catch(error){if(error.code==='ENOENT')continue;throw error;}assert.ok(row.length<=16384);const fields=row.slice(row.lastIndexOf(')')+1).trim().split(/\s+/);if(Number(fields[3])===sid)return false;}return true;}
async function bindable(value){const s=net.createServer();await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(value,'127.0.0.1',resolve);});await new Promise(resolve=>s.close(resolve));}
async function auth(url,token){guard();const response=await fetch(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(5000),headers:token?{Authorization:'Bearer '+token}: {}});try{let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;assert.ok(bytes<=65536);}return response.status;}finally{await response.body?.cancel().catch(()=>{});}}
async function sourcePins(){receipt.sourceBinding='runner-self';assert.equal(hash(await readFile(new URL(import.meta.url))),selfSHA256);for(const [file,pin]of Object.entries({...pins,...helperPins})){receipt.sourceBinding=file;assert.equal(hash(await readFile(path.join(root,file))),pin);}receipt.sourceBinding='all-pins-matched';}
try{
 phase='initial-resource-floor';await floors();phase='source-admission';await sourcePins();for(const name of ['home','go-cache','module-cache'])await mkdir(path.join(out,name),{mode:0o700});
 phase='go-tool-version';assert.match((await run('go',['version'],5)).stdout,/^go version go1\.26\.8 linux\/amd64\n$/);
 const sums={};for(const file of ['services/platform/go.mod','services/platform/go.sum'])sums[file]=hash(await readFile(path.join(root,file)));
 phase='locked-module-prime';await run('go',['list','-C','services/platform','-mod=readonly','-deps','-test','./apiserver'],300);
 for(const [file,pin]of Object.entries(sums))assert.equal(hash(await readFile(path.join(root,file))),pin);
 phase='pinned-postgres-intake';await run('docker',['--host=unix:///var/run/docker.sock','pull',image],180);
 const inspected=JSON.parse((await run('docker',['--host=unix:///var/run/docker.sock','image','inspect',image])).stdout);assert.ok(inspected.length===1&&inspected[0].RepoDigests.includes(image));
 container=(await run('docker',['--host=unix:///var/run/docker.sock','create','--name','zasp-connector-pg-extract-'+randomBytes(8).toString('hex'),'--network=none','--read-only','--entrypoint=/bin/true',image])).stdout.trim();assert.match(container,/^[a-f0-9]{64}$/);
 const pg=path.join(out,'pg');await mkdir(pg,{mode:0o700});await mkdir(path.join(pg,'root/usr/lib/postgresql'),{mode:0o700,recursive:true});await mkdir(path.join(pg,'root/usr/share/postgresql'),{mode:0o700,recursive:true});
 for(const [source,destination]of [['/usr/lib/postgresql/18',path.join(pg,'root/usr/lib/postgresql/18')],['/usr/share/postgresql/18',path.join(pg,'root/usr/share/postgresql/18')],['/usr/lib/x86_64-linux-gnu',path.join(pg,'root/usr/lib/x86_64-linux-gnu')]])await run('docker',['--host=unix:///var/run/docker.sock','cp','-L',container+':'+source,destination]);
 // Resolve the image's top-level sample symlink in the container, not on the host.
 const sampleDirectory=path.join(pg,'root/usr/share/postgresql/18');assert.equal(await realpath(sampleDirectory),sampleDirectory);
 const retainedSample=path.join(pg,'postgresql.conf.sample.official'),sample=path.join(sampleDirectory,'postgresql.conf.sample');
 await run('docker',['--host=unix:///var/run/docker.sock','cp','-L',container+':/usr/share/postgresql/18/postgresql.conf.sample',retainedSample]);
 const sampleStat=await lstat(retainedSample);assert.ok(sampleStat.isFile()&&sampleStat.size>0&&sampleStat.size<=131072);
 // Rename replaces a copied symlink without following its potentially absolute target.
 await rename(retainedSample,sample);assert.ok((await lstat(sample)).isFile());const sampleBytes=await readFile(sample);assert.equal(sampleBytes.length,sampleStat.size);receipt.postgresSample={bytes:sampleBytes.length,sha256:hash(sampleBytes),source:'same-pinned-image-dereferenced-file'};
 await run('docker',['--host=unix:///var/run/docker.sock','rm',container]);container=undefined;
 const bin=path.join(pg,'bin');await mkdir(bin,{mode:0o700});
 const libraryNames=JSON.parse(await readFile(path.join(root,"docs/internal/evidence/cloud-2026-10-07/native-service-readiness/openfga/09-pg-non-glibc-libs-manifest.json"), 'utf8'));assert.ok(Array.isArray(libraryNames)&&libraryNames.length===179);
 const childLibraries=path.join(pg,'non-glibc-child-libraries');await mkdir(childLibraries,{mode:0o700});const uniqueLibraryNames=new Set();const libraryRoot=await realpath(path.join(pg,'root/usr/lib/x86_64-linux-gnu'));
 for(const row of libraryNames){guard();assert.ok(typeof row.name==='string'&&/^[A-Za-z0-9_.+-]{1,128}$/.test(row.name)&&!uniqueLibraryNames.has(row.name));assert.ok(!/^(?:ld-|libc\.|libm\.|libpthread|libdl\.|librt\.|libutil\.|libnss)/.test(row.name));uniqueLibraryNames.add(row.name);const source=await realpath(path.join(libraryRoot,row.name));assert.ok(source.startsWith(libraryRoot+'/')&&(await stat(source)).isFile());await symlink(source,path.join(childLibraries,row.name));}
 receipt.postgresChildLibraryCount=uniqueLibraryNames.size;

 assert.ok((await lstat(path.join(pg,'root/usr/share/postgresql/18/postgres.bki'))).isFile());
 for(const name of ['postgres','initdb','pg_ctl','pg_isready','psql','pg_config']){
  const binary=path.join(pg,'root/usr/lib/postgresql/18/bin',name);assert.ok((await lstat(binary)).isFile());
  const prefix=name==='initdb'?`set -- -L '${pg}/root/usr/share/postgresql/18' "$@"\n`:name==='pg_ctl'?`set -- -p '${bin}/postgres' "$@"\n`:name==='pg_config'?`if [ "$#" -eq 1 ] && [ "$1" = --bindir ]; then printf '%s\\n' '${bin}'; exit 0; fi\n`:'';
  await writeFile(path.join(bin,name),`#!/bin/sh\nset -eu\nexport LD_LIBRARY_PATH='${childLibraries}'\n${prefix}exec '${pg}/root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2' --library-path '${pg}/root/usr/lib/x86_64-linux-gnu:${pg}/root/usr/lib/postgresql/18/lib' '${binary}' "$@"\n`,{mode:0o500,flag:'wx'});
 }
 const testEnv={...closed,GOPROXY:'off',PATH:bin+':'+closed.PATH,ZASP_P7_MODEL_TEST:'1'};
 assert.equal((await run(path.join(bin,'postgres'),['--version'],5,testEnv)).stdout,"postgres (PostgreSQL) 18.3 (Debian 18.3-1.pgdg12+1)\n");
 phase='owned-raw-postgres-version-probe';const rawVersion=await run(path.join(pg,'root/usr/lib/postgresql/18/bin/postgres'),['--version'],5,{...testEnv,LD_LIBRARY_PATH:childLibraries});assert.equal(rawVersion.stdout,"postgres (PostgreSQL) 18.3 (Debian 18.3-1.pgdg12+1)\n");
 phase='owned-initdb-tool-smoke';await run(path.join(bin,'initdb'),['--no-locale','--encoding=UTF8','--auth-local=trust','--auth-host=trust','--username=zasp_e2e','-D',path.join(out,'initdb-tool-smoke-data')],30,testEnv);
 phase='pinned-openfga-intake';const archive=path.join(out,'openfga.tar.gz');
 await run('/usr/bin/curl',['--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-time','90','--max-filesize','21232870','--output',archive,'https://github.com/openfga/openfga/releases/download/v1.21.0/openfga_1.21.0_linux_amd64.tar.gz'],95);await chmod(archive,0o400);
 tool=await loadOfficialHeldTool('openfga',archive,path.join(out,'openfga-held'));receipt.fgaTool=await verifyHeldTool(tool);
 const token=tokenForRedaction=randomBytes(32).toString('hex'),tokenFile=path.join(out,'token');await writeFile(tokenFile,token,{mode:0o600,flag:'wx'});
 fgaPort=await port();grpcPort=await port();assert.notEqual(fgaPort,grpcPort);
 phase='owned-openfga-start';fga=await spawnHeldTool(tool,['run'],{cwd:out,env:{PATH:'/usr/bin:/bin',HOME:closed.HOME,TMPDIR:out,OPENFGA_HTTP_ADDR:'127.0.0.1:'+fgaPort,OPENFGA_GRPC_ADDR:'127.0.0.1:'+grpcPort,OPENFGA_DATASTORE_ENGINE:'memory',OPENFGA_AUTHN_METHOD:'preshared',OPENFGA_AUTHN_PRESHARED_KEYS:token,OPENFGA_PLAYGROUND_ENABLED:'false',OPENFGA_METRICS_ENABLED:'false',OPENFGA_LOG_LEVEL:'warn'},maxOutputBytes:65536});owners.add(fga);fgaStart=await captureStart(fga.child.pid);const executable=await stat('/proc/'+fga.child.pid+'/exe');assert.equal(executable.dev,receipt.fgaTool.device);assert.equal(executable.ino,receipt.fgaTool.inode);
 let serviceExited=false;void fga.completed.then(()=>{serviceExited=true;},()=>{serviceExited=true;});
 const url='http://127.0.0.1:'+fgaPort,readyEnd=performance.now()+30000;
 for(;;){guard();assert.ok(!serviceExited&&performance.now()<readyEnd);try{await observeOwnedListener({pid:fga.child.pid,start:fgaStart,port:fgaPort});await observeOwnedListener({pid:fga.child.pid,start:fgaStart,port:grpcPort});const health=await auth(url+'/healthz',null),denied=await auth(url+'/stores',null),wrong=await auth(url+'/stores',randomBytes(32).toString('hex')),allowed=await auth(url+'/stores',token);if(health===200&&denied===401&&wrong===401&&allowed===200){receipt.authStatuses=[health,denied,wrong,allowed];break;}}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}await new Promise(resolve=>setTimeout(resolve,100));}
 testEnv.ZASP_P6_NATIVE_OPENFGA_URL=url;testEnv.ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE=tokenFile;
 testEnv.ZASP_CONNECTOR_LIFECYCLE_OPENFGA_BINARY=path.join(out,'openfga-held','openfga');testEnv.ZASP_CONNECTOR_LIFECYCLE_OPENFGA_SHA256=receipt.fgaTool.memberSHA256;
 phase='authenticated-oauth-enqueue';const test=await run('go',['test','-C','services/platform','-json','-race','-p=1','-count=1','-timeout=10m','-run','^'+selectedGroup.top+'$','./apiserver'],650,testEnv);
 phase='exact-test-roster';const rows=test.stdout.trim().split('\n').map(line=>JSON.parse(line));validateConnectorAcceptanceTrace(rows,selectedGroup);
 const expected=roster;
 const outputs=rows.map(row=>row.Output??'').join('');const joined=[...outputs.matchAll(/joined owned PostgreSQL pid=(\d+).*pg_ctl exit=0 server Wait exit=0 normal-exit/g)];phase='postgres-join-count';assert.equal(joined.length,selectedGroup.postgresJoins);phase='postgres-join-uniqueness';assert.equal(new Set(joined.map(row=>row[1])).size,joined.length);phase='postgres-pid-absence';for(const row of joined)assert.ok(await absent(Number(row[1])));
 assert.ok(!test.stdout.includes(token)&&!test.stderr.includes(token));receipt.test={names:expected,tops:1,subcases:selectedGroup.subcases,skips:0,packagePass:true,postgresNormalJoined:true,postgresPIDAbsent:true};
 await sourcePins();for(const [file,pin]of Object.entries(sums))assert.equal(hash(await readFile(path.join(root,file))),pin);
}catch(error){if(phase==='exact-test-roster'){receipt.traceFailureStage=describeConnectorAcceptanceTraceFailure(error);const event=describeConnectorAcceptanceTraceEvent(error);console.log('::notice title=Connector acceptance trace refusal::stage='+receipt.traceFailureStage+'; eventAction='+(event?.action??'none')+'; eventTestShape='+(event?.testShape??'none')+'; eventCaseClass='+(event?.caseClass??'none')+'. Closed diagnostic only; acceptance remains refused.');}receipt.failedPhase=phase;receipt.failureClass=failureClass(error);refused=true;}
finally{phase='owned-service-cleanup';
 for(const owner of [...owners].reverse()){try{await owner.stop();const result=await owner.completed;if(owner===fga){assert.ok(result.status===0&&!result.signal&&!result.outputLimitExceeded);assert.ok(!result.stdout.includes(tokenForRedaction)&&!result.stderr.includes(tokenForRedaction));receipt.fgaNormalJoined=true;receipt.fgaPIDAbsent=await absent(owner.child.pid);assert.ok(receipt.fgaPIDAbsent);receipt.fgaSessionAbsent=await sessionEmpty(owner.child.pid);assert.ok(receipt.fgaSessionAbsent);}}catch{refused=true;}owners.delete(owner);}
 if(tool)try{await closeHeldTool(tool);}catch{refused=true;}
 if(container)try{await run('docker',['--host=unix:///var/run/docker.sock','rm',container],30,closed,true);container=undefined;}catch{refused=true;}
 if(fgaPort&&grpcPort)try{await bindable(fgaPort);await bindable(grpcPort);receipt.fgaPortsBindable=true;}catch{refused=true;}
}
samplingStopped=true;clearInterval(sampler);clearTimeout(aggregateTimer);if(sampling)await sampling;
try{await floors();await sourcePins();}catch{refused=true;}
receipt.normalCleanup=owners.size===0&&!container&&receipt.fgaNormalJoined===true&&receipt.fgaPortsBindable===true&&receipt.fgaSessionAbsent===true;
receipt.completed=!refused&&!canceled&&performance.now()<end&&receipt.normalCleanup&&receipt.test?.packagePass===true;
await writeFile(path.join(out,'result.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
finished=true;console.log(JSON.stringify(receipt));
if(!receipt.completed||canceled||refused||performance.now()>=end){const value=n=>Number.isSafeInteger(n)&&n>=0?String(n):'unobserved';const resource=receipt.resourceSnapshot??{};console.error('::error title=Connector authenticated enqueue integration::phase='+ (receipt.failedPhase??phase)+'; class='+(receipt.failureClass??'other-refusal')+'; resource='+(receipt.resourceRefusal?.step??'not-refused')+'; resourceClass='+(receipt.resourceRefusal?.class??'none')+'; workspaceBytes='+value(resource.workspaceFreeBytes)+'; scratchBytes='+value(resource.scratchFreeBytes)+'; memoryHeadroomBytes='+value(resource.memoryHeadroomBytes)+'; binding='+(receipt.sourceBinding??'unobserved')+'. Authenticated enqueue integration refused; no deployment readiness established.');process.exitCode=1;}else console.log('Connector connected '+selectedGroupName+': 1 top / '+selectedGroup.subcases+' subcases PASS; owned PG/FGA normal cleanup. All six workflow groups are required; no fleet or deployment acceptance.');

if(canceled||refused||performance.now()>=end){lateRefusal('terminal-refusal');process.exitCode=1;}
