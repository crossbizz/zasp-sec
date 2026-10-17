import { parseConnectorNativeObservation } from './connector-acceptance-groups.mjs';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, chmod, lstat, statfs, stat, readdir, symlink, realpath, rename } from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { observeHostedMemory } from './hosted-memory-observation.mjs';
import {openSync,writeSync,fsyncSync,closeSync,constants} from 'node:fs';
import { captureStart, observeOwnedListener } from './owned-listener.mjs';
import { spawnOwnedCommand } from './owned-command.mjs';
import { loadOfficialHeldTool, spawnHeldTool, closeHeldTool, verifyHeldTool } from './official-held-tools.mjs';

// Existing authenticated enqueue application group; no added cases, production credentials or deployment.
const image = 'postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba';
const pins = {
  "services/platform/apiserver/security_agent_temporal_ownership_postgres_test.go": "bb7df4a074825f91c29970ef2fed9c4d363f5dcdcbb82e03e5cbc5c3070df78d",
  "services/platform/apiserver/security_agent_temporal_executor_postgres_test.go": "c2ef8641fe329f9f50dba2f9c0e35766c82832966153d86e54b56c41d5bb531b",
  "services/platform/apiserver/authorization_worker_ordered_provider_evidence_test.go": "f1f1f4d26aa6c03a0955e87cc35ca29ec860430abfc5c5c343f81e7eff39a843",
  "services/platform/apiserver/approval_projection_visibility_test.go": "b8f964ffe558539a52e1fca5c97cac4f7add6e366b18a88f0e6682e72def526b",
  "services/platform/agentsec-api/bounded_parallel_readiness_test.go": "4a82a77cf64184177b7f7bde1ee56d736e5d9bd6624b7174e9f45e9a48043951",
  "services/platform/agentsec-api/authorization_runtime_readiness.go": "7999316f721e079c16656412eb594e460ca154f6f78a5cee5a1d894bf000ae21",
  "services/platform/apiserver/authorization_readiness.go": "ad1a94117de4e63b9c7ef15faf4c4744e6a6675b44ad6da1d7991cb63fcb683a",
  "services/platform/apiserver/current_authorization_health_probe_test.go": "09361c7c963d5f3d508b9c534d92c5b7d6bcf2f19c4c46b8413088c0b974c593",
  "services/platform/apiserver/current_authorization_health_probe.go": "3bed74745ef1056405965605ea6c45b949e842bf29065e8665e7900ec3cd8a66",
  "services/platform/apiserver/connector_maintenance_catalog_diagnostic_test.go": "3a0a5a0dc9c6fa4d74cae94d06ddfd470473a2d07dd0d673d1d9c62359a3a426",
  "services/platform/agentsec-api/connector_callback_runtime.go": "69c0fe154628058709eaf886369e3aa92aee8a9526a1bebda091ad8147c6cd95",
  "services/platform/agentsec-api/connector_maintenance_runtime.go": "8f7207d81d37dcceb02dcfd55975eefe407cebca06eaf7b99a6bd9eb555d5dc3",
  "services/platform/agentsec-api/production_runtime.go": "bbcc0ce1843601dfdfbde2ffe2aa710ed26239d7eb27849f2b5e9582338b09ef",
  "services/platform/agentsec-api/runtime.go": "376900f43e60d5896e4804bce8f9a7685000a28396857c8b42b35b8c3554d2d7",
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
  "services/platform/connectormaintenance/authority.go": "378b2b151fe9978ca28a3c40d024c52bff7d3f0b83267839ef1dd61ee3946441",
  "services/platform/connectormaintenance/executor.go": "24ac12fb20e753ec433464e6220bc7aaf4127fb9e7e3803831553bb75e7a40f3",
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
  "services/platform/connectormaintenancecutover/readback_defaults.json": "d4c42d89fa77b89513e732b6d5bdd206c808111096307d38784cc6f1ba639835",
  "services/platform/connectormaintenancecutover/readback_test.go": "e4970d8ef25f042e9948abb5cbb0557c32988a50bd80b3bcddd6c8f74a8da23a",
  "services/platform/agentsec-migrate/main.go": "19c0b192ab81b04c6ff0487fb93c7b6fa566a39a1cd82dcf5f8c44bfd3807426",
  "services/platform/agentsec-migrate/maintenance_profile_commands_test.go": "8745c207020f6b8cf7992aed8a00e518f61869568a50f9bfcebb19f8e004ae22",
  "services/platform/agentsec-worker/authorization_worker_activation_config_test.go": "3b66404d7740592ad2c42e6491861e26f11788b3b6be0b7e68cbe9a6c20bca23",
  "services/platform/apiserver/approval_activation_postgres_test.go": "4a40ff1c879cd4c1af951ba8bc812d0d9ea81a360c856fcde4235b63581ae6e5",
  "services/platform/apiserver/connector_maintenance_callback_restart_postgres_test.go": "fe1f04ee8d9d6c78814a05df0fb976f4aedd5f1667e648c5342fbc14ea1d46bf",
  "services/platform/apiserver/connector_maintenance_lifecycle_postgres_test.go": "345c365921cdc9281ec767e00fd3e934f31fa4badb393f4a6b6e5793bd544e2d",
  "services/platform/apiserver/connector_maintenance_pkce_recovery_test.go": "db05051ac764c5a1d57dac9e8c3691660c284a2a6f5fb088b8cd10acef7c7f96",
  "services/platform/authorization/worker.go": "6693ec0a0aae3b18a0db4ebbaf3f5b80d7c2c54be8983b918e29ec4936554ac2",
  "services/platform/authorization/worker_approval_activation_test.go": "15e44850678ba5b9b385023555fcc501eca600c53c1f912dbf799841387d7b0b",
  "services/platform/authorization/worker_approval_origin.go": "6f83d9f2998fdf8d94beb69e3c4c15fe11037a8bb386303a831f5f1dfee8a69f",
  "services/platform/cmd/zasp-authorization-reconcile/hold_test.go": "07465bbdeb1bcb66a865f855279fe1b764063aba0f17bbcdfecb5726eef9ffe6",
  "services/platform/cmd/zasp-controlled-maintenance-cutover/main.go": "90a0e4a39acaf006571f2a3a610bf1b8b4881c39645fbea10cb5c81290eea5e8",
  "services/platform/cmd/zasp-controlled-maintenance-cutover/main_test.go": "a8e1b3d97076b74daa29f60e117b9ca0f370bcd627d9819152b418c992e8da74",
  "services/platform/cmd/zasp-maintenance-register/main.go": "f2f2ac05671b7738f3c12b1206e7865cff514606189da3a82c888732acd60fc9",
  "services/platform/cmd/zasp-maintenance-register/main_test.go": "5ae1660fd2e5de9961c459d619cf291ae6d730896d9126c2074f68ed2c8069c0",
  "services/platform/connectormaintenancecutover/combined.go": "b841c26caee24f7948d43ec72b1b2d2dc53ce0661845af73a9f417ae93091f84",
  "services/platform/connectormaintenancecutover/coordinator_test.go": "26ce6254da116eb381365e2c90ae97e4c7366d829168e5a55438b40dc8ba9a90",
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
  "services/platform/agentsec-worker/production_runtime.go": "e4c91fda0206a242fd4b461b9145bab76ebb4fcb2ad9ee954bb7ec32204d03a1",
  "services/platform/agentsec-worker/runtime_config.go": "fd7941adad7b11577e2fe2cdc9e6b0473af1175ec911ab84ab18b06e8ba57940",
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
  "services/platform/apiserver/optional_egress_native_postgres_test.go": "e169e86f5c4f9eb092ce3dbc75256a84c2829f85a95424291ef49e1907ed9c17",
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
  "services/platform/apiserver/approval_maintenance_genuine_enqueue_postgres_test.go": "0ae6bb2a4eb4a41f98e475b498fbe9f96347df3d969920e6c4455f3943cadddd",
  "services/platform/apiserver/authorization_worker_planning_proof_postgres_test.go": "b8963bd92123726ed121f2d59a5419d59fd36b7519a91bf0de5dc41d6d6c231a"
};
const top='TestConnectorMaintenanceAuthenticatedOAuthEnqueuePostgres';
const cases=['genuine_same_transaction_origin_and_immutable_enrichment','rollback_removes_every_enqueue_and_provenance_write'];
const helperPins={
  "scripts/connector-acceptance-groups.test.mjs": "56488ada37d53171d7b7387b0c52c1f4815dd1c728aa634503387f14a08f09b9",
  "scripts/connector-acceptance-groups.mjs": "9a4d01d30165dae0e75ca0183878656bb7cf8a30aa51657f87c335fc66ad5b00",
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
const receipt={scope:'authenticated OAuth enqueue captured-inactive application integration only',completed:false,activated:false,production:false,testPins:pins,helperPins,selfSHA256,pgImage:image,commands:[],authStatuses:[],normalCleanup:false};
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
 const allowed=[top,...cases.map(name=>top+'/'+name)];const diagnostic={status:Number.isInteger(result.status)?result.status:null,signal:['SIGTERM','SIGKILL','SIGINT','SIGABRT','SIGSEGV'].includes(result.signal)?result.signal:null,timed,outputLimitExceeded:result.outputLimitExceeded,counts:{run:0,pass:0,fail:0,skip:0},failedCases:[],locations:[],jsonMalformed:false,fixtureStages:[],sqlStates:[],canonicalVersions:[],fixtureErrorCategory:null,postgresCategories:[],migrationDiagnostics:[],rollbackDiagnostic:null,catalogDiagnostic:null,catalogKinds:[],cutoverPrepareStages:[],cutoverActivationStages:[],preparationStages:[],leaseObservations:[]};
 const fixedStages=["postgres-start", "postgres-connect", "canonical-install", "fixture-data", "projection-pool", "owned-fga-model", "tuple-writer", "fga-checker", "projection-configure", "projection-reconcile", "registered-api-connect", "registered-api-role", "database-current-authority", "browser-authentication", "token-authentication", "authorization-resolver", "connector-registry", "reference-registry", "workflow-handler", "router", "canonical-cutover", "data-plane-roles", "data-plane-principals", "current-authorization-modules", "execution-roles", "execution-principals", "temporal-authorization-modules", "current-authorization-replay", "verifier-registration"];const locations=new Set();for(const line of result.stdout.split('\n').filter(Boolean)){let row;try{row=JSON.parse(line);}catch{diagnostic.jsonMalformed=true;continue;}if(allowed.includes(row.Test)&&['run','pass','fail','skip'].includes(row.Action)){diagnostic.counts[row.Action]++;if(row.Action==='fail')diagnostic.failedCases.push(row.Test);}if(typeof row.Output==='string'){
 const observed=parseConnectorNativeObservation(row.Output);if(observed?.kind==='catalog-summary'&&diagnostic.catalogDiagnostic===null)diagnostic.catalogDiagnostic=observed.value;else if(observed?.kind==='catalog-object'&&diagnostic.catalogKinds.length<9&&!diagnostic.catalogKinds.some(value=>value.kind===observed.value.kind))diagnostic.catalogKinds.push(observed.value);else if(observed?.kind==='cutover'&&diagnostic.cutoverPrepareStages.length<4&&!diagnostic.cutoverPrepareStages.includes(observed.stage))diagnostic.cutoverPrepareStages.push(observed.stage);else if(observed?.kind==='activation'&&diagnostic.cutoverActivationStages.length<4&&!diagnostic.cutoverActivationStages.includes(observed.stage))diagnostic.cutoverActivationStages.push(observed.stage);else if(observed?.kind==='preparation'&&diagnostic.preparationStages.length<4&&!diagnostic.preparationStages.includes(observed.stage))diagnostic.preparationStages.push(observed.stage);else if(observed?.kind==='lease'&&diagnostic.leaseObservations.length<8)diagnostic.leaseObservations.push(observed.value);


 for(const label of postgresFailureCategories(row.Output))if(!diagnostic.postgresCategories.includes(label))diagnostic.postgresCategories.push(label);

 for(const match of row.Output.matchAll(/connector migration phase=(worker-profile|approval-profile|connector-profile|oauth-competing-attempt|oauth-first-attempt) statement=(oauth-admission|private-query|approval-definitions|connector-definitions|capture-definitions|namespace-bootstrap|organization-reference|registration-insert|authority-selection) SQLSTATE=([0-9A-Z]{5}) target=(unknown|zasp_organizations|zasp_security_agent_approval_notifications|zasp_authorization80_worker|zasp_authorization80_temporal|zasp_temporal78|zasp_approval_maintenance|zasp_connector_provenance|zasp_connector_maintenance|zasp_discovery_authority|registration) position=([0-9]{1,7}) reason=(unknown|attestation|fence|scope|oauth-catalog|oauth-registration|oauth-fingerprint|oauth-provenance|oauth-principal|oauth-source|cleanup-source|oauth-expired|task-purpose|task-source|task-witness)(?:\s|$)/g))if(diagnostic.migrationDiagnostics.length<16&&Number(match[5])<=2000000)diagnostic.migrationDiagnostics.push({phase:match[1],statement:match[2],sqlState:match[3],target:match[4],position:Number(match[5]),reason:match[6]});
 for(const match of row.Output.matchAll(/connector fixture stage=([a-z-]+)/g))if(fixedStages.includes(match[1])&&diagnostic.fixtureStages.length<32)diagnostic.fixtureStages.push(match[1]);
 for(const match of row.Output.matchAll(/connector fixture SQLSTATE=([0-9A-Z]{5})(?:\s|$)/g))if(diagnostic.sqlStates.length<16)diagnostic.sqlStates.push(match[1]);
 for(const match of row.Output.matchAll(/failed after canonical version ([0-9]{1,4})(?:\s|$)/g))if(diagnostic.canonicalVersions.length<16)diagnostic.canonicalVersions.push(Number(match[1]));
 if(row.Output.includes('connector rollback result=admitted'))diagnostic.rollbackDiagnostic='admitted';else if(row.Output.includes('connector rollback result=non-postgres-error'))diagnostic.rollbackDiagnostic='non-postgres-error';
 if(row.Output.includes('connector fixture errorCategory=non-postgres-or-unclassified'))diagnostic.fixtureErrorCategory='non-postgres-or-unclassified';
 for(const match of row.Output.matchAll(/(?:approval_activation_postgres_test|approval_activation_flow_test|approval_activation_family_flow_test|approval_activation_family_runtime_test|approval_activation_ordered_progress_test|approval_activation_future_family_test|approval_activation_overflow_test|connector_maintenance_failure_observation_test|connector_maintenance_enqueue_postgres_test|connector_enqueue_provenance_postgres_test|authorization_integration_mutations_postgres_test|authorization_projection_fga_test|approval_maintenance_owned_fga_test|postgres_integration_test)\.go:[0-9]{1,6}:/g))locations.add(match[0].slice(0,-1));}
}
 diagnostic.locations=[...locations].slice(0,16);diagnostic.failedCases=diagnostic.failedCases.slice(0,10);receipt.nativeDiagnostic=diagnostic;
 const scalar=n=>Number.isInteger(n)?String(n):'unobserved';console.log('::notice title=Connector native command outcome::status='+scalar(diagnostic.status)+'; timed='+String(timed)+'; signal='+(diagnostic.signal??'none')+'; cap='+String(diagnostic.outputLimitExceeded)+'; namedRUN='+diagnostic.counts.run+'; namedPASS='+diagnostic.counts.pass+'; namedFAIL='+diagnostic.counts.fail+'; namedSKIP='+diagnostic.counts.skip+'; failedCases='+diagnostic.failedCases.join(',')+'; sourceLocations='+diagnostic.locations.join(',')+'; postgresCategories='+diagnostic.postgresCategories.join(',')+'; fixtureStages='+diagnostic.fixtureStages.join(',')+'; SQLSTATE='+diagnostic.sqlStates.join(',')+'; canonicalVersions='+diagnostic.canonicalVersions.join(',')+'; fixtureErrorCategory='+(diagnostic.fixtureErrorCategory??'none')+'; rollbackDiagnostic='+(diagnostic.rollbackDiagnostic??'none')+'; migrationDiagnostics='+JSON.stringify(diagnostic.migrationDiagnostics)+'; catalogDiagnostic='+JSON.stringify(diagnostic.catalogDiagnostic)+'; catalogKinds='+JSON.stringify(diagnostic.catalogKinds)+'; cutoverPrepareStages='+diagnostic.cutoverPrepareStages.join(',')+'; cutoverActivationStages='+diagnostic.cutoverActivationStages.join(',')+'; preparationStages='+diagnostic.preparationStages.join(',')+'; leaseObservations='+JSON.stringify(diagnostic.leaseObservations)+'; JSONMalformed='+String(diagnostic.jsonMalformed)+'. No deployment readiness established.');
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
 phase='authenticated-oauth-enqueue';const test=await run('go',['test','-C','services/platform','-json','-race','-p=1','-count=1','-timeout=10m','-run','^'+top+'$','./apiserver'],650,testEnv);
 phase='exact-roster-and-postgres-cleanup';const rows=test.stdout.trim().split('\n').map(line=>JSON.parse(line));assert.ok(rows.every(row=>row.Action!=='fail'&&row.Action!=='skip'));
 const expected=[top,...cases.map(name=>top+'/'+name)];for(const action of ['run','pass'])assert.deepEqual(rows.filter(row=>row.Action===action&&row.Test).map(row=>row.Test).sort(),expected.slice().sort());assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,1);
 const outputs=rows.map(row=>row.Output??'').join('');const joined=[...outputs.matchAll(/joined owned PostgreSQL pid=(\d+).*pg_ctl exit=0 server Wait exit=0 normal-exit/g)];assert.equal(joined.length,1);assert.ok(await absent(Number(joined[0][1])));
 assert.ok(!test.stdout.includes(token)&&!test.stderr.includes(token));receipt.test={names:expected,tops:1,subcases:2,skips:0,packagePass:true,postgresNormalJoined:true,postgresPIDAbsent:true};
 await sourcePins();for(const [file,pin]of Object.entries(sums))assert.equal(hash(await readFile(path.join(root,file))),pin);
}catch(error){receipt.failedPhase=phase;receipt.failureClass=failureClass(error);refused=true;}
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
if(!receipt.completed||canceled||refused||performance.now()>=end){const value=n=>Number.isSafeInteger(n)&&n>=0?String(n):'unobserved';const resource=receipt.resourceSnapshot??{};console.error('::error title=Connector authenticated enqueue integration::phase='+ (receipt.failedPhase??phase)+'; class='+(receipt.failureClass??'other-refusal')+'; resource='+(receipt.resourceRefusal?.step??'not-refused')+'; resourceClass='+(receipt.resourceRefusal?.class??'none')+'; workspaceBytes='+value(resource.workspaceFreeBytes)+'; scratchBytes='+value(resource.scratchFreeBytes)+'; memoryHeadroomBytes='+value(resource.memoryHeadroomBytes)+'; binding='+(receipt.sourceBinding??'unobserved')+'. Authenticated enqueue integration refused; no deployment readiness established.');process.exitCode=1;}else console.log('Connector authenticated OAuth enqueue: existing 1 top / 2 subcases PASS; owned PG/FGA normal cleanup. No runtime activation or deployment acceptance.');

if(canceled||refused||performance.now()>=end){lateRefusal('terminal-refusal');process.exitCode=1;}
