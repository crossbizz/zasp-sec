// A separately versioned, source-only successor. Historical destinations and
// native/installed acceptance pins remain authority for their original paths.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const p7='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/';
const aDestination=p7+'ordered-current-complete-capture-packet-A-cloud-v1/';
const bDestination=p7+'ordered-current-complete-capture-packet-B-cloud-v1/';
const packet='services/platform/migrations/ordered_current/';
const contractName=packet+'consolidated-capture-contract.json';
const producer='services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go';
const addedSources=['services/platform/migrations/tools/build-ordered-current-consolidated-reference-cloud-v1.mjs','services/platform/migrations/tools/build-ordered-current-consolidated-reference-cloud-v1.test.mjs'];
const baselineManifestSHA256='a0087046b6992479753a3e59ba196e735ab1a6f6608c387e79100e1bb1f81400';
const baselineContractSHA256='6f5a8cc081f159b9c4e130de5969af47f2b98ccde477b3e932a2b56db4d33870';
// Exact reviewed baseline authority, independent of this emitter's own bytes.
// Check every file and ancestor before importing any project module.
const baselineSourcePins=Object.freeze({
 "services/platform/apiserver/authorization_worker_consolidated_reference_boundary_test.go": "de8c2e2f7121287e82b8120e8002eb9bd3f643bc344fea8da961fbd000347078",
 "services/platform/apiserver/authorization_worker_consolidated_reference_controls_test.go": "ecbba06bcd58895f7b03dc52f414ccbc9e2ff28bfef7c37fa6eb3e9db1680547",
 "services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go": "a06ab7aa84d8005ca2990117d85203fb4949d47627cec56672f932f037dd8f28",
 "services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go": "60be84a43d564c9c7da3999a22155a7734a1163f258d58206f8bcfabbabc43f6",
 "services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go": "78427e95a296b9b636154a9d7d81e022772fe43b2503fc972c0f34e1e20488b6",
 "services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql": "06ed7d1310bee92bfd80c92698b91c18e3932a573793dcb32344a3fea56831b8",
 "services/platform/migrations/sql/0027_production_recovery.up.sql": "0e4dcbaf987cc3b5f69cf4d415a028d643c2f95bf5160e827e1607e3f60dbc14",
 "services/platform/migrations/sql/0079_production_authorization_projection.up.sql": "8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987",
 "services/platform/migrations/sql/0080_authorization_hierarchy_create.sql": "97482f048fb4ee282bd4f8506f618b83b1252d5afce267ad3b36edcc8a33d46e",
 "services/platform/migrations/sql/0080_authorization_worker_ordered_current_integrity.sql": "d42d975c4b9cbadf7c5b368d4f14b361cd917c65a114d9629307e73af3021e5f",
 "services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql": "530acbf49171985068c55928cb4f0a89b1c383ab223effd533af9450375b5ef6",
 "services/platform/migrations/tools/build-ordered-current-consolidated-reference.mjs": "4201c823bf7fd3a366e0887150890241c1fdd90aa592e8efdf8d4890d23729d3",
 "services/platform/migrations/tools/build-ordered-current-consolidated-reference.test.mjs": "5a6cbf14405ea09a2a4a4b31190b52c17c7a745313e7be77c76445b7d70c8e5d",
 "services/platform/migrations/tools/build-ordered-current-development-higher.test.mjs": "fc287dd32fe14e3b8f1394618e068ea06d268ee75d9c7ae2a2207fe9ded94ea1",
 "services/platform/migrations/tools/build-ordered-current-development-private.test.mjs": "f3dbfe828801e0ad76add1717a1c0a1d4c87fc1e96000ba78e558790805adb30",
 "services/platform/migrations/tools/build-ordered-current-development.mjs": "11381b173903472e492067c17c605b0f61ebc752b318c6b75b74c1fbffd5a600",
 "services/platform/migrations/tools/build-ordered-current-integrity.mjs": "0df6c0cb40df6bdf18dcc51ee660efedc1fcdccb34e6ba8dd0d406e7acb53c8b",
 "services/platform/migrations/tools/build-ordered-current-integrity.test.mjs": "5f01cbd977c07a87d4deacb2c5aefb42cdb2df3ef523a6c70bb9c6a6017e4997",
 "services/platform/migrations/tools/build-worker-readiness-graph.mjs": "fb66f8649b5fea1cf54dbaa7776665b5375fd64bb6808c2b7c75036812a56da7",
 "services/platform/migrations/tools/ordered-current-build-source-inventory-v1.mjs": "6c91f9981637e1411045944a0c507eb71aa4921d5bc06e3e37dbfbbbcc0a672e",
 "services/platform/migrations/tools/ordered-current-build-source-inventory-v1.test.mjs": "458c96c84e0707b6c57cd50c8ffcadcd2637c34ff904863258728946681c431c",
 "services/platform/migrations/tools/ordered-current-capture-closure.mjs": "d18d8f72a35838954dc5771f2a5acc281aacdb508f73c9d50bee752c9c710f79",
 "services/platform/migrations/tools/ordered-current-capture-closure.test.mjs": "46d2774a448b718e9cee09fe5d0e67551e98b399d1272286b4ae985a08df04a0",
 "services/platform/migrations/tools/ordered-current-capture-intake-v1.mjs": "239e1e45c80a008eb15713a7683a64450ac6d60472e8005e91483c7a3298a1af",
 "services/platform/migrations/tools/ordered-current-capture-intake-v1.test.mjs": "eae5764f6a7b98570fda9322bcbce5df62941756ba21d4e4c77193f6e3737cab",
 "services/platform/migrations/tools/ordered-current-capture-materialized-inputs.mjs": "84fd6de4fda53030b1dd2dfa38acac15c549f01eb521765123b6fe8527a8e848",
 "services/platform/migrations/tools/ordered-current-capture-materialized-inputs.test.mjs": "86e5860a6815837f17f096c48172fe407d3dfe0eae39438415e45732d46c157d",
 "services/platform/migrations/tools/ordered-current-capture-prior-inputs.mjs": "3a457695c67e65d0d4c3af3e390e32c78d1e3b7929546b469535ca310ca402ae",
 "services/platform/migrations/tools/ordered-current-capture-prior-inputs.test.mjs": "806b6da8fee1d03b43000cfd3766ced3665ccae76884d399abb94bc314998ae2",
 "services/platform/migrations/tools/ordered-current-capture-reconciliation-v1.mjs": "9a76e12e728da93fc6ae53dfaf16483099c27853137b215acfcb09f9f0d6538d",
 "services/platform/migrations/tools/ordered-current-capture-recursive-inputs.mjs": "37abb26c462945b96fdedb77a1c652fa202dc2f7cccfeb6816cf9f89a8bd306e",
 "services/platform/migrations/tools/ordered-current-capture-recursive-inputs.test.mjs": "2492d15b81810536d900c4120beb1ecddc6f09124b3f61d1ddbb37470da848c8",
 "services/platform/migrations/tools/ordered-current-capture-special-catalogs.mjs": "0e33e8614eef2e3d950ae8e63b963c591542e2809155c53edf1d6c0d907f91ad",
 "services/platform/migrations/tools/ordered-current-capture-special-catalogs.test.mjs": "106e15ef9dbf2cbdc7dd20480bbb54b108f252a999d9f09e0960ae7273dcb06b",
 "services/platform/migrations/tools/ordered-current-capture-sql.mjs": "30909caf252a6dfad8a48b0673f782a1a6f07253613f0b847c142ef1aefce3d2",
 "services/platform/migrations/tools/ordered-current-capture-sql.test.mjs": "c5a2a11f923d68a173f6bb8d5ff9395143eec642f7890788cf420d824bab333e",
 "services/platform/migrations/tools/ordered-current-capture-wrapper-inputs.mjs": "65ea4c7ef680410ed2c7ca7d40e46d2736e6b7591914b95d404704d59585e8c5",
 "services/platform/migrations/tools/ordered-current-capture-wrapper-inputs.test.mjs": "049f573874f892531ab694b748f855cb0b7e865c906af60ad178956806eec657",
 "services/platform/migrations/tools/ordered-current-catalog.mjs": "4a05085b7bf6beb712b80007804eee01c07d018ea9d1e160357b3c0d9b05400b",
 "services/platform/migrations/tools/ordered-current-consolidated-reference-v2-ab.mjs": "c0369d8c4355a9c64028e2148ada9a66e32d5d9f514ea4587bdb95c34f7ff378",
 "services/platform/migrations/tools/ordered-current-consolidated-reference-v2-ab.test.mjs": "fe16b7254bb0f33691cfd83604bcdd78288856d2be2b278ec4533dc29b58f41d",
 "services/platform/migrations/tools/ordered-current-consolidated-reference-v2.mjs": "d59c0884b55dc1c9fb233885c34dbac5d7d7a3d43b5a2f91d30788813fe07ef0",
 "services/platform/migrations/tools/ordered-current-consolidated-reference-v2.test.mjs": "d43813a9126d0d51457129f515b84cec8c0080e8f9f83e6456f7a473180bed66",
 "services/platform/migrations/tools/ordered-current-consolidated-reference.mjs": "78f28838f980092902a62fe9b06bff9c41a4058ce55bf16f62dcbd4a8e6a4851",
 "services/platform/migrations/tools/ordered-current-consolidated-reference.test.mjs": "edd7ed0b711a1610432e41246c6f34f430799750b16e8161bce242dec274e4e2",
 "services/platform/migrations/tools/ordered-current-consolidation-needs.mjs": "b21aa5ad26d0920010e5083b09810ae392fcec742084a73a00fbf28a2617cc1f",
 "services/platform/migrations/tools/ordered-current-deparse-frame.mjs": "1d84ec51e1f700ff96e84306fe606cb31279bf74bc709b3ff78f80644b8f007a",
 "services/platform/migrations/tools/ordered-current-development-remaining.test.mjs": "c32001e9ffff091fd38038b7525303443859193dcb10cc9d6129d58d4dcb1520",
 "services/platform/migrations/tools/ordered-current-direct-frame-v1.mjs": "4c15aee77f9a6d00d8c63a969487dbe9f2d024db0b0f3814aab76424fc9a533b",
 "services/platform/migrations/tools/ordered-current-direct-frame-v1.test.mjs": "b94f845efc83d77ab1fbd28e52aec514fd53d602f4890214ec271969feea8dc0",
 "services/platform/migrations/tools/ordered-current-direct-reference-v2.mjs": "e8cd72634e84d97cdf44557053f8e968be10f9a11409ae6cc42d07ff99d91b52",
 "services/platform/migrations/tools/ordered-current-direct-reference-v2.test.mjs": "698c834e88820f3ec908475aaa02afea188f4cb2c4acff6d6c71fc9a943ecd5e",
 "services/platform/migrations/tools/ordered-current-missing-reference-contract-v1.mjs": "bcadfaca3a334bbc389f4db4d5f1549c6f8368b714e862970f79ca43ef7ece79",
 "services/platform/migrations/tools/ordered-current-missing-reference-contract-v1.test.mjs": "57cf2adcc9d98ad28fefb8a49e258258371de954a0df5b1e3eef7b32160bb60a",
 "services/platform/migrations/tools/ordered-current-missing-reference-native-packet.mjs": "11c9ada1178aac657f398f03cb6c25477f53c721a1ad36705154639eadcb04a6",
 "services/platform/migrations/tools/ordered-current-missing-reference-native-packet.test.mjs": "0a2fc52d711e440c6a2a2d0becb476d646a47a3deaf457e92f19bc75183e2239",
 "services/platform/migrations/tools/ordered-current-mixed-transforms.mjs": "32dea433679f7ae8756da359250ef96b63f4403ea5614cc9459462e38db699f6",
 "services/platform/migrations/tools/ordered-current-mixed-transforms.test.mjs": "f20a21a94ab74e9dad62034c45ef5efd51be3ece1c03f516387cc7c1a8d98a2b",
 "services/platform/migrations/tools/ordered-current-precision-conflict-settlement-v1.mjs": "28534a474a48a225287f273a69a0e6c12369cf85f42c5e2c5374b6c9f207c8b9",
 "services/platform/migrations/tools/ordered-current-precision-conflict-settlement-v1.test.mjs": "87fb3455e611900af09d49d266a566545a348e71a55e2efc690a302c2e0fa482",
 "services/platform/migrations/tools/ordered-current-precision-resolver-frame-v1.mjs": "8582b04be434d19f979f0626ae2cbb295fcf6e49c4cbf18eff9bb74021ab353d",
 "services/platform/migrations/tools/ordered-current-precision-resolver-frame-v1.test.mjs": "7e9010550eb463f4023ff368ccf57de3e01ccf9e1d262091b637df26cc80e670",
 "services/platform/migrations/tools/ordered-current-private-historical-v1.mjs": "7876610586141346ae8281e877d8cf4e67e0f2567e7baa61fdccbe02555e4317",
 "services/platform/migrations/tools/ordered-current-private-historical-v1.test.mjs": "83c89915be313c051869cd35869da6da35bfe1bb6726488bc77132053dec86dc",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/manifest.json": "8d4fee2253344603a4878751f70f96bcf7d4b4884a5cab2b6ee1016db9d40732",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/sql/0080_authorization_worker_ordered_current_integrity.sql": "d42d975c4b9cbadf7c5b368d4f14b361cd917c65a114d9629307e73af3021e5f",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/build-ordered-current-integrity.mjs": "0df6c0cb40df6bdf18dcc51ee660efedc1fcdccb34e6ba8dd0d406e7acb53c8b",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-capture-intake-v1.mjs": "239e1e45c80a008eb15713a7683a64450ac6d60472e8005e91483c7a3298a1af",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-catalog.mjs": "0901442f9885352359aae1065f12c5457a16176b2e13b487efea39719ccab840",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-consolidated-reference-v2-ab.mjs": "c0369d8c4355a9c64028e2148ada9a66e32d5d9f514ea4587bdb95c34f7ff378",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-consolidated-reference-v2.mjs": "d59c0884b55dc1c9fb233885c34dbac5d7d7a3d43b5a2f91d30788813fe07ef0",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-consolidation-needs.mjs": "b21aa5ad26d0920010e5083b09810ae392fcec742084a73a00fbf28a2617cc1f",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-deparse-frame.mjs": "1d84ec51e1f700ff96e84306fe606cb31279bf74bc709b3ff78f80644b8f007a",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-direct-frame-v1.mjs": "4c15aee77f9a6d00d8c63a969487dbe9f2d024db0b0f3814aab76424fc9a533b",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-direct-reference-v2.mjs": "dfe218686ec7151ae35e91d3d944176e666bdbb9e04d0ada99af0b850303658d",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-missing-reference-contract-v1.mjs": "bcadfaca3a334bbc389f4db4d5f1549c6f8368b714e862970f79ca43ef7ece79",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-missing-reference-native-packet.mjs": "11c9ada1178aac657f398f03cb6c25477f53c721a1ad36705154639eadcb04a6",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-precision-conflict-settlement-v1.mjs": "28534a474a48a225287f273a69a0e6c12369cf85f42c5e2c5374b6c9f207c8b9",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-private-successor-reference.mjs": "454f8e426f10462d414501fb2ff9204122d744e501261f4ac59039b2f8d99306",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-private.mjs": "bf436fea1d3d01364bebb80881b5872321ddfe79663c614066344eeb8a059c70",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-public-function-transforms.mjs": "804cff76c0e5a0e5e060913ccb517c16fc1fd7ea58d9f373c9822d1432c3f136",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-public-selectors.mjs": "56faf97567dea71645706da7d16252d70d97f1c850c3117851bf990b29a05377",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-reference-intake-v2.mjs": "d62d67bf6a6902199946fe1a2c1b262ded0d3ad4db0b92f97b509150a8ee6770",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-reference-needs.mjs": "c2d7863dd400f1be54e2352018260efc522ec2062583bef943bbb030576873b3",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-static-catalog.mjs": "1512b45520124977b8b3ef09b57acf19e31a9c5db31ca54d139c218ec56aa3f6",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-temporal-selectors.mjs": "5fd96eaac6a7c490082a37c07e40f6e62c8f9e0a82f440b951afbfc94cb20221",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-temporal-transforms.mjs": "67a512873f4c1fd9b1b58fcc14b9649e65313a3c5415cb2765c46317f0e0f6ec",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-temporal72.mjs": "cd7013c07ef2cdbd1403534299b0396cf0e656120d32ba4e488469318d7da2ec",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-transform-compiler.mjs": "63e64805a02b1f3fa46cde06395c8f16a29174bd0302e98b148d73cc701edc1b",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-worker-edge-projections.mjs": "84def24449db6f49514c2d60de101eed2bdb5a2c80a5467a5c9e6bc03e602220",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-worker-projections.mjs": "0bcd29c17c316416b38f978b22b4cb2ce561e0655d85b0cdd2f87439e85f65a8",
 "services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-worker-source-closure-v1.mjs": "e13772208ae84576b6f536759f8007c3fe7704998a28eac38dce1c0a27c323ad",
 "services/platform/migrations/tools/ordered-current-private-reference.mjs": "5c0b39f1aaf802ed82671181f2b14d513ad18aa2bb4dd345eff4b613f6d3627a",
 "services/platform/migrations/tools/ordered-current-private-reference.test.mjs": "d969eb9d0702a527ca88604e7d2bd4a538b4d3e1bd6611f4ae557f821fcd0c2c",
 "services/platform/migrations/tools/ordered-current-private-successor-reference.mjs": "6f81cabbd3672c70190f43f9b70918ade8ef97a392e3a491922bdd874e066450",
 "services/platform/migrations/tools/ordered-current-private-successor-reference.test.mjs": "3f4a04fabbffdb14359f002b87bd8addd55e22d2f2ba12a2f7ba07e8272936c7",
 "services/platform/migrations/tools/ordered-current-private.mjs": "f461fed0f80b46c788f5a5ae42f29284bcface0e70ec3048d7d8d11bbe51d3b9",
 "services/platform/migrations/tools/ordered-current-private.test.mjs": "11ebae0ebaf67704a03091d44c73f17e6d9215ca432c3ec8a9045653bb603b3a",
 "services/platform/migrations/tools/ordered-current-product-selectors.mjs": "8de51495fd8943f38d7a9a9a6b8300fbebc1878224be09820246741ea01f5892",
 "services/platform/migrations/tools/ordered-current-product-selectors.test.mjs": "d06084e555b4383996195c26e407dbbd615722c5c9d754a3dbcbe970de9edefb",
 "services/platform/migrations/tools/ordered-current-public-function-transforms.mjs": "804cff76c0e5a0e5e060913ccb517c16fc1fd7ea58d9f373c9822d1432c3f136",
 "services/platform/migrations/tools/ordered-current-public-function-transforms.test.mjs": "66871f7b620ef6b770fccfa7858880bba921e07adba02459b8700a37db02a5a1",
 "services/platform/migrations/tools/ordered-current-public-selectors.mjs": "56faf97567dea71645706da7d16252d70d97f1c850c3117851bf990b29a05377",
 "services/platform/migrations/tools/ordered-current-public-selectors.test.mjs": "949154bb9f132701b7764df49f8191b14f73fbe7671834a581a0b9d22289e707",
 "services/platform/migrations/tools/ordered-current-reference-intake-v2.mjs": "d62d67bf6a6902199946fe1a2c1b262ded0d3ad4db0b92f97b509150a8ee6770",
 "services/platform/migrations/tools/ordered-current-reference-intake-v2.test.mjs": "4c70beaa46386dcba89424cf840e3b746f6279d6c51dac972dbffd1b7bd04fcf",
 "services/platform/migrations/tools/ordered-current-reference-needs.mjs": "c2d7863dd400f1be54e2352018260efc522ec2062583bef943bbb030576873b3",
 "services/platform/migrations/tools/ordered-current-reference-needs.test.mjs": "eff32a642d95df2c4f7f118b91315a8aae7210f29589a88553640be0e9f8bab5",
 "services/platform/migrations/tools/ordered-current-reference.mjs": "f32a0332ad15508bdb50d3173f6bdfc479fbdf97573bd4b0f612c12f597cfb9f",
 "services/platform/migrations/tools/ordered-current-reference.test.mjs": "ce2fb67108e3a4fd9a7cac06a6a4c15ad3d53748c0cc0e7ca3d8deff27a13d0c",
 "services/platform/migrations/tools/ordered-current-remaining-projection-witness-v1-artifacts/reference.json": "3711750bab518ee5fc8f02e8b08e61a3a8ed6f3497ea109e03e9a42764b57701",
 "services/platform/migrations/tools/ordered-current-remaining-projection-witness-v1.mjs": "bfe7755e97da77f5c1c4b147cbed0fa05e539be7e71a16cefcd34d6f7b3376a4",
 "services/platform/migrations/tools/ordered-current-remaining-projection-witness-v1.test.mjs": "d1f0facd864a6d923346ef7953db49acde1f1549e3614835ac24823642cb0732",
 "services/platform/migrations/tools/ordered-current-remaining-reference.mjs": "bad6fe674b18b7fb89b40039f3147363cffb83946ddc687496f22e0ca94b07f3",
 "services/platform/migrations/tools/ordered-current-remaining-reference.test.mjs": "12630fedf573d70a687f4b1b81a2594929c849f9fd6488ed201e27d562f5bd3b",
 "services/platform/migrations/tools/ordered-current-runtime-selectors.mjs": "48d5cf2a4db28ceec6137e25393b5ca9d6cd9c10a42855d7461785f992e1bd2b",
 "services/platform/migrations/tools/ordered-current-runtime-selectors.test.mjs": "76b632da93fc7d423f254eafd48780db1cb3d2d150c463fabb010eb28dc18266",
 "services/platform/migrations/tools/ordered-current-source-closure-v1.mjs": "e58149265c6f8348ef545d385fc5f0ae423d1295ffb331fa77ef1e6b59fa44d2",
 "services/platform/migrations/tools/ordered-current-source-closure-v1.test.mjs": "c8de09304565a265589e82b94ee243bd4fdcc8a5aa356ae6d826ab290c5cbd1d",
 "services/platform/migrations/tools/ordered-current-static-catalog.mjs": "1512b45520124977b8b3ef09b57acf19e31a9c5db31ca54d139c218ec56aa3f6",
 "services/platform/migrations/tools/ordered-current-static-catalog.test.mjs": "3bad0c0cc4f5b6e2c3341d32cf0c26ec6e3ba2246429b010e4831b7a6eeeb601",
 "services/platform/migrations/tools/ordered-current-temporal-selectors.mjs": "5fd96eaac6a7c490082a37c07e40f6e62c8f9e0a82f440b951afbfc94cb20221",
 "services/platform/migrations/tools/ordered-current-temporal-selectors.test.mjs": "34d678c91bad16cd79fe14fcfe3f90e6718141afb2a094183d75a0128f272540",
 "services/platform/migrations/tools/ordered-current-temporal-transforms.mjs": "67a512873f4c1fd9b1b58fcc14b9649e65313a3c5415cb2765c46317f0e0f6ec",
 "services/platform/migrations/tools/ordered-current-temporal-transforms.test.mjs": "1cc7ea44f70c06830c1aa2587b84bdb6cce3331f7c2f855ad4dd321166b69ede",
 "services/platform/migrations/tools/ordered-current-temporal72.mjs": "cd7013c07ef2cdbd1403534299b0396cf0e656120d32ba4e488469318d7da2ec",
 "services/platform/migrations/tools/ordered-current-temporal72.test.mjs": "01276ead30fe335bf21eac778ff184597415cad351fe5e46f7364a45c5359307",
 "services/platform/migrations/tools/ordered-current-temporal77-candidate.mjs": "e45bd60fe353a8e39b7e3c935f0cc07b5c36af966317e4ac9bd3692ec6d55312",
 "services/platform/migrations/tools/ordered-current-temporal77-candidate.test.mjs": "718414e4036b79305fcc1254fae303c0d1d4e56b06a8d087ccdecd14574578b0",
 "services/platform/migrations/tools/ordered-current-temporal77-transforms.mjs": "8c52ad74e0053a64e2958519f3da5cfbad1d517954275644fb38b7d21b41fcff",
 "services/platform/migrations/tools/ordered-current-temporal77-transforms.test.mjs": "1b719b7ff5f9c6c2e94b44241a285534f75a32bdbc4898ecc4094572f1b85379",
 "services/platform/migrations/tools/ordered-current-transform-compiler.mjs": "a4be3198e8277c338636c8ec1f206908def94996114cba46d35d82c5670ab2a3",
 "services/platform/migrations/tools/ordered-current-transform-compiler.test.mjs": "8936188ec04d346a672dc75bbf7a4e09440c7be3f8a5b8b9b2d75ad83f1361e6",
 "services/platform/migrations/tools/ordered-current-worker-edge-projections.mjs": "b66ca401a660094dafe30adf48b762224c9ae7f71fa33bb95bd614dffce41fab",
 "services/platform/migrations/tools/ordered-current-worker-edge-projections.test.mjs": "c488d27dd8aa8eebe710491e16e9bcf24b4302f99a09e875f0a5db3f9dfe385d",
 "services/platform/migrations/tools/ordered-current-worker-higher-integration-v1.mjs": "dcce9de5596315ed425db6bcf4aa24c38b63a66ba61c1914056b2640a1528a18",
 "services/platform/migrations/tools/ordered-current-worker-higher-source-replay-v1.mjs": "0a59ac714b861758fc2579de81cda60415b3d2f6b1f1db8a4aa2a73c55739de3",
 "services/platform/migrations/tools/ordered-current-worker-higher-source-replay-v1.test.mjs": "010a2c0537ffa97afdceeb9fa78b890be4307cd35546e96d9ced9a2a101f6e16",
 "services/platform/migrations/tools/ordered-current-worker-projections.mjs": "0bcd29c17c316416b38f978b22b4cb2ce561e0655d85b0cdd2f87439e85f65a8",
 "services/platform/migrations/tools/ordered-current-worker-projections.test.mjs": "94ca37dd390852cb035d02d04b226f631542923238ee5076e66777264eb64856",
 "services/platform/migrations/tools/ordered-current-worker-selectors.mjs": "03342d1fb5e455a1ae449b45230d4dc6694bd53a8116ea0cfe0af518bdd0f848",
 "services/platform/migrations/tools/ordered-current-worker-selectors.test.mjs": "c9565285cc9567e8891ccb521859ced13c39e628f7bf8c9fdc10f136c155d801",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/complete-capture-wire-contract.md": "563fe703c7dbd43edc4b87595d168e4aaaf1a13cf096779c448e0795c38509d0",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/complete-capture-wire-vectors.json": "438c2f9e563ce01d0052c4e8556d1dea93185d9494d2c46f4d25b1616f059a96",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json": "b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json": "be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/inventory-compiled.json": "4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json": "4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/private-reference-alias1.json": "15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/remaining-reference1.json": "cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/supplementary-reference1.json": "484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1.mjs": "e13772208ae84576b6f536759f8007c3fe7704998a28eac38dce1c0a27c323ad",
 "services/platform/migrations/tools/ordered-current-worker-source-closure-v1.test.mjs": "aee123ad159ce608128be6e7814c0cef1b9fe8e9611e5d2231b209b1a632351d",
 "services/platform/migrations/tools/ordered-current-worker-source-descriptor-v1.mjs": "c06df5cdc10ac82f10ee8586718f39f775b8604953dd9fb3f57e2a56f1649356",
 "services/platform/migrations/tools/ordered-current-worker-source-replay-v1.mjs": "9c5c77f49628a65c44553ddbcce3d0397b65ff1755d2adbb36aa5bccf6b689d4",
 "services/platform/migrations/tools/ordered-current-worker-source-replay-v1.test.mjs": "ceb8aeeb3bde40aa05d12133ab1735d0e7e98435949160d40087d68212a2e9c6",
 "services/platform/migrations/tools/worker-readiness-regions.mjs": "d72a3e431dd7fd2abfd15612a03a7d0d8c2b6dca1b064f37536d4151d4f83309"
});
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const json=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const utf8=(a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b));
const ordered=object=>Object.fromEntries(Object.entries(object).sort(([a],[b])=>utf8(a,b)));
const fail=message=>{throw Error('cloud-v1 reference refused: '+message);};

function noOverrides(){
 if(Object.keys(process.env).some(name=>/^ZASP_ORDERED_(?:CONSOLIDATED|CLOUD)_REFERENCE(?:_|$)/.test(name))||process.env.NODE_OPTIONS)fail('ambient authority');
}
function relativePath(relative){
 if(typeof relative!=='string'||relative===''||path.posix.normalize(relative)!==relative||relative.includes('\\')||path.isAbsolute(relative)||relative.split('/').some(part=>part===''||part==='.'||part==='..'))fail('path');
 return relative;
}
function state(filename){
 try{return fs.lstatSync(filename);}catch(error){if(error.code==='ENOENT')return null;throw error;}
}
function checkedPath(relative,required){
 relativePath(relative);
 if(fs.realpathSync(root)!==path.resolve(root)||!fs.lstatSync(root).isDirectory())fail('root topology');
 let filename=path.resolve(root);
 const parts=relative.split('/');
 for(const [index,part]of parts.entries()){
  filename=path.join(filename,part);
  const item=state(filename);
  if(!item){if(required)fail('absent '+relative);return null;}
  if(item.isSymbolicLink()||(index===parts.length-1?!item.isFile():!item.isDirectory()))fail('nonregular/symlink '+relative);
 }
 return filename;
}
const read=relative=>fs.readFileSync(checkedPath(relative,true));
function closedInventory(directory,expected,prefix=''){
 for(const item of fs.readdirSync(directory,{withFileTypes:true})){
  const relative=prefix+item.name,filename=path.join(directory,item.name),stat=fs.lstatSync(filename);
  if(stat.isSymbolicLink())fail('inventory symlink '+relative);
  if(stat.isDirectory()){
   if(![...expected].some(name=>name.startsWith(relative+'/')))fail('unlisted directory '+relative);
   closedInventory(filename,expected,relative+'/');
  }else if(!stat.isFile()||!expected.has(relative))fail('unlisted member '+relative);
 }
}
function verifiedSources(){
 const sources={};
 for(const [relative,digest]of Object.entries(baselineSourcePins)){
  const raw=read(relative);if(sha(raw)!==digest)fail('baseline source authority '+relative);
  sources[relative]=raw;
 }
 const historical='services/platform/migrations/tools/ordered-current-private-historical-v1/';
 const expected=new Set(Object.keys(baselineSourcePins).filter(name=>name.startsWith(historical)).map(name=>name.slice(historical.length)));
 closedInventory(path.join(root,historical),expected);
 return sources;
}
async function reviewedBaseline(){
 noOverrides();
 const before=verifiedSources();
 // This literal import occurs only after the independent full baseline check.
 const {buildOrderedConsolidatedReference}=await import('./build-ordered-current-consolidated-reference.mjs');
 const built=buildOrderedConsolidatedReference();
 if(sha(built.manifestRaw)!==baselineManifestSHA256||sha(built.files[contractName])!==baselineContractSHA256)fail('baseline derivation');
 if(Object.keys(built.contract.sourcePins).length!==157||JSON.stringify(built.contract.sourcePins)!==JSON.stringify(baselineSourcePins))fail('baseline source roster');
 const after=verifiedSources();
 for(const relative of Object.keys(before))if(!before[relative].equals(after[relative])||!before[relative].equals(built.snapshotFiles[relative]))fail('baseline source changed '+relative);
 return built;
}
function sourcePacket(baseline,variant,sourceFiles){
 const sourcePins=ordered(Object.fromEntries(Object.entries(sourceFiles).map(([relative,raw])=>[relative,sha(raw)])));
 const contract={...baseline.contract,variant,sessionUser:variant==='A'?'zasp_test':'zasp_e2e',sourcePins};
 if(contract.installable!==false||contract.status!=='REFERENCE-CAPTURE-ONLY')fail('source-only flags');
 const files={...baseline.files,[contractName]:json(contract)};
 const snapshotFiles=ordered({...sourceFiles,...files});
 if(Object.keys(sourcePins).length!==159||Object.keys(snapshotFiles).length!==166)fail('successor source roster');
 const manifest={format:1,source:'ordered-current-complete-capture-packet-'+variant+'-cloud-v1',files:ordered(Object.fromEntries(Object.entries(snapshotFiles).map(([relative,raw])=>[relative,sha(raw)])))};
 return {files,snapshotFiles,contract,closure:baseline.closure,manifestRaw:json(manifest)};
}
export async function buildOrderedCurrentCloudReferenceA(){
 if(arguments.length!==0)fail('caller authority');
 const baseline=await reviewedBaseline();
 const sources=Object.fromEntries(Object.keys(baselineSourcePins).map(relative=>[relative,baseline.snapshotFiles[relative]]));
 for(const relative of addedSources){if(Object.hasOwn(sources,relative))fail('source collision');sources[relative]=read(relative);}
 return sourcePacket(baseline,'A',sources);
}
function members(built){return {...built.snapshotFiles,'snapshot-manifest.json':built.manifestRaw};}
function preflight(destination,expected,required){
 const base=destination.slice(0,-1);relativePath(base);
 // checkedPath requires a file leaf; check the destination as an ancestor of
 // the manifest so an existing directory root is validated as a directory.
 checkedPath(destination+'snapshot-manifest.json',false);
 const output=path.join(root,base),item=state(output);
 if(!item){if(required)fail('destination absent '+base);return;}
 if(!item.isDirectory()||item.isSymbolicLink())fail('destination root');
 closedInventory(output,new Set(Object.keys(expected)));
 for(const [relative,raw]of Object.entries(expected)){
  const filename=checkedPath(destination+relative,required);
  if(filename&&!fs.readFileSync(filename).equals(raw))fail('immutable member conflict '+relative);
 }
}
export async function buildOrderedCurrentCloudReferenceB(){
 if(arguments.length!==0)fail('caller authority');
 const a=await buildOrderedCurrentCloudReferenceA();
 // Authority is the actual fixed published A, byte-verified against an
 // independent current derivation. No output digest hardpins its own source.
 preflight(aDestination,members(a),true);
 const actual={};
 for(const [relative,expected]of Object.entries(a.snapshotFiles)){
  const raw=read(aDestination+relative);
  if(!raw.equals(expected))fail('seed read changed '+relative);
  actual[relative]=raw;
 }
 const original=actual[producer].toString('utf8'),oldCall='loadConsolidatedReference(directory)',newCall='loadConsolidatedReferenceVariantB(directory)';
 if(original.split(oldCall).length!==3||original.includes(newCall))fail('producer substitution source');
 const changed=original.replaceAll(oldCall,newCall);
 if(changed.includes(oldCall)||changed.split(newCall).length!==3)fail('producer substitution count');
 const sourceFiles=Object.fromEntries(Object.keys(a.contract.sourcePins).map(relative=>[relative,actual[relative]]));
 sourceFiles[producer]=Buffer.from(changed);
 const actualA={...a,files:Object.fromEntries(Object.keys(a.files).map(relative=>[relative,actual[relative]])),contract:JSON.parse(actual[contractName])};
 const built=sourcePacket(actualA,'B',sourceFiles);
 preflight(aDestination,members(a),true);
 return built;
}
async function run(mode){
 noOverrides();
 const variant=mode.endsWith('-a')?'A':'B',destination=variant==='A'?aDestination:bDestination;
 const built=variant==='A'?await buildOrderedCurrentCloudReferenceA():await buildOrderedCurrentCloudReferenceB(),expected=members(built);
 // Validate the complete destination and every ancestor before creating any
 // directory or member. Identical partial members may be completed; conflicts,
 // unknown members and symlinks are never repaired or overwritten.
 preflight(destination,expected,mode.startsWith('--check-'));
 if(mode.startsWith('--write-'))for(const [relative,raw]of Object.entries(expected)){
  const filename=path.join(root,destination,relative);
  if(checkedPath(destination+relative,false))continue;
  fs.mkdirSync(path.dirname(filename),{recursive:true});
  checkedPath(destination+relative,false);
  fs.writeFileSync(filename,raw,{flag:'wx'});
 }
 return {variant,files:Object.keys(built.files).length,rules:Object.keys(built.contract.rules).length,members:Object.keys(built.snapshotFiles).length,manifestSHA256:sha(built.manifestRaw),contractSHA256:sha(built.files[contractName])};
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url){
 if(process.argv.length!==3||!['--write-a','--check-a','--write-b','--check-b'].includes(process.argv[2]))fail('use only --write-a, --check-a, --write-b or --check-b');
 console.log(JSON.stringify(await run(process.argv[2])));
}
