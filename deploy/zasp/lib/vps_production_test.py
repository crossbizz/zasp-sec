import json
import unittest
from unittest.mock import Mock
from vps_dependencies import LABEL, Rejected
from vps_production import NAMESPACES, prepare_namespaces


class ProductionNamespaces(unittest.TestCase):
    def target(self, namespaces, actual_uid="verified"):
        target = Mock(uid="verified", owner="example-production")
        target.get.side_effect = lambda _, kind, name, **kwargs: (
            {"metadata": {"uid": actual_uid}} if name == "kube-system" else namespaces.get(name, {}))
        return target

    def test_creates_only_absent_peer_namespaces_and_sets_owner_at_creation(self):
        owned = {"metadata": {"labels": {LABEL: "example-production"}}}
        target = self.target({"agentsec": owned, "connectors": owned})
        prepare_namespaces(target)
        created = [json.loads(call.kwargs["data"]) for call in target.kubectl.call_args_list]
        self.assertEqual([o["metadata"]["name"] for o in created], ["staging", "opensearch"])
        self.assertTrue(all(o["metadata"]["labels"] == {LABEL: target.owner} for o in created))
        target = self.target(dict.fromkeys(NAMESPACES, owned))
        prepare_namespaces(target)
        target.kubectl.assert_not_called()

    def test_foreign_namespace_or_cluster_prevents_every_write(self):
        for target in (self.target({"connectors": {"metadata": {}}}), self.target({}, actual_uid="foreign")):
            with self.assertRaises(Rejected):
                prepare_namespaces(target)
            target.kubectl.assert_not_called()
