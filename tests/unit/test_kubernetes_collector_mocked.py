from types import SimpleNamespace

from infraguard.collectors.kubernetes_live import KubernetesLiveCollector


class FakeApi:
    def __getattr__(self, name):
        def call(**kwargs):
            if name == "list_namespace":
                items = [{"metadata": {"name": "team-a"}}]
            elif name == "list_pod_for_all_namespaces":
                items = [
                    {
                        "metadata": {
                            "name": "standalone",
                            "namespace": "team-a",
                            "labels": {"app": "demo"},
                        },
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "env": [{"name": "API_TOKEN", "value": "secret"}],
                                }
                            ]
                        },
                    },
                    {
                        "metadata": {
                            "name": "owned",
                            "namespace": "team-a",
                            "ownerReferences": [{"kind": "ReplicaSet"}],
                        }
                    },
                    {"metadata": {"name": "system", "namespace": "kube-system"}},
                ]
            elif name == "list_service_for_all_namespaces":
                items = [{"metadata": {"name": "api", "namespace": "team-a"}}]
            else:
                items = []
            return SimpleNamespace(items=items, metadata=SimpleNamespace(_continue=None))

        return call


def test_collector_lists_redacts_and_skips_owned_pods(monkeypatch) -> None:
    monkeypatch.setattr(
        "infraguard.collectors.kubernetes_live.config.load_kube_config",
        lambda context=None: None,
    )
    monkeypatch.setattr("infraguard.collectors.kubernetes_live.client.CoreV1Api", FakeApi)
    monkeypatch.setattr("infraguard.collectors.kubernetes_live.client.AppsV1Api", FakeApi)
    monkeypatch.setattr("infraguard.collectors.kubernetes_live.client.BatchV1Api", FakeApi)
    monkeypatch.setattr("infraguard.collectors.kubernetes_live.client.NetworkingV1Api", FakeApi)
    monkeypatch.setattr(
        "infraguard.collectors.kubernetes_live.client.ApiClient",
        lambda: SimpleNamespace(sanitize_for_serialization=lambda item: item),
    )
    collector = KubernetesLiveCollector(context="demo", namespaces=["team-a"])
    resources = list(collector.collect())
    assert collector.describe_target() == "cluster:demo"
    assert [item.ref.key() for item in resources] == [
        "_cluster/Namespace/team-a",
        "team-a/Pod/standalone",
        "team-a/Service/api",
    ]
    assert resources[1].raw["spec"]["containers"][0]["env"][0]["value"] == "***REDACTED***"
