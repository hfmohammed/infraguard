from pathlib import Path

from infraguard.collectors.manifests import ManifestCollector


def test_collects_multidocument_yaml(tmp_path: Path) -> None:
    source = tmp_path / "resources.yaml"
    source.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: one}\n---\n---\napiVersion: v1\nkind: Service\nmetadata: {name: two, namespace: demo}\n")
    resources = list(ManifestCollector([source]).collect())
    assert [resource.ref.key() for resource in resources] == ["default/ConfigMap/one", "demo/Service/two"]


def test_recurses_and_ignores_kustomization(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "app.yml").write_text("apiVersion: v1\nkind: Pod\nmetadata: {name: app}\n")
    (nested / "kustomization.yaml").write_text("resources: [app.yml]\n")
    assert len(list(ManifestCollector([tmp_path]).collect())) == 1


def test_redacts_secret_documents(tmp_path: Path) -> None:
    source = tmp_path / "secret.yaml"
    source.write_text("apiVersion: v1\nkind: Secret\nmetadata: {name: credentials}\ndata: {token: dGVzdA==}\n")
    resource = next(iter(ManifestCollector([source]).collect()))
    assert "data" not in resource.raw

