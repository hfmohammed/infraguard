#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="$repo_root/bin"
source "$repo_root/tools.env"

case "$(uname -s)" in
  Darwin) os="darwin"; archive_os="Darwin" ;;
  Linux) os="linux"; archive_os="Linux" ;;
  *) echo "unsupported operating system: $(uname -s)" >&2; exit 2 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="amd64"; archive_arch="x86_64" ;;
  arm64|aarch64) arch="arm64"; archive_arch="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

mkdir -p "$bin_dir"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

download() {
  local url="$1" output="$2"
  echo "downloading $url"
  curl --fail --location --retry 3 --silent --show-error "$url" --output "$output"
}

install_binary() {
  local name="$1" version="$2" url="$3"
  if [[ -x "$bin_dir/$name" ]]; then
    echo "using $name from $bin_dir"
    return
  fi
  download "$url" "$bin_dir/$name"
  chmod +x "$bin_dir/$name"
  echo "installed $name $version"
}

install_tar_binary() {
  local name="$1" version="$2" url="$3" member="$4"
  if [[ -x "$bin_dir/$name" ]]; then
    echo "using $name from $bin_dir"
    return
  fi
  local archive="$work_dir/$name.tar.gz"
  download "$url" "$archive"
  tar -xzf "$archive" -C "$work_dir"
  mv "$work_dir/$member" "$bin_dir/$name"
  chmod +x "$bin_dir/$name"
  echo "installed $name $version"
}

conftest_number="${CONFTEST_VERSION#v}"
install_binary kind "$KIND_VERSION" \
  "https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-$os-$arch"
install_binary kubectl "$KUBECTL_VERSION" \
  "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/$os/$arch/kubectl"
install_tar_binary helm "$HELM_VERSION" \
  "https://get.helm.sh/helm-$HELM_VERSION-$os-$arch.tar.gz" "$os-$arch/helm"
install_tar_binary conftest "$CONFTEST_VERSION" \
  "https://github.com/open-policy-agent/conftest/releases/download/$CONFTEST_VERSION/conftest_${conftest_number}_${archive_os}_${archive_arch}.tar.gz" "conftest"
install_binary opa "$OPA_VERSION" \
  "https://openpolicyagent.org/downloads/$OPA_VERSION/opa_${os}_${arch}_static"
install_tar_binary kubeconform "$KUBECONFORM_VERSION" \
  "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-$os-$arch.tar.gz" "kubeconform"

if [[ ! -x "$bin_dir/terraform" ]]; then
  terraform_archive="$work_dir/terraform.zip"
  download \
    "https://releases.hashicorp.com/terraform/$TERRAFORM_VERSION/terraform_${TERRAFORM_VERSION}_${os}_${arch}.zip" \
    "$terraform_archive"
  unzip -q "$terraform_archive" -d "$work_dir/terraform"
  mv "$work_dir/terraform/terraform" "$bin_dir/terraform"
  chmod +x "$bin_dir/terraform"
  echo "installed terraform $TERRAFORM_VERSION"
fi

for tool in kind kubectl helm conftest opa kubeconform terraform; do
  test -x "$bin_dir/$tool"
done

"$bin_dir/kind" --version
"$bin_dir/kubectl" version --client
"$bin_dir/helm" version --short
"$bin_dir/conftest" --version
"$bin_dir/opa" version
"$bin_dir/kubeconform" -v
"$bin_dir/terraform" version

echo "toolchain installed in $bin_dir"

