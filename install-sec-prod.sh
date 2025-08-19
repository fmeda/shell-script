#!/usr/bin/env bash
# ========================================================================
# install-sec-prod.sh
# Programa único para bootstrap de ambiente seguro pronto para PRODUÇÃO
# ========================================================================
# Estrutura:
#  0. Helpers & pré-checks
#  1. Pré-requisitos e hardening do host
#  2. Configuração Vault + HSM/PKCS#11
#  3. Configurações Kubernetes (encryption, policies, cosign)
#  4. Supply Chain / CI-CD
#  5. Observabilidade e Auditoria
#  6. Execução principal (main)
# ========================================================================

set -Eeuo pipefail
readonly ME=$(basename "$0")

# ---- Helpers de interface ----
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info(){ echo -e "${GREEN}[+]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
fatal(){ echo -e "${RED}[x]${NC} $*"; exit 1; }

# ---- Pré-checks ----
command -v kubectl >/dev/null 2>&1 || fatal "kubectl não encontrado; configure kubeconfig"
command -v helm >/dev/null 2>&1 || { warn "helm não encontrado — instalando..."; curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash; }

# Variáveis ajustáveis
: "${VAULT_ADDR:=https://vault.example.internal:8200}"
: "${VAULT_HSM_PKCS11_MODULE:=/usr/lib/your-hsm/pkcs11.so}"
: "${VAULT_HSM_SLOT:=0}"
: "${COSIGN_PUB_SECRET:=cosign-public-key}"

# ========================================================================
# 1. Pré-requisitos e hardening do host
# ========================================================================
install_packages() {
  info "Instalando pacotes base..."
  if [ -f /etc/debian_version ]; then
    sudo apt-get update -y
    sudo apt-get install -y nftables wireguard-tools curl jq git openssl \
      apparmor apparmor-utils auditd tpm2-tools tpm2-abrmd policycoreutils \
      ca-certificates gnupg lsb-release
  else
    sudo dnf install -y nftables wireguard-tools curl jq git openssl \
      apparmor audit tpm2-tools tpm2-abrmd policycoreutils \
      ca-certificates gnupg
  fi
}

enable_host_hardening() {
  info "Aplicando hardening de host..."
  sudo swapoff -a || true
  sudo sed -i 's/^\(.*swap.*\)$/#\1/' /etc/fstab || true
  sudo bash -c 'echo "* hard core 0" >> /etc/security/limits.conf'
  if [ -f /etc/default/grub ]; then
    sudo sed -i '/GRUB_CMDLINE_LINUX/s/"$/ lockdown=confidentiality lsm=landlock,apparmor,yama,bpf"/' /etc/default/grub || true
    info "Kernel lockdown preparado — reboot necessário."
  fi
}

deploy_nft_defaultdeny() {
  info "Aplicando firewall nftables (default-deny)..."
  sudo tee /etc/nftables.conf >/dev/null <<'EOF'
flush ruleset
table inet filter {
  chains {
    input { type filter hook input priority 0; policy drop;
      ct state established,related accept
      iif "lo" accept
      udp dport 51820 accept
      tcp dport 10250 accept
      counter
    }
    forward { type filter hook forward priority 0; policy drop;
      ct state established,related accept
    }
    output { type filter hook output priority 0; policy accept; }
  }
}
EOF
  sudo systemctl enable --now nftables || true
}

# ========================================================================
# 2. Vault + HSM
# ========================================================================
vault_setup_pkcs11_template() {
  cat > /tmp/vault-pkcs11.hcl <<HCL
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault/tls/vault.crt"
  tls_key_file  = "/etc/vault/tls/vault.key"
}
storage "file" { path = "/opt/vault/data" }
seal "pkcs11" {
  lib = "${VAULT_HSM_PKCS11_MODULE}"
  slot = ${VAULT_HSM_SLOT}
  key_label = "vault-hsm-unseal-key"
  pin = "REPLACE_WITH_SECURE_PIN" # injete via Secret Manager
  hmac = true
}
ui = true
HCL
  info "Template Vault PKCS#11 gerado: /tmp/vault-pkcs11.hcl"
}

vault_pki_transit_docs() {
  cat > /tmp/vault-bootstrap.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
# Comandos para habilitar PKI + Transit
vault secrets enable -path=pki pki
vault secrets tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal common_name="velar.internal" ttl=87600h
vault secrets enable -path=transit transit
vault write -f transit/keys/velar-transit
# Política de exemplo
cat <<'POL' | vault policy write secure-ns -
path "pki/issue/secure-ns" { capabilities = ["update"] }
path "transit/encrypt/velar-transit" { capabilities = ["update"] }
path "transit/decrypt/velar-transit" { capabilities = ["update"] }
POL
BASH
  chmod +x /tmp/vault-bootstrap.sh
  info "Script bootstrap Vault gerado: /tmp/vault-bootstrap.sh"
}

# ========================================================================
# 3. Kubernetes configs
# ========================================================================
k8s_encryption_config() {
  cat > /tmp/encryption-config.yaml <<'YAML'
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: vault-transit
      endpoint: unix:///var/run/kms-vault.sock
      cachesize: 100
  - aescbc:
      keys:
      - name: key1
        secret: REPLACE_WITH_BASE64_32_BYTES
  - identity: {}
YAML
  info "Configuração de encriptação K8s: /tmp/encryption-config.yaml"
}

gatekeeper_cosign_manifest() {
  cat > /tmp/gatekeeper-cosign.yaml <<'YAML'
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sallowedcosign
spec:
  crd:
    spec:
      names: { kind: K8sAllowedCosign }
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sallowedcosign
      deny[reason] {
        input.review.object.kind == "Pod"
        not input.review.object.metadata.annotations["cosign.sigstore.dev/signed"] == "true"
        reason := "imagem não assinada pelo cosign"
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedCosign
metadata: { name: require-cosign }
spec:
  match:
    kinds: [{ apiGroups: [""], kinds: ["Pod"] }]
YAML
  info "Constraint Cosign gerada: /tmp/gatekeeper-cosign.yaml"
}

opa_rego_sample() {
  cat > /tmp/policy.rego <<'REGO'
package k8s.admission
deny[msg] {
  input.request.kind.kind == "Pod"
  not input.request.object.metadata.annotations["container.apparmor.security.beta.kubernetes.io/app"] == "localhost/velar-app"
  msg = "Pod deve ter perfil AppArmor Velar"
}
REGO
  info "Policy OPA gerada: /tmp/policy.rego"
}

# ========================================================================
# 4. Supply Chain / CI
# ========================================================================
ci_github_actions_sample() {
  cat > /tmp/.github-ci-sample.yaml <<'YAML'
name: CI-Security
on: [push, pull_request]
jobs:
  sbom-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t ghcr.io/org/app:${{ github.sha }} .
      - name: Generate SBOM
        run: syft ghcr.io/org/app:${{ github.sha }} -o json > sbom.json
      - name: Sign image
        run: cosign sign --key env://COSIGN_KEY ghcr.io/org/app:${{ github.sha }}
      - name: Conftest policy
        run: conftest test k8s/**/*.yaml -p policy/
YAML
  info "Pipeline CI exemplo: /tmp/.github-ci-sample.yaml"
}

# ========================================================================
# 5. Observabilidade / Auditoria
# ========================================================================
generate_prometheus_rules() {
  cat > /tmp/security-prometheus-rules.yaml <<'YAML'
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata: { name: security-slos, namespace: secure }
spec:
  groups:
  - name: security
    rules:
    - alert: VaultDown
      expr: up{job="vault"} == 0
      for: 2m
      labels: { severity: critical }
      annotations: { summary: "Vault is down" }
    - alert: CertificateExpiring
      expr: time() > (vault_cert_not_after_seconds - 7200)
      for: 10m
      labels: { severity: warning }
YAML
  info "Regras Prometheus geradas: /tmp/security-prometheus-rules.yaml"
}

# ========================================================================
# 6. Execução principal
# ========================================================================
main() {
  install_packages
  enable_host_hardening
  deploy_nft_defaultdeny
  vault_setup_pkcs11_template
  vault_pki_transit_docs
  k8s_encryption_config
  gatekeeper_cosign_manifest
  opa_rego_sample
  ci_github_actions_sample
  generate_prometheus_rules
  info "Templates gerados em /tmp (revise e aplique)."
  info "PASSOS SEGUINTES:"
  cat <<'STEPS'
1) Configurar HSM/TPM real e revisar /tmp/vault-pkcs11.hcl
2) Deploy Vault com PKCS#11; unseal via HSM
3) Rodar /tmp/vault-bootstrap.sh para habilitar PKI+Transit
4) Configurar kube-apiserver com /tmp/encryption-config.yaml
5) Deploy Gatekeeper + aplicar /tmp/gatekeeper-cosign.yaml
6) Configurar CI/CD com cosign + SBOM (/tmp/.github-ci-sample.yaml)
7) Deploy Prometheus rules (/tmp/security-prometheus-rules.yaml)
8) Testar: pods não assinados → bloqueados; secrets cifrados em etcd; alertas funcionando
STEPS
}
main
