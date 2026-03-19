# API Reference: Kubernetes RBAC Configuration Audit

## Libraries Used

| Library | Purpose |
|---------|---------|
| `kubernetes` | Official Kubernetes Python client for RBAC API |
| `json` | Parse and format RBAC audit results |

## Installation

```bash
pip install kubernetes
```

## Authentication

```python
from kubernetes import client, config

config.load_kube_config()
rbac_api = client.RbacAuthorizationV1Api()
core_api = client.CoreV1Api()
```

## RBAC API Methods

| Method | Description |
|--------|-------------|
| `list_cluster_role()` | List all ClusterRoles |
| `list_cluster_role_binding()` | List all ClusterRoleBindings |
| `list_namespaced_role(namespace)` | List Roles in a namespace |
| `list_namespaced_role_binding(namespace)` | List RoleBindings in namespace |

## Core Operations

### List All ClusterRoleBindings
```python
def list_all_bindings():
    bindings = rbac_api.list_cluster_role_binding()
    for b in bindings.items:
        subjects = [
            f"{s.kind}/{s.name}" for s in (b.subjects or [])
        ]
        print(f"{b.metadata.name} -> {b.role_ref.name}: {subjects}")
```

### Audit Overprivileged Roles
```python
def audit_overprivileged():
    roles = rbac_api.list_cluster_role()
    findings = []
    for role in roles.items:
        for rule in (role.rules or []):
            if rule.verbs and "*" in rule.verbs:
                findings.append({
                    "role": role.metadata.name,
                    "issue": "Wildcard verbs (*) — overly permissive",
                    "severity": "high",
                })
            if rule.resources and "*" in rule.resources:
                findings.append({
                    "role": role.metadata.name,
                    "issue": "Wildcard resources (*)",
                    "severity": "high",
                })
    return findings
```

### Find Default Service Account Usage
```python
def find_default_sa_usage():
    findings = []
    namespaces = core_api.list_namespace()
    for ns in namespaces.items:
        pods = core_api.list_namespaced_pod(ns.metadata.name)
        for pod in pods.items:
            sa = pod.spec.service_account_name
            if sa == "default":
                findings.append({
                    "namespace": ns.metadata.name,
                    "pod": pod.metadata.name,
                    "issue": "Using default service account",
                    "severity": "medium",
                })
    return findings
```

## Output Format

```json
{
  "cluster_roles": 45,
  "cluster_role_bindings": 38,
  "findings": [
    {
      "role": "custom-admin",
      "issue": "Wildcard verbs (*) — overly permissive",
      "severity": "high"
    }
  ]
}
```
