"""Check registry — auto-discovers and instantiates all check modules."""

from __future__ import annotations

from my_check.types import Check


def get_web_checks() -> list[Check]:
    """Return all web check instances."""
    from my_check.checks.web.cookies import CookieSecurityCheck
    from my_check.checks.web.cors import CorsCheck
    from my_check.checks.web.csp import CspCheck
    from my_check.checks.web.dns import DnsCheck
    from my_check.checks.web.headers import HeadersCheck
    from my_check.checks.web.ports import PortsCheck
    from my_check.checks.web.redirects import RedirectsCheck
    from my_check.checks.web.subdomain_takeover import SubdomainTakeoverCheck
    from my_check.checks.web.tls import TlsCheck

    return [
        TlsCheck(),
        HeadersCheck(),
        CspCheck(),
        CorsCheck(),
        CookieSecurityCheck(),
        DnsCheck(),
        PortsCheck(),
        RedirectsCheck(),
        SubdomainTakeoverCheck(),
    ]


def get_k8s_checks() -> list[Check]:
    """Return all Kubernetes check instances."""
    from my_check.checks.k8s.etcd_encryption import EtcdEncryptionCheck
    from my_check.checks.k8s.images import ImagesCheck
    from my_check.checks.k8s.network_policies import NetworkPoliciesCheck
    from my_check.checks.k8s.pss_compliance import PssComplianceCheck
    from my_check.checks.k8s.rbac import RbacCheck
    from my_check.checks.k8s.secrets import SecretsCheck
    from my_check.checks.k8s.workloads import WorkloadsCheck
    from my_check.checks.k8s.wrappers.falco import FalcoCheck
    from my_check.checks.k8s.wrappers.kube_bench import KubeBenchCheck
    from my_check.checks.k8s.wrappers.polaris import PolarisCheck
    from my_check.checks.k8s.wrappers.trivy import TrivyCheck

    return [
        RbacCheck(),
        WorkloadsCheck(),
        NetworkPoliciesCheck(),
        SecretsCheck(),
        ImagesCheck(),
        PssComplianceCheck(),
        EtcdEncryptionCheck(),
        KubeBenchCheck(),
        TrivyCheck(),
        PolarisCheck(),
        FalcoCheck(),
    ]


def get_all_checks() -> list[Check]:
    """Return every registered check."""
    return get_web_checks() + get_k8s_checks()
