"""The wizard offers every check the registry knows."""

from my_check import wizard
from my_check.registry import get_k8s_checks, get_web_checks


def test_customize_step_lists_every_registered_check() -> None:
    web = [value for _, value in wizard.check_choices(get_web_checks())]
    k8s = [value for _, value in wizard.check_choices(get_k8s_checks())]

    assert web == [check.id for check in get_web_checks()]
    assert k8s == [check.id for check in get_k8s_checks()]
    # The ones the hand-written lists used to leave out.
    assert {"web-csp", "web-cors", "web-cookies"} <= set(web)
    assert {"k8s-pss-compliance", "k8s-etcd-encryption"} <= set(k8s)


def test_choice_labels_name_the_check() -> None:
    label, value = wizard.check_choices(get_web_checks())[0]
    assert value in label and "TLS Certificate" in label
