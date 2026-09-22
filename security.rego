package platform.governance

import future.keywords.if

is_non_root(container, pod_security) if {
    container_security := object.get(container, "securityContext", {})
    container_security.runAsNonRoot == true
}

is_non_root(container, pod_security) if {
    pod_security.runAsNonRoot == true
}

deny contains {"msg": msg} if {
    obj := resource_object
    some container in workload_containers(obj)
    pod_security := object.get(pod_spec(obj), "securityContext", {})
    not is_non_root(container, pod_security)
    msg := sprintf("container %q must run as a non-root user", [object.get(container, "name", "unnamed")])
}

deny contains {"msg": msg} if {
    obj := resource_object
    some container in workload_containers(obj)
    container_security := object.get(container, "securityContext", {})
    container_security.privileged == true
    msg := sprintf("container %q cannot run in privileged mode", [object.get(container, "name", "unnamed")])
}
