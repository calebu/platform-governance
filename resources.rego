package platform.governance

import future.keywords.if

deny contains {"msg": msg} if {
    obj := resource_object
    some container in workload_containers(obj)
    not has_required_resource(container, "requests", "cpu")
    msg := sprintf("container %q is missing a CPU request", [object.get(container, "name", "unnamed")])
}

deny contains {"msg": msg} if {
    obj := resource_object
    some container in workload_containers(obj)
    not has_required_resource(container, "requests", "memory")
    msg := sprintf("container %q is missing a memory request", [object.get(container, "name", "unnamed")])
}

deny contains {"msg": msg} if {
    obj := resource_object
    some container in workload_containers(obj)
    not has_required_resource(container, "limits", "cpu")
    msg := sprintf("container %q is missing a CPU limit", [object.get(container, "name", "unnamed")])
}

deny contains {"msg": msg} if {
    obj := resource_object
    some container in workload_containers(obj)
    not has_required_resource(container, "limits", "memory")
    msg := sprintf("container %q is missing a memory limit", [object.get(container, "name", "unnamed")])
}
