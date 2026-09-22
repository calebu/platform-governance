package platform.governance

import future.keywords.if

deny contains {"msg": msg} if {
    obj := resource_object
    some container in workload_containers(obj)
    image := object.get(container, "image", "")
    not is_approved_image(image)
    msg := sprintf("container %q uses an unapproved image %q", [object.get(container, "name", "unnamed"), image])
}
