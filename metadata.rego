package platform.governance

import future.keywords.if

missing_required_label(obj, label) if {
    labels := metadata_labels(obj)
    not labels[label]
}

deny contains {"msg": msg} if {
    obj := resource_object
    some label in required_metadata_labels
    missing_required_label(obj, label)
    msg := sprintf("workload is missing required label %q", [label])
}
