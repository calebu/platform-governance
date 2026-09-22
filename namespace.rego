package platform.governance

import future.keywords.if

namespace_denied(obj) if {
    namespace := namespace_for_object(obj)
    team := team_for_object(obj)
    app := object.get(metadata_labels(obj), "application", obj.metadata.name)
    not is_allowed_namespace(team, namespace, app)
}

deny contains {"msg": msg} if {
    obj := resource_object
    namespace_denied(obj)
    team := team_for_object(obj)
    namespace := namespace_for_object(obj)
    app := object.get(metadata_labels(obj), "application", obj.metadata.name)
    msg := sprintf("team %q is not allowed to deploy application %q in namespace %q", [team, app, namespace])
}
