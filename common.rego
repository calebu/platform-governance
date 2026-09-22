package platform.governance

import future.keywords.if
import future.keywords.in

required_metadata_labels := ["team", "environment", "application", "cost-center"]

approved_registries := [
    "registry.company.com",
    "registry.platform.example.com",
    "ghcr.io/acme",
]

approved_ingress_classes := [
    "nginx-internal",
    "traefik-private",
]

approved_ingress_domains := [
    "example.com",
    "internal.example.com",
    "api.example.com",
]

namespace_policy := {
    "platform": {
        "platform": ["gateway", "observability", "security"],
        "prod": ["gateway", "observability"],
    },
    "payments": {
        "prod": ["payments", "payments-worker"],
        "dev": ["payments", "payments-worker"],
    },
    "analytics": {
        "prod": ["analytics", "analytics-ingest"],
        "dev": ["analytics", "analytics-ingest"],
    },
}

resource_object := obj if {
    request := object.get(input, "request", {})
    request != {}
    obj := request.object
}

resource_object := obj if {
    request := object.get(input, "request", {})
    request == {}
    obj := input
}

pod_spec(obj) := spec if {
    obj.kind == "Pod"
    spec := obj.spec
}

pod_spec(obj) := spec if {
    obj.kind == "CronJob"
    spec := obj.spec.jobTemplate.spec.template.spec
}

pod_spec(obj) := spec if {
    obj.kind != "Pod"
    obj.kind != "CronJob"
    spec := object.get(obj.spec, "template", {}).spec
}

metadata_labels(obj) := object.get(obj.metadata, "labels", {})

workload_containers(obj) := containers if {
    spec := pod_spec(obj)
    containers := array.concat(
        object.get(spec, "containers", []),
        array.concat(
            object.get(spec, "initContainers", []),
            object.get(spec, "ephemeralContainers", []),
        ),
    )
}

namespace_for_object(obj) := object.get(obj.metadata, "namespace", "default")

team_for_object(obj) := object.get(metadata_labels(obj), "team", "")

application_for_object(obj) := object.get(metadata_labels(obj), "application", obj.metadata.name)

image_registry(image) = "docker.io" if {
    not contains(image, "/")
}

image_registry(image) = "docker.io" if {
    parts := split(image, "/")
    registry := parts[0]
    not contains(registry, ".")
    not contains(registry, ":")
    registry != "localhost"
}

image_registry(image) = registry if {
    parts := split(image, "/")
    registry := parts[0]
    contains(registry, ".")
}

image_registry(image) = registry if {
    parts := split(image, "/")
    registry := parts[0]
    contains(registry, ":")
}

image_registry(image) = registry if {
    parts := split(image, "/")
    registry := parts[0]
    registry == "localhost"
}

is_approved_image(image) if {
    registry := image_registry(image)
    registry in approved_registries
}

is_allowed_namespace(team, namespace, app) if {
    namespace_map := object.get(namespace_policy, team, {})
    allowed_apps := object.get(namespace_map, namespace, [])
    app in allowed_apps
}

has_required_resource(container, resource_kind, resource_name) if {
    resources := object.get(container, "resources", {})
    value := object.get(object.get(resources, resource_kind, {}), resource_name, "")
    value != ""
}
