package platform.governance

import future.keywords.if

is_ingress(obj) if {
    obj.kind == "Ingress"
}

approved_ingress_tls(obj) if {
    tls := object.get(obj.spec, "tls", [])
    count(tls) > 0
    some entry in tls
    entry.secretName != ""
}

has_approved_host(host) if {
    host == "example.com"
}

has_approved_host(host) if {
    endswith(host, ".example.com")
}

has_approved_host(host) if {
    some domain in approved_ingress_domains
    host == domain
}

deny contains {"msg": msg} if {
    obj := resource_object
    is_ingress(obj)
    ingress_class := object.get(obj.spec, "ingressClassName", "")
    not ingress_class in approved_ingress_classes
    msg := sprintf("ingress %q uses unapproved ingress class %q", [obj.metadata.name, ingress_class])
}

deny contains {"msg": msg} if {
    obj := resource_object
    is_ingress(obj)
    not approved_ingress_tls(obj)
    msg := sprintf("ingress %q must configure TLS", [obj.metadata.name])
}

deny contains {"msg": msg} if {
    obj := resource_object
    is_ingress(obj)
    rules := object.get(obj.spec, "rules", [])
    some rule in rules
    host := object.get(rule, "host", "")
    host != ""
    not has_approved_host(host)
    msg := sprintf("ingress %q hosts %q must use an approved domain", [obj.metadata.name, host])
}

deny contains {"msg": msg} if {
    obj := resource_object
    is_ingress(obj)
    rules := object.get(obj.spec, "rules", [])
    some rule in rules
    http_rules := object.get(rule, "http", {})
    paths := object.get(http_rules, "paths", [])
    some path_rule in paths
    path := object.get(path_rule, "path", "")
    startswith(path, "/internal")
    msg := sprintf("ingress %q has an unapproved internal path %q", [obj.metadata.name, path])
}
