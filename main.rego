package platform.governance

import future.keywords.if

default allow := true

allow if {
    count(deny) == 0
}
