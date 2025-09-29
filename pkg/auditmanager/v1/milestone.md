# TODO for first release


## Bugs
- [ ] CRD reloading doesn't seem to work properly - rewrite the whole thing to reload all rules on every change (order them by priority)
- [ ] Tags and key are not added to the audit events
- [ ] K8s metadata is not added to the audit events

## Features
- [ ] Implement output format that follows auditbeat format (validata sherlock fields)
- [ ] Actor field

## Tests
- [ ] Unit test coverage

## Others
- [ ] Docs
- [ ] Code review
- [ ] Cleanup

## OLD
- [x] Aggergate audit messages into a single audit event by audit ID
- [x] File watch rules can only handle single path and the CRD enables multiple paths - implement multiple paths
- [x] Validate other rules in CRD
- [x] Bug: when disablig a rule, it doesn't remove the rule from the audit subsystem
- [x] Validate key and tag mappings
- [x] enrich audit events with Kubernetes metadataaudit
- [x] Tag mapping for audit events