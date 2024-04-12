from kubernetes_wrappers import Namespace, Workload, KubernetesObjects
import os
import time

def all_alerts_from_malicious_app(test_framework):
    # Create a namespace
    ns = Namespace(name=None)

    if ns:
        # TODO: control via env var
        # Create a workload
        workload = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directory(),"resources/malicious-job.yaml"))

        # Wait for the workload to be ready
        workload.wait_for_ready(timeout=120)

        # # Wait for the application profile to be created and completed
        # workload.wait_for_application_profile(timeout=400)

        # Wait for the alerts to be generated
        print("Waiting 20 seconds for the alerts to be generated")
        time.sleep(20)

        # This application should have signaled all alerts types by now

        # Get all the alert for the namespace
        alerts = test_framework.get_alerts(namespace=ns)

        # Validate that all alerts are signaled
        expected_alerts = [
            "Unexpected process launched",
            "Unexpected file access",
            "Unexpected system call",
            "Unexpected capability used",
            "Unexpected domain request",
            "Unexpected Service Account Token Access",
            "Kubernetes Client Executed",
            "Exec from malicious source",
            "Kernel Module Load",
            "Exec Binary Not In Base Image",
            # "Malicious SSH Connection", (This rule needs to be updated to be more reliable).
            "Exec from mount",
            "Crypto Mining Related Port Communication"
        ]

        for alert in alerts:
            rule_name = alert['labels']['rule_name']
            if rule_name in expected_alerts:
                expected_alerts.remove(rule_name)

        assert len(expected_alerts) == 0, f"Expected alerts {expected_alerts} were not signaled"







