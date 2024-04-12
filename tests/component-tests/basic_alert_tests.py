from kubernetes_wrappers import Namespace, Workload

import os
import time

def basic_alert_test(test_framework):
    print("Running basic alert test")

    # Create a namespace
    ns = Namespace(name=None)

    if ns:
        # Create a workload
        workload = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directory(),"resources/nginx-deployment.yaml"))

        # Wait for the workload to be ready
        workload.wait_for_ready(timeout=120)

        # Wait for the application profile to be created and completed
        workload.wait_for_application_profile(timeout=400)

        time.sleep(10)

        # Exec into the nginx pod and run "ls" command
        workload.exec_into_pod(command=["ls", "-l"])

        # Wait for the alert to be signaled
        time.sleep(5)

        # Get all the alert for the namespace
        alerts = test_framework.get_alerts(namespace=ns)

        # Validate that all alerts are signaled
        expected_alert = "Unexpected process launched"
        expected_command = "ls"

        for alert in alerts:
            rule_name = alert['labels'].get('rule_name', '')
            command = alert['labels'].get('comm', '')

            if rule_name == expected_alert and command == expected_command:
                return 

        raise AssertionError(f"Expected alert '{expected_alert}' was not signaled")

