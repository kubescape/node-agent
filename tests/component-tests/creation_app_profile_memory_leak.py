import subprocess
import os
import time

from promtopic import save_plot_png, send_promql_query_to_prom
from kubernetes_wrappers import Namespace, Workload, KubernetesObjects

def install_app_no_application_profile_no_leak(test_framework):
    print("Running install app no application profile test")

    # Create a namespace
    ns = Namespace(name=None)
    namespace = ns.name()

    try:
        time_start = time.time()
        # TODO: locost loader 
        
        # Install nginx in kubernetes by applying the nginx deployment yaml without pre-creating the profile
        workload = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directory(),"resources/nginx-deployment.yaml"))
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "tests/component-tests/resources/nginx-service.yaml"])
        
        # Wait for nginx to be ready
        workload.wait_for_ready(timeout=120)

        print("Waiting for the application profile to be created")
        workload.wait_for_application_profile(timeout=400)
        
        # wait for 60 seconds for the GC to run, so the memory leak can be detected
        time.sleep(60)

        # Get node-agent pod name
        kc_pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=node-agent", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        # Build query to get memory usage
        query = 'sum(container_memory_working_set_bytes{pod="%s"}) by (container)'%kc_pod_name
        timestamps, values = send_promql_query_to_prom("install_app_no_application_profile_no_leak_mem", query, time_start,time_end=time.time())
        save_plot_png("install_app_no_application_profile_no_leak_mem", values=values,timestamps=timestamps, metric_name='Memory Usage (bytes)')

        # validate that there is no memory leak, but tolerate 20mb memory leak
        assert int(values[-1]) <= int(values[0]) + 20000000, f"Memory leak detected in node-agent pod. Memory usage at the end of the test is {values[-1]} and at the beginning of the test is {values[0]}"


    except Exception as e:
        print("Exception: ", e)
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1

    subprocess.check_call(["kubectl", "delete", "namespace", namespace])
    return 0

