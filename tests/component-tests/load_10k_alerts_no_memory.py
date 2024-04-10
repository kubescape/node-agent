import subprocess
import time
import os

from promtopic import save_plot_png, send_promql_query_to_prom
from pprof import pprof_recorder
from kubernetes_wrappers import Namespace

def load_10k_alerts_no_memory_leak(test_framework):
    print("Running load 10k alerts no memory leak test")

    # Create a namespace
    ns = Namespace(name=None)

    namespace = ns.name()

    try:
        #  Install nginx profile in kubernetes by applying the nginx profile yaml
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "tests/component-tests/resources/nginx-app-profile.yaml"])
        # Install nginx in kubernetes by applying the nginx deployment yaml with pre-creating profile for the nginx pod
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "tests/component-tests/resources/nginx-deployment.yaml"])
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "tests/component-tests/resources/nginx-service.yaml"])
        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])
        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")

        # Do an inital load on the nginx pod
        print("Starting first load on nginx pod")
        for i in range(10):
            subprocess.check_call(["kubectl", "-n", namespace , "exec", nginx_pod_name, "--", "bash", "-c",
                                   "for i in {1..100}; do touch /tmp/nginx-test-$i; done"])
            if i % 5 == 0:
                print(f"Created file {(i+1)*100} times")

        # wait for 300 seconds for the GC to run, so the memory leak can be detected
        print("Waiting 300 seconds to have a baseline memory usage")
        time.sleep(300)

        # Start to record memory usage
        kc_pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=node-agent", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        pprof_recorder_obj = pprof_recorder('kubescape', kc_pod_name, 6060)
        pprof_recorder_obj.record_detached(duration=600, type="mem", filename="load_10k_alerts_no_memory_leak_mem.pprof")

        time_start = time.time()
        # Exec into the nginx pod and create a file in the /tmp directory in a loop
        for i in range(100):
            subprocess.check_call(["kubectl", "-n", namespace , "exec", nginx_pod_name, "--", "bash", "-c",
                                   "for i in {1..100}; do touch /tmp/nginx-test-$i; done"])
            if i % 5 == 0:
                print(f"Created file {(i+1)*100} times")

        # wait for 300 seconds for the GC to run, so the memory leak can be detected
        print("Waiting 300 seconds to GC to run")
        time.sleep(300)

        # Get node-agent pod name
        kc_pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=node-agent", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        # Build query to get memory usage
        query = 'sum(container_memory_working_set_bytes{pod="%s"}) by (container)'%kc_pod_name
        timestamps, values = send_promql_query_to_prom("load_10k_alerts_no_memory_leak_mem", query, time_start,time_end=time.time())
        save_plot_png("load_10k_alerts_no_memory_leak_mem", values=values,timestamps=timestamps, metric_name='Memory Usage (bytes)')

        # validate that there is no memory leak, but tolerate 6mb memory leak
        assert int(values[-1]) <= int(values[0]) + 6000000, f"Memory leak detected in node-agent pod. Memory usage at the end of the test is {values[-1]} and at the beginning of the test is {values[0]}"


    except Exception as e:
        print("Exception: ", e)
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1

    # Delete the namespace
    subprocess.check_call(["kubectl", "delete", "namespace", namespace])
    return 0




