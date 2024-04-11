from kubernetes_wrappers import Namespace, Workload, KubernetesObjects
import os
import time

def basic_load_activities(test_framework):
    print("Running basic load activities test")

    # Create a namespace
    ns = Namespace(name=None)

    if ns:
        # Create a workload
        nginx = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directory(),"resources/nginx-deployment.yaml"))

        # Wait for the workload to be ready
        nginx.wait_for_ready(timeout=120)

        # Wait for the application profile to be created and completed
        nginx.wait_for_application_profile(timeout=400)

        # Create loader
        loader = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directory(),"resources/locust-deployment.yaml"))

        # Wait for the workload to be ready
        loader.wait_for_ready(timeout=120)

        time_start = time.time()

        # Create a load of 5 minutes
        time.sleep(300)

        time_end= time.time()

        # Get the average CPU usage of Node Agent
        cpu_usage = test_framework.get_average_cpu_usage(namespace='kubescape', workload="node-agent", time_start=time_start, time_end=time_end)

        assert cpu_usage < 0.1, f"CPU usage of Node Agent is too high. CPU usage is {cpu_usage}"
