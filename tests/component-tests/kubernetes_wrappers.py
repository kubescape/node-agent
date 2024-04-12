import subprocess
import random
import string
import yaml
import json
import time

class Namespace:
    def __init__(self, name):
        if name == None:
            # Generate a random namespace name
            self.ns_name = "node-agent-test-" + ''.join(random.choice(string.ascii_lowercase) for i in range(4))
        else:
            self.ns_name = name
        # Create namespace
        if subprocess.call(["kubectl", "get", "namespace", self.ns_name]) != 0:
            subprocess.check_call(["kubectl", "create", "namespace", self.ns_name])
            self.created_ns = True
        else:
            self.ns_name = name
            self.created_ns = False
    def __del__(self):
        # Delete the namespace
        if self.created_ns:
            subprocess.call(["kubectl", "delete", "namespace", self.ns_name])

    def name(self):
        return self.ns_name

    def __str__(self):
        return self.ns_name

class Workload:
    def __init__(self, namespace, workload_file):
        self.namespace = namespace
        self.workload_file = workload_file
        # Apply workload
        subprocess.check_call(["kubectl", "-n", self.namespace.name(), "apply", "-f", self.workload_file])
        # Load the workload file
        with open(self.workload_file, 'r') as f:
            self.workload = yaml.safe_load(f)
            self.workload_kind = self.workload['kind']
            self.workload_name = self.workload['metadata']['name']
            # Get the labels for the Pod
            if self.workload_kind == "Deployment":
                self.workload_labels = self.workload['spec']['template']['metadata']['labels']
            elif self.workload_kind == "Pod":
                self.workload_labels = self.workload['metadata']['labels']
            elif self.workload_kind in ["StatefulSet", "DaemonSet"]:
                self.workload_labels = self.workload['spec']['template']['metadata']['labels']
            elif self.workload_kind == "Job":
                self.workload_labels = self.workload['spec']['template']['metadata']['labels']
            else:
                raise Exception("Unknown workload kind %s"%self.workload_kind)


    def __del__(self):
        # Delete the workload
        subprocess.call(["kubectl", "-n", self.namespace.name(), "delete", "-f", self.workload_file])

    def wait_for_ready(self, timeout):
        # Find the application label in the workload file
        app_label = None
        for key in self.workload_labels:
            if key == "app":
                app_label = self.workload_labels[key]
                break
        if app_label == None:
            raise Exception("Could not find app label in workload file %s"%self.workload_file)

        # Wait for the workload to be ready
        subprocess.check_call(["kubectl", "-n", self.namespace.name(), "wait", "--for=condition=ready", "pod", "-l", "app="+app_label, "--timeout=%ss"%timeout])

    def exec_into_pod(self, command):
        # Find the application label in the workload file
        app_label = None
        for key in self.workload_labels:
            if key == "app":
                app_label = self.workload_labels[key]
                break
        if app_label == None:
            raise Exception("Could not find app label in workload file %s"%self.workload_file)
        # Get the pod name of the pod
        pod_name = subprocess.check_output(["kubectl", "-n", self.namespace.name(), "get", "pod", "-l", "app="+app_label, "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")
        # Exec into the pod
        subprocess.check_call(["kubectl", "-n", self.namespace.name(), "exec", pod_name, "--"] + command)
    
    def get_application_profile(self):
        def get_application_profiles_in_namespace(namespace: Namespace): 
            output = subprocess.check_output(["kubectl", "get", "applicationprofiles", "-n", namespace.name(), "-ojson"]).decode("utf-8").strip("'")
            app_profiles = json.loads(output)
            return app_profiles["items"]

        app_profiles = get_application_profiles_in_namespace(self.namespace)
        for app_profile in app_profiles:
            labels = app_profile['metadata']['labels']
            wl_kind = labels.get('kubescape.io/workload-kind', '')
            wl_name = labels.get('kubescape.io/workload-name', '')
            wl_ns = labels.get('kubescape.io/workload-namespace', '')
            
            if wl_kind == self.workload_kind and wl_name == self.workload_name and wl_ns == self.namespace.name():
                return app_profile        
        return None

    def wait_for_application_profile(self, timeout, interval=5):
        def is_application_profile_complete(app_profile):
            return app_profile['metadata']['annotations'].get('kubescape.io/status', '') == 'completed'
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            app_profile = self.get_application_profile()
            if app_profile is not None and is_application_profile_complete(app_profile):
                return app_profile

            time.sleep(interval)
        raise AssertionError(f"Application profile for workload {self.workload_name} in namespace {self.namespace.name()} was not created within {timeout} seconds")


class KubernetesObjects:
    def __init__(self, namespace, object_file):
        self.namespace = namespace
        self.object_file = object_file
        # Apply workload
        subprocess.check_call(["kubectl", "-n", self.namespace.name(), "apply", "-f", self.object_file])
    def __del__(self):
        # Delete the workload
        subprocess.call(["kubectl", "-n", self.namespace.name(), "delete", "-f", self.object_file])
