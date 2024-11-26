package testutils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/k8s-interface/k8sinterface"
)

const (
	prometheusURL = "http://localhost:9090"
)

func getNodeAgentPods() []string {
	k8sClient := k8sinterface.NewKubernetesApi()
	var podNames []string
	pods, err := k8sClient.KubernetesClient.CoreV1().Pods("kubescape").List(context.TODO(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=node-agent",
	})
	if err != nil {
		fmt.Printf("Error fetching pods: %s\n", err)
		return podNames
	}

	for _, pod := range pods.Items {
		podNames = append(podNames, pod.Name)
	}
	return podNames
}

func GetNodeAgentAverageCPUUsage(start, end time.Time) (map[string]float64, error) {
	response := map[string]float64{}

	nodeAgentPods := getNodeAgentPods()
	for _, podName := range nodeAgentPods {
		query := fmt.Sprintf(`avg by(cpu, instance) (irate(container_cpu_usage_seconds_total{pod="%s"}[5m]))`, podName)
		_, values, err := sendPromQLQueryToProm(query, start, end, "")
		if err != nil {
			return response, err
		}
		// Calculate average
		response[podName] = sum(values) / float64(len(values))

	}
	return response, nil
}

func sum(numbers []float64) float64 {
	var sum float64
	for _, number := range numbers {
		sum += number
	}
	return sum
}

func PlotNodeAgentPrometheusCPUUsage(testcase string, startTime, endTime time.Time) error {
	nodeAgentPods := getNodeAgentPods()
	for _, podName := range nodeAgentPods {
		query := fmt.Sprintf(`sum(node_namespace_pod_container:container_cpu_usage_seconds_total:sum_irate{namespace="kubescape", pod="%s", container="node-agent"}) by (container)`, podName)
		timestamps, values, err := sendPromQLQueryToProm(query, startTime, endTime, "")
		if err != nil {
			return err
		}

		if err := savePlotPNG(testcase+"_"+podName+"_cpu", timestamps, values, "CPU Usage (ms)"); err != nil {
			return err
		}
	}
	return nil
}

type WorkloadMetrics struct {
	Name       string
	Timestamps []float64
	Values     []float64
}

func PlotNodeAgentPrometheusMemoryUsage(testcase string, startTime, endTime time.Time) ([]WorkloadMetrics, error) {
	nodeAgentPods := getNodeAgentPods()
	var workloadMetrics []WorkloadMetrics

	for _, podName := range nodeAgentPods {
		query := fmt.Sprintf(`sum(container_memory_working_set_bytes{pod="%s", container="node-agent"}) by (container)`, podName)

		timestamps, values, err := sendPromQLQueryToProm(query, startTime, endTime, "")
		if err != nil {
			return nil, err
		}

		if err := savePlotPNG(testcase+"_"+podName+"_mem", timestamps, values, "Memory Usage (bytes)"); err != nil {
			return nil, err
		} else {
			workloadMetrics = append(workloadMetrics, WorkloadMetrics{Name: podName, Timestamps: timestamps, Values: values})
		}
	}
	return workloadMetrics, nil
}

// Function to execute PromQL query
func executePromQLQuery(prometheusURL, query string, timeStart, timeEnd time.Time, steps string) ([]interface{}, error) {
	// Prepare the query parameters
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(timeStart.Unix(), 10))
	params.Set("end", strconv.FormatInt(timeEnd.Unix(), 10))
	params.Set("step", steps)

	// Construct the full URL for the request
	fullURL := fmt.Sprintf("%s/api/v1/query_range", prometheusURL)

	// Send the HTTP request
	resp, err := http.Get(fmt.Sprintf("%s?%s", fullURL, params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read and parse the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Unmarshal JSON data
	var result struct {
		Status string `json:"status"`
		Data   struct {
			Result []interface{} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	// Check the status of the query
	if result.Status != "success" {
		return nil, fmt.Errorf("query failed: %s", string(body))
	}

	return result.Data.Result, nil
}

// Function to send a PromQL query to Prometheus and process the results
func sendPromQLQueryToProm(query string, timeStart, timeEnd time.Time, steps string) ([]float64, []float64, error) {
	if steps == "" {
		steps = "1s"
	}

	// Get Prometheus URL from environment variable or use default
	u := prometheusURL
	if envURL, exists := os.LookupEnv("PROMETHEUS_URL"); exists {
		u = envURL
	}

	// Execute the query
	data, err := executePromQLQuery(u, query, timeStart, timeEnd, steps)
	if err != nil {
		return nil, nil, fmt.Errorf("error executing PromQL query: %w", err)
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("no data found in Prometheus")
	}

	// Assuming data is correctly structured as per Prometheus API
	// Extract timestamps and values assuming the format is correct
	result := data[0].(map[string]interface{})
	values := result["values"].([]interface{})
	timestamps := make([]float64, len(values))
	vals := make([]float64, len(values))

	for i, v := range values {
		valuePair := v.([]interface{})
		timestamp := int64(valuePair[0].(float64)) // Convert to int64
		timestamps[i] = float64(time.Unix(timestamp, 0).Unix())
		valString := fmt.Sprint(valuePair[1])
		vals[i], _ = strconv.ParseFloat(valString, 64) // Assume values are valid floats

	}

	return timestamps, vals, nil
}

func savePlotPNG(name string, timestamps []float64, values []float64, metricName string) error {
	// Create a new plot, set the title and labels
	p := plot.New()

	p.Title.Text = fmt.Sprintf("Node Agent %s - %s", metricName, name)
	p.X.Label.Text = "Time (epoch)"
	p.Y.Label.Text = metricName

	// Create a line plotter, and set its style
	pts := make(plotter.XYs, len(timestamps))
	for i := range timestamps {
		pts[i].X = timestamps[i]
		pts[i].Y = values[i]
	}

	line, err := plotter.NewLine(pts)
	if err != nil {
		return fmt.Errorf("error creating line plotter: %w", err)
	}
	p.Add(line)

	// Set the filename and save the plot to a PNG file
	filename := strings.ReplaceAll(strings.ToLower(name), " ", "_") + ".png"
	if err := p.Save(4*vg.Inch, 4*vg.Inch, filename); err != nil {
		return fmt.Errorf("error saving plot to PNG: %w", err)
	}

	return nil
}
