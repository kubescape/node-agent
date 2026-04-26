import os
import requests
from datetime import datetime, timedelta, timezone
import pandas as pd
import matplotlib.pyplot as plt
import logging
from typing import Optional, List, Dict
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PrometheusConfig:
    # url: str = "http://localhost:9090"
    url: str = "http://prometheus-operated.monitoring.svc.cluster.local:9090"
    namespace: str = "kubescape"
    pod_regex: str = ".*"  # All pods
    step_seconds: str = "30"  # Step size for Prometheus queries
    rate_window: str = "5m"  # Rate window for CPU queries

class PrometheusMetricsCollector:
    def __init__(self, config: Optional[PrometheusConfig] = None):
        self.config = config or PrometheusConfig()

        # Get output directory from environment variable with 'output' as default
        self.output_dir = os.getenv('OUTPUT_DIR', 'output')
        logger.info(f"Using output directory: {self.output_dir}")

        # Ensure the output directory exists
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.info(f"Successfully created/verified output directory: {self.output_dir}")
        except Exception as e:
            logger.warning(f"Failed to create {self.output_dir}, falling back to 'output': {e}")
            self.output_dir = 'output'
            os.makedirs(self.output_dir, exist_ok=True)

        # Get duration from environment variable
        try:
            self.duration_minutes = int(os.getenv('DURATION_TIME', '30'))
            logger.info(f"Using duration of {self.duration_minutes} minutes")
        except ValueError as e:
            logger.error(f"Error parsing duration: {e}")
            self.duration_minutes = 30

        # Calculate time window based on duration
        self.end_time = datetime.now(timezone.utc)
        self.start_time = self.end_time - timedelta(minutes=self.duration_minutes)

    def query_prometheus_range(self, query: str) -> Optional[List[Dict]]:
        """Execute a Prometheus range query with error handling."""
        params = {
            'query': query,
            'start': self.start_time.isoformat(),
            'end': self.end_time.isoformat(),
            'step': f"{self.config.step_seconds}s"
        }

        try:
            logger.info(f"Querying Prometheus with: {query}")
            logger.info(f"Time range: {self.start_time} to {self.end_time}")
            response = requests.get(
                f'{self.config.url}/api/v1/query_range',
                params=params,
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            if 'data' in data and 'result' in data['data']:
                return data['data']['result']
            else:
                logger.warning("No data found for the query")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying Prometheus: {str(e)}")
            return None

    def process_metrics(self, metrics: List[Dict], metric_type: str) -> pd.DataFrame:
        """Process metrics into a DataFrame."""
        if not metrics:
            return pd.DataFrame(columns=['Time', 'Pod', 'Value'])

        all_data = []
        for item in metrics:
            pod = item['metric'].get('pod', 'unknown')
            for timestamp, value in item['values']:
                try:
                    timestamp_readable = datetime.fromtimestamp(float(timestamp), timezone.utc)
                    value = float(value)
                    if metric_type == "Memory":
                        value = value / (1024 ** 2)  # Convert to MiB
                    all_data.append({
                        'Time': timestamp_readable,
                        'Pod': pod,
                        'Value': value
                    })
                except (ValueError, TypeError) as e:
                    logger.error(f"Error processing metric value: {str(e)}")
                    continue

        return pd.DataFrame(all_data)

    def filter_zero_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Filter out negative values and handle NaN values."""
        df['Value'] = pd.to_numeric(df['Value'], errors='coerce')
        return df[df['Value'].notna() & (df['Value'] >= 0)]

    def plot_individual(self, df: pd.DataFrame, metric_type: str) -> None:
        """Create plots."""
        if df.empty:
            logger.warning(f"No data to plot for {metric_type}")
            return

        plt.style.use('bmh')

        for pod, pod_data in df.groupby('Pod'):
            try:
                plt.figure(figsize=(12, 6))

                plt.plot(pod_data['Time'], pod_data['Value'],
                        label=pod, marker='o', linestyle='-', markersize=4)

                title = (f"{metric_type} Usage Over {self.duration_minutes} Minutes\n"
                        f"Pod: {pod}")
                plt.title(title, fontsize=16)
                plt.xlabel("Time (UTC)", fontsize=12)
                plt.ylabel(f"{metric_type} ({'MiB' if metric_type == 'Memory' else 'Cores'})",
                         fontsize=12)

                plt.grid(True, linestyle='--', alpha=0.7)
                plt.xticks(rotation=45)
                plt.tight_layout()

                filename = os.path.join(self.output_dir, f"{pod}_{metric_type.lower()}_usage.png")
                plt.savefig(filename, dpi=300, bbox_inches='tight')
                logger.info(f"Saved graph: {filename}")
                plt.close()

            except Exception as e:
                logger.error(f"Error creating plot for pod {pod}: {str(e)}")
                plt.close()

    def save_to_csv(self, df: pd.DataFrame, metric_type: str) -> None:
        """Save data to CSV."""
        if df.empty:
            logger.warning(f"No data to save for {metric_type}")
            return

        try:
            filename = os.path.join(self.output_dir, f"{metric_type.lower()}_metrics.csv")
            df.to_csv(filename, index=False)
            logger.info(f"Saved data to CSV: {filename}")
        except Exception as e:
            logger.error(f"Error saving CSV file: {str(e)}")

    def run(self):
        """Main execution method."""
        logger.info(f"Starting metrics collection for the past {self.duration_minutes} minutes")

        memory_query = (
            f'container_memory_working_set_bytes{{namespace="{self.config.namespace}",'
            f'pod=~"{self.config.pod_regex}", container!="", container!="POD"}}'
        )
        memory_results = self.query_prometheus_range(memory_query)

        if memory_results:
            logger.info("Memory query returned results:")
            for result in memory_results:
                logger.info(f"Metric labels: {result['metric']}")

        cpu_query = (
            f'sum(rate(container_cpu_usage_seconds_total{{namespace="{self.config.namespace}",'
            f'pod=~"{self.config.pod_regex}"}}[{self.config.rate_window}])) by (pod)'
        )
        cpu_results = self.query_prometheus_range(cpu_query)

        if memory_results:
            memory_df = self.process_metrics(memory_results, "Memory")
            memory_df = self.filter_zero_values(memory_df)
            self.save_to_csv(memory_df, "Memory")
            self.plot_individual(memory_df, "Memory")

        if cpu_results:
            cpu_df = self.process_metrics(cpu_results, "CPU")
            cpu_df = self.filter_zero_values(cpu_df)
            self.save_to_csv(cpu_df, "CPU")
            self.plot_individual(cpu_df, "CPU")

        logger.info(f"Metrics collection complete for {self.duration_minutes} minute period")

if __name__ == "__main__":
    collector = PrometheusMetricsCollector()
    collector.run()
