import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
from datetime import datetime

# Configuration
TCAM_SIZES = [750, 1000]
TYPES = ["fixed", "adaptive", "vita"]
BASE_PATH = "results"  # or "/results" depending on your path

# Metrics configuration with display names and colors
metrics_config = {
    "cpu_percent": {
        "type": "avg",
        "display_name": "CPU Usage (%)",
        "color": "#3498db",
        "format": ".2f",
        "is_percentage": True
    },
    "table_occupancy": {
        "type": "avg",
        "display_name": "Table Occupancy (% of TCAM size)",
        "color": "#2ecc71",
        "format": ".2f",
        "is_percentage": True,
        "convert_to_percent": True  # Special flag to convert to percentage of TCAM size
    },
    "rejected_flows": {
        "type": "last",
        "display_name": "Rejected Flows",
        "color": "#e74c3c",
        "format": ".0f",
        "is_percentage": False
    },
    "memory_mb": {
        "type": "avg",
        "display_name": "Memory (MB)",
        "color": "#f39c12",
        "format": ".2f",
        "is_percentage": False
    },
    "packet_in_count": {
        "type": "last",
        "display_name": "Packet-In Count",
        "color": "#9b59b6",
        "format": ".0f",
        "is_percentage": False
    },
}

metrics = list(metrics_config.keys())

# Create graphs directory if it doesn't exist
if not os.path.exists('graphs'):
    os.makedirs('graphs')
    print(f"Created directory: 'graphs'")

# Create a summary file
summary_file = os.path.join('graphs', 'analysis_summary.txt')
with open(summary_file, 'w') as f:
    f.write("="*60 + "\n")
    f.write("METRICS ANALYSIS SUMMARY\n")
    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("="*60 + "\n\n")

# Process each TCAM size
for size in TCAM_SIZES:
    print(f"\n{'='*50}")
    print(f"Processing TCAM size: {size}")
    print('='*50)
    
    # Dictionary to store dataframes and calculated values
    dataframes = {}
    calculated_values = {metric: {} for metric in metrics}
    raw_values = {metric: {} for metric in metrics}  # Store raw values for reference
    
    # Load data for each type
    for type_name in TYPES:
        file_path = os.path.join(BASE_PATH, type_name, str(size), "metrics.csv")
        
        try:
            df = pd.read_csv(file_path)
            dataframes[type_name] = df
            print(f"  ✓ Loaded: {type_name}/{size} - {len(df)} rows")
        except FileNotFoundError:
            print(f"  ✗ Warning: File not found - {file_path}")
            dataframes[type_name] = pd.DataFrame()
        except Exception as e:
            print(f"  ✗ Error loading {file_path}: {e}")
            dataframes[type_name] = pd.DataFrame()
    
    # Calculate values for each metric
    for metric in metrics:
        config = metrics_config[metric]
        calculation_type = config["type"]
        
        for type_name in TYPES:
            df = dataframes[type_name]
            
            if df.empty or metric not in df.columns:
                calculated_values[metric][type_name] = 0
                raw_values[metric][type_name] = 0
                continue
            
            if calculation_type == "avg":
                val = df[metric].mean()
                raw_values[metric][type_name] = val
                
                # Convert table occupancy to percentage of TCAM size
                if metric == "table_occupancy" and config.get("convert_to_percent", False):
                    # Assuming table_occupancy is absolute number of entries
                    # Convert to percentage: (entries / TCAM_SIZE) * 100
                    val = (val / size) * 100
                    calculated_values[metric][type_name] = val
                else:
                    calculated_values[metric][type_name] = val
                    
            else:  # "last"
                val = df[metric].iloc[-1] if not df.empty else 0
                raw_values[metric][type_name] = val
                calculated_values[metric][type_name] = val
    
    # Write values to summary file
    with open(summary_file, 'a') as f:
        f.write(f"\n{'─'*60}\n")
        f.write(f"TCAM SIZE: {size}\n")
        f.write(f"{'─'*60}\n")
        
        for metric in metrics:
            config = metrics_config[metric]
            f.write(f"\n{config['display_name']}:\n")
            
            for type_name in TYPES:
                val = calculated_values[metric][type_name]
                raw_val = raw_values[metric][type_name]
                
                format_str = f"{{:.{config['format'][1:]}}}"
                
                if metric == "table_occupancy":
                    f.write(f"  {type_name:10}: {format_str.format(val)}% ")
                    f.write(f"(raw: {raw_val:.0f} entries of {size})\n")
                elif config.get("is_percentage", False):
                    f.write(f"  {type_name:10}: {format_str.format(val)}%\n")
                else:
                    f.write(f"  {type_name:10}: {format_str.format(val)}\n")
    
    # Create comparison plots for this size
    for metric in metrics:
        config = metrics_config[metric]
        values = [calculated_values[metric][type_name] for type_name in TYPES]
        
        # Create bar chart
        plt.figure(figsize=(12, 7))
        bars = plt.bar(TYPES, values, 
                      color=['#3498db', '#2ecc71', '#e74c3c'], 
                      edgecolor='black', linewidth=1.2, alpha=0.8)
        
        # Customize the plot
        calculation_label = "Average" if config["type"] == "avg" else "Final Value"
        
        # Add unit to ylabel
        ylabel = config['display_name']
        plt.ylabel(ylabel, fontsize=16)
        
        # Add size information to title for table occupancy
        if metric == "table_occupancy":
            title = f"{calculation_label} Table Occupancy (TCAM Size: {size} - {size} entries = 100%)"
        else:
            title = f"{calculation_label} {config['display_name']} (TCAM Size: {size})"
        
        plt.title(title, fontsize=20, fontweight='bold')
        plt.grid(True, alpha=0.3, axis='y')
        plt.xticks(fontsize=16)               # ← x-axis tick labels (TYPES names)
        plt.yticks(fontsize=16)
        # Set y-axis to percentage for table_occupancy
        if metric == "table_occupancy":
            plt.gca().set_ylim(0, 105)  # Give a little headroom above 100%
            plt.gca().yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f'{y:.0f}%'))
        
        # Add value labels on top of bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            format_str = f"{{:{config['format']}}}"
            
            if metric == "table_occupancy":
                label = f"{format_str.format(value)}%"
            else:
                label = format_str.format(value)
            
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    label, ha='center', va='bottom', fontweight='bold', fontsize=16)
        
        # Remove top and right spines for cleaner look
        plt.gca().spines['top'].set_visible(False)
        plt.gca().spines['right'].set_visible(False)
        
        plt.tight_layout()
        
        # Save the figure
        filename = os.path.join('graphs', f"{metric}_size{size}_comparison.png")
        plt.savefig(filename, dpi=100, bbox_inches='tight')
        plt.close()
        print(f"  💾 Saved: {filename}")

# Finalize summary file
with open(summary_file, 'a') as f:
    f.write(f"\n{'='*60}\n")
    f.write("END OF SUMMARY\n")
    f.write(f"{'='*60}\n")

print(f"\n{'='*50}")
print("✓ All diagrams created successfully in 'graphs' folder!")
print(f"✓ Summary file saved: {summary_file}")
print(f"\nNote: Table occupancy is shown as percentage of TCAM size ({TCAM_SIZES})")
print('='*50)
