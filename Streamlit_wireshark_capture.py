import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import streamlit as st
import tempfile
import os
import numpy as np
from collections import Counter
import subprocess
import json
import sys

# Try to import pyshark but provide fallback
PYSHARK_AVAILABLE = False
try:
    import pyshark
    import asyncio
    import nest_asyncio
    
    # Try to apply nest_asyncio
    try:
        nest_asyncio.apply()
        PYSHARK_AVAILABLE = True
    except:
        pass
        
    # Additional event loop setup
    def setup_event_loop():
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("Event loop is closed")
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop
        
except ImportError:
    pass


def extract_features_tshark(pcap_file_path):
    """Extract features using tshark command line tool as fallback"""
    try:
        # Use tshark to extract packet information
        cmd = [
            'tshark', '-r', pcap_file_path, '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_epoch',
            '-e', 'frame.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', '_ws.col.Protocol',
            '-e', 'tcp.analysis.retransmission',
            '-e', 'tcp.flags.reset',
            '-E', 'header=y',
            '-E', 'separator=,',
            '-E', 'quote=d'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            raise Exception(f"tshark failed: {result.stderr}")
        
        # Parse the CSV output
        import io
        df = pd.read_csv(io.StringIO(result.stdout))
        
        # Clean and process the data
        data = []
        for _, row in df.iterrows():
            try:
                protocol = row.get('_ws.col.Protocol', 'UNKNOWN')
                length = int(row.get('frame.len', 0))
                timestamp = float(row.get('frame.time_epoch', 0))
                
                src_ip = row.get('ip.src', 'N/A')
                dst_ip = row.get('ip.dst', 'N/A')
                
                src_port = row.get('tcp.srcport', row.get('udp.srcport', 'N/A'))
                dst_port = row.get('tcp.dstport', row.get('udp.dstport', 'N/A'))
                
                retransmission = str(row.get('tcp.analysis.retransmission', '')).strip() == '1'
                reset_flag = str(row.get('tcp.flags.reset', '')).strip() == '1'
                
                data.append([protocol, length, src_ip, dst_ip, src_port, dst_port, timestamp, retransmission, reset_flag])
            except Exception as e:
                continue
        
        return pd.DataFrame(data, columns=['Protocol', 'Length', 'Src_Address', 'Dst_Address', 'Src_Port', 'Dst_Port',
                                          'Timestamp', 'Retransmission', 'Reset_Flag'])
        
    except Exception as e:
        raise Exception(f"tshark extraction failed: {e}")


def extract_features_pyshark(pcap_file_path):
    """Extract features using PyShark with enhanced error handling"""
    try:
        # Setup event loop
        if PYSHARK_AVAILABLE:
            setup_event_loop()
        
        # Try different PyShark configurations
        configs = [
            {'use_json': True, 'include_raw': True},
            {'use_json': False, 'include_raw': False},
            {'only_summaries': True}
        ]
        
        for config in configs:
            try:
                cap = pyshark.FileCapture(pcap_file_path, **config)
                data = []

                packet_count = 0
                for packet in cap:
                    if packet_count > 1000:  # Limit for testing
                        break
                    
                    try:
                        protocol = packet.highest_layer
                        if protocol in ['STP', 'ARP', 'CDP']:
                            continue

                        length = int(packet.length)
                        src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                        src_port = packet.tcp.srcport if hasattr(packet, 'tcp') else (
                            packet.udp.srcport if hasattr(packet, 'udp') else 'N/A')
                        dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else (
                            packet.udp.dstport if hasattr(packet, 'udp') else 'N/A')
                        timestamp = float(packet.sniff_timestamp)

                        retransmission = False
                        reset_flag = False
                        if hasattr(packet, 'tcp'):
                            retransmission = 'analysis_retransmission' in packet.tcp.field_names
                            reset_flag = packet.tcp.flags_reset == '1' if 'flags_reset' in packet.tcp.field_names else False

                        if src_ip == 'N/A' and dst_ip == 'N/A':
                            src_mac = packet.eth.src if hasattr(packet, 'eth') else 'N/A'
                            dst_mac = packet.eth.dst if hasattr(packet, 'eth') else 'N/A'
                            data.append([protocol, length, src_mac, dst_mac, src_port, dst_port, timestamp, retransmission, reset_flag])
                        else:
                            data.append([protocol, length, src_ip, dst_ip, src_port, dst_port, timestamp, retransmission, reset_flag])
                        
                        packet_count += 1
                    except Exception as e:
                        continue

                cap.close()
                
                if data:  # If we successfully extracted data, return it
                    return pd.DataFrame(data, columns=['Protocol', 'Length', 'Src_Address', 'Dst_Address', 'Src_Port', 'Dst_Port',
                                                      'Timestamp', 'Retransmission', 'Reset_Flag'])
                        
            except Exception as e:
                continue
        
        raise Exception("All PyShark configurations failed")
        
    except Exception as e:
        raise Exception(f"PyShark extraction failed: {e}")


def extract_features(pcap_file_path):
    """Main extraction function with multiple fallback methods"""
    extraction_methods = []
    
    # Add tshark method if available
    try:
        result = subprocess.run(['tshark', '-v'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            extraction_methods.append(('tshark', extract_features_tshark))
    except:
        pass
    
    # Add PyShark method if available
    if PYSHARK_AVAILABLE:
        extraction_methods.append(('pyshark', extract_features_pyshark))
    
    # Try each method
    for method_name, method_func in extraction_methods:
        try:
            st.info(f"Trying {method_name} extraction method...")
            data = method_func(pcap_file_path)
            if not data.empty:
                st.success(f"Successfully extracted features using {method_name}!")
                return data
        except Exception as e:
            st.warning(f"{method_name} extraction failed: {e}")
            continue
    
    # If all methods fail, return empty DataFrame
    st.error("All extraction methods failed. Please ensure:")
    st.write("1. Wireshark/tshark is installed and in your PATH")
    st.write("2. Your PCAP file is not corrupted")
    st.write("3. Try using the test dataset instead")
    
    return pd.DataFrame()


def detect_anomalies(data):
    if data.empty:
        return data
    
    # Prepare features for anomaly detection
    features = data[['Length', 'Timestamp']].copy()
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    # Run Isolation Forest anomaly detection
    model = IsolationForest(contamination=0.05, random_state=42)
    data['Anomaly'] = model.fit_predict(scaled_features)

    # Initialize anomaly types
    data['Anomaly_Type'] = 'Other'
    
    # Classify anomalies based on various criteria
    # First check specific flags
    data.loc[data['Retransmission'], 'Anomaly_Type'] = 'Retransmission'
    data.loc[data['Reset_Flag'], 'Anomaly_Type'] = 'Reset Flag'
    
    # Classify based on packet length
    data.loc[(data['Length'] > 1500) & (data['Anomaly'] == -1), 'Anomaly_Type'] = 'High Packet Length'
    data.loc[(data['Length'] < 100) & (data['Anomaly'] == -1), 'Anomaly_Type'] = 'Low Packet Length'
    
    # Detect possible fragmentation patterns in TLS traffic
    tls_data = data[data['Protocol'].str.contains('TLS', na=False)].copy()
    if not tls_data.empty:
        # Group by source and destination to analyze communication patterns
        for (src, dst), group in tls_data.groupby(['Src_Address', 'Dst_Address']):
            # Detect potential TLS fragmentation (multiple sequential packets)
            if len(group) > 5:  # If there are multiple packets in the sequence
                fragmented_indices = group.index[group['Length'] >= 1400].tolist()
                data.loc[fragmented_indices, 'Anomaly_Type'] = 'TLS Fragmentation'
    
    # Identify potential communication patterns
    # Calculate time deltas between packets for the same src-dst pair
    data['TimeDelta'] = 0.0
    for (src, dst), group in data.groupby(['Src_Address', 'Dst_Address']):
        if len(group) > 1:
            sorted_group = group.sort_values('Timestamp')
            time_deltas = sorted_group['Timestamp'].diff().fillna(0)
            data.loc[sorted_group.index, 'TimeDelta'] = time_deltas

    # Identify possible DoS patterns (high frequency of packets between same hosts)
    for (src, dst), group in data.groupby(['Src_Address', 'Dst_Address']):
        if len(group) > 10:  # Arbitrary threshold for demonstration
            if (group['TimeDelta'] < 0.01).sum() > 5:  # Multiple packets in very short time
                dos_indices = group.index[group['TimeDelta'] < 0.01].tolist()
                data.loc[dos_indices, 'Anomaly_Type'] = 'Potential DoS Pattern'
    
    # Detect unusual HTTP patterns
    http_data = data[data['Protocol'].str.contains('HTTP', na=False)].copy()
    if not http_data.empty:
        # Identify potential unusual HTTP behavior
        unusual_http_indices = http_data.index[
            (http_data['Length'] > 800) & 
            (http_data['Anomaly'] == -1)
        ].tolist()
        data.loc[unusual_http_indices, 'Anomaly_Type'] = 'Unusual HTTP Traffic'
    
    # Classify any remaining anomalies
    data.loc[(data['Anomaly_Type'] == 'Other') & (data['TimeDelta'] > data['TimeDelta'].quantile(0.95)) & (data['Anomaly'] == -1), 'Anomaly_Type'] = 'High Latency'
    data.loc[(data['Anomaly_Type'] == 'Other') & (data['Protocol'].str.contains('UNKNOWN', na=False)), 'Anomaly_Type'] = 'Unexpected Protocol'
    data.loc[(data['Anomaly_Type'] == 'Other') & ((data['Src_Address'] == 'N/A') | (data['Dst_Address'] == 'N/A')), 'Anomaly_Type'] = 'Malformed Packet'
    
    # Detect SSL/TLS certificate issues based on size patterns
    data.loc[(data['Anomaly_Type'] == 'Other') & 
             (data['Protocol'].str.contains('TLS', na=False)) & 
             (data['Length'].between(200, 400)), 'Anomaly_Type'] = 'TLS Handshake'

    return data


def analyze_anomalies(data):
    if data.empty:
        st.warning("No data available for analysis.")
        return
    
    # Get summary statistics
    anomalies = data[data['Anomaly'] == -1]
    st.markdown("## Summary of Detected Anomalies")
    
    if anomalies.empty:
        st.info("No anomalies detected in the current dataset.")
        return
    
    # Display summary statistics
    anomaly_counts = anomalies['Anomaly_Type'].value_counts()
    st.bar_chart(anomaly_counts)
    
    # Display IP address frequency in anomalies
    st.subheader("Top Source IP Addresses in Anomalies")
    src_counts = anomalies['Src_Address'].value_counts().head(5)
    st.write(src_counts)
    
    st.subheader("Top Destination IP Addresses in Anomalies")
    dst_counts = anomalies['Dst_Address'].value_counts().head(5)
    st.write(dst_counts)
    
    # Group anomalies by source-destination pairs
    st.subheader("Communication Patterns in Anomalies")
    comm_patterns = anomalies.groupby(['Src_Address', 'Dst_Address']).size().reset_index(name='Frequency')
    comm_patterns = comm_patterns.sort_values('Frequency', ascending=False).head(10)
    st.write(comm_patterns)
    
    # Show limited detailed analysis to avoid overwhelming output
    st.markdown("## Detailed Anomaly Analysis (First 10 anomalies)")
    for i, (index, row) in enumerate(anomalies.head(10).iterrows()):
        st.markdown(f"### Abnormal Packet at Index {index}")
        st.write(f"- **Protocol**: {row['Protocol']}")
        st.write(f"- **Length**: {row['Length']} bytes")
        st.write(f"- **Source**: {row['Src_Address']}:{row['Src_Port']}")
        st.write(f"- **Destination**: {row['Dst_Address']}:{row['Dst_Port']}")
        st.write(f"- **Anomaly Type**: {row['Anomaly_Type']}")
        st.write(f"- **Timestamp**: {row['Timestamp']}")

        # Provide context-specific recommendations
        if row['Retransmission']:
            st.warning("⚠️ Retransmission detected. Check for network congestion or packet loss.")
        if row['Reset_Flag']:
            st.warning("⚠️ TCP Reset flag observed. Verify application behavior and potential connection issues.")
        if row['Anomaly_Type'] == 'High Latency':
            st.info("ℹ️ High latency detected. Investigate potential network congestion or overloaded servers.")
        if row['Anomaly_Type'] == 'Unexpected Protocol':
            st.info("ℹ️ Unexpected or unknown protocol. Validate protocol usage and check for unauthorized traffic.")
        if row['Anomaly_Type'] == 'Malformed Packet':
            st.error("🚨 Malformed packet detected. Inspect capture details for corruption or error.")
        if row['Anomaly_Type'] == 'TLS Fragmentation':
            st.info("ℹ️ TLS fragmentation detected. This is common for large encrypted transfers but can indicate issues if excessive.")
        if row['Anomaly_Type'] == 'Unusual HTTP Traffic':
            st.warning("⚠️ Unusual HTTP traffic pattern. Consider inspecting the payload for potential suspicious content.")
        if row['Anomaly_Type'] == 'TLS Handshake':
            st.info("ℹ️ TLS handshake pattern detected. Possible SSL/TLS negotiation or certificate exchange.")
        if row['Anomaly_Type'] == 'Potential DoS Pattern':
            st.error("🚨 Potential DoS pattern detected. Investigate high frequency communication between these hosts.")
        if row['Anomaly_Type'] == 'Low Packet Length':
            st.info("ℹ️ Unusually short packet. Could be a keep-alive signal or control packet.")
    
    if len(anomalies) > 10:
        st.info(f"Showing first 10 of {len(anomalies)} anomalies. Download the full report for complete analysis.")


def plot_anomalies(data):
    if data.empty:
        st.warning("No data available for plotting.")
        return
    
    anomalies = data[data['Anomaly'] == -1]
    
    if anomalies.empty:
        st.info("No anomalies to plot.")
        return
    
    # Create figure for packet length vs index
    plt.figure(figsize=(12, 8))
    normal_packets = data[data['Anomaly'] == 1]
    
    # Plot normal packets in background
    plt.scatter(normal_packets.index, normal_packets['Length'], color='lightgrey', label='Normal Packets', alpha=0.3)
    
    # Create a color map for different anomaly types
    anomaly_types = anomalies['Anomaly_Type'].unique()
    colors = plt.cm.tab10(np.linspace(0, 1, len(anomaly_types)))
    
    # Plot each anomaly type with different color
    for i, anomaly_type in enumerate(anomaly_types):
        subset = anomalies[anomalies['Anomaly_Type'] == anomaly_type]
        plt.scatter(subset.index, subset['Length'], color=colors[i], label=anomaly_type, alpha=0.8)
    
    plt.title('Packet Length vs. Index with Highlighted Anomalies')
    plt.xlabel('Packet Index')
    plt.ylabel('Packet Length (bytes)')
    plt.legend()
    st.pyplot(plt)
    
    # Create timeline visualization
    plt.figure(figsize=(14, 8))
    
    # Normalize timestamps relative to start
    min_time = data['Timestamp'].min()
    # Create a copy to avoid modifying the original data
    data_with_relative_time = data.copy()
    data_with_relative_time['Relative_Time'] = data_with_relative_time['Timestamp'] - min_time
    
    # Get normal packets with relative time
    normal_packets_with_time = data_with_relative_time[data_with_relative_time['Anomaly'] == 1]
    anomalies_with_time = data_with_relative_time[data_with_relative_time['Anomaly'] == -1]
    
    # Plot normal packets
    plt.scatter(normal_packets_with_time['Relative_Time'], normal_packets_with_time['Length'], 
                color='lightgrey', label='Normal Packets', alpha=0.3)
    
    # Plot anomalies on timeline
    for i, anomaly_type in enumerate(anomaly_types):
        subset = anomalies_with_time[anomalies_with_time['Anomaly_Type'] == anomaly_type]
        plt.scatter(subset['Relative_Time'], subset['Length'], 
                    color=colors[i], label=anomaly_type, alpha=0.8)
    
    plt.title('Packet Timeline with Highlighted Anomalies')
    plt.xlabel('Relative Time (seconds from start)')
    plt.ylabel('Packet Length (bytes)')
    plt.legend()
    st.pyplot(plt)
    
    # Create protocol distribution chart
    st.subheader("Protocol Distribution in Anomalies")
    protocol_counts = pd.DataFrame(anomalies['Protocol'].value_counts()).reset_index()
    protocol_counts.columns = ['Protocol', 'Count']
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(protocol_counts['Protocol'], protocol_counts['Count'])
    plt.xticks(rotation=45, ha='right')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.title('Distribution of Protocols in Anomalous Packets')
    st.pyplot(fig)


def analyze_tls_patterns(data):
    if data.empty:
        st.warning("No data available for TLS analysis.")
        return
    
    tls_data = data[data['Protocol'].str.contains('TLS', na=False)].copy()
    
    if tls_data.empty:
        st.info("No TLS traffic found in the capture.")
        return
    
    st.subheader("TLS Traffic Analysis")
    
    # Group by source-destination pair
    for (src, dst), group in tls_data.groupby(['Src_Address', 'Dst_Address']):
        st.markdown(f"### TLS Communication: {src} → {dst}")
        
        # Create length histogram
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.hist(group['Length'], bins=20)
        ax.set_title(f'Distribution of TLS Packet Lengths')
        ax.set_xlabel('Packet Length (bytes)')
        ax.set_ylabel('Frequency')
        st.pyplot(fig)
        
        # Analyze handshake patterns
        small_packets = group[group['Length'] < 400]
        large_packets = group[group['Length'] > 1000]
        
        st.write(f"- Small packets (<400 bytes): {len(small_packets)} - potentially handshake/control messages")
        st.write(f"- Large packets (>1000 bytes): {len(large_packets)} - potentially data transfer")
        
        if len(large_packets) > 5 and len(small_packets) > 0:
            st.info("This appears to be a normal TLS session with handshake and data transfer.")
        elif len(small_packets) > 3 and len(large_packets) < 2:
            st.warning("Multiple handshake messages with little data transfer - possible negotiation issues.")
        
        # Show sequence of packet sizes to identify patterns
        if len(group) < 30:  # Only show visualization for reasonably sized groups
            fig, ax = plt.subplots(figsize=(12, 4))
            ax.plot(range(len(group)), group['Length'], marker='o')
            ax.set_title(f'Sequence of TLS Packet Sizes')
            ax.set_xlabel('Sequence Number')
            ax.set_ylabel('Packet Length (bytes)')
            st.pyplot(fig)


def generate_recommendations(data):
    if data.empty:
        st.warning("No data available for generating recommendations.")
        return
    
    anomalies = data[data['Anomaly'] == -1]
    
    st.markdown("## Security Recommendations")
    
    if anomalies.empty:
        st.info("No anomalies detected, but here are some general recommendations:")
        st.markdown("### 💡 Continuous Monitoring")
        st.write("""
        - Continue regular network monitoring to establish baseline behavior.
        - Consider implementing automated anomaly detection systems.
        - Keep network security tools and signatures up to date.
        """)
        return
    
    # Based on anomaly types found, provide recommendations
    anomaly_types = anomalies['Anomaly_Type'].unique()
    
    if 'TLS Fragmentation' in anomaly_types:
        st.markdown("### 💡 TLS Configuration")
        st.write("""
        - Review TLS configuration parameters for optimal segment size.
        - Consider checking for MTU issues if fragmentation is excessive.
        - Verify TLS version and cipher suite selections are up to date.
        """)
    
    if 'Unusual HTTP Traffic' in anomaly_types:
        st.markdown("### 💡 HTTP Traffic Monitoring")
        st.write("""
        - Implement deeper HTTP traffic inspection.
        - Check for unusual user agents or request patterns.
        - Consider a web application firewall if web services are exposed.
        """)
    
    if 'High Latency' in anomaly_types:
        st.markdown("### 💡 Network Performance")
        st.write("""
        - Monitor network devices for congestion or hardware issues.
        - Check bandwidth allocation and QoS settings.
        - Consider network upgrades if latency issues persist.
        """)
    
    if 'Potential DoS Pattern' in anomaly_types:
        st.markdown("### 💡 DoS Protection")
        st.write("""
        - Implement rate limiting on critical services.
        - Consider DDoS protection services for public-facing applications.
        - Set up alerts for unusual traffic volume patterns.
        """)
    
    # General recommendations
    st.markdown("### 💡 General Security Recommendations")
    st.write("""
    - Keep monitoring network traffic for continued anomaly detection.
    - Use this analysis as a baseline and look for deviations in future captures.
    - Consider implementing a SIEM solution for continuous monitoring.
    - Update firewall rules based on identified suspicious traffic patterns.
    """)


def check_dependencies():
    """Check what analysis tools are available"""
    st.sidebar.markdown("### System Status")
    
    # Check tshark
    try:
        result = subprocess.run(['tshark', '-v'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            st.sidebar.success("✅ tshark available")
        else:
            st.sidebar.error("❌ tshark not working")
    except:
        st.sidebar.error("❌ tshark not found")
        st.sidebar.info("Install Wireshark to enable PCAP file analysis")
    
    # Check PyShark
    if PYSHARK_AVAILABLE:
        st.sidebar.success("✅ PyShark available")
    else:
        st.sidebar.warning("⚠️ PyShark issues detected")
        st.sidebar.info("pip install nest-asyncio might help")

# Streamlit Interface
def main():
    st.set_page_config(page_title="Advanced PCAP Anomaly Detector", layout="wide")
    st.title("📊 Advanced PCAP Anomaly Detection")
    st.markdown("""
    This tool analyzes network packet captures for anomalies using machine learning techniques.
    Upload a PCAP file to identify potential security issues, network misconfigurations, or unusual traffic patterns.
    """)

    # Create tabs for different sections
    tab1, tab2, tab3 = st.tabs(["Analysis", "TLS Deep Dive", "Recommendations"])
    
    uploaded_file = st.sidebar.file_uploader("Upload a Wireshark .pcap file", type=["pcap", "pcapng"])
    
    # Allow loading a test dataset
    use_test_data = st.sidebar.checkbox("Use test dataset")
    
    # Configuration options
    st.sidebar.header("Configuration")
    contamination = st.sidebar.slider("Anomaly Threshold (contamination)", 0.01, 0.2, 0.05, 0.01, 
                                    help="Lower values detect fewer but more significant anomalies")

    if uploaded_file or use_test_data:
        if uploaded_file:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(uploaded_file.read())
                tmp_file_path = tmp_file.name
            
            with st.spinner("Extracting features from PCAP..."):
                data = extract_features(tmp_file_path)
            
            try:
                os.remove(tmp_file_path)
            except:
                pass
            
        else:
            # Create test data based on the CSV
            test_data = pd.DataFrame({
                'Protocol': ['HTTP_RAW', 'DATA-TEXT-LINES_RAW', 'HTTP_RAW', 'DATA-TEXT-LINES_RAW', 'TLS_RAW', 'TLS_RAW', 
                            'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW',
                            'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 'TLS_RAW', 
                            'TLS_RAW', 'HTTP_RAW', 'TLS_RAW'],
                'Length': [997, 440, 998, 541, 231, 1484, 345, 329, 280, 99, 440, 1484, 100, 1484, 1085, 1484, 
                          100, 1484, 684, 1484, 1484, 198, 863, 515, 303],
                'Src_Address': ['192.168.3.131', '72.14.213.138', '192.168.3.131', '72.14.213.102', '192.168.3.131', 
                               '72.14.213.147', '72.14.213.147', '192.168.3.131', '72.14.213.147', '72.14.213.147',
                               '72.14.213.147', '72.14.213.147', '72.14.213.147', '72.14.213.147', '72.14.213.147', 
                               '72.14.213.147', '72.14.213.147', '72.14.213.147', '72.14.213.147', '72.14.213.147',
                               '72.14.213.147', '72.14.213.147', '72.14.213.147', '192.168.3.131', '192.168.3.131'],
                'Dst_Address': ['72.14.213.138', '192.168.3.131', '72.14.213.102', '192.168.3.131', '72.14.213.147', 
                               '192.168.3.131', '192.168.3.131', '72.14.213.147', '192.168.3.131', '192.168.3.131',
                               '192.168.3.131', '192.168.3.131', '192.168.3.131', '192.168.3.131', '192.168.3.131', 
                               '192.168.3.131', '192.168.3.131', '192.168.3.131', '192.168.3.131', '192.168.3.131',
                               '192.168.3.131', '192.168.3.131', '192.168.3.131', '65.55.206.209', '72.14.213.147'],
                'Src_Port': ['57011', '80', '55950', '80', '52152', '443', '443', '52152', '443', '443',
                            '443', '443', '443', '443', '443', '443', '443', '443', '443', '443',
                            '443', '443', '443', '55953', '52152'],
                'Dst_Port': ['80', '57011', '80', '55950', '443', '52152', '52152', '443', '52152', '52152',
                            '52152', '52152', '52152', '52152', '52152', '52152', '52152', '52152', '52152', '52152',
                            '52152', '52152', '52152', '80', '443'],
                'Timestamp': [1295981542.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0,
                             1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0,
                             1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0,
                             1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0, 1295981543.0],
                'Retransmission': [False, False, False, False, False, False, False, False, False, False,
                                  False, False, False, False, False, False, False, False, False, False,
                                  False, False, False, False, False],
                'Reset_Flag': [False, False, False, False, False, False, False, False, False, False,
                              False, False, False, False, False, False, False, False, False, False,
                              False, False, False, False, False]
            })
            
            data = test_data
            st.success("Loaded test dataset!")

        if not data.empty:
            with st.spinner("Running anomaly detection..."):
                analyzed_data = detect_anomalies(data)

            with tab1:
                st.subheader("Anomaly Detection Results")
                analyze_anomalies(analyzed_data)
                
                st.subheader("Anomaly Visualization")
                plot_anomalies(analyzed_data)
                
            with tab2:
                analyze_tls_patterns(analyzed_data)
                
            with tab3:
                generate_recommendations(analyzed_data)

            st.sidebar.subheader("Download Results")
            if 'Anomaly' in analyzed_data.columns:
                anomalies = analyzed_data[analyzed_data['Anomaly'] == -1]
                if not anomalies.empty:
                    st.sidebar.dataframe(anomalies)
                    csv = anomalies.to_csv(index=False).encode('utf-8')
                    st.sidebar.download_button("Download Anomaly Report (CSV)", 
                                              data=csv, 
                                              file_name="analyzed_capture.csv", 
                                              mime='text/csv')
                else:
                    st.sidebar.info("No anomalies detected to download.")
        else:
            st.error("Failed to extract features from the PCAP file. Please try using the test dataset or check your PCAP file.")


if __name__ == "__main__":  
    main()