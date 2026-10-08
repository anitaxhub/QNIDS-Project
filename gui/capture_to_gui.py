import threading
import time
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"Scapy load error: {e}")

from cic_flow_tracker import CICFlowTracker
from predict import predict, load_models


class PacketCapture:

    GREEN  = "#10b981"
    RED    = "#ef4444"
    ORANGE = "#f59e0b"

    PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

    def __init__(self, callback=None):
        self.callback     = callback
        self.is_running   = False
        self._thread      = None
        self.packet_count = 0
        self.flow_count   = 0

        # Load RF + Isolation Forest once. Safe to call again — no-ops if already loaded.
        load_models()

        # Live-mode tuned tracker: short timeout + min_packets=1 so that
        # single-packet flood/scan bursts still get classified quickly.
        self.flow_tracker = CICFlowTracker(
            callback=self._on_flow_complete,
            flow_timeout=5,
            min_packets=1
        )

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        print("Capture thread started")

    def stop(self):
        self.is_running = False
        print("Capture stopped")

    def _run(self):
        if not SCAPY_AVAILABLE:
            print("Scapy not available")
            return
        try:
            print("Sniffing started...")
            sniff(
                prn=self._process_packet,
                store=False,
                filter="ip",
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"Sniff error: {e}")

    def _process_packet(self, pkt):
        """Every packet lands here — hand it to the flow tracker.
        Classification happens later, in _on_flow_complete, once a flow
        closes (FIN/RST) or times out."""
        if not self.is_running or IP not in pkt:
            return

        self.packet_count += 1
        try:
            self.flow_tracker.process_packet(pkt)
        except Exception as e:
            print(f"Flow tracking error: {e}")

    def _on_flow_complete(self, features: dict):
        """
        Fired by CICFlowTracker when a flow finishes or times out.
        Runs on the sniffer thread / tracker's cleanup thread — NOT the
        GUI thread. self.callback must stay thread-safe on the GUI side
        (emit a pyqtSignal there, same as your existing wiring).
        """
        self.flow_count += 1
        ts = datetime.now().strftime("%H:%M:%S")

        src_ip   = features.get("_src_ip", "?")
        dst_ip   = features.get("_dst_ip", "?")
        src_port = features.get("_src_port", "?")
        dst_port = features.get("_dst_port", "?")
        protocol = self.PROTO_NAMES.get(features.get("_protocol"), "OTHER")

        total_pkts  = int(features.get("Total Fwd Packets", 0) +
                          features.get("Total Backward Packets", 0))
        total_bytes = int(features.get("Total Length of Fwd Packets", 0) +
                          features.get("Total Length of Bwd Packets", 0))

        try:
            result = predict(features)
        except Exception as e:
            print(f"Predict error: {e}")
            result = {"decision": "Suspicious / Zero-day", "label": "ERROR", "rf_confidence": 0.0}

        decision = result.get("decision", "Suspicious / Zero-day")
        conf     = int(result.get("rf_confidence", 0) * 100)
        missing  = result.get("missing_features", [])

        if decision == "Normal":
            status, color, label = "NORMAL", self.GREEN, "Normal Traffic"
        elif decision.startswith("Known Attack"):
            label  = decision.replace("Known Attack - ", "")
            status = f"ATTACK - {label}"
            color  = self.RED
        else:
            status, color, label = "SUSPICIOUS", self.ORANGE, "Zero-day / Unknown"

        info = (f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                f"{label} | {total_pkts}pkts/{total_bytes}B")

        # Debug line — watch this while testing. If `missing` is never empty,
        # your feature names don't match what the model was trained on.
        print(f"[FLOW {self.flow_count}] {ts} | {src_ip} | {status} ({conf}%) | missing={missing[:3]}")

        if self.callback:
            self.callback(ts, src_ip, info, status, color, conf)