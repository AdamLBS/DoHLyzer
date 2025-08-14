import csv
import os
from collections import defaultdict

from scapy.layers.tls.record import TLS, TLSApplicationData
from scapy.sessions import DefaultSession

from meter.features.context.packet_direction import PacketDirection
from meter.features.context.packet_flow_key import get_packet_flow_key
from meter.flow import Flow
from meter.time_series.processor import Processor
import time
import threading
from threading import RLock
_csv_global_lock = RLock()

EXPIRED_UPDATE = 20
GC_INTERVAL_SECS = 5

class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0

        print(f"🔧 FlowSession init - output_mode: {self.output_mode}, output_file: {self.output_file}")

        if self.output_mode == 'flow':
            print(f"📝 Opening CSV file: {self.output_file}")

            abs_path = os.path.abspath(self.output_file)
            csv_dir = os.path.dirname(abs_path) or "."
            os.makedirs(csv_dir, exist_ok=True)
            print(f"🔗 CSV absolute path (inside container): {abs_path}")

            self._csv_path = abs_path
            # Header requis si fichier inexistant ou vide au démarrage
            self._csv_needs_header = (not os.path.exists(abs_path)) or (os.path.getsize(abs_path) == 0)
            self._csv_global_lock = _csv_global_lock
            print("✅ CSV path registered; will open on each write")

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)
        self._gc_lock = threading.Lock()
        self._gc_thread_running = True
        self._gc_thread = threading.Thread(target=self._gc_loop, name="FlowSession-GC", daemon=True)
        self._gc_thread.start()
        super(FlowSession, self).__init__(*args, **kwargs)


    def _write_csv_row(self, data: dict):
        """Rouvre le CSV, écrit (header si nécessaire) puis flush+fsync, de façon thread-safe (process)."""
        with self._csv_global_lock:
            # (Re)détection header en fonction de la taille réelle du fichier
            needs_header = self._csv_needs_header
            try:
                needs_header = needs_header or (os.path.getsize(self._csv_path) == 0)
            except FileNotFoundError:
                needs_header = True

            # Ouverture à chaque écriture
            with open(self._csv_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if needs_header:
                    print("📝 Writing CSV header")
                    writer.writerow(list(data.keys()))
                    self._csv_needs_header = False

                print(f"📝 Writing CSV row {self.csv_line + 1}")
                writer.writerow(list(data.values()))
                f.flush()
                os.fsync(f.fileno())
                try:
                    size = os.path.getsize(self._csv_path)
                    print(f"💾 CSV flushed. Size now = {size} bytes @ {self._csv_path}")
                except Exception:
                    pass


    def _gc_loop(self):
        """
        Boucle de GC périodique: s'exécute même sans trafic.
        Appelle garbage_collect avec un latest_time basé sur time.time().
        """
        while self._gc_thread_running:
            try:
                self.garbage_collect(time.time())
            except Exception as e:
                print(f"⚠️ Periodic GC error: {e}")

            # Attendre avant le prochain passage
            time.sleep(GC_INTERVAL_SECS)

    def toPacketList(self):
        self._gc_thread_running = False
        if hasattr(self, "_gc_thread"):
            try:
                self._gc_thread.join(timeout=2.0)
            except Exception:
                pass
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        self.close()
        return super(FlowSession, self).toPacketList()

    def close(self):
        """Ferme les ressources (CSV, etc.)."""
        self._gc_thread_running = False
        if hasattr(self, "_gc_thread"):
            try:
                self._gc_thread.join(timeout=2.0)
            except Exception:
                pass
        try:
            with getattr(self, "_gc_lock", threading.Lock()):
                if hasattr(self, 'csv_file') and self.csv_file and not self.csv_file.closed:
                    self.csv_file.flush()
                    os.fsync(self.csv_file.fileno())
                    self.csv_file.close()
        except Exception as e:
            print(f"⚠️ Error while closing CSV file: {e}")

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != 'flow':
            if TLS not in packet:
                return

            if TLSApplicationData not in packet:
                return

            if len(packet[TLSApplicationData]) < 40:
                # PING frame (len = 34) or other useless frames
                return

        self.packets_count += 1

        # Creates a key variable to check
        packet_flow_key = get_packet_flow_key(packet, direction)
        flow = self.flows.get((packet_flow_key, count))

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            if flow is None:
                # If no flow exists create a new flow
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                # If the packet exists in the flow but the packet is sent
                # after too much of a delay than it is a part of a new flow.
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:

                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        flow.add_packet(packet, direction)

        if self.packets_count >= 4000 or (flow.duration > 120 and self.output_mode == 'flow'):
            print('Packet count: {}'.format(self.packets_count))
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        with self._gc_lock:
            print('🗑️ Garbage Collection Began. Flows = {}'.format(len(self.flows)))
            keys = list(self.flows.keys())
            for idx, k in enumerate(keys, start=1):
                flow = self.flows.get(k)
                if flow is None:
                    continue
                print(f"🔍 Processing flow {idx}/{len(keys)}: duration={flow.duration}s, "
                    f"latest_timestamp_diff={(latest_time - flow.latest_timestamp) if latest_time else 'None'}")

                if self.output_mode == 'flow':
                    condition1 = latest_time is None
                    condition2 = (latest_time is not None) and ((latest_time - flow.latest_timestamp) > EXPIRED_UPDATE)
                    condition3 = flow.duration > 20

                    print(f"📊 GC Flow conditions - time_none: {condition1}, expired>{EXPIRED_UPDATE}s: {condition2}, duration>20s: {condition3}")

                    if condition1 or condition2 or condition3:
                        data = flow.get_data()
                        # (remplacer tout ce qui écrit dans le CSV) par :
                        self._write_csv_row(data)
                        self.csv_line += 1
                        print("🗑️ Flow deleted from memory")
                        del self.flows[k]
                    else:
                        print(f"⏳ Flow not ready for writing - keeping in memory")
                else:
                    if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE:
                        output_dir = os.path.join(self.output_file, 'doh' if flow.is_doh() else 'ndoh')
                        os.makedirs(output_dir, exist_ok=True)
                        proc = Processor(flow)
                        flow_clumps = proc.create_flow_clumps_container()
                        flow_clumps.to_json_file(output_dir)
                        del self.flows[k]
            print('✅ Garbage Collection Finished. Flows remaining = {}, Written = {}'.format(len(self.flows), self.csv_line))


def generate_session_class(output_mode, output_file):
    return type('NewFlowSession', (FlowSession,), {
        'output_mode': output_mode,
        'output_file': output_file,
    })