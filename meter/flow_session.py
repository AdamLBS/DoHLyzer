import csv
import os
from collections import defaultdict

from scapy.layers.tls.record import TLS, TLSApplicationData
from scapy.sessions import DefaultSession

from meter.features.context.packet_direction import PacketDirection
from meter.features.context.packet_flow_key import get_packet_flow_key
from meter.flow import Flow
from meter.time_series.processor import Processor

EXPIRED_UPDATE = 10


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0

        print(f"🔧 FlowSession init - output_mode: {self.output_mode}, output_file: {self.output_file}")

        if self.output_mode == 'flow':
            print(f"📝 Opening CSV file: {self.output_file}")
            self.csv_file = open(self.output_file, 'w')
            self.csv_writer = csv.writer(self.csv_file)
            print(f"✅ CSV writer created successfully")

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

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

        if self.packets_count >= 500 or (flow.duration > 60 and self.output_mode == 'flow'):
            print('Packet count: {}'.format(self.packets_count))
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        print('🗑️ Garbage Collection Began. Flows = {}'.format(len(self.flows)))
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)
            print(f"🔍 Processing flow {len(keys)-len(keys)+list(keys).index(k)+1}/{len(keys)}: duration={flow.duration}s, latest_timestamp_diff={(latest_time - flow.latest_timestamp) if latest_time else 'None'}")

            if self.output_mode == 'flow':
                condition1 = latest_time is None
                condition2 = latest_time and (latest_time - flow.latest_timestamp) > EXPIRED_UPDATE  
                
                print(f"📊 GC Flow conditions - time_none: {condition1}, expired>{EXPIRED_UPDATE}s: {condition2} ${latest_time - flow.latest_timestamp}s")
                
                if condition1 or condition2:
                    print("✅ Writing flow to CSV...")
                    data = flow.get_data()
                    if self.csv_line == 0:
                        print(f"📝 Writing CSV header")
                        self.csv_writer.writerow(data.keys())
                    print(f"📝 Writing CSV row {self.csv_line + 1}")
                    self.csv_writer.writerow(data.values())
                    # Check if the CSV file is open if not create it
                    if not hasattr(self, 'csv_file'):
                        self.csv_file = open(self.output_file, 'w', newline='')
                        self.csv_writer = csv.writer(self.csv_file)
                        print(f"CSV File not found, created new one: {self.output_file}")
                    self.csv_line += 1
                    
                    # 🔧 FORCER l'écriture sur disque
                    import sys
                    sys.stdout.flush()
                    if hasattr(self, 'csv_file'):
                        self.csv_file.flush()
                        import os
                        os.fsync(self.csv_file.fileno())
                    
                    print(f"🗑️ Flow deleted from memory")
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