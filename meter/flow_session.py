import csv
import os
from collections import defaultdict

from scapy.layers.tls.record import TLS, TLSApplicationData
from scapy.sessions import DefaultSession

from meter.features.context.packet_direction import PacketDirection
from meter.features.context.packet_flow_key import get_packet_flow_key
from meter.flow import Flow
from meter.time_series.processor import Processor

EXPIRED_UPDATE = 40


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0

        print(f"🏗️ Initializing FlowSession...")
        print(f"🔧 Checking if output_mode exists: {hasattr(self, 'output_mode')}")
        
        if hasattr(self, 'output_mode'):
            print(f"📝 Output mode: {self.output_mode}")
            if self.output_mode == 'flow':
                print(f"📂 Opening CSV file: {self.output_file}")
                try:
                    self.output_handle = open(self.output_file, 'w', newline='')
                    self.csv_writer = csv.writer(self.output_handle)
                    print("✅ CSV writer initialized successfully")
                except Exception as e:
                    print(f"❌ Error opening CSV file: {e}")
            else:
                print("📝 Not flow mode, no CSV writer needed")
        else:
            print("⚠️ output_mode not set yet, will be set by generate_session_class")

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)
        self.pcap_file = kwargs.get('pcap_file', 'unknown')

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        print(f"📦 Packet received: {packet.summary()}")
        count = 0
        direction = PacketDirection.FORWARD

        print(f"🔧 Debug - output_mode: {self.output_mode}")
        
        if self.output_mode != 'flow':
            print("🔍 Mode != 'flow', checking TLS filters...")
            if TLS not in packet:
                print("❌ No TLS layer, returning")
                return

            if TLSApplicationData not in packet:
                print("❌ No TLSApplicationData, returning")
                return

            if len(packet[TLSApplicationData]) < 40:
                print("❌ TLSApplicationData too small, returning")
                # PING frame (len = 34) or other useless frames
                return
        else:
            print("✅ Mode is 'flow', no TLS filter applied")

        self.packets_count += 1
        print(f"✅ Packet count incremented to: {self.packets_count}")

        # Creates a key variable to check
        print(f"🔑 Creating packet flow key...")
        try:
            packet_flow_key = get_packet_flow_key(packet, direction)
            print(f"✅ Packet flow key created: {packet_flow_key}")
        except Exception as e:
            print(f"❌ Error creating packet flow key: {e}")
            return
        except Exception as e:
            print(f"❌ Error creating packet flow key: {e}")
            return
        
        flow = self.flows.get((packet_flow_key, count))
        print(f"📊 Looking for flow with key: ({packet_flow_key}, {count})")
        print(f"📊 Flow found: {flow is not None}")

        # If there is no forward flow with a count of 0
        if flow is None:
            print("🔄 No forward flow found, checking reverse direction...")
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
            print(f"📊 Reverse flow found: {flow is not None}")

            if flow is None:
                print("🆕 No flow found, creating new forward flow...")
                # If no flow exists create a new flow
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction, self.pcap_file)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow
                print(f"✅ New flow created and stored with key: ({packet_flow_key}, {count})")

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                print("⏰ Reverse flow expired, creating new version...")
                # If the packet exists in the flow but the packet is sent
                # after too much of a delay than it is a part of a new flow.
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction, self.pcap_file)
                        self.flows[(packet_flow_key, count)] = flow
                        print(f"✅ New expired flow created with count: {count}")
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            print("⏰ Forward flow expired, creating new version...")
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:

                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction, self.pcap_file)
                    self.flows[(packet_flow_key, count)] = flow
                    print(f"✅ New expired forward flow created with count: {count}")
                    break
        else:
            print("✅ Using existing flow")

        print(f"🔄 Adding packet to flow...")
        flow.add_packet(packet, direction)
        print(f"✅ Flow updated: {flow} (duration: {flow.duration}s)")

        # ✅ CONDITIONS OPTIMISÉES POUR ML
        condition1 = self.packets_count % 50 == 0        # Tous les 50 paquets (vs 10000)
        condition2 = flow.duration > 2                   # 2 secondes (vs 120s)
        condition3 = len(self.flows) > 20                # Éviter surcharge mémoire
        condition4 = flow.packet_count >= 10             # Flows avec assez de data
        
        print(f"🗑️ GC conditions - packets%50: {condition1}, duration>2s: {condition2}, flows>20: {condition3}, packets>=10: {condition4}")
        
        if condition1 or condition2 or condition3 or condition4:
            print('🗑️ Triggering garbage collection!')
            print('Packet count: {}'.format(self.packets_count))
            print('Flow count: {}'.format(len(self.flows)))
            print('Garbage collecting...')
            self.garbage_collect(packet.time)
        else:
            print(f"⏳ No GC yet - packet {self.packets_count}/50, duration {flow.duration}s/2s, flows {len(self.flows)}/20")

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        print('🗑️ Garbage Collection Began. Flows = {}'.format(len(self.flows)))
        keys = list(self.flows.keys())
        flows_processed = 0
        flows_written = 0
        
        for k in keys:
            flow = self.flows.get(k)
            flows_processed += 1
            print(f"🔍 Processing flow {flows_processed}/{len(keys)}: duration={flow.duration}s, latest_timestamp_diff={latest_time - flow.latest_timestamp if latest_time else 'None'}")

            if self.output_mode == 'flow':
                condition1 = latest_time is None
                condition2 = latest_time and (latest_time - flow.latest_timestamp) > 5  # 5 sec (vs 40s)
                condition3 = flow.duration > 1                                          # 1 sec (vs 90s)
                condition4 = flow.packet_count >= 5                                     # Au moins 5 paquets
                
                print(f"📊 GC Flow conditions - time_none: {condition1}, expired>5s: {condition2}, duration>1s: {condition3}, packets>=5: {condition4}")
                
                if condition1 or condition2 or condition3 or condition4:
                    print(f"✅ Writing flow to CSV...")
                    try:
                        data = flow.get_data()
                        if self.csv_line == 0:
                            print("📝 Writing CSV headers")
                            self.csv_writer.writerow(data.keys())
                        print(f"📝 Writing CSV row {self.csv_line + 1}")
                        self.csv_writer.writerow(data.values())
                        self.csv_line += 1
                        flows_written += 1
                        
                        # Forcer l'écriture sur disque pour le ML pipeline
                        if hasattr(self, 'output_handle') and self.output_handle:
                            self.output_handle.flush()
                        
                        del self.flows[k]
                        print(f"🗑️ Flow deleted from memory")
                    except Exception as e:
                        print(f"❌ Error writing flow to CSV: {e}")
                else:
                    print(f"⏳ Flow not ready for writing")
            else:
                print(f"🔍 Processing JSON mode flow...")
                if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE:
                    output_dir = os.path.join(self.output_file, 'doh' if flow.is_doh() else 'ndoh')
                    os.makedirs(output_dir, exist_ok=True)
                    proc = Processor(flow)
                    flow_clumps = proc.create_flow_clumps_container()
                    flow_clumps.to_json_file(output_dir)
                    del self.flows[k]
                    flows_written += 1
                    
        print(f'✅ Garbage Collection Finished. Flows remaining = {len(self.flows)}, Written = {flows_written}')


def generate_session_class(output_mode, output_file, pcap_file=None):
    class NewFlowSession(FlowSession):
        def __init__(self, *args, **kwargs):
            kwargs['pcap_file'] = pcap_file
            super().__init__(*args, **kwargs)

    NewFlowSession.output_mode = output_mode
    NewFlowSession.output_file = output_file
    return NewFlowSession
