#!/usr/bin/env python

import argparse
import os

from scapy.all import load_layer
from scapy.sendrecv import AsyncSniffer

from meter.flow_session import generate_session_class


def create_sniffer(input_file, input_interface, output_mode, output_file):
    assert (input_file is None) ^ (input_interface is None)

    pcap_path = input_file if input_file is not None else None
    NewFlowSession = generate_session_class(output_mode, output_file, pcap_file=pcap_path)


    if input_file is not None:
        return AsyncSniffer(offline=input_file, filter='ip and tcp port 443', prn=None, session=NewFlowSession, store=False)
    else:
        return AsyncSniffer(iface=input_interface, filter='ip and tcp port 443', prn=None,
                            session=NewFlowSession, store=False)


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-n', '--online', '--interface', action='store', dest='input_interface',
                             help='capture online data from INPUT_INTERFACE')
    input_group.add_argument('-f', '--offline', '--file', action='store', dest='input_file',
                             help='capture offline data from INPUT_FILE')

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument('-c', '--csv', '--flow', action='store_const', const='flow', dest='output_mode',
                              help='output flows as csv')
    output_group.add_argument('-s', '--json', '--sequence', action='store_const', const='sequence', dest='output_mode',
                              help='output flow segments as json')

    parser.add_argument('output', help='output file name (in flow mode) or directory (in sequence mode)')
    args = parser.parse_args()

    load_layer('tls')

    session_class = generate_session_class(
        args.output_mode, args.output, pcap_file=args.input_file
    )
    sniffer = AsyncSniffer(
        offline=args.input_file,
        iface=args.input_interface,
        session=session_class,
        filter='ip and tcp port 443'
    )

    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == '__main__':
    main()
