from scapy.all import *  # Import all Scapy modules for packet parsing
import ffmpeg            # Python wrapper for FFmpeg for video conversion

# File paths
PCAP_FILE = "SOMEIP-002.pcapng"
OUTPUT_BINARY_FILE = "output_stream.ts"      # Will store the raw NAL stream
VIDEO_FILE = "output.mp4"                    # Final playable video
VIDEO_FILE_FLIPPED = "outputFlipped.mp4"     # Horizontally flipped version

# Step 1: Read packets from a PCAP file
print("Reading packets...")
packets = rdpcap(PCAP_FILE)

# Filter packets that have:
# - An Ethernet layer
# - A VLAN tag (Dot1Q)
# - AVTP Type
filtered_packets = [
    pkt for pkt in packets
    if pkt.haslayer(Ether)
    and pkt.haslayer(Dot1Q)
    and pkt.getlayer(Dot1Q).type == 0x22F0
]

print("Modifying stream and writing to file")
with open(OUTPUT_BINARY_FILE, "wb") as f:
    for index, pkt in enumerate(filtered_packets):
        # Extract the raw bytes from the payload after the VLAN tag
        raw_data = bytes(pkt.getlayer(Dot1Q).payload)
        avtp_payload = None

        # If packet is too short, skip it
        if len(raw_data) < 22:
            print("Skipping packet ", index)
            continue

        # Extract payload length (2 bytes at offset 20–21)
        payload_size = raw_data[20:22]
        nal_msg_length = int.from_bytes(payload_size, byteorder='big')

        # Extract the actual AVTP payload (starting from offset 24)
        avtp_payload = raw_data[24:24 + nal_msg_length]

        # Handle NAL unit reassembly based on FU-A fragmentation
        FU_indicator = avtp_payload[0]   # First byte indicates fragment type
        FU_header = avtp_payload[1]      # Second byte has start/end flags
        s_flag = FU_header >> 7          # Start bit (1 if start of fragment)
        e_flag = (FU_header >> 6) & 0x1  # End bit (1 if end of fragment)

        # Case: SPS or PPS NAL units (e.g., 0x67 = SPS, 0x68 = PPS)
        if FU_indicator == 0x67 or FU_indicator == 0x68:
            # Prepend Annex B start code
            avtp_payload = b'\x00\x00\x00\x01' + avtp_payload

        # Case: IDR slice reassembly
        elif FU_indicator == 0x7c:
            byte_after_start = b'\x65'  # NAL header for IDR slice
            avtp_payload = avtp_payload[2:]  # Strip FU indicator + header
            if s_flag == 1:
                # Prepend start code and reconstructed NAL header
                avtp_payload = b'\x00\x00\x00\x01' + byte_after_start + avtp_payload

        # Case: non-IDR slice reassembly
        elif FU_indicator == 0x5c:
            byte_after_start = b'\x41'  # NAL header for non-IDR slice
            avtp_payload = avtp_payload[2:]  # Strip FU indicator + header
            if s_flag == 1:
                # Prepend start code and reconstructed NAL header
                avtp_payload = b'\x00\x00\x00\x01' + byte_after_start + avtp_payload

        else:
            # Skip unrecognized or malformed packet
            print("Skipping packet ", index)
            continue

        # Write the processed payload to the binary stream file
        if avtp_payload:
            f.write(avtp_payload)

# Step 3: Convert the NAL binary stream to MP4 using FFmpeg
print("Converting to video now")
ffmpeg.input(OUTPUT_BINARY_FILE).output(VIDEO_FILE).run()

# Step 4: Flip the video horizontally (e.g., for mirror effect)
stream = ffmpeg.input(VIDEO_FILE)
stream = ffmpeg.hflip(stream)
stream = ffmpeg.output(stream, VIDEO_FILE_FLIPPED)
ffmpeg.run(stream)