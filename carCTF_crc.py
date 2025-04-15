import crcmod

messages_original = [0x74000300, 0xc1010300, 0x31020300, 0x84030300, 0xfe040300, 0x4b050300, 0xbb060300, 0x0e070300, 0x4f080300, 0xfa090300, 0x0a0a0300, 0xbf0b0300, 0xc50c0300, 0x700d0300, 0x800e0300]
guessed_payloads = []
crc = crcmod.mkCrcFun(poly=0x12F, initCrc=0xFF, rev=False)

def extract_checksum_from_messages(msgs):
    checksums = []
    payloads = []
    for m in msgs:
        tmp_chksum = m & 0xFF000000
        payloads.append(m - tmp_chksum)
        tmp_chksum = tmp_chksum >> 24
        checksums.append(tmp_chksum)
    return payloads, checksums
        
def shift_for_secret_payload(msgs):
    data_shifted = []
    for m in msgs:
        data_shifted.append(m << 8)
    return data_shifted

messages, expected_checksums = extract_checksum_from_messages(messages_original)
messages = shift_for_secret_payload(messages)

for y in range(0,15):
    initial_msg = messages[y]
    expected_crc = expected_checksums[y]

    for x in range(0, 256):
        gussed_payload = x
        checksum = crc((initial_msg+gussed_payload).to_bytes(4, byteorder='big'))
        checksum = checksum ^ 0xff
        if checksum == expected_crc:
            guessed_payloads.append(x)
            break



print("guessed secret bytes are (in int): {}".format(guessed_payloads))
print("so in hex the secret byte is: ", hex(guessed_payloads[0]))


challenge_message = 0x0f0300
challenge_message = challenge_message << 8

checksum_challenge = crc((challenge_message + guessed_payloads[0]).to_bytes(4, byteorder='big'))
checksum_challenge = checksum_challenge ^ 0xff
checksum_challenge = hex(checksum_challenge)
print("checksum is: {}".format(checksum_challenge))