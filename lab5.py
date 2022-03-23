import hashlib
import time
from time import strftime, gmtime
import socket

HDR_SZ = 24
BUF_SZ = 6400
BTC_IP = "108.7.47.223"
PORT = 8333
MY_IP = "127.0.0.1"
MAGIC = 'F9BEB4D9'
COMMAND_SIZE = 12
VERSION = 70015

BLOCK_NUM = 4121260 % 10000  # 1260
BLOCK_GENESIS = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f


def get_msg_header(command, payload):
    """
    Return massage header combined by magic, command, payload's size, and check_sum
    :param command: state of message
    :param payload: context of message
    :return: information of message
    """
    magic = bytes.fromhex(MAGIC)
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = uint32_t(len(payload))
    check_sum = get_checksum(payload)
    msg_header = b''.join((magic, command_name, payload_size, check_sum))

    return msg_header


def get_version_msg():
    """
    all information of the message
    :return: version's message
    """
    version = int32_t(VERSION)
    services = uint64_t(0)
    timestamp = int64_t(int(time.time()))
    addr_recv_services = uint64_t(1)
    addr_recv_ip_address = ipv6_from_ipv4(BTC_IP)
    addr_recv_port = uint16_t(PORT)
    addr_trans_services = uint64_t(0)
    addr_trans_ip_address = ipv6_from_ipv4(MY_IP)
    addr_trans_port = uint16_t(59550)
    nonce = uint64_t(0)
    user_agent_bytes = compactsize_t(0)
    start_height = int32_t(0)
    relay = bool_t(False)

    message = b''.join((version, services, timestamp, addr_recv_services, addr_recv_ip_address, addr_recv_port,
                        addr_trans_services, addr_trans_ip_address, addr_trans_port, nonce, user_agent_bytes,
                        start_height, relay))

    return message


def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    return int.from_bytes(b, byteorder='little', signed=False)


def get_checksum(b):
    """
    Return size of b
    :param b: message
    :return: size of b
    """
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]


def print_message(msg, text=None):
    """
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HDR_SZ:]
    # payloadSize = unmarshal_uint(msg[16:20])
    command = print_header(msg[:HDR_SZ], get_checksum(payload))
    if command == 'version':
        print_version_msg(payload)
    # FIXME print out the payloads of other types of messages, too
    if command == 'inv':
        print_inv_msg(msg)
    return command


def print_inv_msg(msg):
    """
    Display inventory message
    :param msg: contents of message
    :return: None
    """
    payload = msg[HDR_SZ:]
    payloadSize = unmarshal_uint(msg[16:20])

    count = payloadSize % 36
    count_msg = payload[0:count]
    rest = payload[count:]
    _, num_of_entries = unmarshal_compactsize(count_msg)

    for x in range(num_of_entries):
        entry = rest[0:36]
        print_inv_entries(entry)
        rest = rest[36:]


def print_inv_entries(b):
    """
    Display inventory entries
    :param b: entry of message
    :return: None
    """
    type = unmarshal_uint(b[:4])
    hash = b[4:]
    hash = swab_to_little(hash)

    # print(type)
    # print(hash.hex())


def swab_to_little(hash):
    """
    transfer big endian to small endian
    :param hash: contents of message
    :return: hash in format of small endian
    """
    temp = bytearray(hash).fromhex(hash.hex())
    temp.reverse()
    return temp


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command


def get_extra(b):
    """
    Return version's and verack's information
    :param b: contents of message
    :return: version's and verack's information
    """
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    i += uasz
    extra = b[i + 5:]
    recv_msg = b[0:i + 5]
    return extra, recv_msg


def char32_t(n):
    """
    >>> 'Ox{:064x}'.format(BLOCK_GENESIS)
    'Ox000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
    >>> char32_t(BLOCK_GENESIS).hex()
    '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'
    """
    return n.to_bytes(32, byteorder='little', signed=False)


def block_genesis_to_byte(block_genesis):
    """
    Return genesis transferred to byte
    :param block_genesis:
    :return: byte type of block genesis
    """
    return char32_t(block_genesis)


def getblocks_message(b, hash_count):
    """
     >>> get_blocks_msg([BLOCK_GENESIS]).hex()
    'f9beb4d9676574626c6f636b730000004500000084f4958d7f110100016fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000000000000000000000000000000000000000000000000000000000'
    :return:
    """

    version = int32_t(VERSION)
    hash_count = compactsize_t(hash_count)
    block_header = b
    stop_hash = char32_t(0)

    msg = b''.join((version, hash_count, block_header, stop_hash))
    header = get_msg_header('getblocks', msg)

    return b''.join((header, msg))


def remove_header_and_count(msg):
    """
    Return payload trimed from message
    :param msg: all contents of message
    :return: payload
    """
    payload = msg[HDR_SZ:]
    payloadSize = unmarshal_uint(msg[16:20])

    count = payloadSize % 36

    rest = payload[count:]
    return rest


def get_getdata_message(b, count):
    """
    Return the block message
    :param b: key of block
    :param count: number of hash Id
    :return: imformaiton of block
    """
    count = compactsize_t(count)
    msg = b''.join((count, b))

    header = get_msg_header('getdata', msg)

    return b''.join((header, msg))


def get_last_5_hash(msg):
    """
    Return the last 5 hash of inventory
    :param msg: inventory
    :return: the last 5 hash of inventory
    """
    payload = msg[HDR_SZ:]
    payloadSize = unmarshal_uint(msg[16:20])

    count = payloadSize % 36
    count_msg = payload[0:count]
    rest = payload[count:]
    _, num_of_entries = unmarshal_compactsize(count_msg)

    num_of_entries_to_cut = num_of_entries - 5
    num_of_bytes_to_cut = num_of_entries_to_cut * 36

    rest_5 = rest[num_of_bytes_to_cut:]

    return rest_5


def reverse_last_5(msg):
    """
    Reverse the last 5 hashes
    :param msg: last 5 hashes
    :return: reveres 5 hashes
    """
    one = msg[4:36]
    two = msg[40:72]
    three = msg[76:108]
    four = msg[112:144]
    five = msg[148:]

    reversed_last_5 = b''.join((five, four, three, two, one))

    return reversed_last_5


def get_my_block(msg, my_id):
    """
    Return information of the block corresponding to my SeattleU Id
    :param msg: inventory
    :param my_id: My SeattleU Id
    :return: information of the block corresponding to my SeattleU Id
    """
    payload = remove_header_and_count(msg)
    byte_to_cut = my_id * 36
    my_hash = payload[byte_to_cut: byte_to_cut + 36]

    hash = my_hash[4:]
    hash = swab_to_little(hash)
    print('my hash ID: ' + hash.hex())

    return my_hash


if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((BTC_IP, PORT))
        except socket.error as error:
            print("Failed to connect")
            exit(1)
        msg = get_version_msg()
        msg_header = get_msg_header('version', msg)
        print_message(msg_header + msg, "sending")
        s.send(msg_header + msg)
        data = s.recv(BUF_SZ)
        header = data[:24]
        rest = data[24:]
        verack, version = get_extra(rest)
        print_message(header + version, "received")

        print_message(verack, "sending")

        s.send(verack)
        print('My verack message')
        print_message(verack, "received")
        contents = s.recv(BUF_SZ)

        first_content = contents[:24]
        print_message(first_content, "received")
        second_content = contents[24:57]
        print_message(second_content, "received")
        third_content = contents[57:90]
        print_message(third_content, "received")
        forth_content = contents[90:122]
        print_message(forth_content, "received")
        fifth_content = contents[122:154]
        print_message(fifth_content, "received")

        block_0_byte = block_genesis_to_byte(BLOCK_GENESIS)
        block_msg = getblocks_message(block_0_byte, 1)
        s.send(block_msg)
        print_message(block_msg, "sending")

        inventory = b''
        for step in range(0, 3):
            i = 0
            inventory = b''
            while len(inventory) < 18027:
                data = s.recv(BUF_SZ)
                inventory += data

            print_message(inventory, "received")

            print_inv_msg(inventory)

            last_5_for_inv1 = get_last_5_hash(inventory)
            reversed_last_5_for_inv1 = reverse_last_5(last_5_for_inv1)

            if step < 2:
                block_msg_2 = getblocks_message(reversed_last_5_for_inv1, 5)
                s.send(block_msg_2)
                print_message(block_msg_2, "sending")

        print('\nThis is my block hash key')
        my_block_num = BLOCK_NUM % 500 - 1
        my_block = get_my_block(inventory, my_block_num)

        send_my_getdata = get_getdata_message(my_block, 1)
        print_message(send_my_getdata, "sending")
        s.send(send_my_getdata)
        my_block_msg = s.recv(BUF_SZ)
        print_message(my_block_msg, "received")