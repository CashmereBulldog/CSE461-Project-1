"""
main.py: A Python script for a network communication client.

This script contains functions and logic for a network communication client that connects to a
server on the address "attu2.cs.washington.edu" and performs a series of stages involving UDP and
TCP communication. The stages include sending UDP packets, receiving acknowledgments, and extracting
various pieces of information from server responses.

The script also defines utility functions for generating header bytes for TCP and UDP payloads.

Authors: mchris02@uw.edu, danieb36@uw.edu, rhamilt@uw.edu
Date: 10-23-23
"""
import socket
import select
from utils import generate_header, pad_packet, BIND_PORT

# SERVER_ADDR = "attu2.cs.washington.edu"
SERVER_ADDR = 'localhost'
STUDENT_ID = 857
MAXIMUM_TIMEOUT = 5
MAXIMUM_TIMEOUT_STAGE_B = 0.5


def stage_a():
    """ Stage A for Part 1.
    Sends a single UDP packet containing the string "hello world" without the quotation marks to
    attu2.cs.washington.edu on port 12235

    :return: A tuple containing the following integers -
        - num: An integer representing a numerical value from the server's response.
        - length: An integer representing a length value from the server's response.
        - udp_port: An integer representing a port value from the server's response.
        - secret_a: An integer representing a secret key from the server's response.

    Note: If the connection to the server fails or there are issues receiving acks or the secret
    response, the function will return None for the respective values.
    """
    print("***** STAGE A *****")
    txt = b'hello world\0'
    num, length, udp_port, secret_a = None, None, None, None

    # Generate header
    packet = generate_header(len(txt), 0, 1, STUDENT_ID) + txt

    # Create new socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send a packet to the given port
    bytes_sent = 0
    while bytes_sent == 0:
        bytes_sent = sock.sendto(packet, (SERVER_ADDR, BIND_PORT))

    # Wait for a response back
    ready = select.select([sock], [], [], MAXIMUM_TIMEOUT)
    response_received = False
    while not response_received:
        if ready[0]:
            response_received = True
            result = sock.recv(28)
            num = int.from_bytes(result[12:16], byteorder='big')
            length = int.from_bytes(result[16:20], byteorder='big')
            udp_port = int.from_bytes(result[20:24], byteorder='big')
            secret_a = int.from_bytes(result[24:28], byteorder='big')
            print(f"num:      {num}\n"
                  f"length:   {length}\n"
                  f"udp_port: {udp_port}\n"
                  f"secret_a: {secret_a}")

    # Close socket
    print("***** STAGE A *****\n")
    sock.close()
    return (num, length, udp_port, secret_a)

def stage_b(num, length, udp_port, secret_a):
    """ Stage B for Part 1
    Sends num UDP packets to the server on port udp_port. Each data packet is size length+4. Each
    payload contains all zeros.

    :param num: An integer representing the number of UDP packets to send to the server.
    :param length: An integer representing the length of the payload in each packet.
    :param udp_port: An integer representing the port to which the socket connects.
    :param secret_a: An integer representing a secret key to be included in the packet headers.

    :return: A tuple containing the following integers -
        - tcp_port: An integer representing a TCP port value from the server's response.
        - secret_b: An integer representing a secret key from the server's response.

    Note: If the connection to the server fails or there are issues receiving acks or the secret
    response, the function will return None for the respective values.
    """
    print("***** STAGE B *****")

    # Create new socket
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send num packets
    for i in range(num):
        print ("Sending packet", i)
        packet = generate_header(length + 4, secret_a, 1, STUDENT_ID) \
            + i.to_bytes(4, byteorder='big') \
            + (b'\0' * length)

        # Pad payload of size(len + 4) so that it is divisible by 4
        packet = pad_packet(packet, len(packet))

        ack_received = False

        while not ack_received:
            try:
                bytes_sent = 0
                while bytes_sent == 0:
                    bytes_sent = sock_b.sendto(packet, (SERVER_ADDR, udp_port))
                # Listen for ack response
                ready = select.select([sock_b], [], [], MAXIMUM_TIMEOUT_STAGE_B)
                if ready[0]:
                    acked_packet_id = -1
                    try:
                        result = sock_b.recv(16)
                        acked_packet_id = int.from_bytes(result[12:16], byteorder='big')
                    except Exception as e:
                        print("The error on trying to receive data was ", e)

                    if acked_packet_id == i:
                        ack_received = True
                    else:
                        print("Unknown acked_packet_id received")
            except Exception as e:
                print("an error occurred:", e)

    # Listen for secret response
    tcp_port = None
    secret_b = None
    ready = select.select([sock_b], [], [], MAXIMUM_TIMEOUT)
    if ready[0]:
        result = sock_b.recv(20)
        tcp_port = int.from_bytes(result[12:16], byteorder='big')
        secret_b = int.from_bytes(result[16:20], byteorder='big')
        print(f"tcp_port: {tcp_port}\n"
              f"secret_b: {secret_b}")

    # Close socket
    sock_b.close()

    print("***** STAGE B *****\n")
    return tcp_port, secret_b


def stage_c(tcp_port, secret_b):
    """ Stage C for Part 1
    Server sends three integers: num2, len2, secretC, and a character c

    :param tcp_port: An integer representing the TCP port to connect to on the server.
    :param secret_a: An integer representing a secret key to be included in the packet headers.

    :return: A tuple containing the following integers -
        - num2: Integer from server's response.
        - len2: Integer from server's response.
        - secret_c: An integer representing a secret key from the server's response.
        - c: char from server's response.
    """
    print("***** STAGE C *****")
    num2, len2, secret_c, c = None, None, None, None

    # Connect socket
    sock_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_c.connect((SERVER_ADDR, tcp_port))

    """
    Technically the packet doesn't need to be made, but it doesn't really make
    sense that they would give us a secret_b that we don't need to send
    # Create packet
    packet = generate_header(0, secret_b, 1, STUDENT_ID) # No body, length is 0

    # Send message to server
    sock_c.send(packet)
    """

    ready = select.select([sock_c], [], [], MAXIMUM_TIMEOUT)
    if ready[0]:
        result = sock_c.recv(28)
        num2 = int.from_bytes(result[12:16], byteorder='big')
        len2 = int.from_bytes(result[16:20], byteorder='big')
        secret_c = int.from_bytes(result[20:24], byteorder='big')
        c = result[24].to_bytes(1, byteorder='big')
        print(f"num2:     {num2}\n"
              f"len2:     {len2}\n"
              f"secret_c: {secret_c}\n"
              f"c:        {c}")
    else:
        print("Did not receive TCP response")

    print("***** STAGE C *****\n")
    return num2, len2, secret_c, c, sock_c


def stage_d(tcp_port, num2, len2, secret_c, c, connection):
    """ Stage D for Part 1
    Sends num2 TCP packets to the server on port udp_port. Each data packet is size len2+4. Each
    payload contains all bytes of the character c.

    :param tcp_port: An integer representing the port to which the socket connects.
    :param num2: An integer representing the number of TCP packets to send to the server.
    :param len2: An integer representing the length of the payload in each packet.
    :param secret_c: An integer representing a secret key to be included in the packet headers.
    :param c: A character with which to fill the payload

    :return:
        - secret_d: An integer representing a secret key from the server's response.

    Note: If the connection to the server fails or there are issues receiving acks or the secret
    response, the function will return None for the respective values.
    """
    print("***** STAGE D *****")

    # Create new socket
    sock_d = connection

    # Send num packets
    for i in range(num2):
        packet = generate_header(len2, secret_c, 1, STUDENT_ID) + (c * len2)
        if len(packet) % 4 != 0:
            packet += (c * (4 - len(packet) % 4))
        print("Sending packet", i)
        packet = pad_packet(packet, len(packet))

        # Send message to server
        sock_d.send(packet)

    # Listen for secret response
    secret_d = None
    try:
        ready = select.select([sock_d], [], [], MAXIMUM_TIMEOUT)
        if ready[0]:
            result = sock_d.recv(16)
            secret_d = int.from_bytes(result[12:16], byteorder='big')
            print(f"secret_d: {secret_d}")
        else:
            print("failure, never received a response")
    except Exception as e:
        print("an error occurred:", e)
        sock_d.close()

    # Close socket
    sock_d.close()

    print("***** STAGE D *****\n")


def main():
    """ Main function that calls the stages for the client """
    num, length, udp_port, secret_a = stage_a()
    tcp_port, secret_b = stage_b(num, length, udp_port, secret_a)
    num2, len2, secret_c, c, sock_c = stage_c(tcp_port, secret_b)
    stage_d(tcp_port, num2, len2, secret_c, c, sock_c)


if __name__ == "__main__":
    main()
