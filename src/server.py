import socket
from random import randint
from random import choice
from string import ascii_letters
from urllib import response
import threading

from src import client
from utils import generate_header, BIND_PORT, pad_packet

MAXIMUM_TIMEOUT = 3  # Socket will close if no response is received for this many seconds


def check_header(header: bytes,
                 expected_length: int,
                 expected_secret: int) -> bool:
    """
        Check to make sure we got all the values we expected in the header

        :return: A boolean representing whether the header was valid
    """
    assert len(header) == 12  # Sanity check that we supplied the correct values

    # Ensure payload is requested length
    if int.from_bytes(header[:4], byteorder='big') != expected_length:
        return False

    # Ensure secret code is correct
    if int.from_bytes(header[4:8], byteorder='big') != expected_secret:
        return False

    # Ensure client sending is always step 1
    if int.from_bytes(header[8:10], byteorder='big') != 1:
        return False

    return True


def stage_a():
    """ Stage A for Part 2.
    Client sends a single UDP packet containing the string "hello world" without the quotation marks
    to this server, server responds with an ack of randomly generated numbers

    :return: A tuple containing the following integers -
        - num: An randint representing a numerical value from the server's response.
        - length: A randint representing a length value from the server's response.
        - udp_port: A randint representing a port value from the server's response.
        - secret_a: A randint representing a secret key from the server's response.
        - student_id: The student id of the client to ensure we're getting the
          same messages
    """
    print("Start of server stage A")
    num = length = udp_port = secret_a = student_id = None

    # Create UDP socket
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("listener is ", listener)

    # Bind to address and IP
    listener.bind(("localhost", BIND_PORT))

    # Receive a single message
    message, client_addr = listener.recvfrom(24)

    if check_header(message[:12], expected_length=len(b'hello world\0'), expected_secret=0):
        num, length, udp_port, secret_a = randint(0, 20), randint(0, 100), randint(12236, 13000), randint(0, 256)

        student_id = int.from_bytes(message[10:12], byteorder='big')

        ack = generate_header(16, 0, step=2, student_id=student_id) \
              + num.to_bytes(4, byteorder='big') \
              + length.to_bytes(4, byteorder='big') \
              + udp_port.to_bytes(4, byteorder='big') \
              + secret_a.to_bytes(4, byteorder='big')

        listener.sendto(ack, client_addr)
        print(f"num:      {num}\n"
              f"length:   {length}\n"
              f"udp_port: {udp_port}\n"
              f"secret_a: {secret_a}")
    else:
        print("Client message was not formatted correctly")

    listener.close()

    # listener.close()
    print("calling stage_b")
    stage_b(num, length, udp_port, secret_a, student_id)


def stage_b_talk_to_client(server, message, client_addr):
    server.sendto(message, client_addr)


def stage_b(num, length, udp_port, secret_a, student_id):
    print("Start of server stage B")
    print("num is ", num)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind to address and IP
    server.bind(("localhost", udp_port))
    print("Listening on port:", udp_port)

    iteration = 0
    secret_b = None
    tcp_port = None
    threads = []
    while True:
        print("iteration is ", iteration)
        padding = 4 - (length % 4)
        data, client_addr = server.recvfrom(12 + (length + 4) + padding)

        if len(data) % 4 != 0:
            print("Length of packet is not divisible by 4 :", len(data))
            break

        header_check = check_header(data[:12], length + 4, secret_a)
        if not header_check:
            print('badly formatted header')
            break

        # Payload: First 4 bytes contains  integer identifying the packet.
        # The first packet should have this identifier set to 0,
        # while the last packet should have its counter set to num-1
        first_4_bytes = int.from_bytes(data[12:16], byteorder="big")
        print(first_4_bytes)
        if first_4_bytes != iteration:
            print("Iteration is incorrect")
            break

        # Check that the rest of the packet is filled with zeros:
        for item in data[16:]:
            if item != 0:
                print("ERROR: remainder of packet should be filled with zeros!")
                break

        # Randomly decide if ack should be sent.
        to_send = randint(0, 2)
        if to_send > 0:
            # Include the payload identifier of packet in ack.
            message = generate_header(4, secret_a, 2, student_id) + data[12:16]
            t = threading.Thread(None, stage_b_talk_to_client(server, message, client_addr), None, (client,), None)
            t.start()
            threads.append(t)
            for thread in threads:
                thread.join()
            # Only increase iteration if ack was sent.
            iteration = iteration + 1

        if iteration == num:
            # All num packets were received. Send tcp port number, and a secretB.
            print("iteration == num, exiting loop")
            secret_b = randint(0, 500)
            tcp_port = randint(1024, 65353)
            break

    # All num packets were received. Send tcp port number, and a secretB.
    if iteration != num:
        print("ERROR: Not all packets were received")

    for thread in threads:
        thread.join()

    # Send the port number and secretB
    print("tcp_port is ", tcp_port)
    print("secret_b is ", secret_b)

    message = generate_header(4, secret_a, 2, student_id) + tcp_port.to_bytes(4, byteorder='big') + secret_b.to_bytes(4,                                                                                                                byteorder='big')
    server.sendto(message, client_addr)

    stage_c(tcp_port, secret_b, student_id)


def stage_c(tcp_port: int, secret_b: int, student_id: int):
    print("Start of server stage C")
    """ Stage C for Part 2.

    Server sends three integers: num2, len2, secretC, and a character c

    :param tcp_port: An integer representing the TCP port to connect to on the server.
    :param secret_b: An integer representing a secret key to be included in the packet headers.
    """
    # Create TCP socket
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind to address and IP
    listener.bind(("localhost", tcp_port))
    listener.listen(MAXIMUM_TIMEOUT)

    while True:
        try:
            connection, address = listener.accept()
            print("Connection from ", address)

            # Send data back to the client
            num2, len2, secret_c, c = randint(0, 20), randint(0, 100), randint(0, 256), choice(ascii_letters)
            print("Random generated:\n"
                  f"num2:     {num2}\n"
                  f"len2:     {len2}\n"
                  f"secret_c: {secret_c}\n"
                  f"c:        {c}")
            response = generate_header(13, secret_b, step=2, student_id=student_id) \
                       + num2.to_bytes(4, byteorder='big') \
                       + len2.to_bytes(4, byteorder='big') \
                       + secret_c.to_bytes(4, byteorder='big') \
                       + ord(c).to_bytes(1, byteorder='big')
            response = pad_packet(response, len(response))
            connection.send(response)

            # Call Stage D after successful conversation, not closing socket
            # stage_d(num2, len2, secret_c, c, connection)
        except:
            # Close the connection
            listener.close()
    stage_d(num_2, len_2, secret_c, c, student_id, connection)


def stage_d(num2, len2, secret_c, c, student_id, connection):
    print("Start of server stage d")
    packets_received = 0
    valid = True
    while packets_received < num2:
        msg = connection.recv(12 + len2)  # Header plus length
        if check_header(msg[:12], len2, secret_c):
            valid &= msg[12:] != c * len2
            if not valid: break
        else:
            print("Client message was not formatted correctly")

    if valid:
        secret_d = randint(0, 256)
        ack = generate_header(4, secret_c, step=2, student_id=student_id) \
              + secret_d.to_bytes(4, byteorder='big')
        connection.send(ack)
    else:
        print("Client message was not formatted correctly")

    print("Closing TCP connection")
    connection.close()

    print("Done!")


def main():
    """ Main function that calls the stages for the server """
    stage_a()


if __name__ == "__main__":
    main()
