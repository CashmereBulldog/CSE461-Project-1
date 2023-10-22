import socket
from random import randint
from utils import generate_header, BIND_PORT

def check_header(header : bytes,
                 expected_length : int,
                 expected_secret : int) -> bool:
    """
        Check to make sure we got all the values we expected in the header
        
        :return: A boolean representing whether the header was valid
    """
    assert len(header) == 12 # Sanity check that we supplied the correct values

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
    num = length = udp_port = secret_a = student_id = None

    # Create UDP socket
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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
    else:
        print ("Client message was not formatted correctly")

    return (num, length, udp_port, secret_a, student_id)

def main():
    """ Main function that calls the stages for the server """
    num, length, udp_port, secret_a, student_id = stage_a()


if __name__ == "__main__":
    main()
