"""
utils.py: A Python script for defining helper functions for the protocol implementation.

Authors: mchris02@uw.edu, danieb36@uw.edu, rhamilt@uw.edu
Date: 10-25-23
"""
BIND_PORT = 12235
HEADER_SIZE = 12


def generate_header(payload_len: int,
                    psecret: int,
                    step: int,
                    student_id: int):
    """
    Helper function that generates header bytes for all TCP and UDP payloads sent to the server and
    sent by the server.

                0               1               2               3
            0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                          payload_len                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            psecret                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |              step             |   last 3 digits of student #  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :param payload_len: An integer representing the length of the payload to be sent.
    :param psecret: A byte sequence representing a secret key to be included in the header.
    :param step: An integer step number of the current protocol stage.
    :param student_id: An integer of the last 3 digits of the student's ID number.


    :returns: A byte sequence representing the constructed header, following the specified format.
    """
    return payload_len.to_bytes(4, byteorder='big') + \
        psecret.to_bytes(4, byteorder='big') + \
        step.to_bytes(2, byteorder='big') + \
        student_id.to_bytes(2, byteorder='big')


def check_header(header: bytes,
                 expected_length: int,
                 expected_secret: int,
                 expected_step: int = 1) -> bool:
    """
    Helper function that verifies the supplied header meets expected criteria

    This function verifies that the supplied header meets the expected criteria.

    :param header: A byte array representing the header data.
    :param expected_length: The expected payload length value for the header.
    :param expected_secret: The expected secret code for the header.
    :param expected_step: The expected step number for the header. (Default is 1)

    :return: True if the header is valid; False otherwise.
    """
    assert len(header) == HEADER_SIZE  # Sanity check that we supplied the correct values

    # Ensure payload is requested length
    if int.from_bytes(header[:4], byteorder='big') != expected_length:
        print("Invalid payload length specified in header")
        return False

    # Ensure secret code is correct
    if int.from_bytes(header[4:8], byteorder='big') != expected_secret:
        print("Invalid psecret specified in header")
        return False

    # Ensure step is correct
    if int.from_bytes(header[8:10], byteorder='big') != expected_step:
        print("Invalid step specified in header")
        return False

    return True


def pad_packet(packet: bytes) -> bytes:
    """
    Helper function that takes a packet and adds padding until it is 4-byte aligned

    :param: packet: the bytes object to transform

    :returns: A byte sequence that has been padded with extra zeros and its size is divisible by 4
    """
    length = len(packet)
    if length % 4 == 0:
        return packet
    packet += (b'\0' * (4 - length % 4))
    return packet
