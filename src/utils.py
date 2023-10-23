"""
utils.py: A Python script for defining helper functions for the protocol implementation.

Authors: mchris02@uw.edu, danieb36@uw.edu, rhamilt@uw.edu
Date: 10-23-23
"""
BIND_PORT = 12235

def generate_header(payload_len : int,
                    psecret : int,
                    step : int,
                    student_id : int):
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

def pad_packet(packet : bytes, length : int) -> bytes:
    """
    Helper function that takes a packet and makes its length divisible by 4

    :param: packet: the bytes object to transform
    :param: length: the current length of the packet

    :returns: A byte sequence that has been padded with extra zeros to be divisible by 4
    """
    if length % 4 == 0:
        return packet
    packet += (b'\0' * (4 - length % 4))
    return packet
