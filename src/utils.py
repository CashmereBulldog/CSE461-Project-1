def generate_header(payload_len : int,
                    psecret : int,
                    step : int ,
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
