from base64 import b64encode


def is_hex(s: str) -> bool:
    """A method that checks if a given string is hex encoded.
    :parameter s    The string in question.
    :returns true if s is hex encoded, false otherwise."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def hex_to_ascii(s: str) -> str:
    """A method that converts hex encoded strings to ascii encoded strings.
    :parameter s    A hex encoded string
    :returns The parameter s encoded in ASCII format
    """
    return bytearray.fromhex(s).decode()


def hex_to_base64(hex_string: str) -> str:
    """A method that takes a hex encoded string as input and returns the input string base64 encoded.
    :parameter hex_string   A string of hex encoded characters.
    :returns A base64 encoded string which contains the same contents as the parameter string"""
    return b64encode(bytes.fromhex(hex_string)).decode()


def fixed_xor(str1: str, str2: str) -> str:
    """A method that takes two equal length hex strings and returns their XOR combination.
    Note that the order of the parameters do not matter to the output.
    :parameter str1 A hex encoded string.
    :parameter str2 A hex encoded string.
    :raises valueError if the length of the inputs are not equal or not hex encoded.
    :returns a hex encoded str which is the XOR combination of the inputs"""
    # throw an error if the two strings are not the same length
    if len(str1) != len(str2):
        raise ValueError("Length of input strings do not match")
    # throw an error if the strings are not hex encoded
    if not is_hex(str1) or not is_hex(str2):
        raise ValueError("Input strings are not hex encoded")

    # convert to bytes
    bytes1: bytes = bytes.fromhex(str1)
    bytes2: bytes = bytes.fromhex(str2)
    # run XOR algorithm
    output = bytes(a ^ b for a, b in zip(bytes1, bytes2))

    return output.hex()


def xor(plaintext: str, key: str) -> str:
    """A method that takes two hex strings and returns their XOR combination.
    The length of the key relevant to the plaintext does not matter, but the order of the parameters do.
    :parameter plaintext    A hex encoded string to be encrypted.
    :parameter key  A hex encoded string to use as the symmetric encryption key.
    :raises valueError if the inputs are not hex encoded.
    :returns a hex encoded str which is the XOR combination of the inputs"""
    # throw an error if the strings are not hex encoded
    if not is_hex(plaintext) or not is_hex(key):
        raise ValueError("Input strings are not hex encoded")
    bytes1: bytes = bytes.fromhex(plaintext)
    bytes2: bytes = bytes.fromhex(key)
    output: bytearray = bytearray(bytes1)

    for i in range(0, len(output)):
        # modulus allows uneven key sizes, effectively repeating the key along the plaintext
        output[i] = bytes1[i] ^ bytes2[i % len(bytes2)]

    return output.hex()