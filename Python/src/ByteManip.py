from base64 import b64encode


def is_hex(s: str) -> bool:
    """A method that checks if a given string is hex encoded.
    :param s:    The string in question.
    :returns true if s is hex encoded, false otherwise."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def hex_to_ascii(s: str) -> str:
    """A method that converts hex encoded strings to ascii encoded strings.
    :param s:    A hex encoded string
    :returns The parameter s encoded in ASCII format
    """
    return bytes.fromhex(s).decode('ascii')


def ascii_to_hex(s: str) -> str:
    """A method that converts hex encoded strings to ascii encoded strings.
    :param s:    An ascii encoded string
    :returns The parameter s encoded in hex format
    """
    return s.encode().hex()


def hex_to_base64(hex_string: str) -> str:
    """A method that takes a hex encoded string as input and returns the input string base64 encoded.
    :param hex_string:   A string of hex encoded characters.
    :returns A base64 encoded string which contains the same contents as the parameter string"""
    return b64encode(bytes.fromhex(hex_string)).decode()


def fixed_xor(str1: str, str2: str) -> str:
    """A method that takes two equal length hex strings and returns their XOR combination.
    Note that the order of the parameters do not matter to the output.
    :param str1: A hex encoded string.
    :param str2: A hex encoded string.
    :raises valueError: if the length of the inputs are not equal or not hex encoded.
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


def xor(message: bytes, key: bytes) -> bytes:
    """A method that takes two hex strings and returns their XOR combination.
    The length of the key relevant to the plaintext does not matter, but the order of the parameters do.
    :param message:  The bytes which make up the message to be encrypted/decrypted.
    :param key:      The bytes which make up the symmetric key
    :returns A set of bytes which is the XOR result of the parameters."""
    output: bytearray = bytearray(len(message))
    for i in range(0, len(output)):
        # modulus allows uneven key sizes, effectively repeating the key along the plaintext
        output[i] = message[i] ^ key[i % len(key)]
    return output


def count_set_bits(n: int) -> int:
    """Counts the number of set bits (bits represented by a 1 in binary) in a number
    using the Brian Kernighan Algorithm.
    :param  n:   The number to check the bits on
    :returns    The number of set bits in n
    """
    count = 0
    while n:
        n &= n-1
        count += 1
    return count


def pad_block(block: bytes, block_size: int) -> bytes:
    """
    Pads a plaintext block of bytes to the desired block size using PKCS#7 padding
    :param block:
    :param block_size:
    :return: The original block padded using PKCS#7 padding. If the block is already greater than or equal to the
                desired block size, then the original block parameter is returned unaltered.
    """
    pad = block_size - len(block)
    if pad <= 0:  # if already of desired size or greater, return the original block.
        return block

    output = bytearray(block_size)
    for i in range(0, len(block)):
        output[i] = block[i]  # copy over values to the resized block
    for i in range(len(block), block_size):  # iterate over non-copied spaces
        output[i] = pad  # Add padding to the end
    return output
