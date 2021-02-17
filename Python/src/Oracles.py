from Crypto.Cipher import AES
import secrets  # secure random number generation for generating keys and IV
import string
from Python.src.ByteManip import pad_block


def gibberish(nbytes: int) -> str:
    """Generates a string with an underlying number of bytes equal to the parameter
    which is cryptographically random human-readable gibberish
    :param nbytes the number of desired bytes in the string
    :return: a string of gibberish with nbytes number of bytes
    """
    return ''.join(secrets.choice(string.printable) for i in range(nbytes))


def rand_encrypt(plaintext: str, verbose: bool = False) -> (str, AES.MODE_ECB | AES.MODE_CBC):
    """
    Given a piece of plaintext, encrypt the plaintext using a random 16-bit AES key, and randomly choosing the mode
    from CBC mode or ECB mode.
    :param plaintext: A string to be encrypted
    :param verbose: A boolean to give information about the encryption for testing.
    :return: The plaintext parameter encrypted as cyphertext, and the encryption mode used (for testing).
    """
    # Generate random key
    rand_key = secrets.token_bytes(16)  # 16 bytes of cryptographically random bits
    # randomly append 5-10 bytes before and after the plaintext
    plaintext = gibberish((secrets.randbelow(6) + 5)) + plaintext + gibberish((secrets.randbelow(6) + 5))
    # pad the plaintext so that its length in bytes is a multiple of 16
    p_bytes = len(bytes(plaintext, 'utf-8'))
    if p_bytes % 16 != 0:
        needed_bytes = 16 - p_bytes % 16
        plaintext = pad_block(bytes(plaintext, "utf-8"), p_bytes + needed_bytes).decode("utf-8")
    # determine the encryption mode randomly, giving an equal chance of being ECB or CBC
    if secrets.randbits(1):  # equal change of 1 or 0, which is True or False
        cipher = AES.new(rand_key, AES.MODE_CBC, secrets.token_bytes(16))
        return cipher.encrypt(plaintext), AES.MODE_CBC
    else:
        cipher = AES.new(rand_key, AES.MODE_ECB)
        return cipher.encrypt(plaintext), AES.MODE_ECB


def detection_oracle(cyphertext: bytes) -> AES.MODE_ECB | AES.MODE_CBC:
    """
    Determines if some bytes were encrypted using AES ECB mode or AES CBC mode.
    Not guaranteed to have 100% accuracy if there are no repeating blocks in the plaintext.
    :param cyphertext: The cyphertext in question
    :return: The AES mode likely used to encrypt the cyphertext
    """
    for i in range(0, len(cyphertext), 16):  # iterating over every block
        if cyphertext[i:(i+16)] in cyphertext[(i+16):]:  # if the first block was ever repeated, likely ECB
            return AES.MODE_ECB
    return AES.MODE_CBC
