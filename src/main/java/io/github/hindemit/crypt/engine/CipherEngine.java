package io.github.hindemit.crypt.engine;

/**
 * Interface representing a generic cipher engine for block ciphers.
 *
 * @author Hindemit
 */
public interface CipherEngine {

    /**
     * Initializes the cipher with a given key.
     *
     * @param key the secret key as a byte array
     */
    void init(byte[] key);

    /**
     * Encrypts a single block of data.
     *
     * @param input     the input byte array containing plaintext
     * @param inOffset  the starting offset in the input array
     * @param output    the output byte array to hold ciphertext
     * @param outOffset the starting offset in the output array
     */
    void encryptBlock(byte[] input, int inOffset, byte[] output, int outOffset);

    /**
     * Decrypts a single block of data.
     *
     * @param input     the input byte array containing ciphertext
     * @param inOffset  the starting offset in the input array
     * @param output    the output byte array to hold plaintext
     * @param outOffset the starting offset in the output array
     */
    void decryptBlock(byte[] input, int inOffset, byte[] output, int outOffset);

    /**
     * Returns the block size of this cipher in bytes.
     *
     * @return the block size
     */
    int getBlockSize();
}
