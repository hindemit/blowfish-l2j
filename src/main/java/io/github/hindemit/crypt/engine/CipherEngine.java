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
    void init(final boolean forEncryption, final byte[] key);

    /**
     * Returns the block size of this cipher in bytes.
     *
     * @return the block size
     */
    int getBlockSize();

    /**
     * Processes a single block of data.
     *
     * @param input     the input byte array
     * @param inOffset  the offset into the input array
     * @param output    the output byte array
     * @param outOffset the offset into the output array
     */
    void processBlock(final byte[] input, final int inOffset, final byte[] output, final int outOffset);
}
