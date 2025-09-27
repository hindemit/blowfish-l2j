package io.github.hindemit.crypt;

import io.github.hindemit.crypt.engine.BlowfishEngine;
import io.github.hindemit.crypt.engine.CipherEngine;

public class L2jBlowfishCryptor implements Cryptor {

    private final CipherEngine crypt;
    private final CipherEngine decrypt;

    public L2jBlowfishCryptor(final String key) {
        byte[] keyBytes = key.getBytes();

        crypt = new BlowfishEngine();
        crypt.init(true, keyBytes);

        decrypt = new BlowfishEngine();
        decrypt.init(false, keyBytes);
    }

    /**
     * Verifies and updates the checksum of the given byte array.
     *
     * <p>The checksum is computed as the XOR of 4-byte (int) blocks
     * across the array, excluding the last 8 bytes. The result is written
     * back into the last 4 bytes before the trailing 4 bytes of the array.</p>
     *
     * @param raw the byte array to verify and update
     * @return {@code true} if the stored checksum matches the computed one,
     * {@code false} otherwise
     */
    @Override
    public boolean checksum(final byte[] raw) {
        long checksum = 0;
        int count = raw.length - 8;

        int i = 0;
        for (; i < count; i += 4) {
            checksum ^= toInt(raw, i);
        }

        long stored = toInt(raw, i);
        writeInt(raw, i, checksum);

        return stored == checksum;
    }

    /**
     * Decrypts the given byte array using the underlying cipher.
     *
     * <p>Input must be a multiple of the cipher block size (8 bytes for Blowfish).</p>
     *
     * @param raw the encrypted data
     * @return the decrypted data as a new byte array
     */
    @Override
    public byte[] decrypt(final byte[] raw) {
        return applyCipher(raw, decrypt);
    }

    /**
     * Encrypts the given byte array using the underlying cipher.
     *
     * <p>Input must be a multiple of the cipher block size (8 bytes for Blowfish).</p>
     *
     * @param raw the plain data to encrypt
     * @return the encrypted data as a new byte array
     */
    @Override
    public byte[] crypt(final byte[] raw) {
        return applyCipher(raw, crypt);
    }

    /**
     * Applies the given cipher engine to process the data block by block.
     *
     * @param raw   the input data (must be a multiple of the block size)
     * @param engine the cipher engine (encryption or decryption)
     * @return the transformed data
     * @throws IllegalArgumentException if the input length is not a multiple of the block size
     */
    private byte[] applyCipher(final byte[] raw, final CipherEngine engine) {
        final int blockSize = engine.getBlockSize();

        if (raw.length % blockSize != 0) {
            throw new IllegalArgumentException("Invalid data length: must be multiple of " + blockSize);
        }

        final byte[] result = new byte[raw.length];
        final int blocks = raw.length / blockSize;

        for (int i = 0; i < blocks; i++) {
            int offset = i * blockSize;
            engine.processBlock(raw, offset, result, offset);
        }

        return result;
    }

    /**
     * Converts 4 bytes from the given array starting at offset
     * into a 32-bit integer (little-endian order).
     */
    private int toInt(final byte[] data, final int offset) {
        return (data[offset] & 0xFF) |
                ((data[offset + 1] & 0xFF) << 8) |
                ((data[offset + 2] & 0xFF) << 16) |
                ((data[offset + 3] & 0xFF) << 24);
    }

    /**
     * Writes a 32-bit integer into the given array at the specified offset
     * (little-endian order).
     */
    private void writeInt(final byte[] data, final int offset, final long value) {
        data[offset] = (byte) (value & 0xFF);
        data[offset + 1] = (byte) ((value >>> 8) & 0xFF);
        data[offset + 2] = (byte) ((value >>> 16) & 0xFF);
        data[offset + 3] = (byte) ((value >>> 24) & 0xFF);
    }
}
