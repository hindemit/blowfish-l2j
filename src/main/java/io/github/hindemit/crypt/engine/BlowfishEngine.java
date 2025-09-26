package io.github.hindemit.crypt.engine;

import io.github.hindemit.crypt.utils.BlowfishConstants;

import static io.github.hindemit.crypt.utils.BlowfishConstants.*;

/**
 * Implementation of the Blowfish block cipher engine.
 *
 * <p>This class provides encryption and decryption of data in 8-byte blocks using the
 * Blowfish algorithm. The cipher must be initialized with a key before any block processing.</p>
 *
 * <p>The cipher supports both encryption and decryption modes. The block size is
 * {@link BlowfishConstants#BLOCK_SIZE} bytes.</p>
 *
 * @author Hindemit
 */
public class BlowfishEngine implements CipherEngine {

    /** The Blowfish P-array and S-boxes (omitted for brevity). */
    private final int[] s0;
    private final int[] s1;
    private final int[] s2;
    private final int[] s3;
    private final int[] pArray;

    /** Indicates whether the cipher is currently set for encryption or decryption. */
    private boolean encrypting = false;

    /** The key currently in use by the cipher. */
    private byte[] workingKey = null;

    public BlowfishEngine() {
        s0 = new int[S_BOX_SK];
        s1 = new int[S_BOX_SK];
        s2 = new int[S_BOX_SK];
        s3 = new int[S_BOX_SK];
        pArray = new int[P_SZ];
    }

    /**
     * Initializes the cipher for encryption or decryption using the specified key.
     *
     * <p>This method sets the mode (encryption or decryption), stores the working key,
     * and initializes the subkeys and S-boxes by calling {@link #setKey(byte[])}.</p>
     *
     * @param encrypting {@code true} to initialize for encryption, {@code false} for decryption
     * @param key the secret key as a byte array
     */
    public void init(final boolean encrypting, final byte[] key) {
        this.encrypting = encrypting;
        this.workingKey = key;
        setKey(this.workingKey);
    }

    /**
     * Returns the block size of the cipher.
     *
     * @return the block size in bytes ({@link BlowfishConstants#BLOCK_SIZE})
     */
    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    /**
     * Processes a single block of data using the Blowfish cipher.
     *
     * <p>The method either encrypts or decrypts the block depending on the current mode
     * (determined by {@link #encrypting}). Input and output buffers must be at least
     * {@link BlowfishConstants#BLOCK_SIZE} bytes long from the specified offsets.</p>
     *
     * @param input     the input byte array containing data to be processed
     * @param inOffset  the starting offset in the input array
     * @param output    the output byte array where processed data will be stored
     * @param outOffset the starting offset in the output array
     * @throws IllegalStateException    if the cipher has not been initialized with a key
     * @throws IllegalArgumentException if the input or output buffer is too short
     */
    @Override
    public void processBlock(final byte[] input, final int inOffset, final byte[] output, final int outOffset) {
        checkState();
        checkBuffer(input, inOffset, "input");
        checkBuffer(output, outOffset, "output");

        if (encrypting) {
            encryptBlock(input, inOffset, output, outOffset);
        } else {
            decryptBlock(input, inOffset, output, outOffset);
        }
    }

    private void checkState() {
        if (workingKey == null) {
            throw new IllegalStateException("Blowfish not initialised");
        }
    }

    private void checkBuffer(byte[] buffer, int offset, String name) {
        if (offset < 0 || offset + BLOCK_SIZE > buffer.length) {
            throw new IllegalArgumentException(name + " buffer too short");
        }
    }

    /**
     * Encrypts a single block of data.
     *
     * @param input     the input byte array
     * @param inOffset  the offset in the input array
     * @param output    the output byte array
     * @param outOffset the offset in the output array
     */
    private void encryptBlock(final byte[] input, final int inOffset, final byte[] output, final int outOffset) {
        int xl = bytesTo32Bits(input, inOffset);
        int xr = bytesTo32Bits(input, inOffset + 4);

        int[] result = feistelTransform(xl, xr);

        bits32ToBytes(result[1], output, outOffset); // note the swap
        bits32ToBytes(result[0], output, outOffset + 4);
    }

    /**
     * Decrypts a single block of data.
     *
     * @param input     the input byte array
     * @param inOffset  the offset in the input array
     * @param output    the output byte array
     * @param outOffset the offset in the output array
     */
    private void decryptBlock(final byte[] input, final int inOffset, final byte[] output, final int outOffset) {
        int xl = bytesTo32Bits(input, inOffset);
        int xr = bytesTo32Bits(input, inOffset + 4);

        xl ^= pArray[ROUNDS + 1];
        for (int i = ROUNDS; i > 0; i -= 2) {
            xr ^= fFunction(xl) ^ pArray[i];
            xl ^= fFunction(xr) ^ pArray[i - 1];
        }
        xr ^= pArray[0];

        bits32ToBytes(xr, output, outOffset);
        bits32ToBytes(xl, output, outOffset + 4);
    }

    private int bytesTo32Bits(final byte[] b, final int i) {
        return ((b[i + 3] & 0xff) << 24) |
                ((b[i + 2] & 0xff) << 16) |
                ((b[i + 1] & 0xff) << 8) |
                (b[i] & 0xff);
    }

    private void bits32ToBytes(final int in, final byte[] b, final int offset) {
        b[offset] = (byte) in;
        b[offset + 1] = (byte) (in >> 8);
        b[offset + 2] = (byte) (in >> 16);
        b[offset + 3] = (byte) (in >> 24);
    }

    /**
     * Blowfish non-linear transformation function F.
     *
     * <p>Splits the 32-bit input into 4 bytes and mixes them
     * through S-boxes with addition and XOR operations.</p>
     *
     * @param x 32-bit input
     * @return transformed 32-bit output
     */
    private int fFunction(final int x) {
        int a = (x >>> 24) & 0xFF;   // most significant byte
        int b = (x >>> 16) & 0xFF;
        int c = (x >>> 8) & 0xFF;
        int d = x & 0xFF;            // least significant byte

        int result = (s0[a] + s1[b]);
        result = result ^ s2[c];
        result = result + s3[d];

        return result;
    }

    /**
     * Encrypts the given table in place using the current P-array and S-boxes.
     *
     * <p>This method is used during key expansion to generate
     * the subkeys (P-array and S-boxes) of Blowfish.</p>
     *
     * @param xl    left 32-bit half
     * @param xr    right 32-bit half
     * @param table the table (P-array or S-box) to update
     */
    private void processTable(int xl, int xr, final int[] table) {
        final int size = table.length;

        for (int s = 0; s < size; s += 2) {
            int[] result = feistelTransform(xl, xr);

            // Store the result in the table
            table[s] = result[1];
            table[s + 1] = result[0];

            // Swap for next iteration
            xr = xl;
            xl = table[s];
        }
    }

    /**
     * Initializes the Blowfish subkeys (P-array and S-boxes) with the given key.
     *
     * <p>This method performs the Blowfish key schedule:
     * <ul>
     *     <li>Copies the initial constants into P-array and S-boxes.</li>
     *     <li>XORs the key material into the P-array.</li>
     *     <li>Encrypts all-zero data and replaces the P-array and S-box entries
     *         with the resulting ciphertexts.</li>
     * </ul>
     * </p>
     *
     * @param key the secret key
     */
    private void setKey(final byte[] key) {
        // Step 1: Initialize subkeys with constants
        initializeSubkeys();

        // Step 2: XOR key material into P-array
        xorKeyWithPArray(key);

        // Step 3: Expand key by processing tables
        processTable(0, 0, pArray);
        processTable(pArray[P_SZ - 2], pArray[P_SZ - 1], s0);
        processTable(s0[S_BOX_SK - 2], s0[S_BOX_SK - 1], s1);
        processTable(s1[S_BOX_SK - 2], s1[S_BOX_SK - 1], s2);
        processTable(s2[S_BOX_SK - 2], s2[S_BOX_SK - 1], s3);
    }

    /**
     * Copies the Blowfish constants into P-array and S-boxes.
     */
    private void initializeSubkeys() {
        System.arraycopy(KS0, 0, s0, 0, S_BOX_SK);
        System.arraycopy(KS1, 0, s1, 0, S_BOX_SK);
        System.arraycopy(KS2, 0, s2, 0, S_BOX_SK);
        System.arraycopy(KS3, 0, s3, 0, S_BOX_SK);
        System.arraycopy(KP, 0, pArray, 0, P_SZ);
    }

    /**
     * XORs the secret key material into the P-array.
     *
     * @param key the secret key
     */
    private void xorKeyWithPArray(final byte[] key) {
        int keyLength = key.length;
        int kPos = 0;

        for (int i = 0; i < P_SZ; i++) {
            int word = 0;
            for (int j = 0; j < 4; j++) {
                word = (word << 8) | (key[kPos++] & 0xFF);
                if (kPos >= keyLength) {
                    kPos = 0;
                }
            }
            pArray[i] ^= word;
        }
    }

    /**
     * Encrypts (or transforms) a single 64-bit block using the P-array and F-function.
     *
     * @param xl initial left 32-bit word
     * @param xr initial right 32-bit word
     * @return a 2-element array containing the transformed [xl, xr]
     */
    private int[] feistelTransform(int xl, int xr) {
        // Initial whitening
        xl ^= pArray[0];

        // Perform all but final round (Feistel structure)
        for (int i = 1; i < ROUNDS; i += 2) {
            xr ^= fFunction(xl) ^ pArray[i];
            xl ^= fFunction(xr) ^ pArray[i + 1];
        }

        // Final whitening
        xr ^= pArray[ROUNDS + 1];

        return new int[]{xl, xr};
    }
}
