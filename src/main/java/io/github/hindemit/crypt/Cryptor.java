package io.github.hindemit.crypt;

/**
 * Interface representing a generic cryptographic processor.
 *
 * <p>Implementations of this interface provide methods to encrypt,
 * decrypt, and verify the integrity of data using a checksum.</p>
 *
 * @author Hindemit
 */
public interface Cryptor {

    /**
     * Computes a checksum or verifies the integrity of the given data.
     *
     * @param raw the input data to verify the checksum
     * @return {@code true} if the data passes the checksum verification, {@code false} otherwise
     */
    boolean checksum(final byte[] raw);

    /**
     * Decrypts the given data.
     *
     * @param raw the encrypted data to decrypt
     * @return the decrypted data as a byte array
     */
    byte[] decrypt(final byte[] raw);

    /**
     * Encrypts the given data.
     *
     * @param raw the plain data to encrypt
     * @return the encrypted data as a byte array
     */
    byte[] crypt(final byte[] raw);
}
