//
//  ICryptoSuite.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System.Collections.Generic;
using DiME.Capability;

namespace DiME.Crypto;

/// <summary>
/// An interface that classes need to implement to provide cryptographic services.
/// </summary>
public interface ICryptoSuite
{
    /// <summary>
    /// Returns the name of the cryptographic suite, usually a short series of letters, i.e. STN for the standard
    /// Dime cryptography suite.
    /// </summary>
    /// <returns>Identifier of the cryptographic suite.</returns>
    string Name();
        
    /// <summary>
    /// Generates a unique name for a key. The generated name is not sensitive and may be distributed without
    /// compromising the key.
    /// </summary>
    /// <param name="key">The key to generate a name for.</param>
    /// <returns>A unique name.</returns>
   string GenerateKeyName(Key key);

    /// <summary>
    /// Generates a cryptographic signature from an item using the provided key.
    /// </summary>
    /// <param name="item">The item that should be signed.</param>
    /// <param name="key">The key to use when signing the data.</param>
    /// <returns>The signature as a byte array.</returns>
    byte[] GenerateSignature(Item item, Key key);
        
    /// <summary>
    /// Verifies a cryptographic signature for a data byte array using the provided key.
    /// </summary>
    /// <param name="item">The item that the signature should be verified towards.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="key">True is verified successfully, false if not.</param>
    /// <returns></returns>
    bool VerifySignature(Item item, byte[] signature, Key key);

    /// <summary>
    /// Generates a cryptographic key for the provided usage, if possible.
    /// </summary>
    /// <param name="capabilities">The intended capabilities of the generated key.</param>
    /// <returns>The generated key.</returns>
    Key GenerateKey(List<KeyCapability> capabilities);
       
    /// <summary>
    /// Generates a shared secret from two keys or key pars. These keys must have capability 'Exchange'.
    /// The server/issuer of a key exchange is always the initiator and the client/audience is always the receiver
    /// (no matter on which side this method is called).
    /// </summary>
    /// <param name="clientKey">The key or key pair from the client (usually the audience).</param>
    /// <param name="serverKey">The key or key pair from the server (usually the issuer).</param>
    /// <param name="capabilities">TThe intended use of the generated key.</param>
    /// <returns>The generated shared key.</returns>
    Key GenerateSharedSecret(Key clientKey, Key serverKey, List<KeyCapability> capabilities);
        
    /// <summary>
    /// Encrypts a plain text byte array using the provided key.
    /// </summary>
    /// <param name="data">The byte array to encrypt.</param>
    /// <param name="key">The key to use for the encryption.</param>
    /// <returns>The encrypted cipher text as a byte array.</returns>
    byte[] Encrypt(byte[] data, Key key);
        
    /// <summary>
    /// Decrypts a cipher text byte array using the provided key.
    /// </summary>
    /// <param name="data">The byte array to decrypt.</param>
    /// <param name="key">The key to use for the decryption.</param>
    /// <returns>The plain text as a byte array.</returns>
    byte[] Decrypt(byte[] data, Key key);
       
    /// <summary>
    /// Generates a secure hash digest of the provided data.
    /// </summary>
    /// <param name="data">The hash digest of the provided data, encoded as a string.</param>
    /// <returns>The hash digest of the provided data.</returns>
    string GenerateHash(byte[] data);

    /// <summary>
    /// Encodes a key from a byte array to a string.
    /// </summary>
    /// <param name="rawKey">The raw key byte-array to encode.</param>
    /// <param name="claim">The name of the claim to encode the key for, should be {@link Claim#KEY} or {@link Claim#PUB}</param>
    /// <returns>The encoded key.</returns>
    string EncodeKeyBytes(byte[] rawKey, Claim claim);

    /// <summary>
    /// Decodes an encoded key to a byte array.
    /// </summary>
    /// <param name="encodedKey">The encoded key.</param>
    /// <param name="claim">The name of the claim to decode the key for, should be {@link Claim#KEY} or {@link Claim#PUB}</param>
    /// <returns>The decoded key.</returns>
    byte[] DecodeKeyBytes(string encodedKey, Claim claim);

}