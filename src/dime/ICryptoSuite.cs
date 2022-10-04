//
//  ICryptoSuite.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System.Collections.Generic;

namespace DiME;

/// <summary>
/// 
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
    /// Generates a unique identifier for a key. The generated identifier is not sensitive and may be distributed without
    /// compromising the key.
    /// </summary>
    /// <param name="key">The key to generate an identifier for.</param>
    /// <returns>A unique identifier.</returns>
    byte[] GenerateKeyName(byte[][] key);

    /// <summary>
    /// Generates a cryptographic signature from a data byte array using the provided key.
    /// </summary>
    /// <param name="data">The data that should be signed.</param>
    /// <param name="key">The key to use when signing the data.</param>
    /// <returns>The signature as a byte array.</returns>
    byte[] GenerateSignature(byte[] data, byte[] key);
        
    /// <summary>
    /// Verifies a cryptographic signature for a data byte array using the provided key.
    /// </summary>
    /// <param name="data">The data that the signature should be verified towards.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="key">True is verified successfully, false if not.</param>
    /// <returns></returns>
    bool VerifySignature(byte[] data, byte[] signature, byte[] key);

    /// <summary>
    /// Generates a cryptographic key for the provided usage, if possible.
    /// </summary>
    /// <param name="capabilities">The intended capabilities of the generated key.</param>
    /// <returns>The generated key.</returns>
    byte[][] GenerateKey(List<KeyCapability> capabilities);
       
    /// <summary>
    /// Generates a shared secret from two keys or key pars. These keys must have {#{@link Key.Use#EXCHANGE}} listad as
    ///  usage. The server/issuer of a key exchange is always the initiator and the client/audience is always the
    ///  receiver (no matter on which side this method is called).
    /// </summary>
    /// <param name="clientKey">The key or key pair from the client (usually the audience).</param>
    /// <param name="serverKey">The key or key pair from the server (usually the issuer).</param>
    /// <param name="use">TThe intended use of the generated key.</param>
    /// <returns>The generated shared key.</returns>
    byte[] GenerateSharedSecret(byte[][] clientKey, byte[][] serverKey, List<KeyCapability> use);
        
    /// <summary>
    /// Encrypts a plain text byte array using the provided key.
    /// </summary>
    /// <param name="data">The byte array to encrypt.</param>
    /// <param name="key">The key to use for the encryption.</param>
    /// <returns>The encrypted cipher text as a byte array.</returns>
    byte[] Encrypt(byte[] data, byte[] key);
        
    /// <summary>
    /// Decrypts a cipher text byte array using the provided key.
    /// </summary>
    /// <param name="data">The byte array to decrypt.</param>
    /// <param name="key">The key to use for the decryption.</param>
    /// <returns>The plain text as a byte array.</returns>
    byte[] Decrypt(byte[] data, byte[] key);
       
    /// <summary>
    /// Generates a secure hash digest of the provided data.
    /// </summary>
    /// <param name="data">The data that should be hashed.</param>
    /// <returns>The hash digest of the provided data.</returns>
    byte[] GenerateHash(byte[] data);
    
}