//
//  Crypto.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using DiME.Capability;

namespace DiME.Crypto;

/// <summary>
/// Cryptographic helper methods, which also abstracts the rest of the implementation from any underlying
/// cryptographic library used.
/// </summary>
public class Crypto
{
        
    #region --- PUBLIC ---
        
    /// <summary>
    /// Default constructor.
    /// </summary>
    public Crypto()
    {
        RegisterCryptoSuite(new NaClSuite(NaClSuite.SuiteName));
        RegisterCryptoSuite(new LegacySuite(LegacySuite.LegacyDscSuite));
        RegisterCryptoSuite(new LegacySuite(LegacySuite.LegacyStnSuite));
        _defaultSuiteName = NaClSuite.SuiteName;
    }

    /// <summary>
    /// Holds the default cryptographic suite name. This will be used when no suite is specified for cryptographic
    /// operations. This will be set by default to the Dime standard cryptographic suite (STN).
    /// </summary>
    public string DefaultSuiteName
    {
        get
        {
            lock(_lock)
                return _defaultSuiteName;
        }
        set
        {
            lock (_lock)
            {
                if (!HasCryptoSuite(value))
                    throw new ArgumentException($"Invalid cryptographic suite: {value}.");
                _defaultSuiteName = value;
            }
        }
    }

    /// <summary>
    /// Will generate a unique key name from the provided key. This will be used to extract which key was used to
    /// create a signature. How a key name is generated is specific to the cryptographic suite used.
    /// </summary>
    /// <param name="key">The key to generate an name for.</param>
    /// <returns>A key name, as a String.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public string GenerateKeyName(Key key)
    {
        if (key is null) { throw new ArgumentNullException(nameof(key), "Unable to generate, key must not be null."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        return impl.GenerateKeyName(key);
    }

    /// <summary>
    /// Generates a cryptographic signature from a provided item and key.
    /// </summary>
    /// <param name="item">The item that should be signed.</param>
    /// <param name="key">The key that should be used to sign the item.</param>
    /// <returns>The signature that was generated.</returns>
    /// <exception cref="ArgumentException"></exception>
    public Signature GenerateSignature(Item item, Key key)
    {
        if (item is null) { throw new ArgumentNullException(nameof(item), "Unable to generate signature, item to sign must not be null."); }
        if (key?.Secret == null) { throw new ArgumentNullException(nameof(key), "Unable to generate signature, key or secret key must not be null."); }
        if (!key.HasCapability(KeyCapability.Sign)) { throw new ArgumentException("Unable to generate signature, provided key does not specify 'Sign' capability."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        var bytes = impl.GenerateSignature(item, key);
        return new Signature(bytes, item.IsLegacy ? null : GenerateKeyName(key));
    }

    /// <summary>
    /// Verifies a cryptographic signature of an item using provided signature and key.
    /// </summary>
    /// <param name="item">The item to verify the signature with.</param>
    /// <param name="signature">The signature to verify with.</param>
    /// <param name="key">The key to use when verifying.</param>
    /// <returns>True if verified successfully, false otherwise.</returns>
    /// <exception cref="ArgumentException"></exception>
    public bool VerifySignature(Item item, Signature signature, Key key)
    {
        if (item is null) { throw new ArgumentNullException(nameof(item), "Unable to verify signature, item to sign must not be null."); }
        if (signature is null) { throw new ArgumentNullException(nameof(signature), "Unable to verify signature, item to sign must not be null."); }
        if (key?.Public == null) { throw new ArgumentNullException(nameof(key), "Unable to verify signature, key or public key must not be null."); }
        if (!key.HasCapability(KeyCapability.Sign)) { throw new ArgumentException("Unable to verify, provided key does not specify 'Sign' capability."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        return impl.VerifySignature(item, signature.Bytes, key);
    }
    
    /// <summary>
    /// Generates a cryptographic key of a provided type. If no cryptographic suite is provided, then the default suite
    /// will be used.
    /// </summary>
    /// <param name="capabilities">The capabilities of the key to generate.</param>
    /// <param name="suiteName">The cryptographic suite that should be used when generating the key, may be null for default suite.</param>
    /// <returns>The generated key.</returns>
    public Key GenerateKey(List<KeyCapability> capabilities, string suiteName = null)
    {
        if (capabilities == null || capabilities.Count == 0) { throw new ArgumentNullException(nameof(capabilities), "Key usage must not be null or empty."); }
        var impl = CryptoSuite(suiteName ?? DefaultSuiteName);
        return impl.GenerateKey(capabilities);
    }

    /// <summary>
    /// Generates a shared secret from two keys with use 'Exchange'. The initiator of the key exchange is always the
    /// server and the receiver of the key exchange is always the client (no matter on which side this method is
    /// called).
    /// </summary>
    /// <param name="clientKey">The client key to use (the receiver of the exchange).</param>
    /// <param name="serverKey">The server key to use (the initiator of the exchange).</param>
    /// <param name="capabilities">The capabilities that should be specified for the generated key.</param>
    /// <returns>The generated shared secret key.</returns>
    /// <exception cref="ArgumentException"></exception>
    public Key GenerateSharedSecret(Key clientKey, Key serverKey, List<KeyCapability> capabilities)
    {
        if (!clientKey.HasCapability(KeyCapability.Exchange) || !serverKey.HasCapability(KeyCapability.Exchange)) { throw new ArgumentException("Unable to generate, provided keys do not specify 'Exchange' use."); }
        if (!clientKey.CryptoSuiteName.Equals(serverKey.CryptoSuiteName)) { throw new ArgumentException("Unable to generate, both keys must be generated using the same cryptographic suite."); }
        var impl = CryptoSuite(clientKey.CryptoSuiteName);
        return impl.GenerateSharedSecret(clientKey, serverKey, capabilities);
    }

    /// <summary>
    /// Encrypts a plain text byte array using the provided key.
    /// </summary>
    /// <param name="plainText">The byte array to encrypt.</param>
    /// <param name="key">The key to use for the encryption.</param>
    /// <returns>The encrypted cipher text.</returns>
    /// <exception cref="ArgumentException"></exception>
    public byte[] Encrypt(byte[] plainText, Key key)
    {
        if (plainText == null || plainText.Length == 0) { throw new ArgumentNullException(nameof(plainText), "Plain text to encrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new ArgumentNullException(nameof(key),"Key must not be null."); }
        if (!key.HasCapability(KeyCapability.Encrypt)) { throw new ArgumentException("Unable to encrypt, provided key does not specify 'Encrypt' use."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        return impl.Encrypt(plainText, key);
    }

    /// <summary>
    /// Decrypts a cipher text byte array using the provided key.
    /// </summary>
    /// <param name="cipherText">The byte array to decrypt.</param>
    /// <param name="key">The key to use for the decryption.</param>
    /// <returns>The decrypted plain text.</returns>
    /// <exception cref="ArgumentException"></exception>
    public byte[] Decrypt(byte[] cipherText, Key key)
    {
        if (cipherText == null || cipherText.Length == 0) { throw new ArgumentNullException(nameof(cipherText), "Cipher text to decrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new ArgumentNullException(nameof(key),"Key must not be null."); }
        if (!key.HasCapability(KeyCapability.Encrypt)) { throw new ArgumentException("Unable to decrypt, provided key does not specify 'Encrypt' use."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        return impl.Decrypt(cipherText, key);
    }
    
    /// <summary>
    /// Generates a secure hash of a byte array. If no cryptographic suite is provided, then the default suite
    /// will be used.
    /// </summary>
    /// <param name="data">The data that should be hashed.</param>
    /// <param name="suiteName">The cryptographic suite that should be used to generate the hash.</param>
    /// <returns>The generated secure hash, encoded as a string</returns>
    public string GenerateHash(byte[] data, string suiteName = null)
    {
        var impl = CryptoSuite(suiteName ?? DefaultSuiteName);
        return impl.GenerateHash(data);
    }

    /// <summary>
    /// Encodes a key from a byte array to a string. The encoding format is determined by the cryptographic suite
    /// specified.
    /// </summary>
    /// <param name="rawKey">The raw key bytes to encode.</param>
    /// <param name="claim">The name of the claim to encode the key for, must be Claim.Key or Claim.Pub.</param>
    /// <param name="suiteName">The cryptographic suite to use.</param>
    /// <returns>The encoded key.</returns>
    public string EncodeKeyBytes(byte[] rawKey, Claim claim, string suiteName)
    {
        var impl = CryptoSuite(suiteName);
        return impl.EncodeKeyBytes(rawKey, claim);
    }

    /// <summary>
    /// Decodes an encoded key to a byte array. The encoded format must match the cryptographic suite specified to be
    /// successful.
    /// </summary>
    /// <param name="encodedKey">The encoded key.</param>
    /// <param name="claim">The name of the claim to encode the key for, must be Claim.Key or Claim.Pub.</param>
    /// <param name="suiteName">The cryptographic suite to use.</param>
    /// <returns>The decoded key.</returns>
    public byte[] DecodeKeyBytes(string encodedKey, Claim claim, string suiteName)
    {
        var impl = CryptoSuite(suiteName);
        return impl.DecodeKeyBytes(encodedKey, claim);
    }
    
    /// <summary>
    /// Registers a cryptographic suite. If a cryptographic suite is already register with the same name as the
    /// provided cryptographic suite then IllegalArgumentException will be thrown.
    /// </summary>
    /// <param name="impl">The implementation instance of ICryptoSuite.</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public void RegisterCryptoSuite(ICryptoSuite impl) {
        if (impl == null) { throw new ArgumentNullException(nameof(impl), "Instance of ICrypto implementation must not be null."); }
        var name = impl.Name();
        if (_suiteMap == null)
            _suiteMap = new Dictionary<string, ICryptoSuite>();
        else if (_suiteMap.ContainsKey(name))
            throw new ArgumentException("Cryptographic suite already exists with name: " + name, nameof(impl));
        _suiteMap.Add(name, impl);
    }

    /// <summary>
    /// Indicates if a cryptographic suite with the provided name is supported (and registered).
    /// </summary>
    /// <param name="name">The name of the cryptographic suite to check for.</param>
    /// <returns>True if supported, false if not.</returns>
    public bool HasCryptoSuite(string name)
    {
        return _suiteMap != null && _suiteMap.ContainsKey(name);
    }

    /// <summary>
    /// Returns a set of the names of all registered cryptographic suites.
    /// </summary>
    /// <returns>Set of registered cryptographic suites, names only.</returns>
    public List<string> AllCryptoSuites()
    {
        //if (_suiteMap == null) return null;
        return _suiteMap.Keys.ToList();
    }

    #endregion

    #region -- PRIVATE --

    private Dictionary<string, ICryptoSuite> _suiteMap;
    private string _defaultSuiteName;
    private readonly object _lock = new();

    private ICryptoSuite CryptoSuite(string name)
    {
        if (_suiteMap == null || _suiteMap.Count == 0) { throw new InvalidOperationException("Unable to perform cryptographic operations, no suites registered."); }
        var impl = _suiteMap[name];
        if (impl == null) { throw new InvalidOperationException($"Unable to find cryptographic suite with name: {name}."); }
        return impl;
    }
        
    #endregion

}