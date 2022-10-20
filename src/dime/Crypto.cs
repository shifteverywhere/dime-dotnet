//
//  Crypto.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DiME.Exceptions;

namespace DiME;

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
        var impl = new StandardSuite();
        RegisterCryptoSuite(impl);
        _defaultSuiteName = impl.Name();
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
            lock(_lock)
                _defaultSuiteName = value;
        }
    }

    /// <summary>
    /// Will generate a unique key identifier from the provided key. This will be used to extract which key was used to
    /// create a signature. How a key identifier is generated is specific to the cryptographic suite used.
    /// </summary>
    /// <param name="key">The key to generate an identifier for.</param>
    /// <returns>A key identifier, as a String.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public string GenerateKeyIdentifier(Key key)
    {
        if (key is null) { throw new ArgumentNullException(nameof(key), "Unable to generate, key must not be null."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        var name = impl.GenerateKeyName(new byte[][] { key.KeyBytes(Claim.Key), key.KeyBytes(Claim.Pub) });
        return name is not null ? Utility.ToHex(name) : null;
    }

    /// <summary>
    /// Generates a cryptographic signature from a data string.
    /// </summary>
    /// <param name="data">The string to sign.</param>
    /// <param name="key">The key to use for the signature.</param>
    /// <returns>The signature that was generated.</returns>
    /// <exception cref="ArgumentException"></exception>
    public byte[] GenerateSignature(string data, Key key)
    {
        if (!key.HasCapability(KeyCapability.Sign)) { throw new ArgumentException("Unable to sign, provided key does not specify Sign usage."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        return impl.GenerateSignature(Encoding.UTF8.GetBytes(data), key.KeyBytes(Claim.Key));
    }

    /// <summary>
    /// Verifies a cryptographic signature for a data string.
    /// </summary>
    /// <param name="data">The string that should be verified with the signature.</param>
    /// <param name="signature">The signature that should be verified.</param>
    /// <param name="key">The key that should be used for the verification.</param>
    /// <returns>True if verified successfully, false otherwise.</returns>
    /// <exception cref="ArgumentException"></exception>
    public bool VerifySignature(string data, byte[] signature, Key key)
    {
        if (!key.HasCapability(KeyCapability.Sign)) { throw new ArgumentException("Unable to sign, provided key does not specify Sign usage."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        var pub = key.KeyBytes(Claim.Pub);
        return impl.VerifySignature(Encoding.UTF8.GetBytes(data), signature, key.KeyBytes(Claim.Pub));
    }

    /// <summary>
    /// Generates a shared secret from two keys with use 'Exchange'. The initiator of the key exchange is always the
    /// server and the receiver of the key exchange is always the client (no matter on which side this method is
    /// called).
    /// </summary>
    /// <param name="clientKey">The client key to use (the receiver of the exchange).</param>
    /// <param name="serverKey">The server key to use (the initiator of the exchange).</param>
    /// <param name="use">The use that should be specified for the generated key.</param>
    /// <returns>The generated shared secret key.</returns>
    /// <exception cref="ArgumentException"></exception>
    public byte[] GenerateSharedSecret(Key clientKey, Key serverKey, List<KeyCapability> use)
    {
        if (!clientKey.HasCapability(KeyCapability.Exchange) || !serverKey.HasCapability(KeyCapability.Exchange)) { throw new ArgumentException("Unable to generate, provided keys do not specify 'Exchange' use."); }
        if (!clientKey.CryptoSuiteName.Equals(serverKey.CryptoSuiteName)) { throw new ArgumentException("Unable to generate, both keys must be generated using the same cryptographic suite."); }
        var impl = CryptoSuite(clientKey.CryptoSuiteName);
        var rawClientKeys = new byte[][] { clientKey.KeyBytes(Claim.Key), clientKey.KeyBytes(Claim.Pub) };
        var rawServerKeys = new byte[][] { serverKey.KeyBytes(Claim.Key), serverKey.KeyBytes(Claim.Pub) };
        return impl.GenerateSharedSecret(rawClientKeys, rawServerKeys, use);
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
        if (!key.HasCapability(KeyCapability.Encrypt)) { throw new ArgumentException("Unable to encrypt, provided key does not specify 'Encrypt' use."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        return impl.Encrypt(plainText, key.KeyBytes(Claim.Key));
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
        if (!key.HasCapability(KeyCapability.Encrypt)) { throw new ArgumentException("Unable to decrypt, provided key does not specify 'Encrypt' use."); }
        var impl = CryptoSuite(key.CryptoSuiteName);
        return impl.Decrypt(cipherText, key.KeyBytes(Claim.Key));
    }

    /// <summary>
    /// Generates a cryptographic key of a provided type. This will use the cryptographic suite that is set as the
    /// default.
    /// </summary>
    /// <param name="capabilities">The capabilities of the key to generate.</param>
    /// <returns>The generated key.</returns>
    public byte[][] GenerateKey(List<KeyCapability> capabilities)
    {
        return GenerateKey(capabilities, DefaultSuiteName);
    }

    /// <summary>
    /// Generates a cryptographic key of a provided type.
    /// </summary>
    /// <param name="capabilities">The capabilities of the key to generate.</param>
    /// <param name="suiteName">The cryptographic suite that should be used when generating the key.</param>
    /// <returns>The generated key.</returns>
    public byte[][] GenerateKey(List<KeyCapability> capabilities, string suiteName)
    {
        var impl = CryptoSuite(suiteName);
        return impl.GenerateKey(capabilities);
    }

    /// <summary>
    /// Generates a secure hash of a byte array. This will use the cryptographic suite that is set as the default.
    /// </summary>
    /// <param name="data">The data that should be hashed.</param>
    /// <returns>The generated secure hash.</returns>
    public byte[] GenerateHash(byte[] data)
    {
        return GenerateHash(data, DefaultSuiteName);
    }

    /// <summary>
    /// Generates a secure hash of a byte array.
    /// </summary>
    /// <param name="data">The data that should be hashed.</param>
    /// <param name="suiteName">The cryptographic suite that should be used to generate the hash.</param>
    /// <returns>The generated secure hash.</returns>
    public byte[] GenerateHash(byte[] data, string suiteName)
    {
        ICryptoSuite impl = CryptoSuite(suiteName);
        return impl.GenerateHash(data);
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