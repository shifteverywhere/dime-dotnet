# DiME C#/.NET reference implementation

DiME (Data Integrity Message Envelope) is a powerful universal data format that is built for secure, and integrity-protected communication between entities in a trusted network. It is built with modern thinking and ease of use throughout. Although it can be used together with X.509 certificates, it has its own built-in public key-based entity identification through a trusted chain. This makes it equally suitable as an alternative to certificate-based PKIs.

Potential use cases for DiME include:

- IoT networks for distributing sensitive data, including collected sensor data, operation instructions, patches, and firmware updates
- Automatic processing where audit trails and results logging is crucial
- Peer-to-peer messaging where each response gets linked using secure cryptographic bonds
- Distribution of sensitive information and records within large networks
- Establishing application-based networks with trusted entities

The strength of DiME is its modular format, where applications and networks can pick and mix to suit their own specific needs. At the same time, it removes the need to build complicated mechanisms for authenticating senders and validating payloads of data.

More information can be found on the official documentation page: [docs](https://docs.dimeformat.io)

## Code examples

Here are a few simple examples of how to use DiME. Note that there are much more features available, refer to the official documentation for further details.

### Key generation example

Creating a public-key pair to use for creating Identity Issuing Requests (IIRs), signing messages, or issuing other identities:

```
var key = Key.Generate(KeyCapability.Sign);
```

### Self-issuing example

Create a self-issued, or root, identity with the capability to issue other identities:

```
var subjectId = Guid.NewGuid();
var key = Key.Generate(KeyCapability.Sign);            
var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
var iir = IdentityIssuingRequest.Generate(key, caps);
var root = iir.SelfIssue(subjectId, Dime.ValidFor1Year * 10, key, "example-system");
```

### Issue an identity from the root Identity

Issue a new identity from a root identity (the one created above):

```
var subjectId = Guid.NewGuid();
var key = Key.Generate(KeyCapability.Sign);
var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
var iir = IdentityIssuingRequest.Generate(key, caps);
var client = iir.Issue(subjectId, Dime.ValidFor1Year, key, root, true, caps);
```

This will create a trust chain. Normally the IIR is generated on the client-side and sent to the server to request a new identity. The generated key should be kept on the client-side and stored securely. The key is needed when generating and verifying messages.

In the above example, the client would be asking for an identity with the capabilities Generic and Identify. Generally, Identify should be given when the client has been authenticated, and when authentication is not don,e only Generic would be used. This is system and application-specific.

### Verify the trust of an identity

Verify the trust of a client's identity using a local key ring:

```
Dime.KeyRing.Put(root);
client.Verify();
```

Verify the trust of a client's identity from a specified identity:

```
client.Verify(root);
```

Note that the above example has the same effect as the previous example. However, being able to specify which identity to verify from may be useful in more complex trust structures.

### Claims

DiME uses the notion of claims. A claim is a fact or piece of information about the item, or the owner of the item. The Item class has methods that allow accessing and setting claims. These include GetClaim, PutClaim, and RemoveClaim.

To get a claim:
```
client.GetClaim<Guid>(Claim.Sub); // Will return the subject id of the client item
```

To set a claim:
```
client.PutClaim<Guid>(Claim.Sub, "5e52c1e0-a185-4422-a4fa-4f1870a15464"); // Will set the subject id of the client item
```

### Message example

Creating a signed message with a payload:

```
var payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
var message = new Message(client.GetClaim<Guid>(Claim.Sub), root.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
message.SetPayload(payload);
message.Sign(key);
var exported = message.Export();
```

The message is signed with a previously created key, which is associated with the issuer (sender). Finally, the message is exported to a DiME encoded string that can be sent to the audience (receiver).

### End-to-end encrypted message example

Creating a signed message with an end-to-end encrypted payload:

```
var localKey = Key.Generate(KeyCapability.Exchange);
var message = new Message(client.GetClaim<Guid>(Claim.Sub), root.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."), localKey, remoteKey);
message.Sign(key);
var exported = message.Export();
```

The remoteKey used in the example has to be distributed earlier. Notice that localKey is generated with the key type Exchange.

### Linking a received message to a response message

Linking messages together, so that it is possible to verify that a response is actually for a particular message received earlier:

```
var receivedMessage = Item.Import<Message>(exportedMessageReceived);
var responseMessage = new Message(receivedMessage.GetClaim<Guid>(Claim.Iss), client.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
responseMessage.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
responseMessage.AddItemLink(receivedMessage);
responseMessage.Sign(Commons.AudienceKey);
var exportedMessageResponse = responseMessage.Export();
```

### Generating thumbprints

Generating a thumbprint from a DiME identity that has been imported:

```
var identity = Item.Import<Identity>(exportedIdentity);
var thumbprint = identity.GenerateThumbprint()
```

Generating a thumbprint from a DiME envelope (exported DiME item):

```
var thumbprint = Item.Thumbprint(exportedIdentity));
```

Thumbprints can be used to quickly verify if the DiME item has changed, or if it is the item that was expected. A thumbprint is a cryptographic hash of the whole DiME item.
