//
//  AlienTests.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

using System;
using System.Collections.Generic;
using System.Text;
using DiME;
using DiME.Capability;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using DiME.KeyRing;

namespace DiME_test;

/// <summary>
/// Tests DiME envelopes/items from other platforms (Java)
/// </summary>
[TestClass]
public class AlienTests
{
    
    [TestMethod]
    public void KeyTest1()
    {
        const string alienKey =
            "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE3VDE3OjE2OjExLjA4NzMzMFoiLCJrZXkiOiJTVE4uNEJNeXF6enFjdkVqdVdEbU4yRE45WUF1Tk1TYlBuUW9NZ0VFQ2RmanNEb2oxRGdmS2hHSFdNeWVqMXhIV1pmOUdSVlA0eWZ5UUR1YnNQYUN3NXpMaHlSQ1BDUVFGIiwicHViIjoiU1ROLmJxYVdReEpRamt0QVhuNjZ2d2FGVTU1Y0t5MzFxdWFIb0ZkemNvNk1pZkUxYXU0cUgiLCJ1aWQiOiIxMTI1ZTAyMC1iNDJiLTRhOGYtOWZmYS0wMjZiNDE3OTVlZDgifQ";
        var key = Item.Import<Key>(alienKey);
        Assert.IsNotNull(key);
        Assert.IsTrue(key.HasCapability(KeyCapability.Sign));
        Assert.AreEqual(DateTime.Parse("2022-10-17T17:16:11.087330Z").ToUniversalTime(), key.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual("STN.4BMyqzzqcvEjuWDmN2DN9YAuNMSbPnQoMgEECdfjsDoj1DgfKhGHWMyej1xHWZf9GRVP4yfyQDubsPaCw5zLhyRCPCQQF", key.Secret);
        Assert.AreEqual("STN.bqaWQxJQjktAXn66vwaFU55cKy31quaHoFdzco6MifE1au4qH", key.Public);
        Assert.AreEqual(Guid.Parse("1125e020-b42b-4a8f-9ffa-026b41795ed8"), key.GetClaim<Guid>(Claim.Uid));
    }
    
    [TestMethod]
    public void KeyTest2()
    {
        const string alienKey =
            "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiY3R4IjoidGVzdC1jb250ZXh0IiwiaWF0IjoiMjAyMi0xMC0xN1QxNzo0Mjo1MS4wOTMyNDRaIiwicHViIjoiU1ROLnhVbTZlYkhiWDRQNmd2NnFLZWp1ZzlHYXRnOXgxVHc3a0NQa1Y4V3hNbzlyazV3ZjkiLCJ1aWQiOiI1MTA0ZTFiOS1mYWNmLTRhZjMtODhkMy1lMTI3NWIwNzUyZGIifQ";
        var key = Item.Import<Key>(alienKey);
        Assert.IsNotNull(key);
        Assert.IsTrue(key.HasCapability(KeyCapability.Exchange));
        Assert.AreEqual(Commons.Context, key.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(DateTime.Parse("2022-10-17T17:42:51.093244Z").ToUniversalTime(), key.GetClaim<DateTime>(Claim.Iat));
        Assert.IsNull(key.Secret);
        Assert.AreEqual("STN.xUm6ebHbX4P6gv6qKejug9Gatg9x1Tw7kCPkV8WxMo9rk5wf9", key.Public);
        Assert.AreEqual(Guid.Parse("5104e1b9-facf-4af3-88d3-e1275b0752db"), key.GetClaim<Guid>(Claim.Uid));
    }

    [TestMethod]
    public void IdentityIssuingRequestTest1()
    {
        const string alienIir = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDIyLTEwLTE3VDE3OjI0OjE1LjQ1NjkxM1oiLCJwdWIiOiJTVE4uMnU5NnF1OFVRYnNiREdkQUtrQ3plUlJTaGhQUTc4dEJ0QkFOekVOZ0hqUmo0SDZ1VlUiLCJ1aWQiOiIxODM4OTA0NC05MmMwLTRhODctOGUxNC1hMDFlOGJlNzU4NzMifQ.MTYwMmViNWFhZGQwNmMxMy4zNmYxMzBhYmVjMWRlZDM5ZGVmNzNmZGU5MjY0MzgzOTUwZmQ3MDk1NWY2MzFjZDZhZjZkZGNmYjM4NDM2OGY0MzM3NGM3ZDZiMDFlNDBiMjAzZjllZTcwNTI3YjY3Njc4NTBlMDY1MWMzYmZmZDgzMmRkNWY3YzQ3ZjhhNWEwNA";
        var iir = Item.Import<IdentityIssuingRequest>(alienIir);
        Assert.IsNotNull(iir);
        Assert.IsTrue(iir.WantsCapability(IdentityCapability.Generic));
        Assert.AreEqual(DateTime.Parse("2022-10-17T17:24:15.456913Z").ToUniversalTime(), iir.GetClaim<DateTime>(Claim.Iat));
        var key = iir.PublicKey;
        Assert.IsNotNull(key);
        Assert.AreEqual("STN.2u96qu8UQbsbDGdAKkCzeRRShhPQ78tBtBANzENgHjRj4H6uVU", key.Public);
        Assert.AreEqual(Guid.Parse("18389044-92c0-4a87-8e14-a01e8be75873"), iir.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(IntegrityState.Complete, iir.Verify(key));
    }

    [TestMethod]
    public void IdentityIssuingRequestTest2()
    {
        const string alienIir = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDI0LTAxLTI2VDIyOjA5OjA5LjY1NTQ4NzEyNFoiLCJwdWIiOiJOYUNsLnJjeDU0cUJ5RW9KUTlzaDVYZkpNZ2h1RU9vVysvY1praEhZUXlRYzUwNnMiLCJ1aWQiOiJkNDI2ODczOS0xOTYzLTQwYTgtOWUxNS0wMDcwMzg5Y2U0NDMifQ.M2Q5YWE1MWU2Y2E0MzFmZS4zODg2ZWFlMWZhZDQ4ZDI2N2E2MDQ1ZjU5MWJiODA5ODkyMjc3MTA5ZGE0YzBjMjBmMmE3M2IxMzBhY2I0MDEwOTJlMDAzODliODU3NjdiYzI3MDE2MjQ0NjU0N2M2NGZlOTRkMzgwNmM3NDQ3NjM3YzA4NWM5NDIxOThlY2EwZA";
        var iir = Item.Import<IdentityIssuingRequest>(alienIir);
        Assert.IsNotNull(iir);
        var caps = new List<IdentityCapability> { IdentityCapability.Generic };
        Commons.InitializeKeyRing();
        var identity = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Day, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps,
            caps);
        Assert.IsNotNull(identity);
        Assert.AreEqual(IntegrityState.Complete, identity.Verify());
    }

    [TestMethod]
    public void IdentityTest1()
    {
        const string alienIdentity =
            "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMTdUMTc6MzU6MDAuNjMxMjAzWiIsImlhdCI6IjIwMjItMTAtMTdUMTc6MzU6MDAuNjMxMjAzWiIsImlzcyI6ImNlNTc4YjM2LWJhMmMtNGNmMS1hZTVjLTM3YzU2NWFmNmUxMSIsInB1YiI6IlNUTi4yOWpXTlBYRWtnTmpvcHhGZHN6amhBWEFZU21TcHYxQ0tWOThycEdrc3paWndlWlA0QiIsInN1YiI6ImM4ZDEzNDJmLTdhMjItNDUyYy1hYjhmLWI0ZDIzYWM1MGM2MiIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiMzUxZmMxYTYtY2I3Ni00YTNhLTgzMDQtOTg0ZjM4ZjYwOTc2In0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB3TWxReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB3TTFReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFYTnpJam9pWWpRell6UTRNamd0TURrMk1TMDBZbVEyTFdJM1lXTXRaVGMyWWprNE9HSmhabVl3SWl3aWNIVmlJam9pVTFST0xtMXJWVTF2WjJWdmFGVTVRM1YxY0RsVlYzWnhNVEo2VTI5Vk5qUmxURlZYVlZoeE1UbG1PWEJaU2pOaFNsWkdVRU1pTENKemRXSWlPaUpqWlRVM09HSXpOaTFpWVRKakxUUmpaakV0WVdVMVl5MHpOMk0xTmpWaFpqWmxNVEVpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJalV5T1RNMlptUTBMV1ZtTldNdE5EbGxOUzA1T1RreUxUSmxaVEJsWkRBeFpETXdNaUo5Lk1qWTNNRFUzWm1RNU4yVXlNRE5tTmk1all6TTNNbU5rWTJFek1EQmtaRFU1TkRZMk5HWmhNMkUxWXpaa00yUTFNakpqTmpSbE9EbG1NalE1TmpjME9EVXdNamN3TlRReFkyVXlOalZrTUdOalpUVmhaVFJsTmpFMk1tUTNNREpqTURFNE1tWTJZalUyTkRKa09ERTVOREUxTW1Oa056ZzNZMlkxTlRFd056Qm1abVV4Tm1aaU0yRXpOemcxTXpFd05B.MDFiODQxNmIzMjk0NmJmYi5lMzcyNjM2NjczZDdmZjQyOGY0YzJmMmY0N2Y1NzBhNmM1NDBkMTI4NzFhYzA4YTg1YTM2Njk3YWRkZTlhMjZhZTE4ZDRiZjUyYWIwYmM2MzJjZjg2ZDI4MWNhMzA0NGY2NTQ3ZTgyZDU4MzIyZDA1MzU2N2MyNDFkZjk4NTgwMA";
        var identity = Item.Import<Identity>(alienIdentity);
        Assert.IsNotNull(identity);
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Generic));
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Identify));
        Assert.AreEqual(DateTime.Parse("2023-10-17T17:35:00.631203Z").ToUniversalTime(), identity.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(DateTime.Parse("2022-10-17T17:35:00.631203Z").ToUniversalTime(), identity.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(Guid.Parse("ce578b36-ba2c-4cf1-ae5c-37c565af6e11"), identity.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual("STN.29jWNPXEkgNjopxFdszjhAXAYSmSpv1CKV98rpGkszZZweZP4B", identity.PublicKey.Public);
        Assert.AreEqual(Guid.Parse("c8d1342f-7a22-452c-ab8f-b4d23ac50c62"), identity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(Commons.SystemName, identity.GetClaim<string>(Claim.Sys));
        Assert.AreEqual(Guid.Parse("351fc1a6-cb76-4a3a-8304-984f38f60976"), identity.GetClaim<Guid>(Claim.Uid));
        Assert.IsNotNull(identity.TrustChain);
    }

    [TestMethod]
    public void DataTest1()
    {
        const string alienData =
            "Di:DAT.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJleHAiOiIyMDIyLTEwLTE3VDE3OjQ2OjQxLjI1Mjg2NVoiLCJpYXQiOiIyMDIyLTEwLTE3VDE3OjQ1OjQxLjI1Mjg2NVoiLCJpc3MiOiJlZjRkNWJmMC1mOWVkLTQzZTktYmE3ZC0wMGNkNDEwYzJmMmMiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiODRiNDlhNGMtOGM2OS00YTM5LWFkMjQtN2M1NjUyMTY5ZGEzIn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
        var data = Item.Import<Data>(alienData);
        Assert.IsNotNull(data);
        Assert.AreEqual(Commons.Context, data.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(DateTime.Parse("2022-10-17T17:46:41.252865Z").ToUniversalTime(), data.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(DateTime.Parse("2022-10-17T17:45:41.252865Z").ToUniversalTime(), data.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(Guid.Parse("ef4d5bf0-f9ed-43e9-ba7d-00cd410c2f2c"), data.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.Mimetype, data.GetClaim<string>(Claim.Mim));
        Assert.AreEqual(Guid.Parse("84b49a4c-8c69-4a39-ad24-7c5652169da3"), data.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(data.GetPayload()));
    }

    [TestMethod]
    public void TagTest1()
    {
        const string alienKey =
            "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE3VDE3OjE2OjExLjA4NzMzMFoiLCJrZXkiOiJTVE4uNEJNeXF6enFjdkVqdVdEbU4yRE45WUF1Tk1TYlBuUW9NZ0VFQ2RmanNEb2oxRGdmS2hHSFdNeWVqMXhIV1pmOUdSVlA0eWZ5UUR1YnNQYUN3NXpMaHlSQ1BDUVFGIiwicHViIjoiU1ROLmJxYVdReEpRamt0QVhuNjZ2d2FGVTU1Y0t5MzFxdWFIb0ZkemNvNk1pZkUxYXU0cUgiLCJ1aWQiOiIxMTI1ZTAyMC1iNDJiLTRhOGYtOWZmYS0wMjZiNDE3OTVlZDgifQ";
        const string alienTag =
            "Di:TAG.eyJpc3MiOiJlZjRkNWJmMC1mOWVkLTQzZTktYmE3ZC0wMGNkNDEwYzJmMmMiLCJsbmsiOiJEQVQuNmZiNjI1MTktMTRlYy00ZTE1LWExYmEtYWQwYzI3YzlkNDIwLjFlMGIyOTk1MDIzZGVlZGQxZDQ1YjEwMjhkNTFmMzJjMWFlNDlhOTkwMDdmMDJlOTc5NjNkYTY1MzNkZGE3MmUiLCJ1aWQiOiIxNDE5MjZmOS1kMDYxLTQ4YWMtODJlYi1mNjA4MGMxZWVmZGQifQ.Y2M1NTU4MmFjNzk1YzhjNC5hODZlYmVmMmRmMzg4ZTk4YjNiNjc5NzRmYmE2NWE0MGE4ZmM1ZWEwZTBkOTI5NzM4NTRkMTRkYWE0YWYzNzRlYjQ2NTNiMWVjZWU5YTllNzg5NWIzODg3YTRmMDI4NTdjNmQ3YWNkYjY2ZTBkN2E2NGQ1M2M2NTUyMWQ3NGIwNQ";
        const string localData =
            "Di:DAT.eyJpYXQiOiIyMDIyLTEwLTE3VDE4OjI3OjMxLjc2OTc2N1oiLCJpc3MiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJ1aWQiOiI2ZmI2MjUxOS0xNGVjLTRlMTUtYTFiYS1hZDBjMjdjOWQ0MjAifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
        var key = Item.Import<Key>(alienKey);
        Assert.IsNotNull(key);
        var tag = Item.Import<Tag>(alienTag);
        Assert.IsNotNull(tag);
        Assert.AreEqual(Guid.Parse("ef4d5bf0-f9ed-43e9-ba7d-00cd410c2f2c"), tag.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Guid.Parse("141926f9-d061-48ac-82eb-f6080c1eefdd"), tag.GetClaim<Guid>(Claim.Uid));
        var data = Item.Import<Data>(localData);
        Assert.IsNotNull(data);
        Assert.AreEqual(IntegrityState.Complete, tag.Verify(key, new List<Item>() {data}));
        Assert.AreEqual(IntegrityState.FailedLinkedItemMismatch, tag.Verify(key, new List<Item>() {key}));
    }

    [TestMethod]
    public void EnvelopeTest1()
    {
        const string localExchangeKey = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyMi0xMC0xN1QxODowMjoxMy40NTIzNzVaIiwia2V5IjoiU1ROLjJYcldFNWd0ekZiN3V4RE1wYnNLenNoZVZLaDVUM3dxYlVFMWY4YzlFcDVjU05Mb0FEIiwicHViIjoiU1ROLjJmaGQ5ektXNFFReWJQYlBkckNaZUthek1MdFVadkVNVkh6VGE3WlJ3VVppdndjZFgzIiwidWlkIjoiMmUxMjY0NjMtYWVkZC00MWYwLWE3ZGYtNzY4OTZlOGFkMmU3In0";
        const string alienEnvelope = "Di:MSG.eyJhdWQiOiJjYzMwNWY3NC02MWRjLTRlY2UtYmQ1MC1jYTg4NWQwYzM2OWYiLCJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJleHAiOiIyMDIyLTEwLTE4VDE4OjEwOjA5LjU2MDIxOVoiLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjEwOjA5LjU2MDIxOVoiLCJpc3MiOiJlZjRkNWJmMC1mOWVkLTQzZTktYmE3ZC0wMGNkNDEwYzJmMmMiLCJ1aWQiOiI2MjAzYzZjMS05MDBmLTQwOGMtYWEzZS1iZTUwODQwYzdlZDAifQ.Dk05UFcNKyakCbVa5Xf8bbGn6V1PY2laayKgzL8uwdZQDjUt8eu+Q1lLu7/HVfiXqZn0XMsB0z+ePYHN3x/uZJVyGmva.YjkyMjMwYzBkNTY0YjU0NS44NDlmMTdiM2FiZTUzNmYyODI5MmNkZmI0NGRlZWIyOTZkMjVhZWVlNzhmMjhkMTY1YTIxNDYyYjUwZWI0MTkzZjQzZmVmZjdjMzAwMGIwYTdiM2U2NmQ3OTM3MzcxNDUwODdmNWVlNWRlMzc4MDJjNGQ3MzQwODAxNWU5OWIwOA:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyMi0xMC0xN1QxODoxMDowOS41MTc2NDFaIiwicHViIjoiU1ROLjJWdWdqVnlrRGlWVEQzRWhyNHRNb3VtM2hvWmY2VUg5Ylc2dWJYV2EzSEpCbUFZUEYxIiwidWlkIjoiYTRmZmU0ZjUtNWQ3Zi00ZmM0LTljNWQtN2ZhZmE2MjhkODBlIn0";
        var envelope = Envelope.Import(alienEnvelope);
        Assert.IsNotNull(envelope);
        Assert.AreEqual(2, envelope.Items.Count);
        var alienExchangeKey = (Key) envelope.GetItem(Claim.Uid, Guid.Parse("a4ffe4f5-5d7f-4fc4-9c5d-7fafa628d80e"));
        Assert.IsNotNull(alienExchangeKey);
        var message = (Message) envelope.GetItem(Claim.Uid, Guid.Parse("6203c6c1-900f-408c-aa3e-be50840c7ed0"));
        Assert.IsNotNull(message);
        var exchangeKey = Item.Import<Key>(localExchangeKey);
        Assert.IsNotNull(exchangeKey);
        var payload = message.GetPayload(alienExchangeKey, exchangeKey);
        Assert.IsNotNull(payload);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(payload));
    }
    
}