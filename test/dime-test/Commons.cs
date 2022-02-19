//
//  Commons.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using DiME;

namespace DiME_test
{
    [TestClass]
    public class Commons
    {
        #region -- PUBLIC --

        public const string _SYSTEM_NAME = "dime-dotnet-ref";
        public static Key TrustedKey => _trustedKey ??= Item.Import<Key>(EncodedTrustedKey);
        public static Identity TrustedIdentity => _trustedIdentity ??= Item.Import<Identity>(EncodedTrustedIdentity);
        public static Key IntermediateKey => _intermediateKey ??= Item.Import<Key>(EncodedIntermediateKey);
        public static Identity IntermediateIdentity => _intermediateIdentity ??= Item.Import<Identity>(EncodedIntermediateIdentity);
        public static Key IssuerKey => _issuerKey ??= Item.Import<Key>(EncodedIssuerKey);
        public static Identity IssuerIdentity => _issuerIdentity ??= Item.Import<Identity>(EncodedIssuerIdentity);
        public static Key AudienceKey => _audienceKey ??= Item.Import<Key>(EncodedAudienceKey);
        public static Identity AudienceIdentity => _audienceIdentity ??= Item.Import<Identity>(EncodedAudienceIdentity);

        #endregion

        /// TESTS ///

        [TestMethod]
        public void GenerateCommons() 
        {
            Identity.SetTrustedIdentity(null);
            var trustedKey = Key.Generate(KeyType.Identity);
            var trustedIdentity = GenerateIdentity(trustedKey, trustedKey, null, IdentityIssuingRequest._VALID_FOR_1_YEAR * 10, new List<Capability>() { Capability.Generic, Capability.Issue });
            Console.WriteLine("#region -- TRUSTED IDENTITY --");
            Console.WriteLine("private static readonly string _encodedTrustedKey = \"" + trustedKey.Export() + "\";");
            Console.WriteLine("private static readonly string _encodedTrustedIdentity = \"" + trustedIdentity.Export() + "\";\n");

            Identity.SetTrustedIdentity(trustedIdentity);
            var intermediateKey = Key.Generate(KeyType.Identity);
            var intermediateIdentity = GenerateIdentity(intermediateKey, trustedKey, trustedIdentity, IdentityIssuingRequest._VALID_FOR_1_YEAR * 5, new List<Capability>() { Capability.Generic, Capability.Identify, Capability.Issue });
            Console.WriteLine("#region -- INTERMEDIATE IDENTITY ---");
            Console.WriteLine("private static readonly string _encodedIntermediateKey = \"" + intermediateKey.Export() + "\";");
            Console.WriteLine("private static readonly string _encodedIntermediateIdentity = \""+ intermediateIdentity.Export() + "\";\n");

            var issuerKey = Key.Generate(KeyType.Identity);
            var issuerIdentity = GenerateIdentity(issuerKey, intermediateKey, intermediateIdentity, IdentityIssuingRequest._VALID_FOR_1_YEAR, new List<Capability>() { Capability.Generic, Capability.Identify });
            Console.WriteLine("#region -- ISSUER IDENTITY (SENDER) --");
            Console.WriteLine("private static readonly string _encodedIssuerKey = \"" + issuerKey.Export() + "\";");
            Console.WriteLine("private static readonly string _encodedIssuerIdentity = \""+ issuerIdentity.Export() +"\";\n");

            var audienceKey = Key.Generate(KeyType.Identity);
            var audienceIdentity = GenerateIdentity(audienceKey, intermediateKey, intermediateIdentity, IdentityIssuingRequest._VALID_FOR_1_YEAR, new List<Capability>() { Capability.Generic, Capability.Identify });

            Console.WriteLine("#region -- AUDIENCE IDENTITY (RECEIVER) --");
            Console.WriteLine("private static readonly string _encodedAudienceKey = \"" + audienceKey.Export() + "\";");
            Console.WriteLine("private static readonly string _encodedAudienceIdentity = \""+ audienceIdentity.Export() +"\";\n");
        }

        #region -- TRUSTED IDENTITY --

        private const string EncodedTrustedKey = "Di:KEY.eyJ1aWQiOiIyOWQ0ZGExYy05MjdmLTQ3ODctYTU2Yi1hNTVmOTRhOTFjMmYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA0MjczOVoiLCJrZXkiOiJTMjFUWlNMMWNOWFk3RVFHWVhxZjg2TFFBUUFhdGRxWjV6aGlvOFU1Q1VUQjVoQmhpeGVaOHNDWUc1UVA1aXJodjRKcWtkYWducjRwUGYzOU5jTVcxOThqOVdjV1Nvd1FNQWJnIiwicHViIjoiMlREWGRvTnVRR21lUmRKU0p5RXdXUUtGM0IyWW1mQVNtNWJBTjhNUmJZdXBiZUpmUk5aQkplTHVkIn0";
        private const string EncodedTrustedIdentity = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiI0MzU2MjBkNi1mYWMxLTQyOTQtOTYyNS0xZTYwYjVlNTExNDEiLCJzdWIiOiI4MTcxN2VkOC03N2FlLTQ2MzMtYTA5YS02YWM1ZDk0ZWYyOGQiLCJpc3MiOiI4MTcxN2VkOC03N2FlLTQ2MzMtYTA5YS02YWM1ZDk0ZWYyOGQiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA3MTAxNVoiLCJleHAiOiIyMDMxLTExLTMwVDIyOjI1OjA4LjA3MTAxNVoiLCJwdWIiOiIyVERYZG9OdVFHbWVSZEpTSnlFd1dRS0YzQjJZbWZBU201YkFOOE1SYll1cGJlSmZSTlpCSmVMdWQiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdfQ.5MBTKOJLxOG87Ad2JzZgU1xBffYuQK9nCyFxRN+01Aj7SUMTNwimZPU1lA5V7NRkTgZeEX2H9bw9DhHlLg22DA";
        private static Key _trustedKey;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --

        private const string EncodedIntermediateKey = "Di:KEY.eyJ1aWQiOiJmMjQwYTZlNS04YjA3LTRjM2MtYjNhMi03ZWExOTY5NmFiMWEiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4MzU4NloiLCJrZXkiOiJTMjFUWlNMVkJ3QkFmRDlFcHNkYzROd2VxdjRTa3ZqOTJ3akNxMk1XcmJ1Z3NKYWFaNlRrWnQxek1EWlZNa2Z1NnFkem9mSnV1WHhGWmJkNTh0cG1CSlRQN2JNVW5UUWVqUVpkIiwicHViIjoiMlREWGRvTnZWc0dWSDhDOVVadWRwYkJ2VlNLMUZlaTVyNFlUWk14YUJhem9zbzJwTHBQV1RNZmNOIn0";
        private const string EncodedIntermediateIdentity = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiI3MWY5NGFkNy03ZjAzLTQ2NDUtOTIwYi0wZDhkOWEyYTFkMWIiLCJzdWIiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpc3MiOiI4MTcxN2VkOC03N2FlLTQ2MzMtYTA5YS02YWM1ZDk0ZWYyOGQiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzMyMVoiLCJleHAiOiIyMDI2LTEyLTAxVDIyOjI1OjA4LjA4NzMyMVoiLCJwdWIiOiIyVERYZG9OdlZzR1ZIOEM5VVp1ZHBiQnZWU0sxRmVpNXI0WVRaTXhhQmF6b3NvMnBMcFBXVE1mY04iLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXX0.79J9eu3qerj1n1tJRiBPzsTDsA5ijXn5DK7fUn4JQrhseBW7IkadAzCEDkPrKhPme0ksjua28TB+ULhxla2nCA";
        private static Key _intermediateKey;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- ISSUER IDENTITY (SENDER) --

        private const string EncodedIssuerKey = "Di:KEY.eyJ1aWQiOiI5ZDA3MDliMS1kOWZmLTQzNGUtYjQwMC01MzMyMDMwMjE0YzUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzU4MloiLCJrZXkiOiJTMjFUWlNMRWRNWTJwVjlzaXBjZTgxN0NvaHBiaFZqVnYxUWRweGI4MkZQWmEzSkxmN05SanFvU0tnb3NZekdMdzlVOEc3NDdtVmZnOHp3SHVBbUZMOUQ2U0ZyMlJtN25EaEMyIiwicHViIjoiMlREWGRvTnVNRmk4andDM0RON1gyWnFtWmtGZjVhN3FldHpYVFdBZm5reWg2Z3JxWVBxOTROZW5uIn0";
        private const string EncodedIssuerIdentity = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiIyYzZmYTYwMS1mOWIyLTQxNGQtOThhNy00YWY5MDVkY2U1NzIiLCJzdWIiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJleHAiOiIyMDIyLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJwdWIiOiIyVERYZG9OdU1GaThqd0MzRE43WDJacW1aa0ZmNWE3cWV0elhUV0Fmbmt5aDZncnFZUHE5NE5lbm4iLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.pdZhvANop6iCyBvAmWqUFnviqTZRlw/mF4fjLj4MdbVRdsJDF8eOUYQJk+HoqAXE4i9NV18uAioVkKR1LM1WDw";
        private static Key _issuerKey;
        private static Identity _issuerIdentity;
        #endregion

        #region -- AUDIENCE IDENTITY (RECEIVER) --

        private const string EncodedAudienceKey = "Di:KEY.eyJ1aWQiOiJiNmI5ZWY5ZS0xNzQwLTRlOTUtOGQxMC1iM2UzMzM4ODYwM2YiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA5MDgyOVoiLCJrZXkiOiJTMjFUWlNMQkZoeWViZ0F3TFFVOUNncnJLUVA0eW9laEF3cEJRWU1oVkx1WEFNQXN2aFVmZ2R1SkZBaHBydERlZkdoMmNkWmlQVmJZYkVhU0JhZjRWQVpQRE13aDVLMm5SWXJWIiwicHViIjoiMlREWGRvTnVOR1ZvdTVwREt2aE1kcVRhVjlaRDZKUGIzdXN4aW9XSzVTZnh3Wmp4S1BnaGlZQjNpIn0";
        private const string EncodedAudienceIdentity = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiJkNTQ2YWVlMC1jZTMzLTRjMTQtYTAyNC1iNDQxMDFmNjkzYjMiLCJzdWIiOiIxODUwNjYyYi05NjQxLTQyNjYtYTI5OC0zN2FiZWRlZmI1NjciLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA5MDk2NloiLCJleHAiOiIyMDIyLTEyLTAyVDIyOjI1OjA4LjA5MDk2NloiLCJwdWIiOiIyVERYZG9OdU5HVm91NXBES3ZoTWRxVGFWOVpENkpQYjN1c3hpb1dLNVNmeHdaanhLUGdoaVlCM2kiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.mtVuL3cSpU8ivcngyILz/yTOn5ETZgV2DQ7W7lAagvCt1I12dnZ5QJfxsDHf/6aDsa85h1/hhkNuFKVT8rEfAQ";
        private static Key _audienceKey;
        private static Identity _audienceIdentity;
        #endregion

        private static Identity GenerateIdentity(Key subjectKey, Key issuerKey, Identity issuerIdentity, long validFor, List<Capability> capabilities) {
            var subjectId = Guid.NewGuid();
            var iir = IdentityIssuingRequest.Generate(subjectKey, capabilities);
            var identity = issuerIdentity == null ? iir.SelfIssue(subjectId, validFor, issuerKey, _SYSTEM_NAME) : iir.Issue(subjectId, validFor, issuerKey, issuerIdentity, true, capabilities);
            return identity;
        }
    }

}
