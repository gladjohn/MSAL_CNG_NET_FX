using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO;
using System.Text;
using System.Security.Cryptography.X509Certificates;



namespace CNGKey
{
    internal class Program
    {
        private const CngKeyCreationOptions NCryptUseVirtualIsolationFlag = (CngKeyCreationOptions)0x00020000;

        //A set name for the Key that MSAL will create for SLC
        private const string keyName = "MSALSLCKey28";

        static void Main(string[] args)
        {
            //Creates a key with a certificate 
            var createdKey = CreateKey(keyName);

            //Set ACL on File Path 
            SetAclOnKeyStoragePath(createdKey);

            //Open Key
            OpenKey(keyName);

            Console.Read();
        }

        /// <summary>
        /// In CNG (Cryptography Next Generation), a machine key and an ephemeral key are two different types 
        /// of keys used for different purposes. A machine key is a key that is associated with a specific 
        /// computer or device, rather than with a particular user. Machine keys are typically used for encryption 
        /// and decryption operations that are performed by the computer or device itself, rather than by a specific user.
        /// Ephemeral keys, on the other hand, are keys that are created and used only for a short period of time, 
        /// usually during a single cryptographic operation. Ephemeral keys are typically used for key exchange or key 
        /// agreement protocols, where two parties need to establish a shared secret key.
        /// </summary>
        private static string CreateKey(string keyName)
        {
            const string NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr";
            const CngPropertyOptions DACL_SECURITY_INFORMATION = (CngPropertyOptions)4;

            Console.WriteLine("-----------------------------------------------------------------------");
            Console.WriteLine("Creating a RSA key.");

            try
            {
                //Create a RSA Key Pair 
                var cert = CreateNewRsaKeyPair();

                //ACLs on Key Container
                //SetAclsOnCspKeyContainer(cert);

                //Get the RSA Private Key
                RSA key = cert.GetRSAPrivateKey();

                //Export the Private Key Blob
                byte[] exported = (key as RSACng).Key.Export(CngKeyBlobFormat.GenericPrivateBlob);

                //Set Access Control 
                CryptoKeySecurity sec = new CryptoKeySecurity();

                sec.AddAccessRule(
                    new CryptoKeyAccessRule(
                        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                        CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                        AccessControlType.Allow));

                sec.AddAccessRule(
                    new CryptoKeyAccessRule(
                        new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
                        CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                        AccessControlType.Allow));

                // Create CngKeyCreationParameters
                var keyParams = new CngKeyCreationParameters
                {
                    KeyUsage = CngKeyUsages.AllUsages,
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,

                    //Machine keys are stored in the machine-level key store and are accessible to all users who have the appropriate permissions.
                    //This means that any user on the computer can access and use the machine key.
                    KeyCreationOptions = CngKeyCreationOptions.MachineKey | CngKeyCreationOptions.OverwriteExistingKey,
                    ExportPolicy = CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport,
                    UIPolicy = new CngUIPolicy(CngUIProtectionLevels.None),
                    Parameters =
                    {
                        new CngProperty(CngKeyBlobFormat.GenericPrivateBlob.Format, exported, CngPropertyOptions.None),
                        new CngProperty(NCRYPT_SECURITY_DESCR_PROPERTY, sec.GetSecurityDescriptorBinaryForm(), CngPropertyOptions.Persist | DACL_SECURITY_INFORMATION)
                    }
                };

                // Create a new CNG key
                CngKey cngKey = CngKey.Create(CngAlgorithm.Rsa, keyName, keyParams);

                //Print the key props 
                PrintKeyProps(cngKey, "created");
                Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
                return cngKey.UniqueName;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine();
                return ex.Message;
            }
        }

        private static void PrintKeyProps(CngKey key, string action)
        {
            Console.WriteLine($"Key UniqueName'{key.UniqueName}' {action} successfully.");
            Console.WriteLine($"Key Name'{key.KeyName}' {action} successfully.");
            Console.WriteLine($"Is Machine Key ? {key.IsMachineKey} ");
            Console.WriteLine($"Is Ephemeral Key ? {key.IsEphemeral} ");
        }

        static X509Certificate2 CreateNewRsaKeyPair()
        {
            // Create a new RSA key pair
            RSA rsa = RSA.Create();

            // Create a certificate request using the RSA key
            CertificateRequest req = new CertificateRequest(
                "cn=MSALSLC",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );

            // Generate a new certificate from the request
            DateTimeOffset now = DateTimeOffset.UtcNow;
            X509Certificate2 cert = req.CreateSelfSigned(now, now.AddDays(365));

            // Display the certificate information
            Console.WriteLine($"Cert Subject: {cert.Subject}");
            Console.WriteLine($"Cert Issuer: {cert.Issuer}");
            Console.WriteLine($"Cert Serial Number: {cert.SerialNumber}");
            Console.WriteLine($"Cert Thumbprint: {cert.Thumbprint}");

            return cert;
        }

        private static void OpenKey(string keyName)
        {
            Console.WriteLine("-----------------------------------------------------------------------");
            Console.WriteLine("Open a key with Key name");

            try
            {
                // Specify the optional flags for opening the key
                CngKeyOpenOptions options = CngKeyOpenOptions.MachineKey;
                options |= CngKeyOpenOptions.Silent;

                // Open the key with the specified options
                using (CngKey openedKey = CngKey.Open(keyName, new CngProvider("Microsoft Software Key Storage Provider"), options))
                {
                    Console.WriteLine("Key opened successfully: " + openedKey.KeyName);
                    PrintKeyProps(openedKey, "opened");
                }
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("Error opening key: " + ex.Message);
            }

            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        }

        private static void SetAclsOnCspKeyContainer(X509Certificate2 certificate)
        {
            if (certificate.PrivateKey is RSACryptoServiceProvider rsa)
            {
                // Specify the parameters for the CSP
                var cspParams = new CspParameters(rsa.CspKeyContainerInfo.ProviderType, rsa.CspKeyContainerInfo.ProviderName, rsa.CspKeyContainerInfo.KeyContainerName)
                {
                    Flags = CspProviderFlags.UseArchivableKey | CspProviderFlags.UseMachineKeyStore,
                    CryptoKeySecurity = rsa.CspKeyContainerInfo.CryptoKeySecurity
                };

                cspParams.CryptoKeySecurity.AddAccessRule(new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));

                cspParams.CryptoKeySecurity.AddAccessRule(new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
                    CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));

                cspParams.CryptoKeySecurity.AddAccessRule(new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSid, null),
                    CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));

                cspParams.CryptoKeySecurity.AddAccessRule(new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));

                using (var rsa2 = new RSACryptoServiceProvider(cspParams))
                {
                    rsa.PersistKeyInCsp = true;
                }
            }
        }

        /// <summary>
        /// Need to set ACL on storage path for reading the key
        /// </summary>
        /// <param name="keyName"></param>
        static void SetAclOnKeyStoragePath(string keyName)
        {
            // Get the current security descriptor for the key
            string keyPath = string.Format(@"c:\ProgramData\Microsoft\Crypto\Keys\{0}", keyName);

            //Set Access Control 
            CryptoKeySecurity sec = new CryptoKeySecurity();

            sec.AddAccessRule(
                new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    //CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));

            sec.AddAccessRule(
                new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
                    //CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));

            sec.AddAccessRule(
                new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSid, null),
                    CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));

            sec.AddAccessRule(
                new CryptoKeyAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    CryptoKeyRights.FullControl | CryptoKeyRights.ReadData | CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead,
                    AccessControlType.Allow));


            // Get the existing file security settings
            FileSecurity fileSecurity = File.GetAccessControl(keyPath);

            // Get the user or group's SecurityIdentifier object
            SecurityIdentifier sid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid | WellKnownSidType.NetworkServiceSid | WellKnownSidType.BuiltinAdministratorsSid, null);

            // Create a new access rule for the user or group
            FileSystemAccessRule accessRule = new FileSystemAccessRule(
                sid,
                FileSystemRights.ReadAndExecute | FileSystemRights.Write,
                AccessControlType.Allow);

            // Add the access rule to the file's access control list
            fileSecurity.AddAccessRule(accessRule);

            // Save the modified access control list to the key file
            File.SetAccessControl(keyPath, fileSecurity);
        }
    }
}
