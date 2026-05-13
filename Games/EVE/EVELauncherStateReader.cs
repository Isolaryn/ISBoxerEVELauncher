using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ISBoxerEVELauncher.Games.EVE
{
    public class ImportCandidate
    {
        public long UserId { get; set; }
        public string Username { get; set; }
        public string RefreshToken { get; set; }
        public bool IsActive { get; set; }
    }

    public static class EVELauncherStateReader
    {
        private const string ExpectedClientId = "eveLauncherTQ";
        private const string DpapiPrefix = "DPAPI";
        private const int GcmNonceSize = 12;
        private const int GcmTagSize = 16;
        private const int ChromiumHeaderSize = 3;

        private static string GetEvePath()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "EVE Online");
        }

        private static string GetLocalStatePath()
        {
            return Path.Combine(GetEvePath(), "Local State");
        }

        private static string GetStateJsonPath()
        {
            return Path.Combine(GetEvePath(), "state.json");
        }

        public static bool StateFileExists()
        {
            return File.Exists(GetLocalStatePath()) && File.Exists(GetStateJsonPath());
        }

        public static List<ImportCandidate> Read()
        {
            byte[] key = UnwrapMasterKey(File.ReadAllText(GetLocalStatePath()));
            string decrypted = DecryptStateJson(File.ReadAllText(GetStateJsonPath()), key);
            return ParseCandidates(decrypted);
        }

        private static byte[] UnwrapMasterKey(string localStateJson)
        {
            JsonNode root = JsonNode.Parse(localStateJson);
            string encoded = root?["os_crypt"]?["encrypted_key"]?.GetValue<string>();
            if (string.IsNullOrEmpty(encoded))
                throw new InvalidDataException("EVE Launcher Local State is missing os_crypt.encrypted_key.");

            byte[] wrapped = Convert.FromBase64String(encoded);
            byte[] prefix = Encoding.ASCII.GetBytes(DpapiPrefix);
            if (wrapped.Length <= prefix.Length)
                throw new InvalidDataException("EVE Launcher Local State encrypted_key is too short.");
            for (int i = 0; i < prefix.Length; i++)
            {
                if (wrapped[i] != prefix[i])
                    throw new InvalidDataException("EVE Launcher Local State encrypted_key does not start with the expected DPAPI prefix.");
            }

            byte[] blob = new byte[wrapped.Length - prefix.Length];
            Buffer.BlockCopy(wrapped, prefix.Length, blob, 0, blob.Length);
            return ProtectedData.Unprotect(blob, null, DataProtectionScope.CurrentUser);
        }

        private static string DecryptStateJson(string stateJsonText, byte[] key)
        {
            JsonNode root = JsonNode.Parse(stateJsonText);
            string encoded = root?["state"]?.GetValue<string>();
            if (string.IsNullOrEmpty(encoded))
                throw new InvalidDataException("EVE Launcher state.json is missing the encrypted state field.");

            byte[] blob = Convert.FromBase64String(encoded);
            if (blob.Length < ChromiumHeaderSize + GcmNonceSize + GcmTagSize)
                throw new InvalidDataException("EVE Launcher state.json encrypted payload is too short.");

            byte[] nonce = new byte[GcmNonceSize];
            Buffer.BlockCopy(blob, ChromiumHeaderSize, nonce, 0, GcmNonceSize);

            int cipherStart = ChromiumHeaderSize + GcmNonceSize;
            int cipherLen = blob.Length - cipherStart - GcmTagSize;
            byte[] ciphertext = new byte[cipherLen];
            Buffer.BlockCopy(blob, cipherStart, ciphertext, 0, cipherLen);

            byte[] tag = new byte[GcmTagSize];
            Buffer.BlockCopy(blob, blob.Length - GcmTagSize, tag, 0, GcmTagSize);

            byte[] plaintext = BCryptAesGcm.Decrypt(key, nonce, ciphertext, tag);
            return Encoding.UTF8.GetString(plaintext);
        }

        private static List<ImportCandidate> ParseCandidates(string decryptedStateJson)
        {
            var result = new List<ImportCandidate>();
            JsonNode root = JsonNode.Parse(decryptedStateJson);
            JsonNode tq = root?["v2.1/users"]?["eve-online"]?["tranquility"];
            if (tq == null) return result;

            long? activeUserId = null;
            JsonNode activeNode = tq["activeUserId"];
            if (activeNode != null)
            {
                try { activeUserId = activeNode.GetValue<long>(); } catch { }
            }

            JsonArray ids = tq["ids"] as JsonArray;
            JsonNode entities = tq["entities"];
            if (ids == null || entities == null) return result;

            foreach (JsonNode idNode in ids)
            {
                if (idNode == null) continue;
                long userId;
                try { userId = idNode.GetValue<long>(); } catch { continue; }

                JsonNode entity = entities[userId.ToString()];
                if (entity == null) continue;

                JsonNode tokens = entity["tokens"];
                string refreshToken = tokens?["refreshToken"]?.GetValue<string>();
                string clientId = tokens?["clientId"]?.GetValue<string>();
                if (string.IsNullOrEmpty(refreshToken)) continue;
                if (!string.Equals(clientId, ExpectedClientId, StringComparison.Ordinal)) continue;

                string name = entity["name"]?.GetValue<string>();
                if (string.IsNullOrEmpty(name)) continue;

                result.Add(new ImportCandidate
                {
                    UserId = userId,
                    Username = name,
                    RefreshToken = refreshToken,
                    IsActive = activeUserId.HasValue && activeUserId.Value == userId,
                });
            }

            return result;
        }

        private static class BCryptAesGcm
        {
            private const string Bcrypt = "bcrypt.dll";
            private const string AES_ALGORITHM = "AES";
            private const string GCM_CHAIN_MODE = "ChainingModeGCM";
            private const string PROP_CHAINING_MODE = "ChainingMode";
            private const string PROP_OBJECT_LENGTH = "ObjectLength";
            private const uint STATUS_SUCCESS = 0;
            private const uint STATUS_AUTH_TAG_MISMATCH = 0xC000A002;

            [DllImport(Bcrypt, CharSet = CharSet.Unicode)]
            private static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

            [DllImport(Bcrypt)]
            private static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

            [DllImport(Bcrypt, CharSet = CharSet.Unicode)]
            private static extern uint BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

            [DllImport(Bcrypt, CharSet = CharSet.Unicode)]
            private static extern uint BCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

            [DllImport(Bcrypt)]
            private static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, byte[] pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

            [DllImport(Bcrypt)]
            private static extern uint BCryptDestroyKey(IntPtr hKey);

            [DllImport(Bcrypt)]
            private static extern uint BCryptDecrypt(
                IntPtr hKey,
                byte[] pbInput, int cbInput,
                ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pAuthInfo,
                byte[] pbIV, int cbIV,
                byte[] pbOutput, int cbOutput,
                out int pcbResult, uint dwFlags);

            [StructLayout(LayoutKind.Sequential)]
            private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
            {
                public int cbSize;
                public int dwInfoVersion;
                public IntPtr pbNonce;
                public int cbNonce;
                public IntPtr pbAuthData;
                public int cbAuthData;
                public IntPtr pbTag;
                public int cbTag;
                public IntPtr pbMacContext;
                public int cbMacContext;
                public int cbAAD;
                public long cbData;
                public int dwFlags;
            }

            public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
            {
                IntPtr hAlg = IntPtr.Zero;
                IntPtr hKey = IntPtr.Zero;
                GCHandle nonceHandle = default(GCHandle);
                GCHandle tagHandle = default(GCHandle);
                try
                {
                    uint status = BCryptOpenAlgorithmProvider(out hAlg, AES_ALGORITHM, null, 0);
                    if (status != STATUS_SUCCESS) throw new CryptographicException("BCryptOpenAlgorithmProvider failed: 0x" + status.ToString("X8"));

                    byte[] gcmBytes = Encoding.Unicode.GetBytes(GCM_CHAIN_MODE + "\0");
                    status = BCryptSetProperty(hAlg, PROP_CHAINING_MODE, gcmBytes, gcmBytes.Length, 0);
                    if (status != STATUS_SUCCESS) throw new CryptographicException("BCryptSetProperty(ChainingMode) failed: 0x" + status.ToString("X8"));

                    byte[] objLenBytes = new byte[4];
                    int got;
                    status = BCryptGetProperty(hAlg, PROP_OBJECT_LENGTH, objLenBytes, objLenBytes.Length, out got, 0);
                    if (status != STATUS_SUCCESS) throw new CryptographicException("BCryptGetProperty(ObjectLength) failed: 0x" + status.ToString("X8"));
                    int objLen = BitConverter.ToInt32(objLenBytes, 0);

                    byte[] keyObject = new byte[objLen];
                    status = BCryptGenerateSymmetricKey(hAlg, out hKey, keyObject, objLen, key, key.Length, 0);
                    if (status != STATUS_SUCCESS) throw new CryptographicException("BCryptGenerateSymmetricKey failed: 0x" + status.ToString("X8"));

                    nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                    tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);

                    var info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                    info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                    info.dwInfoVersion = 1;
                    info.pbNonce = nonceHandle.AddrOfPinnedObject();
                    info.cbNonce = nonce.Length;
                    info.pbTag = tagHandle.AddrOfPinnedObject();
                    info.cbTag = tag.Length;

                    byte[] plaintext = new byte[ciphertext.Length];
                    int written;
                    status = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, ref info, null, 0, plaintext, plaintext.Length, out written, 0);
                    if (status == STATUS_AUTH_TAG_MISMATCH)
                        throw new CryptographicException("EVE Launcher state failed AES-GCM authentication. The file may be corrupted.");
                    if (status != STATUS_SUCCESS)
                        throw new CryptographicException("BCryptDecrypt failed: 0x" + status.ToString("X8"));

                    if (written != plaintext.Length)
                    {
                        byte[] trimmed = new byte[written];
                        Buffer.BlockCopy(plaintext, 0, trimmed, 0, written);
                        return trimmed;
                    }
                    return plaintext;
                }
                finally
                {
                    if (nonceHandle.IsAllocated) nonceHandle.Free();
                    if (tagHandle.IsAllocated) tagHandle.Free();
                    if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
                    if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
                }
            }
        }
    }
}
