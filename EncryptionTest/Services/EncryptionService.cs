using System.Security.Cryptography;

namespace EncryptionTest.Services;

public class EncryptionService
{
  // use a generator such as: https://generate.plus/en/base64
  // to generate a base64 string key and vector, the length of both must match
  // must be 128, 192, or 256 bits in length, so the byte length of the string generated
  // should be 16, 24, or 32 bytes in length (128/8, 192/8, 256/8)
  // ex: wxf7WJZFZ+n4zNCjgho1MtyRdidwDZ7u3EsVrISVptQ= for a 256 bit encrypted key
  private readonly byte[] _keyBytes = Convert.FromBase64String("your_key_here");
  private readonly byte[] _vectorBytes = Convert.FromBase64String("your_vector_here");
  
  public byte[] Encrypt(string text)
  {
    return EncryptStringToBytes(text, _keyBytes, _vectorBytes);
  }

  public string Decrypt(byte[] cipherText)
  {
    return DecryptStringFromBytes(cipherText, _keyBytes, _vectorBytes);
  }
  
  private static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
  {
    if (plainText is not { Length: > 0 })
      throw new ArgumentNullException(nameof(plainText));
    if (key is not { Length: > 0 })
      throw new ArgumentNullException(nameof(key));
    if (iv is not { Length: > 0 })
      throw new ArgumentNullException(nameof(iv));

    using var aesAlg = Aes.Create();
    aesAlg.Key = key;
    aesAlg.IV = iv;

    var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

    using var msEncrypt = new MemoryStream();
    using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
    using (var swEncrypt = new StreamWriter(csEncrypt))
    {
      swEncrypt.Write(plainText);
    }
    var encrypted = msEncrypt.ToArray();

    return encrypted;
  }

  private static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
  {
    if (cipherText is not { Length: > 0 })
      throw new ArgumentNullException(nameof(cipherText));
    if (key is not { Length: > 0 })
      throw new ArgumentNullException(nameof(key));
    if (iv is not { Length: > 0 })
      throw new ArgumentNullException(nameof(iv));

    using var aesAlg = Aes.Create();
    
    aesAlg.Key = key;
    aesAlg.IV = iv;

    var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

    using var msDecrypt = new MemoryStream(cipherText);
    using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
    using var srDecrypt = new StreamReader(csDecrypt);
    
    var plaintext = srDecrypt.ReadToEnd();

    return plaintext;
  }
}