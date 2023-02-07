using EncryptionTest.Services;

var encryptionService = new EncryptionService();

const string testText = "This is some test text";

var encrypted = encryptionService.Encrypt(testText);
Console.WriteLine(encrypted.ToString());
var decrypted = encryptionService.Decrypt(encrypted);
Console.WriteLine(decrypted);