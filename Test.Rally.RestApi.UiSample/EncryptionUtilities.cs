using Rally.RestApi.Auth;

namespace Test.Rally.RestApi.UiSample
{
  public class EncryptionUtilities : IEncryptionRoutines
  {
    public string EncryptString(string keyString, string textToEncrypt)
    {
      return textToEncrypt;
    }

    public string DecryptString(string keyString, string textToEncrypt)
    {
      return textToEncrypt;
    }
  }
}
