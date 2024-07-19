using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int key;
            for(key=2; key <= plainText.Length; key++)
            {
                if(Encrypt(plainText, key) == cipherText)
                {
                    break;
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            string plainText = "";
            int rowLength = (cipherText.Length / key);
            rowLength += (cipherText.Length % key);

            for (int i = 0; i < rowLength; i++)
            {
                for (int j = 0; j < cipherText.Length; j += rowLength)
                {
                    if (j + i < cipherText.Length)
                        plainText += cipherText[j + i];
                }
            }

            return plainText.ToLower();
        }

        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();
            string cipherText = "";
            for (int i=0; i<key; i++)
            {
                for(int j=0; j< plainText.Length; j+=key)
                {
                    if(j + i< plainText.Length) 
                        cipherText += plainText[j+i];
                }
            }
            return cipherText.ToUpper();
        }
    }
}
