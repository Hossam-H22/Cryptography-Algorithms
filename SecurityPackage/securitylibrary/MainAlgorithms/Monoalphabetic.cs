using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            char[] arrKey = new char[26];
            for (int i = 0; i < plainText.Length; i++)
            {
                arrKey[plainText.ToLower()[i] - 'a'] = cipherText.ToLower()[i];
            }

            List<char> keyChar = new List<char>();
            for (int i = 0; i < 26; i++) keyChar.Add((char)('a' + i));

            for (int i = 0; i < 26; i++)
            {
                if (arrKey[i] != '\0')
                {
                    keyChar.Remove(arrKey[i]);
                }
            }

            string key = "";
            for (int i = 0; i < 26; i++)
            {
                if (arrKey[i] != '\0')
                {
                    key += arrKey[i];
                }
                else
                {
                    char c = keyChar[0];
                    keyChar.Remove(c);
                    key += c;
                }
            }

            //Console.WriteLine(key);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += (char)(key.IndexOf(cipherText.ToLower()[i]) + 'a');
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += key[plainText.ToLower()[i] - 'a'];
            }
            return cipherText.ToLower();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            Dictionary<char, int> frequencyChar = new Dictionary<char, int>();

            // Step 1: Calculate frequency of each character
            foreach (char c in cipher.ToLower())
            {
                if (Char.IsLetter(c))
                {
                    if (frequencyChar.ContainsKey(c))
                    {
                        frequencyChar[c]++;
                    }
                    else
                    {
                        frequencyChar.Add(c, 1);
                    }
                }
            }

            // Step 2: Sort characters by frequency
            var sortedFrequencyChar = frequencyChar.OrderByDescending(pair => pair.Value)
                                                   .Select(pair => pair.Key);

            string referenceKeys = "etaoinsrhldcumfpgwybvkxjqz";
            Dictionary<char, char> keyChar = new Dictionary<char, char>();

            // Step 3: Map characters to reference keys
            int counter = 0;
            foreach (char c in sortedFrequencyChar)
            {
                if (counter < referenceKeys.Length)
                {
                    keyChar.Add(c, referenceKeys[counter]);
                    counter++;
                }
                else
                {
                    break; // Break if we run out of reference keys
                }
            }

            // Step 4: Decrypt cipher text using the generated mapping
            StringBuilder plainText = new StringBuilder();
            foreach (char c in cipher.ToLower())
            {
                if (keyChar.ContainsKey(c))
                {
                    plainText.Append(keyChar[c]);
                }
                else
                {
                    plainText.Append(c); // Keep non-alphabetic characters as is
                }
            }

            return plainText.ToString();
        }
    }
}
