using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string ret = "";
            char[,] matrix = GenerateKeyMatrix(key);
            Dictionary<char, KeyValuePair<int, int>> flatM = FlattenMatrix(matrix);

            string pairs = "";
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char fc = cipherText[i];
                char sc = cipherText[i + 1];

                if (flatM[fc].Key == flatM[sc].Key)
                {
                    fc = matrix[flatM[fc].Key, (flatM[fc].Value - 1 + 5) % 5];
                    sc = matrix[flatM[sc].Key, (flatM[sc].Value - 1 + 5) % 5];
                }
                else if (flatM[fc].Value == flatM[sc].Value)
                {
                    fc = matrix[(flatM[fc].Key - 1 + 5) % 5, flatM[fc].Value];
                    sc = matrix[(flatM[sc].Key - 1 + 5) % 5, flatM[sc].Value];
                }
                else
                {
                    char nfc = matrix[flatM[fc].Key, flatM[sc].Value];
                    char nsc = matrix[flatM[sc].Key, flatM[fc].Value];

                    fc = nfc;
                    sc = nsc;
                }

                pairs += fc;
                pairs += sc;
            }

            ret += pairs[0];
            for (int i = 1; i < pairs.Length; i++)
            {
                if (i < pairs.Length - 1 && pairs[i] == 'x' && pairs[i - 1] == pairs[i + 1] && i % 2 != 0)
                    continue;
                if (i == pairs.Length - 1 && pairs[i] == 'x')
                    continue;
                ret += pairs[i];
            }
            return ret;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            string ret = "";

            char[,] matrix = GenerateKeyMatrix(key);
            Dictionary<char, KeyValuePair<int, int>> flatM = FlattenMatrix(matrix);

            List<String> pairs = new List<String>();
            pairs = DivideToTwos(plainText);

            for (int i = 0; i < pairs.Count; i++)
            {
                char fc = pairs[i][0];
                char sc = pairs[i][1];

                if (flatM[fc].Key == flatM[sc].Key)
                {
                    fc = matrix[flatM[fc].Key, (flatM[fc].Value + 1) % 5];
                    sc = matrix[flatM[sc].Key, (flatM[sc].Value + 1) % 5];
                }
                else if (flatM[fc].Value == flatM[sc].Value)
                {
                    fc = matrix[(flatM[fc].Key + 1) % 5, flatM[fc].Value];
                    sc = matrix[(flatM[sc].Key + 1) % 5, flatM[sc].Value];
                }
                else
                {
                    char nfc = matrix[flatM[fc].Key, flatM[sc].Value];
                    char nsc = matrix[flatM[sc].Key, flatM[fc].Value];

                    fc = nfc;
                    sc = nsc;
                }
                ret += fc;
                ret += sc;
            }

            return ret;
        }

        private Dictionary<char, KeyValuePair<int, int>> FlattenMatrix(char[,] matrix)
        {
            Dictionary<char, KeyValuePair<int, int>> ret = new Dictionary<char, KeyValuePair<int, int>>();

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    ret[matrix[i, j]] = new KeyValuePair<int, int>(i, j);
                }
            }

            ret['j'] = ret['i'];
            return ret;
        }

        private List<string> DivideToTwos(string plainText)
        {
            List<string> result = new List<string>();

            for (int i = 0; i < plainText.Length; i += 2)
            {
                char firstChar = plainText[i];
                char secondChar = (i + 1 < plainText.Length) ? plainText[i + 1] : 'x';

                if (firstChar == secondChar)
                {
                    result.Add($"{firstChar}x");
                    i--;
                }
                else
                {
                    result.Add($"{firstChar}{secondChar}");
                }
            }

            return result;
        }

        private char[,] GenerateKeyMatrix(string key)
        {
            char[,] matrix = new char[5, 5];
            int keyIdx = 0;
            int alphabetIdx = 0;
            bool[] usedCharacters = new bool[26];

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    char currentChar;

                    if (keyIdx < key.Length)
                    {
                        do
                        {
                            currentChar = key[keyIdx];

                            if (currentChar == 'j')
                            {
                                currentChar = 'i';
                            }
                            keyIdx++;
                        } while (usedCharacters[currentChar - 'a']);

                        matrix[row, col] = currentChar;
                        usedCharacters[currentChar - 'a'] = true;
                    }
                    else
                    {
                        do
                        {
                            currentChar = (char)('a' + alphabetIdx);
                            if (currentChar == 'j')
                            {
                                currentChar = 'i';
                            }
                            alphabetIdx++;
                        } while (usedCharacters[currentChar - 'a']);
                    }

                    matrix[row, col] = currentChar;

                    usedCharacters[currentChar - 'a'] = true;
                }
            }
            return matrix;
        }
    }
}
