using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
		char[,] PopulateCharacterTable(int numRows, int numColumns, int plainLength, string plainTextLC, ref int characterIndex)
		{
			char[,] characterTable = new char[numRows, numColumns];

			for (int rowIndex = 0; rowIndex < numRows; rowIndex++)
			{
				for (int colIndex = 0; colIndex < numColumns; colIndex++)
				{
					if (characterIndex < plainLength)
					{
						characterTable[rowIndex, colIndex] = plainTextLC[characterIndex];
						characterIndex++;
					}
					else
					{
						characterTable[rowIndex, colIndex] = 'X';
					}
				}
			}

			return characterTable;
		}

		List<int> DecodeMessage(char[,] characterTable, int numRows, int numColumns, int cipherLength, string cipherTextLC)
		{
			List<int> keyList = new List<int>(numColumns);

			for (int colIndex = 0; colIndex < numColumns; colIndex++)
			{
				int pointer = 0;
				int checkCount = 0;
				int counter = 2;

				for (int rowIndex = 0; rowIndex < numRows; rowIndex++)
				{
					if ((pointer >= cipherLength || characterTable[rowIndex, colIndex] == cipherTextLC[pointer]))
					{
						checkCount++;
						if (checkCount >= numRows)
						{
							keyList.Add((int)Math.Ceiling(pointer / (float)numRows));
							break;
						}
						pointer++;
					}
					else
					{
						rowIndex = -1;
						int counterIncrement = counter++;
						pointer = counterIncrement * numRows - numRows;
					}
				}
			}

			return keyList;
		}

		public List<int> Analyse(string plainText, string cipherText)
        {
			string plainTextLC = plainText.ToLower();
			string cipherTextLC = cipherText.ToLower();

			int horizontalShift = 0;
			bool brk = false;

			int plainLength = plainTextLC.Length;
			int cipherLength = cipherTextLC.Length;

			// This set of nested loops searches for a sequence that matchees between plain and cipher
			// - checking if the first character of the cipher matches with the current character of the plain.
			// - if any match, then it iterates on the remaining characters of the plain to find matches for the fllowing cipher characters.
			// - when a matching part is found, it calculates the horiz shift and sets the brk boolean to indicate success, then breaks out of all loops
			for (int i = 0; i < plainLength; i++)
			{
				if (cipherTextLC[0] == plainTextLC[i])
				{
					for (int j = i + 1; j < cipherLength; j++)
					{
						if (cipherTextLC[1] == plainTextLC[j])
						{
							for (int k = j + 1; k < cipherLength; k++)
							{
								if (k - j > j - i)
								{
									break;
								}
								else if (cipherTextLC[2] == plainTextLC[k] && k - j == j - i)
								{
									horizontalShift = j - i;
									brk = true;
									break;
								}
							}
						}
						if (brk)
						{
							break;
						}
					}
				}
				if (brk)
				{
					break;
				}
			}

			int numOfColumns = horizontalShift;
			int numOfRows = (int)Math.Ceiling(plainLength / (float)horizontalShift);
			int characterIndex = 0;

			char[,] characterTable = PopulateCharacterTable(numOfRows, numOfColumns, plainLength, plainTextLC, ref characterIndex);

			List<int> keyList = DecodeMessage(characterTable, numOfRows, numOfColumns, cipherLength, cipherTextLC);
			return keyList;
		}

		public string Decrypt(string cipherText, List<int> key)
		{
			int numColumns = key.Count;
			int numRows = (int)Math.Ceiling((double)cipherText.Length / numColumns);
			char[,] matrix = new char[numRows, numColumns];
			char[,] decryptedText = new char[numRows, numColumns];
			int padding = matrix.Length - cipherText.Length;
			string decipheredText = "";

			if (padding == 0)
			{
				int index = 0;
				for (int i = 0; i < numColumns; i++)
				{
					for (int j = 0; j < numRows; j++)
					{
						if (index < cipherText.Length)
						{
							matrix[j, i] = cipherText[index];
							index++;
						}
					}
				}
			}
			else
			{
				int index = 0;
				for (int i = numColumns - 1; i > numColumns - padding - 1; i--)
				{
					matrix[numRows - 1, i] = 'X';
				}
				for (int i = 0; i < numColumns; i++)
				{
					for (int j = 0; j < numRows; j++)
					{
						if (matrix[j, i] == 'X')
						{
							continue;
						}
						if (index < cipherText.Length)
						{
							matrix[j, i] = cipherText[index];
							index++;
						}
					}
				}
			}

			int columnIndex = 0;
			foreach (int i in key)
			{
				for (int j = 0; j < numRows; j++)
				{
					decryptedText[j, columnIndex] = matrix[j, i - 1];
				}
				columnIndex++;
			}

			foreach (char c in decryptedText)
			{
				decipheredText += c;
			}

			return decipheredText.ToLower();
		}

		public string Encrypt(string plainText, List<int> key)
		{
			float result = (float)plainText.Length / (float)key.Count;
			char[,] matrix = new char[(int)Math.Ceiling(result), key.Count];
			string ciphertext = "";
			int row = 0, col = 0, target = 1, count = 0, index = 0;

			foreach (char character in plainText)
			{
				matrix[row, col] = character;

				col++;
				if (col > (key.Count - 1))
				{
					col = 0;
					row++;
				}
			}

			for (int i = 0; i < matrix.GetLength(0); i++)
			{
				for (int j = 0; j < matrix.GetLength(1); j++)
				{
					if (matrix[i, j] == '\0')
					{
						matrix[i, j] = 'X';
					}
				}
			}

			while (index < key.Count)
			{
				if (key[index] == target)
				{
					for (int j = 0; j < matrix.GetLength(0); j++)
					{
						ciphertext += matrix[j, count];
					}
					index = 0;
					target++;
					count = 0;
				}
				else
				{
					index++;
					count++;
				}
			}

			return ciphertext.ToLower();
		}
	}
}
