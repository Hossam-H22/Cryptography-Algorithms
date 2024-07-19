# Cryptography Algorithms

Cryptographic algorithms are essential for securing data in various applications, including communications, data storage, and authentication. They can be broadly categorized into three types: symmetric-key algorithms, asymmetric-key algorithms, and cryptographic hash functions.

<br>

## 1. Symmetric-Key Algorithms

These algorithms use the same key for both encryption and decryption. The key must be kept secret, and both the sender and receiver must have access to it.

- **Ceaser** - [Code](SecurityPackage/securitylibrary/MainAlgorithms/Ceaser.cs)

    - This cipher is one of the simplest and oldest known encryption techniques.
    - It is a type of substitution cipher where each letter in the plaintext is shifted a fixed number of places down or up the alphabet.



- **Monoalphabetic** - [Code](SecurityPackage/securitylibrary/MainAlgorithms/Monoalphabetic.cs)
  
    - It is a type of substitution cipher where each letter in the plaintext is mapped to a fixed corresponding letter in the ciphertext alphabet.
    - Unlike the Caesar cipher, which uses a uniform shift, a monoalphabetic cipher uses a more complex permutation of the alphabet.
 
    

- **Polyalphabetic** - [Repeating Key Code](SecurityPackage/securitylibrary/MainAlgorithms/RepeatingKeyVigenere.cs) , [Auto Key Code](SecurityPackage/securitylibrary/MainAlgorithms/AutokeyVigenere.cs)
  
    - It is a type of substitution cipher that uses multiple substitution alphabets to encrypt the message.
    - This makes it more secure than monoalphabetic ciphers because it complicates frequency analysis.
 


- **Playfair** - [Code](SecurityPackage/securitylibrary/MainAlgorithms/PlayFair.cs)

    -  It is a type of digraph substitution cipher, which encrypts pairs of letters (digraphs) instead of single letters.
    -  It was invented by Charles Wheatstone in 1854 but is named after Lord Playfair, who promoted its use.
    -  The Playfair cipher is more secure than simple monoalphabetic ciphers due to its digraph nature, making frequency analysis more challenging.
 

   
- **Hill Cipher** - [Code](SecurityPackage/securitylibrary/MainAlgorithms/HillCipher.cs)

    - It is a polygraphic substitution cipher based on linear algebra.
    - Invented by Lester S. Hill in 1929, it uses matrix multiplication to encrypt blocks of plaintext.
    - The Hill cipher is more complex and secure compared to monoalphabetic ciphers, especially when larger matrix sizes are used.



- **Rail fence** - [Code](SecurityPackage/securitylibrary/MainAlgorithms/RailFence.cs)

    - It is a type of transposition cipher that rearranges the characters of the plaintext in a zigzag pattern across multiple "rails" (rows) and then reads off each row in order to create the ciphertext.
    - It's named for the way the text is written out, resembling the rails of a fence.



- **Columnar** - [Code](SecurityPackage/securitylibrary/MainAlgorithms/Columnar.cs)

    - Columnar Transposition cipher is a method of encryption where the plaintext is written out in rows of a fixed length (determined by the key), and the ciphertext is formed by reading the columns in a specific order, dictated by the key.



- **AES (Advanced Encryption Standard)** - [Code](SecurityPackage/securitylibrary/AES/AES.cs)
    - It is a symmetric encryption algorithm widely used across the globe for securing data.
    - It was established by the U.S. National Institute of Standards and Technology (NIST) in 2001 and is based on the Rijndael cipher developed by cryptographers Vincent Rijmen and Joan Daemen.
 


- **DES (Data Encryption Standard)** - [Code](SecurityPackage/securitylibrary/DES/DES.cs)
    - It is a symmetric-key block cipher that was widely used for data encryption from the 1970s until more secure algorithms like AES superseded it because DES has a shorter key length making it vulnerable to brute-force attacks.
    - DES encrypts data in 64-bit blocks using a 56-bit key.





<br>





## 2. Symmetric-Key Algorithms

These algorithms use a pair of keys – a public key for encryption and a private key for decryption. This key pair is mathematically linked.


- **RSA (Rivest-Shamir-Adleman)** - [Code](SecurityPackage/securitylibrary/RSA/RSA.cs)

    - It is a widely used public-key cryptosystem that enables secure data transmission and digital signatures.
    - It relies on the mathematical properties of large prime numbers and is foundational to modern cryptography.



- **Diffie-Hellman** - [Code](SecurityPackage/securitylibrary/DiffieHellman/DiffieHellman.cs)

    - It is used primarily for secure key exchange, allowing two parties to establish a shared secret key over an insecure channel.
    - It was introduced by Whitfield Diffie and Martin Hellman in 1976 and is a foundational technique in cryptography.
    - Unlike symmetric algorithms, which use the same key for both encryption and decryption, Diffie-Hellman is based on asymmetric principles where the keys used for exchanging information are different from the keys used for encryption and decryption.



- **ElGamal** - [Code](SecurityPackage/securitylibrary/ElGamal/ELGAMAL.cs)

    - ElGamal encryption is a public-key cryptosystem that is based on the difficulty of the discrete logarithm problem.
    - It was proposed by Taher Elgamal in 1985.
    - The ElGamal encryption algorithm is used for secure communication, digital signatures, and key exchange.
 


<br>
