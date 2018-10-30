package RSA_Encryption;

import java.math.BigInteger;
import java.security.SecureRandom;
/*========================================
Steps for RSA 
1. select two prime numbers p and q
2. get product of p and q, becomes the modulus in encryption and decryption key
3. calculate Φ(n) "phi function"
4. choose number for encytpion key. It must be coprime with n and Φ(n).
   Also it must be greater than 1 and less than Φ(n)
5. choose number for decryption key. Such that d*e(mod Φ(n) ) = 1
===========================================*/
public class KeyGenerator 
{
	private BigInteger p;		// random prime number
	private BigInteger q;		// random prime number
	private BigInteger n;		// p * q = value to implement modulus math
	private BigInteger phi;		// Φ(n) =  (p-1)*(q-1) 
	private BigInteger e;		// public key
	private BigInteger d;		// private key
	//=========================================================
	public KeyGenerator() 
	{ 
		this.p = primeGenerator();
		this.q = primeGenerator();
		this.n = calcN();
		this.phi = calcPhi();
		this.e = publicKey();
		this.d = privateKey();
	}//end of constructor
	//===============================================================
	// Methods to set Variables in constructor. 
	private BigInteger primeGenerator() 
	{
		BigInteger randomPrime;
		// Why uses SecureRandom instead of Random?
        // Random returns 48bit and uses system clock as seed.
        // SecureRandom, upto 128 bits and uses random data from OS
		SecureRandom secureRandom = new SecureRandom();
		do 
		{	// probablePrime(bitlength of the returned BigInteger,source of random bits to select c)
			// secureRandom.nextInt(80)+48 -> bitlenghts between 48 to 128
			randomPrime = BigInteger.probablePrime(secureRandom.nextInt(80)+48,secureRandom);
			// isProbablePrime(int certainty), returns true if BigInteger is probably prime
			// higher the certainty number you pass, the more certain you can be, 
			// i.e. 100 means it's prime with probability 1 - (1/2)100, which is extremely close to 1.
			// source: https://stackoverflow.com/questions/21740745/clarification-of-the-certainty-factor-in-isprobableprime
		} while(randomPrime.isProbablePrime(100) != true);
		return randomPrime;
	}// end of primeGenerator--------------------------------------------------------
    private BigInteger calcN() 
    {	// p*q
    	return this.p.multiply(this.q);
    }// end of calcN------------------------------------------------------------
    private BigInteger calcPhi() 
    {	// (p-a)(q-1)
        return (this.p.subtract(BigInteger.ONE).multiply(this.q.subtract(BigInteger.ONE)));
    }//end of calcPhi----------------------------------------------------------------------
	private BigInteger publicKey() 
	{	// Publickey must be greather than 1 and less than Φ(n)
		// it must also be coprime to n and Φ(n)
		BigInteger publicKey;
	    do 
	    {	// gcd of any prime# and any # is 1, so a prime number is coprime to n and Φ(n)
	    	publicKey = primeGenerator();
	    	// 1st#.compareTo(2nd#). if 1st number is smaller than 2nd number, compareTo will return -1
	    } while (publicKey.compareTo(phi) != -1); 
	    return publicKey;
	}// end of publicKey-------------------------------------------------------
	private BigInteger privateKey() 
	{	//d*e(mod Φ(n) ) = 1
		return e.modInverse(phi);
	}// end of privateKey------------------------------------------------------------
	//=============================================================================================
	public BigInteger getModValue()
	{
		return this.n;
	}// end of getModValue
    public void printPublicKey()
    {
        System.out.println("Public Key (E): "+ e );
        System.out.println("Mod Number (N): "+ n);
    }// end of printPublicKey
	//=============================================================================================
    // Encryption and Decryption methods
    // encryption is the manipulation of numbers, we must find a numberic way to represent the string message
    // we do so my changing the string into a byte[]
    public byte[] encryptMessage(byte[] message)
    {//encrypting = (message^publicKey)%modValue
        return (new BigInteger(message)).modPow(this.e, this.n).toByteArray();
    }// end of encryptMessage----------------------
    public byte[] decryptMessage(byte[] message)// D = (cypherText^privateKey)%modNum
    {// decription = (encryptedMessage^privateKey)%modValue
        return (new BigInteger(message)).modPow(this.d, this.n).toByteArray();
    }// end of decryptMessage
    //================================================================
    // Signature and verification methods
    public byte[] signature(byte[] message)
    {// signature = (message^privateKey)%modValue
       return (new BigInteger(message)).modPow(this.d,this.n).toByteArray();        
    }// end of signature
    public byte[] verification(byte[] message)
    {// verification = (signature^publicKey)%modValue
       return (new BigInteger(message)).modPow(this.e,this.n).toByteArray();
    }// end of verification
    //==================================================================================================
}// end of class
