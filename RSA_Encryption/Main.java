package RSA_Encryption;

public class Main 
{
	public static void main(String[] args) 
	{
        String message ="Hello"; // string message to encrypt and decrypt
        
        KeyGenerator key = new KeyGenerator();
        
        System.out.println("The message to be encrypted is: "+message);
        key.printPublicKey();
        
        // encrypting message
        // string.getBytes, converts String into byte[]
        byte[] encrypted = key.encryptMessage(message.getBytes()); 
        
        // decrypting message
        byte[] decrypted = key.decryptMessage(encrypted);
        // taking decrypted message bye[] and trasnfroming them back into a string
        String decryptedString = new String(decrypted);
        System.out.println("Decrypted message is: " +decryptedString);
        
        // test to compare original message and decrypted message
        System.out.print("Comparing the original and decrypted messages: ");
        stringComparison(message,decryptedString);
        System.out.println();
        
        
        // signature method
        String signatureString = "signature";
        byte[] signature = key.signature(signatureString.getBytes());
        
        // validation method
        byte[] verification = key.verification(signature); 
        String verificationString = new String(verification);
        System.out.print("Testing signature and verification methods: ");
        stringComparison(signatureString,verificationString);
        System.out.println();
	}// --------------------end of main
	// method to compare original message with the decrypted message
	static void stringComparison(String message, String decryptedMessage)
    {
        if(message.equals(decryptedMessage))
        {
            System.out.println("the two strings are the same");
        }
        else
        {
            System.out.println("the two strings are not the same");
        }
    }//--------------------end of stringComparison()
}// end of class
