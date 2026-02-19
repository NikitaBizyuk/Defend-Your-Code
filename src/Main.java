import java.math.BigInteger;
import java.util.Scanner;
import java.util.regex.*;
public class Main {
    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        String firstName = validateName(input,"FIRST NAME");
        String lastName =  validateName(input, "LAST NAME");
        int integerValueOne = validateIntValue(input, "Value 1");
        int integerValueTwo = validateIntValue(input,"Value 2");
        String InputFileName = verifyTxtFile(input, "Input File");
        String outputFileName = verifyTxtFile(input, "output File");

    }

    /**
     * validateName() uses regex to ensure that the users input
     * does not violate any requirements. This method is used
     * for both first name and last name.
     * @param input Scanner input from the user.
     * @param firstLastName string value directing user to enter first or last name
     * @return a string that represents the users name and matches all input requirements.
     */
    public static String validateName(Scanner input, String firstLastName){
        boolean valid = false;
        String name = "";
        Pattern p = Pattern.compile("[A-Za-z-']{1,50}");
        String requirements = "Input must meet following requirements:\n " +
        "\t1) Input must include characters (A-Z or a-z) inclusive.\n" +
                "\t2) Special characters such as (- and ') are permitted.\n" +
                "\t3) input length must be greater then or equal to 1 and less then or equal to 50\n";
        System.out.println("PLEASE ENTER YOUR " + firstLastName + ":\n" +
                requirements + "\nENTER " + firstLastName + ":");
        name = input.nextLine();
        Matcher m = p.matcher(name);
        while(!m.matches()){
                System.out.println("HOUSTON WE HAVE A PROBLEM! " + requirements + "\t" + name +
                        "\tDoes not meet the following requirements." +
                        "\n\tPlease try again!");
                name = input.nextLine();
                m = p.matcher(name);
        }
        return name;
    }

    /**
     * validateIntValue() verifies the users input to ensure
     * that it meets the requirements for the input value.
     * This function uses to helper methods. The first is validateRegExValue() to
     * validate correct formating and character use. The second helper function is
     * verifyBounds() which ensures that no integer overflow takes place.
     * @param input Scanner input value
     * @param intVal prompting user to enter (value 1) or (value 2)
     * @return an integer value that meets all regex requirements and is within bounds
     * of a 4 byte integer.
     */
    public static int validateIntValue(Scanner input, String intVal){
        String userInput = "";
        String requirements = "value must be inclusive between -2,147,483,648  to  2,147,483,647";
        String promptUser = ("PLEASE ENTER A VALUE FOR " + intVal +
                "\n" + requirements + "\n" + intVal + ":");
        Pattern p = Pattern.compile("^[+-]?(?:\\d{1,3}(?:,\\d{3})*|\\d+)$");
        System.out.println(promptUser);
        userInput = input.nextLine();
        String cleanedInput = validateRegExValue(userInput,p,requirements,intVal,input);
        BigInteger theInput = new BigInteger(cleanedInput);
       return verifyBounds(p, requirements, intVal, theInput, input);
    }

    /**
     * validateRegExValue() checks to make sure input meets regex requirements.
     * @param userInput User input stored as a string
     * @param p pattern object that stores regex
     * @param requirements string to restate requirements to user if necessary.
     * @param intVal (value 1) or (value 2)
     * @param input scanner input
     * @return valid string that meets regex requirements
     */
    public static String validateRegExValue(String userInput,Pattern p, String requirements,
                                            String intVal, Scanner input){
        Matcher m = p.matcher(userInput);
        while(!m.matches()){
            System.out.println("\tYour input does not match the requirements listed above.\n" +
                    "\t" + "PLEASE ENTER A VALUE FOR " + intVal +
                    "\n" + requirements + "\n" + intVal + ":");
            userInput = input.nextLine();
            m = p.matcher(userInput);
        }
        return userInput.replace(",", "");
    }

    /**
     * verifyBounds() verifies the input value to ensure no
     * integer overflow takes place
     * @param p pattern object storing regex
     * @param requirements String for requirements prompting
     * @param intVal (value 1) or (value 2)
     * @param theInput users input in BigInteger object
     * @param input scanner input to prompt in terminal
     * @return integer that meets both bounds and regex
     */
    public static int verifyBounds(Pattern p, String requirements,
                                   String intVal, BigInteger theInput, Scanner input){
        BigInteger maxVal = new BigInteger("2147483647");
        BigInteger minVal = new BigInteger("-2147483648");
        while((theInput.compareTo(maxVal) > 0) || (theInput.compareTo(minVal) < 0)){
            String userInput;
            String cleanedInput;
            if(theInput.compareTo(maxVal) > 0){
                System.out.println("Your input was greater then the value of 2,147,483,647\n" +
                        "\tthis will result in an integer overflow.\n" +
                        "Please try again:");
                userInput = input.nextLine();
                cleanedInput = validateRegExValue(userInput,p,requirements,intVal,input);
                theInput = new BigInteger(cleanedInput);
            } else {
                System.out.println("Your input was less then the value of -2,147,483,648\n" +
                        "this will result in an integer overflow.\n" +
                        "Please try again:");
                userInput = input.nextLine();
                cleanedInput = validateRegExValue(userInput,p,requirements,intVal,input);
                theInput = new BigInteger(cleanedInput);
            }
        }
        return theInput.intValueExact();
    }

    /**
     * verifyTxtFile() uses regex to ensure that the file
     * is a txt file and meets all naming convention requirements.
     * @param input scanner input
     * @return string representing the name of the file that
     * meets regex requirements
     */
    public static String verifyTxtFile(Scanner input, String io){
        String userInput = "";
        String requirements = ("-File type (.txt) accepted only.\n" +
                "-Naming conventions allow for characters A-Z,0-9, special characters such as\n" +
                "(._-)\n" +
                "-length of file name must be greater than or equal to 1");
        Pattern p = Pattern.compile("^[A-Za-z0-9._-]+\\.txt$");
        System.out.println("\nPlease enter an " + io + " name that matches the requirements listed below: \n" +
                requirements + "\n" +
                "Enter " + io + " name: ");
        userInput = input.nextLine();
        Matcher m = p.matcher(userInput);
        while(!m.matches()){
            System.out.println("File name or type does not follow the requirements listed below: \n"
            + requirements + "\n" +
                    "Please enter " + io + " file name here: ");
            userInput = input.nextLine();
            m = p.matcher(userInput);
        }
        return userInput;
    }
}