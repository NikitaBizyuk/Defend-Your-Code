/*
 Team Members:
 Assignment: Defend Your Code
 1) Validate ALL user inputs (names, ints, file names, passwords).
 2) Never crash. The program must keep running until valid input is obtained.
 3) Log ANY errors/exceptions to an error log file (error.log).
 4) Prevent integer overflow for both SUM and PRODUCT (32-bit signed int).
 5) Passwords must NOT be stored in plaintext.
    - Use random SALT + PBKDF2 hash
    - Write salt+hash to a file
    - For verification: READ salt+hash back from file and compare
*/

import java.io.*;                       // File I/O for output file + error log + password store
import java.math.BigInteger;            // Used to safely check bounds and prevent overflow
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;            // Modern file read/write helpers
import java.security.SecureRandom;      // Cryptographically secure random salt
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;      // Timestamp for error.log
import java.util.*;                     // Scanner, Arrays, Base64, Date, List
import java.util.regex.*;               // Regex validation
import javax.crypto.SecretKeyFactory;   // PBKDF2 hash implementation
import javax.crypto.spec.PBEKeySpec;

public class Main2 {

  // Error log file
  private static final String Error_Log = "error.log";

  // Password store file (salt+hash).
  private static final String Password_Store = "password_store.txt";

  // 32-bit signed integer bounds (to enforce 4-byte int rules)
  private static final BigInteger INT32_MAX = BigInteger.valueOf(Integer.MAX_VALUE); //  2147483647
  private static final BigInteger INT32_MIN = BigInteger.valueOf(Integer.MIN_VALUE); // -2147483648

  public static void main(String[] args) {
    Scanner input = new Scanner(System.in);

    // Read first name + last name
    String firstName = validateName(input, "FIRST NAME");
    String lastName  = validateName(input, "LAST NAME");

    // Read two int values (must be 32-bit signed int)
    int integerValueOne, integerValueTwo, sum, product;

    while (true) {
      integerValueOne = validateIntValue(input, "Value 1");
      integerValueTwo = validateIntValue(input, "Value 2");

      // Use BigInteger for safe arithmetic
      BigInteger sumBig  = BigInteger.valueOf(integerValueOne).add(BigInteger.valueOf(integerValueTwo));
      BigInteger prodBig = BigInteger.valueOf(integerValueOne).multiply(BigInteger.valueOf(integerValueTwo));

      // If both results fit in 32-bit, we are safe to cast
      if (fitsInt32(sumBig) && fitsInt32(prodBig)) {
        sum = sumBig.intValue();
        product = prodBig.intValue();
        break;
      }

      // Log overflow event and keep running
      logError("Sum/Product overflow for a=" + integerValueOne + ", b=" + integerValueTwo, null);
      System.out.println(" Sum or product would overflow a 32-bit int. Please re-enter BOTH integers.");
    }

    // ---------------------------------------------------------------------
    // Prompt for input file name
    // Teammate function verifyTxtFile() validates naming pattern only.
    // Professor also expects:
    // - input file must EXIST and be READABLE
    //
    // Defense:
    // - After regex validation, we perform existence/readability checks.
    // - If it fails, we re-prompt.
    // ---------------------------------------------------------------------
    String inputFileName = verifyTxtFile(input, "Input File");
    inputFileName = verifyExistingReadableInputFile(input, inputFileName);

    // Read input file contents (required: write contents into output file)
    String inputFileContents = readFileContentsWithRetry(input, inputFileName);

    // 5) Prompt for output file name
    //
    // Professor expects:
    // - output file must be WRITABLE or CREATABLE
    // - It may overwrite existing file (we allow to overwrite)
    //
    // Defense:
    // - After regex validation, we check filesystem permissions.
    String outputFileName = verifyTxtFile(input, "Output File");
    outputFileName = verifyWritableOutputFile(input, outputFileName);


    // 6) Password flow
    //
    // Requirements:
    // - prompt password
    // - enforce password rules
    // - generate salt
    // - hash with PBKDF2
    // - write salt+hash to file
    // - prompt user to re-enter password
    // - READ salt+hash from file and compare hashes
    // - if mismatched, restart password flow
    //
    // Defense:
    // - store only hash+salt, never plaintext
    // - loop until password matches and meets requirements
    handlePasswordFlow(input);

    // Write output file with labeled data
    //
    // Professor requirement:
    // - clearly label each field:
    //   First name, Last name, integers, sum, product, input file name, contents
    //
    // Defense:
    // - If write fails (permissions, disk issues), log error and re-prompt output file.
    // ---------------------------------------------------------------------
    writeOutputFileWithRetry(input, outputFileName,
            firstName, lastName,
            integerValueOne, integerValueTwo,
            sum, product,
            inputFileName, inputFileContents);

    System.out.println("✅ All inputs validated. Output written to: " + outputFileName);
  }

  /**
   * validateName() uses regex to ensure that the user's input
   * does not violate any requirements. This method is used
   * for both first name and last name.
   * Security / defense intent:
   * - Prevent empty / invalid characters from entering the system.
   * - Avoid crashes by looping until valid input is received.
   *
   * @param input Scanner reading from stdin.
   * @param firstLastName label telling user which name to enter.
   * @return a string that represents the user's name and matches requirements.
   */
  public static String validateName(Scanner input, String firstLastName) {

    // Allows letters, hyphen, apostrophe; length 1..50
    Pattern p = Pattern.compile("[A-Za-z-']{1,50}");

    // User instructions
    String requirements =
            "Input must meet following requirements:\n " +
                    "\t1) Input must include characters (A-Z or a-z) inclusive.\n" +
                    "\t2) Special characters such as (- and ') are permitted.\n" +
                    "\t3) input length must be >= 1 and <= 50\n";

    System.out.println("PLEASE ENTER YOUR " + firstLastName + ":\n" +
            requirements + "\nENTER " + firstLastName + ":");

    String name = input.nextLine();
    Matcher m = p.matcher(name);

    // Defensive loop: keep prompting until regex passes
    while (!m.matches()) {
      System.out.println("HOUSTON WE HAVE A PROBLEM! " + requirements + "\t" + name +
              "\tDoes not meet the following requirements." +
              "\n\tPlease try again!");
      name = input.nextLine();
      m = p.matcher(name);
    }

    return name;
  }

  /**
   * validateIntValue() verifies the user's integer input.
   * Security / defense intent:
   * - Reject non-integer strings
   * - Enforce 32-bit integer range
   * - Avoid crashes: loop until valid
   * NOTE:
   * - This function alone ensures each input fits in int32.
   * - Overflow for sum/product is handled outside in main().
   */
  public static int validateIntValue(Scanner input, String intVal) {

    String requirements = "value must be inclusive between -2,147,483,648  to  2,147,483,647";
    String promptUser = ("PLEASE ENTER A VALUE FOR " + intVal +
            "\n" + requirements + "\n" + intVal + ":");

    // Allows comma formatting (e.g., 1,000). Then commas are removed.
    Pattern p = Pattern.compile("^[+-]?(?:\\d{1,3}(?:,\\d{3})*|\\d+)$");

    System.out.println(promptUser);
    String userInput = input.nextLine();

    // Step 1: validate regex formatting, return cleaned numeric string
    String cleanedInput = validateRegExValue(userInput, p, requirements, intVal, input);

    // Step 2: convert to BigInteger to avoid parse overflow and do range checks safely
    BigInteger theInput = new BigInteger(cleanedInput);

    // Step 3: verify bounds -2147483648..2147483647
    return verifyBounds(p, requirements, intVal, theInput, input);
  }

  /**
   * validateRegExValue() checks input against regex pattern.
   *
   * Defense:
   * - Prevent non-numeric text causing NumberFormatException or logic errors.
   * - Loop until input matches allowed format.
   *
   * @return valid numeric string (commas removed)
   */
  public static String validateRegExValue(String userInput, Pattern p, String requirements,
                                          String intVal, Scanner input) {
    Matcher m = p.matcher(userInput);

    while (!m.matches()) {
      System.out.println("\tYour input does not match the requirements listed above.\n" +
              "\tPLEASE ENTER A VALUE FOR " + intVal +
              "\n" + requirements + "\n" + intVal + ":");
      userInput = input.nextLine();
      m = p.matcher(userInput);
    }

    // Remove commas if user typed formatted integer like 1,000
    return userInput.replace(",", "");
  }

  /**
   * verifyBounds() enforces int32 bounds.
   *
   * Defense:
   * - Prevent overflow when converting to int.
   * - Keep prompting until value is within bounds.
   *
   * @return int32-safe integer
   */
  public static int verifyBounds(Pattern p, String requirements,
                                 String intVal, BigInteger theInput, Scanner input) {
    BigInteger maxVal = new BigInteger("2147483647");
    BigInteger minVal = new BigInteger("-2147483648");

    while ((theInput.compareTo(maxVal) > 0) || (theInput.compareTo(minVal) < 0)) {

      if (theInput.compareTo(maxVal) > 0) {
        System.out.println("Your input was greater then the value of 2,147,483,647\n" +
                "\tthis will result in an integer overflow.\n" +
                "Please try again:");
      } else {
        System.out.println("Your input was less then the value of -2,147,483,648\n" +
                "this will result in an integer overflow.\n" +
                "Please try again:");
      }

      String userInput = input.nextLine();
      String cleanedInput = validateRegExValue(userInput, p, requirements, intVal, input);
      theInput = new BigInteger(cleanedInput);
    }

    // Safe conversion (guaranteed within int32 bounds here)
    return theInput.intValueExact();
  }

  /**
   * verifyTxtFile() uses regex to ensure the file name:
   * - ends with .txt
   * - uses allowed characters
   *
   * IMPORTANT:
   * - This does NOT check existence or permissions.
   * - We add additional checks outside this function to satisfy professor requirements.
   */
  public static String verifyTxtFile(Scanner input, String io) {
    String requirements = ("-File type (.txt) accepted only.\n" +
            "-Naming conventions allow for characters A-Z,0-9, special characters such as\n" +
            "(._-)\n" +
            "-length of file name must be greater than or equal to 1");

    Pattern p = Pattern.compile("^[A-Za-z0-9._-]+\\.txt$");

    System.out.println("\nPlease enter an " + io + " name that matches the requirements listed below: \n" +
            requirements + "\n" +
            "Enter " + io + " name: ");
    String userInput = input.nextLine();
    Matcher m = p.matcher(userInput);

    while (!m.matches()) {
      System.out.println("File name or type does not follow the requirements listed below: \n"
              + requirements + "\n" +
              "Please enter " + io + " file name here: ");
      userInput = input.nextLine();
      m = p.matcher(userInput);
    }

    return userInput;
  }

  /**
   * Helper Method:
   * Utility check: does a BigInteger value fit into 32-bit signed int range?
   * Used for sum/product overflow defense.
   */
  private static boolean fitsInt32(BigInteger v) {
    return v.compareTo(INT32_MIN) >= 0 && v.compareTo(INT32_MAX) <= 0;
  }

  /**
   * verifyExistingReadableInputFile():
   * Professor requirement: input file must exist and be readable.
   *
   * Defense:
   * - Prevent FileNotFound errors later
   * - Prevent crashes due to unreadable file
   */
  private static String verifyExistingReadableInputFile(Scanner input, String fileName) {
    while (true) {
      try {
        File f = new File(fileName);

        // Must exist, must be a regular file, must be readable
        if (f.exists() && f.isFile() && f.canRead()) return fileName;

        logError("Input file missing/unreadable: " + fileName, null);
        System.out.println("Input file must exist and be readable. Please enter again.");
        fileName = verifyTxtFile(input, "Input File");

      } catch (Exception e) {
        logError("Error validating input file: " + fileName, e);
        System.out.println("Error validating input file. Please try again.");
        fileName = verifyTxtFile(input, "Input File");
      }
    }
  }

  /**
   * verifyWritableOutputFile():
   * Professor requirement: output file must be writable or creatable.
   *
   * Defense:
   * - Prevent failures when writing output file
   */
  private static String verifyWritableOutputFile(Scanner input, String fileName) {
    while (true) {
      try {
        if (canWriteFile(fileName)) return fileName;

        logError("Output file not writable/creatable: " + fileName, null);
        System.out.println("Output file is not writable/creatable. Please enter again.");
        fileName = verifyTxtFile(input, "Output File");

      } catch (Exception e) {
        logError("Error validating output file: " + fileName, e);
        System.out.println("Error validating output file. Please try again.");
        fileName = verifyTxtFile(input, "Output File");
      }
    }
  }

  /**
   * canWriteFile():
   * - If file exists: must be a file and writable
   * - If file does not exist: parent directory must be writable (so we can create it)
   */
  private static boolean canWriteFile(String fileName) {
    File f = new File(fileName);
    if (f.exists()) {
      return f.isFile() && f.canWrite();
    }
    File parent = f.getAbsoluteFile().getParentFile();
    if (parent == null) parent = new File(".");
    return parent.exists() && parent.isDirectory() && parent.canWrite();
  }

  /**
   * readFileContentsWithRetry():
   * Reads input file contents. If reading fails, re-prompt for file name.
   * - Avoid program termination on IOException
   * - Keep prompting until readable file is provided
   */
  private static String readFileContentsWithRetry(Scanner input, String inputFileName) {
    while (true) {
      try {
        return Files.readString(new File(inputFileName).toPath(), StandardCharsets.UTF_8);
      } catch (IOException e) {
        logError("Failed to read input file: " + inputFileName, e);
        System.out.println("Failed to read input file. Please re-enter input file name.");
        inputFileName = verifyTxtFile(input, "Input File");
        inputFileName = verifyExistingReadableInputFile(input, inputFileName);
      }
    }
  }

  /**
   * writeOutputFileWithRetry():
   * Writes all required labeled data to output file.
   * - If file write fails due to permissions/disk, we log error and re-prompt.
   * - Add BEGIN/END boundaries so input file content cannot "fake" labels.
   */
  private static void writeOutputFileWithRetry(Scanner input,
                                               String outputFileName,
                                               String firstName,
                                               String lastName,
                                               int a,
                                               int b,
                                               int sum,
                                               int product,
                                               String inputFileName,
                                               String inputFileContents) {
    while (true) {
      try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
              new FileOutputStream(outputFileName, false), StandardCharsets.UTF_8))) {

        writer.write("First Name: " + firstName); writer.newLine();
        writer.write("Last Name: " + lastName); writer.newLine();
        writer.write("First Integer: " + a); writer.newLine();
        writer.write("Second Integer: " + b); writer.newLine();
        writer.write("Sum: " + sum); writer.newLine();
        writer.write("Product: " + product); writer.newLine();
        writer.write("Input File Name: " + inputFileName); writer.newLine();
        writer.newLine();

        writer.write("---- BEGIN INPUT FILE CONTENTS ----"); writer.newLine();
        writer.write(inputFileContents); writer.newLine();
        writer.write("---- END INPUT FILE CONTENTS ----"); writer.newLine();

        return;

      } catch (IOException e) {
        logError("Failed to write output file: " + outputFileName, e);
        System.out.println("Failed to write output file. Please re-enter output file name.");
        outputFileName = verifyTxtFile(input, "Output File");
        outputFileName = verifyWritableOutputFile(input, outputFileName);
      }
    }
  }

  /**
   * Helper Method:
   * - prompt password (must satisfy password policy)
   * - generate salt and hash
   * - write salt+hash to file
   * - prompt again
   * - read back salt+hash from file and compare
   * - loop until match
   *
   * Defense:
   * - Never store plaintext password.
   * - Do not crash on crypto or I/O errors.
   */
  private static void handlePasswordFlow(Scanner input) {
    while (true) {
      try {
        System.out.println("\nEnter password (8-64 chars; must include upper, lower, digit, special; no spaces):");
        String p1 = input.nextLine();

        if (!isValidPassword(p1)) {
          logError("Password failed validation rules.", null);
          System.out.println(" Password does not meet requirements. Try again.");
          continue;
        }

        // Generate random salt (unique per password)
        byte[] salt = generateSalt(16);

        // Hash password with PBKDF2 (slow hash -> better against brute force)
        byte[] hash = pbkdf2Hash(p1.toCharArray(), salt);
        if (hash == null) {
          logError("Password hashing failed.", null);
          System.out.println("Hashing failed. Try again.");
          continue;
        }

        // Write to file: salt + hash (Base64)
        writePasswordStore(salt, hash);

        // READ BACK from file (explicit professor requirement)
        PasswordRecord record = readPasswordStore();
        if (record == null) {
          logError("Failed to read password store for verification.", null);
          System.out.println("Could not read password store. Try again.");
          continue;
        }

        System.out.println("Re-enter password to verify:");
        String p2 = input.nextLine();

        // Hash second entry using the same salt
        byte[] hash2 = pbkdf2Hash(p2.toCharArray(), record.salt);
        if (hash2 == null) {
          logError("Password verification hashing failed.", null);
          System.out.println("Hashing failed. Try again.");
          continue;
        }

        // Compare stored hash vs. new hash
        if (Arrays.equals(record.hash, hash2)) {
          System.out.println("Password verified.");
          return;
        }

        logError("Password mismatch.", null);
        System.out.println("Passwords did not match. Start over.");

      } catch (Exception e) {
        logError("Error in password flow.", e);
        System.out.println("Password flow error. Try again.");
      }
    }
  }

  /**
   * Password policy:
   * - length 8..64
   * - must have uppercase, lowercase, digit, special
   * - no whitespace
   */
  private static boolean isValidPassword(String pwd) {
    return pwd != null
            && pwd.matches("^(?=.{8,64}$)(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9])\\S+$");
  }

  /**
   * generateSalt():
   * Use SecureRandom to generate cryptographically strong salt.
   */
  private static byte[] generateSalt(int length) {
    byte[] salt = new byte[length];
    new SecureRandom().nextBytes(salt);
    return salt;
  }

  /**
   * pbkdf2Hash():
   * PBKDF2WithHmacSHA256 is widely accepted for password hashing.
   * The high iteration count makes brute-force attacks more expensive.
   */
  private static byte[] pbkdf2Hash(char[] password, byte[] salt) {
    try {
      PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      return factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      logError("PBKDF2 error.", e);
      return null;
    }
  }

  /**
   * writePasswordStore():
   * Store salt and hash (Base64 encoded) into Password_Store.
   * This file is used later for verification.
   */
  private static void writePasswordStore(byte[] salt, byte[] hash) {
    try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
            new FileOutputStream(Password_Store, false), StandardCharsets.UTF_8))) {

      writer.write("salt=" + Base64.getEncoder().encodeToString(salt));
      writer.newLine();
      writer.write("hash=" + Base64.getEncoder().encodeToString(hash));
      writer.newLine();

    } catch (IOException e) {
      logError("Failed to write password store.", e);
    }
  }

  /**
   * readPasswordStore():
   * Reads back salt+hash from file.
   * If file is missing/corrupt, returns null (do not crash).
   */
  private static PasswordRecord readPasswordStore() {
    try {
      List<String> lines = Files.readAllLines(new File(Password_Store).toPath(), StandardCharsets.UTF_8);
      String saltLine = null, hashLine = null;

      for (String line : lines) {
        if (line.startsWith("salt=")) saltLine = line.substring("salt=".length()).trim();
        if (line.startsWith("hash=")) hashLine = line.substring("hash=".length()).trim();
      }

      if (saltLine == null || hashLine == null) return null;

      byte[] salt = Base64.getDecoder().decode(saltLine);
      byte[] hash = Base64.getDecoder().decode(hashLine);
      return new PasswordRecord(salt, hash);

    } catch (Exception e) {
      logError("Failed to read password store.", e);
      return null;
    }
  }

  /**
   * Simple container class holding salt+hash read from file.
   */
  private static class PasswordRecord {
    final byte[] salt;
    final byte[] hash;
    PasswordRecord(byte[] salt, byte[] hash) {
      this.salt = salt;
      this.hash = hash;
    }
  }

  /**
   * logError():
   * Writes error messages (and optional exception) to error.log.
   *
   * Critical requirement:
   * - DO NOT throw exceptions from logger.
   *   If logging fails, we ignore it to prevent program crash.
   */
  private static void logError(String message, Exception e) {
    try (BufferedWriter writer =
                 new BufferedWriter(new FileWriter(Error_Log, true))) {

      String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

      writer.write("[" + timestamp + "] " + message);
      writer.newLine();

      if (e != null) {
        writer.write("Exception: " + e);
        writer.newLine();
      }

      writer.newLine();

    } catch (IOException ignored) {
      // Never crash from the logger.
    }
  }
}