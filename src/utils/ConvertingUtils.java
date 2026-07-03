package utils;

import java.util.HexFormat;

public class ConvertingUtils {

    /*
     * Method to convert a String into a byte array.
     */
    public static byte[] toByteArray(String input) {
        return input.getBytes();
    }

    /*
     * Method to convert a byte array into a hex string.
     */
    public static String toHexString(byte[] input) {
        return HexFormat.of().formatHex(input);
    }

    /*
     * Method to convert a hex string into a byte array.
     */
    public static byte[] fromHexString(String input) {
        return HexFormat.of().parseHex(input);
    }

}
