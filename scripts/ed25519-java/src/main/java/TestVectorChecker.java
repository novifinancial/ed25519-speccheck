import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import java.io.FileNotFoundException;
import java.io.FileReader;

public class TestVectorChecker {

    public static void main(String[] args) throws FileNotFoundException {
        String jsonFilename = "../../cases.json";
        JsonReader reader = new JsonReader(new FileReader(jsonFilename));
        Ed25519TestCase[] testCases = new Gson().fromJson(reader, Ed25519TestCase[].class);

        // For i2p ed25519-java
        System.out.print("|ed25519-java   |");
        for (Ed25519TestCase testCase : testCases) {
            if (testCase.verify_i2p()) {
                System.out.print(" V |");
            } else {
                System.out.print(" X |");
            }
        }
        System.out.println("");

        // For BC ed25519
        System.out.print("|BouncyCastle   |");
        for (Ed25519TestCase testCase : testCases) {
            if (testCase.verify_bc()) {
                System.out.print(" V |");
            } else {
                System.out.print(" X |");
            }
        }
        System.out.println("");
    }
}
