import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import java.io.FileNotFoundException;
import java.io.FileReader;

public class TestVectorChecker {

    // --- OUTPUT ---
    // 0: false
    // 1: true
    // 2: false
    // 3: true
    // 4: false
    // 5: true
    // 6: false
    // 7: true
    // 8: false
    // 9: true
    public static void main(String[] args) throws FileNotFoundException {
        String jsonFilename = "ed25519_edge_cases_test_vector.json";
        JsonReader reader = new JsonReader(new FileReader(jsonFilename));
        Ed25519TestCase[] testCases = new Gson().fromJson(reader, Ed25519TestCase[].class);

        // For i2p ed25519-java
        System.out.println("--- i2p OUTPUT ---");
        int index = 0;
        for (Ed25519TestCase testCase : testCases) {
            System.out.println(index++ + ": " + testCase.verify_i2p());
        }
        System.out.println("");

        // For BC ed25519
        System.out.println("--- BC OUTPUT ---");
        index = 0;
        for (Ed25519TestCase testCase : testCases) {
            System.out.println(index++ + ": " + testCase.verify_bc());
        }
    }
}
