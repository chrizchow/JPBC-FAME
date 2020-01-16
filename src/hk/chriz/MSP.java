package hk.chriz;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class MSP {

    private static final int [][] M1 = {
            {1}};

    private static final int [][] M2 = {
            {1,  1},
            {0, -1}};

    private static final int [][] M3 = {
            {1,  1,  0},
            {0, -1,  1},
            {0,  0, -1}};

    /*
    private static final int [][] M3 = {
            {1,  1,  1},
            {0,  0, -1},
            {0, -1}};
     */

    private static final int [][] M4 = {
            {1,  1,  0,  0},
            {0, -1,  1,  0},
            {0,  0, -1,  1},
            {0,  0,  0, -1}};

    private static final int [][] M5 = {
            {1,  1,  0,  0,  0},
            {0, -1,  1,  0,  0},
            {0,  0, -1,  1,  0},
            {0,  0,  0, -1,  1},
            {0,  0,  0,  0, -1}};

    private static final int [][] M6 = {
            {1,  1,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0},
            {0,  0, -1,  1,  0,  0},
            {0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0, -1}};

    private static final int [][] M7 = {
            {1,  1,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0, -1}};

    private static final int [][] M8 = {
            {1,  1,  0,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0,  0, -1}};

    private static final int [][] M9 = {
            {1,  1,  0,  0,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0,  0,  0},
            {0,  0,  0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0,  0,  0, -1}};

    private static final int [][] M10 = {
            {1,  1,  0,  0,  0,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0,  0,  0,  0},
            {0,  0,  0,  0, -1,  1,  0,  0,  0,  0},
            {0,  0,  0,  0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0,  0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0,  0,  0,  0, -1}};

    private static final int [][][] cheatyMSPs =
            {null, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10};


    // convert policy string to msp
    // FIXME: Hard-coded to support AND operations only
    public static Map<String, int[]> convert_policy_to_msp(String policy) {
        String [] attrs = policy.split(" and ");
        if (attrs.length > 10 || attrs.length < 1) {
            System.err.println("MSP conversion error!");
            System.exit(1);
        }
        Map<String, int[]> msp = new HashMap<>();
        for (int i=0; i<attrs.length; i++) {
            //System.out.println("\""+attrs[i]+ "\" -> " + Arrays.toString(cheatyMSPs[attrs.length][i]));
            msp.put(attrs[i], cheatyMSPs[attrs.length][i]);
        }
        return msp;
    }

}
