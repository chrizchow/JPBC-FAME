package hk.chriz;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class FAME {

    private Pairing curveParams;
    private static final int DLIN = 2;

    public FAMEPubKey pk;
    Field G, H, GT, Zr;

    public FAME() {
        // Load parameters to RAM:
        curveParams = PairingFactory.getPairing("a.properties");
        //PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pk = new FAMEPubKey(curveParams);

        // For convenience:
        G = curveParams.getG1();
        H = curveParams.getG2();
        GT = curveParams.getGT();
        Zr = curveParams.getZr();

    }

    // Generates public key and master secret key.
    public FAMEMasterKey setup() {

        // generate two instances of the k-linear assumption
        ArrayList<Element> A = new ArrayList<>();
        ArrayList<Element> B = new ArrayList<>();
        for (int i=0; i<DLIN; i++) {
            A.add(Zr.newRandomElement());
            B.add(Zr.newRandomElement());
        }

        // vector
        ArrayList<Element> k = new ArrayList<>();
        for (int i=0; i<DLIN+1; i++) {
            k.add(Zr.newRandomElement());       // d1, d2, d3
        }

        // pick a random element from the two source groups and pair them
        Element g = G.newRandomElement();
        Element h = H.newRandomElement();
        Element e_gh = curveParams.pairing(g, h);

        // compute the [A]_2 term
        ArrayList<Element> h_A = new ArrayList<>();
        for (int i=0; i<DLIN; i++) {
            h_A.add(h.duplicate().powZn(A.get(i)));
        }
        h_A.add(h);       // chriz: should be useless

        // compute the e([k]_1, [A]_2) term
        ArrayList<Element> g_k = new ArrayList<>();
        for (int i=0; i<DLIN+1; i++) {
            g_k.add(g.duplicate().powZn(k.get(i)));
        }

        ArrayList<Element> e_gh_kA = new ArrayList<>();
        for (int i=0; i<DLIN; i++) {
            Element kAk = k.get(i).duplicate().mul(A.get(i)).add(k.get(DLIN)); // k[i] * A[i] + k[2]
            e_gh_kA.add(e_gh.duplicate().powZn(kAk));        // e_gh ^ (k[i] * A[i] + k[2])
        }

        // the public key
        pk.h = h.duplicate();
        pk.h_A = h_A;
        pk.e_gh_kA = e_gh_kA;

        // the master secret key
        FAMEMasterKey msk = new FAMEMasterKey();
        msk.g = g;
        msk.h = h.duplicate();
        msk.g_k = g_k;
        msk.A = A;
        msk.B = B;

        return msk;
    }

    // Generate a key for a list of attributes.
    public FAMESecretKey keygen(FAMEMasterKey msk, String [] attrs) throws NoSuchAlgorithmException {

        // pick randomness
        ArrayList<Element> r = new ArrayList<>();
        Element sum = Zr.newZeroElement();
        for (int i=0; i<DLIN; i++) {
            Element rand = Zr.newRandomElement();
            r.add(rand);
            sum.add(rand);
        }

        // compute the [Br]_2 term
        ArrayList<Element> Br = new ArrayList<>();
        for (int i=0; i<DLIN; i++) {
            Br.add(msk.B.get(i).duplicate().mul(r.get(i)));
        }
        Br.add(sum);    // the last term is r1 + r2

        // now compute [Br]_2
        ArrayList<Element> K_0 = new ArrayList<>();
        for (int i=0; i<DLIN+1; i++) {
            K_0.add(msk.h.duplicate().powZn(Br.get(i)));
        }

        // compute [W_1 Br]_1, ...
        Map<String, ArrayList<Element>> K = new HashMap<>();
        ArrayList<Element> A = msk.A;
        Element g = msk.g;
        for (String attr: attrs) {
            ArrayList<Element> key = new ArrayList<>();
            Element sigma_attr = Zr.newRandomElement();
            for (int t=0; t<DLIN; t++) {
                Element prod = G.newOneElement();
                Element a_t = A.get(t);
                for (int l=0; l<DLIN+1; l++) {
                    String input_for_hash = attr + l + t;
                    System.out.println("input_for_hash: "+input_for_hash);
                    Element hashed = G.newElement();
                    elementFromString(hashed, input_for_hash);
                    Element br_at = Br.get(l).duplicate().div(a_t);
                    prod.mul(hashed.powZn(br_at));     // H(y1t) ^ (b1*r1/at)
                }
                Element sigma_attr_at = sigma_attr.duplicate().div(a_t);
                prod.mul(g.duplicate().powZn(sigma_attr_at)); // prod = prod * (g ^ (σ'/a_t))
                key.add(prod);
            }
            Element minus_sigma_attr = sigma_attr.duplicate().mul(-1);
            key.add(g.duplicate().powZn(minus_sigma_attr)); // g ^ (-σ)
            K.put(attr, key);
        }

        // compute [k + VBr]_1
        ArrayList<Element> Kp = new ArrayList<>();
        ArrayList<Element> g_k = msk.g_k;
        Element sigma = Zr.newRandomElement();
        for (int t=0; t<DLIN; t++) {
            Element prod = g_k.get(t).duplicate();
            Element a_t = A.get(t);
            for (int l=0; l<DLIN+1; l++) {
                String input_for_hash = "01" + l + t;
                System.out.println("input_for_hash (01): "+input_for_hash);
                Element hashed = G.newElement();
                elementFromString(hashed, input_for_hash);
                prod.mul(hashed.powZn(Br.get(l).duplicate().mul(a_t)));
            }
            prod.mul(g.duplicate().powZn(sigma.duplicate().div(a_t)));
            Kp.add(prod);
        }
        Element minus_sigma = sigma.duplicate().mul(-1);
        Kp.add(g_k.get(DLIN).duplicate().mul(g.duplicate().powZn(minus_sigma))); // g^d3 * g^(-σ)

        // return secret key
        FAMESecretKey skey = new FAMESecretKey();
        skey.K_0 = K_0;
        skey.K = K;
        skey.Kp = Kp;
        return skey;

    }

    public FAMECipherText encrypt(String policy_str, byte[] plaintext) throws Exception {

        // generate intermediate AES key:
        Element msg = GT.newRandomElement();
        System.out.println("Encryption AES Key: " + msg.toBigInteger());

        // MSP:
        Map<String, int[]> msp = MSP.convert_policy_to_msp(policy_str);
        int num_cols = msp.size();      // FIXME: not always true
        System.out.println("longest row is: "+num_cols);

        // pick randomness
        ArrayList<Element> s = new ArrayList<>();
        Element sum = Zr.newZeroElement();
        for (int i=0; i<DLIN; i++) {
            Element rand = Zr.newRandomElement();
            s.add(rand);
            sum.add(rand);
        }

        // compute the [As]_2 term
        ArrayList<Element> C_0 = new ArrayList<>();
        ArrayList<Element> h_A = pk.h_A;
        for (int i=0; i<DLIN; i++) {
            C_0.add(h_A.get(i).duplicate().powZn(s.get(i)));
        }
        C_0.add(h_A.get(DLIN).duplicate().powZn(sum));

        // compute the [(V^T As||U^T_2 As||...) M^T_i + W^T_i As]_1 terms

        // pre-compute hashes
        ArrayList<ArrayList<ArrayList<Element>>> hash_table = new ArrayList<>();
        for (int j=0; j<num_cols; j++) {
            ArrayList<ArrayList<Element>> x = new ArrayList<>();
            String input_for_hash1 = "0" + (j+1);
            for (int l=0; l<DLIN+1; l++) {
                ArrayList<Element> y = new ArrayList<>();
                String input_for_hash2 = input_for_hash1 + l;
                for (int t=0; t<DLIN; t++) {
                    String input_for_hash3 = input_for_hash2 + t;
                    System.out.println("enc - input_for_hash3: "+input_for_hash3);
                    Element hashed_value = G.newElement();
                    elementFromString(hashed_value, input_for_hash3);
                    y.add(hashed_value);
                }
                x.add(y);
            }
            hash_table.add(x);
        }

        Map<String, ArrayList<Element>> C = new HashMap<>();
        for (Map.Entry<String, int []> entry : msp.entrySet()){
            String attr = entry.getKey();
            int [] row = entry.getValue();
            ArrayList<Element> ct = new ArrayList<>();
            String attr_stripped = attr;    // no need
            for (int l=0; l<DLIN+1; l++) {
                Element prod = G.newOneElement();
                int cols = row.length;
                for (int t=0; t<DLIN; t++) {
                    String input_for_hash = attr_stripped + l + t;
                    System.out.println("enc - input_for_hash: "+input_for_hash);
                    Element prod1 = G.newElement();
                    elementFromString(prod1, input_for_hash);
                    for (int j=0; j<cols; j++) {
                        Element rowj = Zr.newElement(row[j]);
                        prod1.mul(hash_table.get(j).get(l).get(t).duplicate().powZn(rowj));
                    }
                    prod.mul(prod1.duplicate().powZn(s.get(t))); // not necessary to duplicate
                }
                ct.add(prod);
            }
            C.put(attr, ct);
        }

        // compute the e(g, h)^(k^T As) . m term
        Element Cp = GT.newOneElement();
        for (int i=0; i<DLIN; i++) {
            Cp.mul(pk.e_gh_kA.get(i).duplicate().powZn(s.get(i)));
        }
        Cp.mul(msg);

        // encrypted message:
        FAMECipherText cipherText = new FAMECipherText();
        cipherText.policy_str = policy_str;
        cipherText.C_0 = C_0;
        cipherText.C = C;
        cipherText.Cp = Cp;
        cipherText.aesBuf = AESCoder.encrypt(msg.toBytes(), plaintext); // AES encrypt
        return cipherText;

    }

    public byte[] decrypt(FAMESecretKey key, FAMECipherText ctxt) throws Exception {

        for (String attr : ctxt.C.keySet()) {
            if (!key.K.containsKey(attr)) {
                System.err.println("Policy not satisfied. ("+attr+")");
                System.exit(2);
            }
        }

        // decrypt the intermediate AES key:
        Element prod1_GT = GT.newOneElement();
        Element prod2_GT = GT.newOneElement();
        for (int i=0; i<DLIN+1; i++) {
            Element prod_H = G.newOneElement();
            Element prod_G = G.newOneElement();
            for (String node : ctxt.C.keySet()) {
                String attr = node;             // will be useful if MSP is complete
                String attr_stripped = node;    // no need
                prod_H.mul(key.K.get(attr_stripped).get(i));
                prod_G.mul(ctxt.C.get(attr).get(i));
            }
            prod1_GT.mul(pk.pairing.pairing(key.Kp.get(i).duplicate().mul(prod_H), ctxt.C_0.get(i)));
            prod2_GT.mul(pk.pairing.pairing(prod_G, key.K_0.get(i)));
        }
        Element aesKey = ctxt.Cp.duplicate().mul(prod2_GT).div(prod1_GT);

        // Use the AES key to decrypt the message:
        System.out.println("Decryption AES Key: " + aesKey.toBigInteger());
        return AESCoder.decrypt(aesKey.toBytes(), ctxt.aesBuf);
    }

    private static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

    public void printParameters(FAMEMasterKey msk, FAMESecretKey sk) {
        if (pk != null) {
            System.out.println("============ Public Key Parameters ==============");
            System.out.println("h: "+ pk.h);
            System.out.println("h_A: "+Arrays.toString(pk.h_A.toArray()));
            System.out.println("e_gh_kA: "+Arrays.toString(pk.e_gh_kA.toArray()));
            System.out.println("=================================================\n");
        }
        if (msk != null) {
            System.out.println("============ Master Key Parameters ==============");
            System.out.println("A: "+Arrays.toString(msk.A.toArray()));
            System.out.println("B: "+Arrays.toString(msk.B.toArray()));
            System.out.println("h: "+msk.h);
            System.out.println("g: "+msk.g);
            System.out.println("g_k: "+Arrays.toString(msk.g_k.toArray()));
            System.out.println("=================================================\n");
        }
        if (sk != null) {
            System.out.println("============ Secret Key Parameters ==============");
            for (Map.Entry<String, ArrayList<Element>> node: sk.K.entrySet()) {
                System.out.println("K (key: \""+node.getKey()+"\") - "+ Arrays.toString(node.getValue().toArray()));
            }
            System.out.println("K_0: "+ Arrays.toString(sk.K_0.toArray()));
            System.out.println("Kp: "+ Arrays.toString(sk.Kp.toArray()));
            System.out.println("=================================================\n");
        }
    }

}
