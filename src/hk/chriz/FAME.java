package hk.chriz;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class FAME {

    private Pairing curveParams;
    private static final int DLIN = 2;

    public FAMEPubKey pub;
    Field G, H, GT, Zp;

    public FAME() {
        // Load parameters to RAM:
        curveParams = PairingFactory.getPairing("a.properties");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pub = new FAMEPubKey(curveParams);

        // For convenience:
        G = curveParams.getG1();
        H = curveParams.getG2();
        GT = curveParams.getGT();
        Zp = curveParams.getZr();

    }

    // Generates public key and master secret key.
    public FAMEMasterKey setup() {

        // generate two instances of the k-linear assumption
        ArrayList<Element> A = new ArrayList<>();
        ArrayList<Element> B = new ArrayList<>();
        for (int i=0; i<DLIN; i++) {
            A.add(Zp.newRandomElement());
            B.add(Zp.newRandomElement());
        }

        // vector
        ArrayList<Element> k = new ArrayList<>();
        for (int i=0; i<DLIN+1; i++) {
            k.add(Zp.newRandomElement());       // d1, d2, d3
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
            Element kA = k.get(i).duplicate().mul(A.get(i)).add(k.get(DLIN));
            e_gh_kA.add(e_gh.duplicate().powZn(kA));
        }

        // the public key
        pub.h = h.duplicate();
        pub.h_A = h_A;
        pub.e_gh_kA = e_gh_kA;

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
        Element sum = Zp.newZeroElement();
        for (int i=0; i<DLIN; i++) {
            Element rand = Zp.newRandomElement();
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
            Element sigma_attr = Zp.newRandomElement();
            for (int t=0; t<DLIN; t++) {
                Element prod = G.newOneElement();
                Element a_t = A.get(t);
                for (int l=0; l<DLIN+1; l++) {
                    String input_for_hash = attr + l + t;
                    System.out.println("input_for_hash: "+input_for_hash);
                    Element hashed = G.newElement();
                    elementFromString(hashed, input_for_hash);
                    prod.mul(hashed.powZn(Br.get(l).duplicate().div(a_t)));     // H(y1t) ^ (b1*r1/at)
                }
                prod.mul(g.duplicate().powZn(sigma_attr.duplicate().div(a_t))); // g ^ (σ'/a_t)
                key.add(prod);
            }
            key.add(g.duplicate().powZn(Zp.newZeroElement().sub(sigma_attr))); // g ^ (-σ)
            K.put(attr, key);
        }

        // compute [k + VBr]_1
        ArrayList<Element> Kp = new ArrayList<>();
        ArrayList<Element> g_k = msk.g_k;
        Element sigma = Zp.newRandomElement();
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
        Kp.add(g_k.get(DLIN).duplicate().mul(g.duplicate().powZn(Zp.newZeroElement().sub(sigma)))); // g^d3 * g^(-σ)

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
        Map<String, int[]> msp = MSP.convert_policy_to_msp(policy_str);
        int num_cols = msp.size();      // FIXME: not always true

        // pick randomness
        ArrayList<Element> s = new ArrayList<>();
        Element sum = Zp.newZeroElement();
        for (int i=0; i<DLIN; i++) {
            Element rand = Zp.newRandomElement();
            s.add(rand);
            sum.add(rand);
        }

        // compute the [As]_2 term
        ArrayList<Element> C_0 = new ArrayList<>();
        ArrayList<Element> h_A = pub.h_A;
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
            for (int l=0; l<DLIN+1; l++) {
                Element prod = G.newOneElement();
                int cols = row.length;
                for (int t=0; t<DLIN; t++) {
                    String input_for_hash = attr + l + t;
                    Element prod1 = G.newElement();
                    elementFromString(prod1, input_for_hash);
                    for (int j=0; j<cols; j++) {
                        prod1.mul(hash_table.get(j).get(l).get(t).duplicate().powZn(Zp.newElement(row[j])));
                    }
                    prod.mul(prod1.powZn(s.get(t)));
                }
                ct.add(prod);
            }
            C.put(attr, ct);
        }

        // compute the e(g, h)^(k^T As) . m term
        Element Cp = GT.newOneElement();
        for (int i=0; i<DLIN; i++) {
            Cp.mul(pub.e_gh_kA.get(i).duplicate().powZn(s.get(i)));
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

    public void decrypt() {
        // TODO: waiting for implementation.
    }

    private static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

}
