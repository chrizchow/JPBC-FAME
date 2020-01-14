package hk.chriz;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;

public class FAMEPubKey {
    Element h;
    ArrayList<Element> h_A;
    ArrayList<Element> e_gh_kA;
    Pairing pairing;

    public FAMEPubKey(Pairing pairing) {
        this.pairing = pairing;
    }
}
