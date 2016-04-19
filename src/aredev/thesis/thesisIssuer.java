package aredev.thesis;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.*;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.info.InfoException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Created by Abdullah Rasool on 16-4-16.
 */
public class thesisIssuer {

    private IdemixPublicKey pk;
    private IdemixSecretKey sk;
    private List<BigInteger> attributes;
    private thesisParameters tp;

    /**
     * Setting keys
     * Issuing a credential
     * Generating a proof of knowledge (with disclosed attributes and proof of
     * undisclosed attributes)
     * Writing proof to XML file
     */
    public thesisIssuer() {
        tp = new thesisParameters();
        pk = tp.getPk();
        sk = tp.getSk();
        attributes = tp.getAttributes();

        IdemixCredential cd = null;
        try {

            cd = this.issueCredential();
            ProofD proof = this.generateDisclosureProof(cd, Arrays.asList(1));
            this.proofDToXml(proof);
        } catch ( ParserConfigurationException | CredentialsException e) {
            e.printStackTrace();
        }
        //System.out.println(new BigInteger(1, "one".getBytes()).toString());
    }

    /**
     * Issue a credential
     */
    public IdemixCredential issueCredential() throws CredentialsException {
        Random r = new Random();
        IdemixSystemParameters parameters = pk.getSystemParameters();

        BigInteger context = new BigInteger(parameters.l_h, r);
        BigInteger n_1 = new BigInteger(parameters.l_statzk, r);
        BigInteger secret = new BigInteger(parameters.l_m, r);      //Value used for hiding and binding

        CredentialBuilder builder = new CredentialBuilder(pk, attributes, context);
        IssueCommitmentMessage commitmentMessage = builder.commitToSecretAndProve(secret, n_1);     //Commit to secret value

        IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
        IssueSignatureMessage message = issuer.issueSignature(commitmentMessage, attributes, n_1);      //Make signature on attributes
        return builder.constructCredential(message);
    }

    /**
     * Generate proof of undisclosed attributes and has disclosed attributes
     * @param credential
     * @param indexes
     * @return
     */
    public ProofD generateDisclosureProof(IdemixCredential credential, List<Integer> indexes){
        Random r = new Random();
        IdemixSystemParameters parameters = pk.getSystemParameters();

        BigInteger context = new BigInteger(parameters.l_h, r);
        BigInteger nonce1 = new BigInteger(parameters.l_statzk, r);     //For freshness

        tp.setContext(context);
        tp.setNonce(nonce1);

        ProofD proof =  credential.createDisclosureProof(indexes, context, nonce1);
        System.out.println(proof.getDisclosedAttributes());

        return proof;
    }

    /**
     * Writes a proof to XML
     * @param proof
     * @throws ParserConfigurationException
     */
    public void proofDToXml(ProofD proof) throws ParserConfigurationException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document d = db.newDocument();
        Element rootElement = d.createElement("proof");
        d.appendChild(rootElement);

        Element proofC = d.createElement("c");
        proofC.appendChild(d.createTextNode(proof.get_c().toString()));
        rootElement.appendChild(proofC);

        Element proofA = d.createElement("A");
        proofA.appendChild(d.createTextNode(proof.getA().toString()));
        rootElement.appendChild(proofA);

        Element proofeResponse = d.createElement("e_resp");
        proofeResponse.appendChild(d.createTextNode(proof.get_e_response().toString()));
        rootElement.appendChild(proofeResponse);

        Element proofvResponse = d.createElement("v_resp");
        proofvResponse.appendChild(d.createTextNode(proof.get_v_response().toString()));
        rootElement.appendChild(proofvResponse);

        Element proofaResponses = d.createElement("a_resps");
        proofaResponses.appendChild(d.createTextNode(proof.get_a_responses().toString()));
        rootElement.appendChild(proofaResponses);

        Element proofaDisclosed = d.createElement("a_disc");
        proofaDisclosed.appendChild(d.createTextNode(proof.get_a_disclosed().toString()));
        rootElement.appendChild(proofaDisclosed);

        try {
            writeXml(d);
        } catch (TransformerException e) {
            e.printStackTrace();
        }
    }

    /**
     * Writes XML to file
     * @param d
     * @throws TransformerException
     */
    private void writeXml(Document d) throws TransformerException {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        DOMSource source = new DOMSource(d);

        StreamResult result = new StreamResult(new File("/home/aredev/Documents/credentials/proof.xml"));
        transformer.transform(source, result);

        //StreamResult consoleResult = new StreamResult(System.out);
        //transformer.transform(source, consoleResult);
    }
}
