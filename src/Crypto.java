import java.awt.Component;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

/**
 * GUI application used to create digital envelopes, signatures and seals.
 * 
 * @author Domagoj Pavlović
 *
 */
public class Crypto extends JFrame {

	/**
	 * Default serial version ID.
	 */
	private static final long serialVersionUID = 1L;
	/**
	 * Available key lengths for RSA keys.
	 */
	public static final Integer[] RSA_KEY_LENGHTS = { 1024, 2048, 3072, 4096 };
	/**
	 * Available options for symmetric keys.
	 */
	public static final String[] SYMMETRIC_KEY_OPTIONS = { "3DES-112", "3DES-168", "AES-128", "AES-192", "AES-256" };
	/**
	 * Available options for symmetric encryption methods.
	 */
	public static final String[] SYMMETRIC_ENCRYPTION_METHODS = { "ECB", "CBC", "OFB", "CFB", "CTR" };
	/**
	 * Available hashing algorithms.
	 */
	public static final String[] HASHING_ALGORITHMS = { "SHA2", "SHA3" };
	/**
	 * Available versions of hashing algorithms.
	 */
	public static final Integer[] HASHING_VERSIONS = { 256, 512 };
	/**
	 * List used to track all current GUI elements.
	 */
	List<Component> removeList = new ArrayList<>();

	/**
	 * Entry point to the program.
	 * 
	 * @param args not used
	 */
	public static void main(String[] args) {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				Crypto c = new Crypto();
				c.setVisible(true);
				c.setSizeAdapter();
			}
		});
	}

	/**
	 * Default constructor used to start the GUI.
	 */
	public Crypto() {
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		setTitle("Crypto");
		setLocation(200, 200);
		setResizable(false);
		initGUI();
	}

	/**
	 * Function used to initialize the GUI layout and draw the main menu buttons.
	 */
	private void initGUI() {
		setLayout(new GridLayout(0, 1));
		reset();
	}

	/**
	 * Used to add elements to the GUI. The elements are also tracked in a list so
	 * they can be removed when re-drawing the GUI.
	 * 
	 * @param c the component to be added
	 */
	private void addComp(Component c) {
		add(c);
		removeList.add(c);
		revalidate();
		repaint();
	}

	/**
	 * Used to remove all the elements from the GUI using the tracking list.
	 */
	private void removeComps() {
		for (Component c : removeList) {
			remove(c);
		}
		removeList.clear();
		revalidate();
		repaint();
	}

	/**
	 * Function used to determine the size of the GUI depending on the number of
	 * elements.
	 */
	private void setSizeAdapter() {

		final int HEIGHT = 40 * removeList.size();
		final int WIDHT = 500;

		Insets insets = getInsets();
		setSize(WIDHT + insets.left + insets.right, HEIGHT + insets.top + insets.bottom);
	}

	/**
	 * Function used to draw the default menu GUI.
	 */
	private void reset() {
		removeComps();
		JButton newPairOfKeys = new JButton("Create a new key pair.");
		JButton digitalEnvelope = new JButton("Create a digital envelope.");
		JButton digitalSignature = new JButton("Digitally sign a file.");
		JButton digitalStamp = new JButton("Create a digital seal.");
		JButton decrypt = new JButton("Decrypt a digital envelope.");
		JButton checkSign = new JButton("Check a digital signature.");
		JButton seal = new JButton("Verify and decrypt a digital seal.");

		addComp(newPairOfKeys);
		addComp(digitalEnvelope);
		addComp(digitalSignature);
		addComp(digitalStamp);
		addComp(decrypt);
		addComp(checkSign);
		addComp(seal);

		newPairOfKeys.addActionListener(new NewKeysListener());
		digitalEnvelope.addActionListener(new EnvelopeListener());
		digitalSignature.addActionListener(new SignatureListener());
		digitalStamp.addActionListener(new SealListener());
		decrypt.addActionListener(new DecryptListener());
		checkSign.addActionListener(new CheckSignatureListener());
		seal.addActionListener(new VerifySealListener());
		setSizeAdapter();
	}

	/**
	 * Takes a name of a file in the current working directory of the project. Reads
	 * the file and makes a map entry from every line in the file. Lines are
	 * expected to be in format "name value". The name becomes the key of the entry
	 * and the value becomes the value of the entry.
	 * 
	 * @param fileName the name of the file to be read
	 * @return a map created from reading the file
	 * @throws IOException in case of an error reading the file
	 */
	private static Map<String, String> makeMapFromFile(String fileName) throws IOException {
		Map<String, String> output = new HashMap<>();

		List<String> lines = Files.readAllLines(Paths.get(fileName));
		for (String line : lines) {
			String[] splitLine = line.split(" ");
			output.put(splitLine[0], splitLine[1]);
		}
		return output;
	}

	/**
	 * Listener registered to the main menu GUI function of creating new keys. Draws
	 * the key creating GUI.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class NewKeysListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			removeComps();

			addComp(new JLabel("Name of new keys:", SwingConstants.CENTER));

			JTextField textField = new JTextField("Default");
			addComp(textField);

			addComp(new JLabel("Key length:", SwingConstants.CENTER));

			JComboBox<Integer> keyLenghts = new JComboBox<>(RSA_KEY_LENGHTS);
			addComp(keyLenghts);

			JButton finishButton = new JButton("Create");
			addComp(finishButton);
			finishButton.addActionListener(new NewKeysFinishListener(textField, keyLenghts));

			setSizeAdapter();
		}
	}

	/**
	 * Listener registered to the confirmation button in creating keys. Executes the function of creating a pair of keys; public and private.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class NewKeysFinishListener implements ActionListener {

		JTextField textField;
		JComboBox<Integer> comboBox;
		String publicKeyPrefix = "PublicKey";
		String secretKeyPrefix = "SecretKey";
		String suffix = ".txt";

		public NewKeysFinishListener(JTextField textField, JComboBox<Integer> comboBox) {
			this.textField = textField;
			this.comboBox = comboBox;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			String text = textField.getText();
			int keyLength = (int) comboBox.getSelectedItem();
			File pk = new File(publicKeyPrefix + text + suffix);
			File sk = new File(secretKeyPrefix + text + suffix);
			if (pk.exists() || sk.exists()) {
				JOptionPane.showMessageDialog(Crypto.this, "Files with the name already exist.");
				return;
			}

			try {
				pk.createNewFile();
				sk.createNewFile();
			} catch (Exception ex) {
				throw new RuntimeException("Error creating key files.");
			}

			KeyPairGenerator kpg = null;

			try {
				kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(keyLength);
				KeyPair kp = kpg.generateKeyPair();
				RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
				RSAPrivateKey pvt = (RSAPrivateKey) kp.getPrivate();
				BigInteger pubKey = pub.getPublicExponent();
				BigInteger privKey = pvt.getPrivateExponent();
				BigInteger modulus = pub.getModulus();

				FileWriter writerSecret = new FileWriter(secretKeyPrefix + text + suffix);
				FileWriter writerPublic = new FileWriter(publicKeyPrefix + text + suffix);

				writerSecret.write("type secret_key\n");
				writerSecret.write("algorithm RSA-" + keyLength + "\n");
				writerSecret.write("modulus " + modulus + "\n");
				writerSecret.write("secret_exponent " + privKey + "\n");

				writerPublic.write("type public_key\n");
				writerPublic.write("algorithm RSA-" + keyLength + "\n");
				writerPublic.write("modulus " + modulus + "\n");
				writerPublic.write("public_exponent " + pubKey + "\n");

				writerSecret.close();
				writerPublic.close();

			} catch (NoSuchAlgorithmException e1) {
				throw new RuntimeException("Error creating keys.");
			} catch (IOException e1) {
				e1.printStackTrace();
			}

			JOptionPane.showMessageDialog(Crypto.this, "Successfully created a pair of keys.");
			reset();
		}
	}

	/**
	 * Listener registered to the main menu GUI function of creating a digital envelope. Draws the envelope creating GUI.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class EnvelopeListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			removeComps();

			addComp(new JLabel("Symmetric encryption algorithm and key length:", SwingConstants.CENTER));

			JComboBox<String> algorithmPicker = new JComboBox<>(SYMMETRIC_KEY_OPTIONS);
			addComp(algorithmPicker);

			addComp(new JLabel("Encryption method:", SwingConstants.CENTER));

			JComboBox<String> methodPicker = new JComboBox<>(SYMMETRIC_ENCRYPTION_METHODS);
			addComp(methodPicker);

			addComp(new JLabel("Receiver's public key file:", SwingConstants.CENTER));

			JTextField textFieldPublicKey = new JTextField("PublicKeyDefault.txt");
			addComp(textFieldPublicKey);

			addComp(new JLabel("File name:", SwingConstants.CENTER));

			JTextField textFieldFileName = new JTextField("file.txt");
			addComp(textFieldFileName);

			JButton finishButton = new JButton("Encrypt");
			addComp(finishButton);
			finishButton.addActionListener(
					new EnvelopeFinishListener(algorithmPicker, methodPicker, textFieldPublicKey, textFieldFileName));

			setSizeAdapter();
		}
	}

	/**
	 * Listener registered to the confirmation button in creating digital envelopes. Executes the function of generating a symmetric key, encrypts a file with the key and uses a public key to encrypt the symmetric key.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class EnvelopeFinishListener implements ActionListener {

		JComboBox<String> algorithmPicker;
		JComboBox<String> methodPicker;
		JTextField textFieldPublicKey;
		JTextField textFieldFileName;

		public EnvelopeFinishListener(JComboBox<String> algorithmPicker, JComboBox<String> methodPicker,
				JTextField textFieldPublicKey, JTextField textFieldFileName) {
			this.algorithmPicker = algorithmPicker;
			this.methodPicker = methodPicker;
			this.textFieldPublicKey = textFieldPublicKey;
			this.textFieldFileName = textFieldFileName;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			String algorithm = (String) algorithmPicker.getSelectedItem();
			String method = (String) methodPicker.getSelectedItem();
			String publicKeyFile = textFieldPublicKey.getText();
			String file = textFieldFileName.getText();

			IvParameterSpec ivspec;

			String[] algorithmSplit = algorithm.split("-");
			if (algorithmSplit[0].equals("3DES")) {
				algorithmSplit[0] = "DESede";
				ivspec = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
			} else {
				ivspec = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
			}

			try {
				KeyGenerator keyGen = KeyGenerator.getInstance(algorithmSplit[0]);
				keyGen.init(Integer.valueOf(algorithmSplit[1]));
				SecretKey symmetricKey = keyGen.generateKey();
				FileWriter fileWriter = new FileWriter("encrypted" + file);
				fileWriter.write("type envelope\n");
				fileWriter.write("algorithm " + algorithm + "-" + method + "\n");
				fileWriter.write("file ");

				Cipher cipher = Cipher.getInstance(algorithmSplit[0] + "/" + method + "/PKCS5Padding");
				if (method.equals("ECB")) {
					cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
				} else {
					cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivspec);
				}
				File inputFile = new File(file);

				FileInputStream inputStream = new FileInputStream(inputFile);
				byte[] inputBytes = new byte[(int) inputFile.length()];
				inputStream.read(inputBytes);
				inputStream.close();
				byte[] outputBytes = cipher.doFinal(inputBytes);

				fileWriter.write(Base64.getEncoder().encodeToString(outputBytes) + "\n");

				Map<String, String> publicKeyFileMap = makeMapFromFile(publicKeyFile);

				PublicKey pubKey = KeyFactory.getInstance("RSA")
						.generatePublic(new RSAPublicKeySpec(new BigInteger(publicKeyFileMap.get("modulus")),
								new BigInteger(publicKeyFileMap.get("public_exponent"))));

				Cipher cipher2 = Cipher.getInstance("RSA");
				cipher2.init(Cipher.ENCRYPT_MODE, pubKey);

				byte[] cryptedKey = cipher2.doFinal(symmetricKey.getEncoded());
				fileWriter.write("key " + Base64.getEncoder().encodeToString(cryptedKey) + "\n");
				fileWriter.close();

			} catch (Exception e1) {
				e1.printStackTrace();
			}
			JOptionPane.showMessageDialog(Crypto.this, "Successfully encrypted file.");
			reset();
		}
	}

	/**
	 * Listener registered to the main menu GUI function of creating signatures. Draws the signature creating GUI.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class SignatureListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			removeComps();

			addComp(new JLabel("Hashing algorithm:", SwingConstants.CENTER));

			JComboBox<String> algorithmPicker = new JComboBox<>(HASHING_ALGORITHMS);
			addComp(algorithmPicker);

			addComp(new JLabel("Algorithm version:", SwingConstants.CENTER));

			JComboBox<Integer> versionPicker = new JComboBox<>(HASHING_VERSIONS);
			addComp(versionPicker);

			addComp(new JLabel("File name:", SwingConstants.CENTER));

			JTextField textFieldFileName = new JTextField("file.txt");
			addComp(textFieldFileName);

			addComp(new JLabel("Private key:", SwingConstants.CENTER));

			JTextField textFieldPrivateKey = new JTextField("SecretKeyDefault.txt");
			addComp(textFieldPrivateKey);

			JButton finishButton = new JButton("Sign");
			addComp(finishButton);
			finishButton.addActionListener(new SignatureFinishListener(algorithmPicker, versionPicker,
					textFieldFileName, textFieldPrivateKey));

			setSizeAdapter();
		}
	}

	/**
	 * Listener registered to the confirmation button in creating digital signatures. Executes the function of hashing the file and encrypting the hash using a private key.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class SignatureFinishListener implements ActionListener {

		JComboBox<String> algorithmPicker;
		JComboBox<Integer> versionPicker;
		JTextField textFieldFileName;
		JTextField textFieldPrivateKey;

		public SignatureFinishListener(JComboBox<String> algorithmPicker, JComboBox<Integer> versionPicker,
				JTextField textFieldFileName, JTextField textFieldPrivateKey) {
			this.algorithmPicker = algorithmPicker;
			this.versionPicker = versionPicker;
			this.textFieldFileName = textFieldFileName;
			this.textFieldPrivateKey = textFieldPrivateKey;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			String algorithm = (String) algorithmPicker.getSelectedItem();
			int version = (int) versionPicker.getSelectedItem();
			String fileName = textFieldFileName.getText();
			String privateKey = textFieldPrivateKey.getText();

			try {
				MessageDigest digest;
				if (algorithm.equals("SHA2") && version == 256) {
					digest = MessageDigest.getInstance("SHA-256");
				} else if (algorithm.equals("SHA2") && version == 512) {
					digest = MessageDigest.getInstance("SHA-512");
				} else if (algorithm.equals("SHA3") && version == 256) {
					digest = new SHA3.Digest256();
				} else {
					digest = new SHA3.Digest512();
				}

				File inputFile = new File(fileName);
				FileInputStream fis = new FileInputStream(inputFile);
				byte[] dataBytes = new byte[1024];
				int nread = 0;
				while ((nread = fis.read(dataBytes)) != -1) {
					digest.update(dataBytes, 0, nread);
				}
				fis.close();

				FileWriter fileWriter = new FileWriter("signed" + fileName);
				fileWriter.write("type signature\n");
				fileWriter.write("algorithm " + algorithm + "-" + version + "\n");
				fileWriter.write("filename " + fileName + "\n");

				Map<String, String> privateKeyFileMap = makeMapFromFile(privateKey);

				PrivateKey privKey = KeyFactory.getInstance("RSA")
						.generatePrivate(new RSAPrivateKeySpec(new BigInteger(privateKeyFileMap.get("modulus")),
								new BigInteger(privateKeyFileMap.get("secret_exponent"))));

				Cipher cipher2 = Cipher.getInstance("RSA");
				cipher2.init(Cipher.ENCRYPT_MODE, privKey);

				byte[] dig = digest.digest();
				byte[] cryptedKey = cipher2.doFinal(dig);
				fileWriter.write("signature " + Base64.getEncoder().encodeToString(cryptedKey) + "\n");
				fileWriter.close();

			} catch (Exception e1) {
				e1.printStackTrace();
			}

			JOptionPane.showMessageDialog(Crypto.this, "Successfully created signature.");
			reset();
		}
	}

	/**
	 * Listener registered to the main menu GUI function of creating a seal. Draws the seal creating GUI.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class SealListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			removeComps();

			addComp(new JLabel("Symmetric encryption algorithm and key length:", SwingConstants.CENTER));

			JComboBox<String> algorithmPicker = new JComboBox<>(SYMMETRIC_KEY_OPTIONS);
			addComp(algorithmPicker);

			addComp(new JLabel("Encryption method:", SwingConstants.CENTER));

			JComboBox<String> methodPicker = new JComboBox<>(SYMMETRIC_ENCRYPTION_METHODS);
			addComp(methodPicker);

			addComp(new JLabel("Receiver's public key file:", SwingConstants.CENTER));

			JTextField textFieldPublicKey = new JTextField("PublicKeyDefault.txt");
			addComp(textFieldPublicKey);

			addComp(new JLabel("File name:", SwingConstants.CENTER));

			JTextField textFieldFileName = new JTextField("file.txt");
			addComp(textFieldFileName);

			addComp(new JLabel("Hashing algorithm:", SwingConstants.CENTER));

			JComboBox<String> hashingAlgorithmPicker = new JComboBox<>(HASHING_ALGORITHMS);
			addComp(hashingAlgorithmPicker);

			addComp(new JLabel("Hashing algorithm version:", SwingConstants.CENTER));

			JComboBox<Integer> versionPicker = new JComboBox<>(HASHING_VERSIONS);
			addComp(versionPicker);

			addComp(new JLabel("Private key:", SwingConstants.CENTER));

			JTextField textFieldPrivateKey = new JTextField("SecretKeyDefault.txt");
			addComp(textFieldPrivateKey);

			JButton finishButton = new JButton("Seal");
			addComp(finishButton);
			finishButton.addActionListener(new SealFinishListener(algorithmPicker, methodPicker, textFieldPublicKey,
					textFieldFileName, hashingAlgorithmPicker, versionPicker, textFieldPrivateKey));

			setSizeAdapter();
		}
	}

	/**
	 * Listener registered to the confirmation button in creating digital seals. Uses the listeners for creating an envelope and creating a digital signature and combines their functionality to make a digital seal.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class SealFinishListener implements ActionListener {

		JComboBox<String> algorithmPicker;
		JComboBox<String> methodPicker;
		JTextField textFieldPublicKey;
		JTextField textFieldFileName;
		JComboBox<String> hashingAlgorithmPicker;
		JComboBox<Integer> versionPicker;
		JTextField textFieldPrivateKey;

		public SealFinishListener(JComboBox<String> algorithmPicker, JComboBox<String> methodPicker,
				JTextField textFieldPublicKey, JTextField textFieldFileName, JComboBox<String> hashingAlgorithmPicker,
				JComboBox<Integer> versionPicker, JTextField textFieldPrivateKey) {
			this.algorithmPicker = algorithmPicker;
			this.methodPicker = methodPicker;
			this.textFieldPublicKey = textFieldPublicKey;
			this.textFieldFileName = textFieldFileName;
			this.hashingAlgorithmPicker = hashingAlgorithmPicker;
			this.versionPicker = versionPicker;
			this.textFieldPrivateKey = textFieldPrivateKey;
		}

		@Override
		public void actionPerformed(ActionEvent e) {

			EnvelopeFinishListener first = new EnvelopeFinishListener(algorithmPicker, methodPicker, textFieldPublicKey,
					textFieldFileName);
			first.actionPerformed(null);
			JTextField fileNameForSecondAction = new JTextField("encrypted" + textFieldFileName.getText());
			SignatureFinishListener second = new SignatureFinishListener(hashingAlgorithmPicker, versionPicker,
					fileNameForSecondAction, textFieldPrivateKey);
			second.actionPerformed(null);
			reset();
		}
	}

	/**
	 * Listener registered to the main menu GUI function of decrypting a digital envelope. Draws the GUI used for decrypting an envelope.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class DecryptListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			removeComps();

			addComp(new JLabel("File name:", SwingConstants.CENTER));

			JTextField textFieldFileName = new JTextField("encryptedfile.txt");
			addComp(textFieldFileName);

			addComp(new JLabel("Private key file:", SwingConstants.CENTER));

			JTextField textFieldPrivKey = new JTextField("SecretKeyDefault.txt");
			addComp(textFieldPrivKey);

			JButton finishButton = new JButton("Decrypt");
			addComp(finishButton);
			finishButton.addActionListener(new DecryptFinishListener(textFieldFileName, textFieldPrivKey));

			setSizeAdapter();
		}
	}

	/**
	 * Listener registered to the confirmation button in decrypting digital envelopes. Executes the function inverse to creating a digital envelope.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class DecryptFinishListener implements ActionListener {

		JTextField textFieldFileName;
		JTextField textFieldPrivKey;

		public DecryptFinishListener(JTextField textFieldFileName, JTextField textFieldPrivKey) {
			this.textFieldFileName = textFieldFileName;
			this.textFieldPrivKey = textFieldPrivKey;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			String fileName = textFieldFileName.getText();
			String privKeyFileName = textFieldPrivKey.getText();

			try {
				Map<String, String> privateKeyFileMap = makeMapFromFile(privKeyFileName);

				PrivateKey privKey = KeyFactory.getInstance("RSA")
						.generatePrivate(new RSAPrivateKeySpec(new BigInteger(privateKeyFileMap.get("modulus")),
								new BigInteger(privateKeyFileMap.get("secret_exponent"))));

				Map<String, String> fileMap = makeMapFromFile(fileName);

				Cipher cipher2 = Cipher.getInstance("RSA");
				cipher2.init(Cipher.DECRYPT_MODE, privKey);

				byte[] decryptedKey = cipher2.doFinal(Base64.getDecoder().decode(fileMap.get("key")));

				String algorithm = fileMap.get("algorithm");
				String[] algorithmSplit = algorithm.split("-");

				System.out.println(algorithmSplit[2]);

				IvParameterSpec ivspec;

				Cipher cipher;
				if (algorithmSplit[0].equals("3DES")) {
					algorithmSplit[0] = "DESede";
					ivspec = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
					cipher = Cipher.getInstance(algorithmSplit[0] + "/" + algorithmSplit[2] + "/PKCS5Padding");
					if (algorithmSplit[2].equals("ECB")) {
						cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKey, "DESede"));
					} else {
						cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKey, "DESede"), ivspec);
					}

				} else {
					ivspec = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
					cipher = Cipher.getInstance(algorithmSplit[0] + "/" + algorithmSplit[2] + "/PKCS5Padding");
					if (algorithmSplit[2].equals("ECB")) {
						cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKey, "AES"));
					} else {
						cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKey, "AES"), ivspec);
					}
				}

				byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(fileMap.get("file")));

				JOptionPane.showMessageDialog(Crypto.this, "Decrypted message: " + new String(decrypted));

			} catch (Exception e1) {
				e1.printStackTrace();
			}
			reset();
		}
	}

	/**
	 * Listener registered to the main menu GUI function of verifying signatures. Draws the GUI used for verifying signatures.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class CheckSignatureListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			removeComps();

			addComp(new JLabel("File name:", SwingConstants.CENTER));

			JTextField textFieldFileName = new JTextField("file.txt");
			addComp(textFieldFileName);

			addComp(new JLabel("Signature file name:", SwingConstants.CENTER));

			JTextField textFieldSignatureFileName = new JTextField("signedfile.txt");
			addComp(textFieldSignatureFileName);

			addComp(new JLabel("Public key file:", SwingConstants.CENTER));

			JTextField textFieldPubKey = new JTextField("PublicKeyDefault.txt");
			addComp(textFieldPubKey);

			JButton finishButton = new JButton("Decrypt");
			addComp(finishButton);
			finishButton.addActionListener(
					new CheckSignatureFinishListener(textFieldFileName, textFieldSignatureFileName, textFieldPubKey));

			setSizeAdapter();
		}
	}

	/**
	 * Listener registered to the confirmation button in verifying signatures. Executes the function inverse to creating a signature.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class CheckSignatureFinishListener implements ActionListener {

		JTextField textFieldFileName;
		JTextField textFieldSignatureFileName;
		JTextField textFieldPubKey;
		boolean valid = false;

		public CheckSignatureFinishListener(JTextField textFieldFileName, JTextField textFieldSignatureFileName,
				JTextField textFieldPubKey) {
			this.textFieldFileName = textFieldFileName;
			this.textFieldSignatureFileName = textFieldSignatureFileName;
			this.textFieldPubKey = textFieldPubKey;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			String fileName = textFieldFileName.getText();
			String signatureFileName = textFieldSignatureFileName.getText();
			String pubKeyFileName = textFieldPubKey.getText();

			try {
				Map<String, String> pubKeyFileMap = makeMapFromFile(pubKeyFileName);

				PublicKey pubKey = KeyFactory.getInstance("RSA")
						.generatePublic(new RSAPublicKeySpec(new BigInteger(pubKeyFileMap.get("modulus")),
								new BigInteger(pubKeyFileMap.get("public_exponent"))));

				Map<String, String> signatureFileMap = makeMapFromFile(signatureFileName);

				Cipher cipher2 = Cipher.getInstance("RSA");
				cipher2.init(Cipher.DECRYPT_MODE, pubKey);

				byte[] cryptedKey = cipher2.doFinal(Base64.getDecoder().decode(signatureFileMap.get("signature")));

				String[] alg = signatureFileMap.get("algorithm").split("-");
				String algorithm = alg[0];
				int version = Integer.valueOf(alg[1]);

				MessageDigest digest;
				if (algorithm.equals("SHA2") && version == 256) {
					digest = MessageDigest.getInstance("SHA-256");
				} else if (algorithm.equals("SHA2") && version == 512) {
					digest = MessageDigest.getInstance("SHA-512");
				} else if (algorithm.equals("SHA3") && version == 256) {
					digest = new SHA3.Digest256();
				} else {
					digest = new SHA3.Digest512();
				}

				File inputFile = new File(fileName);
				FileInputStream fis = new FileInputStream(inputFile);
				byte[] dataBytes = new byte[1024];
				int nread = 0;
				while ((nread = fis.read(dataBytes)) != -1) {
					digest.update(dataBytes, 0, nread);
				}
				fis.close();

				String received = Hex.toHexString(cryptedKey);
				String checked = Hex.toHexString(digest.digest());

				String output;
				if (received.equals(checked)) {
					valid = true;
					output = "";
				} else {
					output = "not ";
				}
				JOptionPane.showMessageDialog(Crypto.this, "The signature is " + output + "valid.");

			} catch (Exception e1) {
				e1.printStackTrace();
			}

			reset();
		}
	}

	/**
	 * Listener registered to the main menu GUI function of decrypting and verifying a seal. Draws the GUI used for seal decryption.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class VerifySealListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			removeComps();

			addComp(new JLabel("File name:", SwingConstants.CENTER));

			JTextField textFieldFileName = new JTextField("encryptedfile.txt");
			addComp(textFieldFileName);

			addComp(new JLabel("Private key file used to decrypt the symmetric key:", SwingConstants.CENTER));

			JTextField textFieldPrivKey = new JTextField("SecretKeyDefault.txt");
			addComp(textFieldPrivKey);

			addComp(new JLabel("Signature file name:", SwingConstants.CENTER));

			JTextField textFieldSignatureFileName = new JTextField("signedencryptedfile.txt");
			addComp(textFieldSignatureFileName);

			addComp(new JLabel("Public key file used to decrypt the signature:", SwingConstants.CENTER));

			JTextField textFieldPubKey = new JTextField("PublicKeyDefault.txt");
			addComp(textFieldPubKey);

			JButton finishButton = new JButton("Decrypt");
			addComp(finishButton);
			finishButton.addActionListener(new VerifySealFinishListener(textFieldFileName, textFieldPrivKey,
					textFieldSignatureFileName, textFieldPubKey));

			setSizeAdapter();
		}
	}

	/**
	 * Listener registered to the confirmation button in decrypting and verifying seals. Executes the function inverse to creating a digital seal.
	 * 
	 * @author Domagoj Pavlović
	 *
	 */
	private class VerifySealFinishListener implements ActionListener {

		JTextField textFieldFileName;
		JTextField textFieldPrivKey;
		JTextField textFieldSignatureFileName;
		JTextField textFieldPubKey;

		public VerifySealFinishListener(JTextField textFieldFileName, JTextField textFieldPrivKey,
				JTextField textFieldSignatureFileName, JTextField textFieldPubKey) {
			this.textFieldFileName = textFieldFileName;
			this.textFieldPrivKey = textFieldPrivKey;
			this.textFieldSignatureFileName = textFieldSignatureFileName;
			this.textFieldPubKey = textFieldPubKey;
		}

		@Override
		public void actionPerformed(ActionEvent e) {

			CheckSignatureFinishListener first = new CheckSignatureFinishListener(textFieldFileName,
					textFieldSignatureFileName, textFieldPubKey);
			first.actionPerformed(null);
			if (first.valid) {
				DecryptFinishListener second = new DecryptFinishListener(textFieldFileName, textFieldPrivKey);
				second.actionPerformed(null);
			}
			reset();
		}
	}
}