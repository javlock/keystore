package com.github.javlock.keystore;

import java.awt.BorderLayout;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.operator.OperatorCreationException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.github.javlock.keystore.data.KeystoreData;
import com.github.javlock.keystore.utils.KeyUtils;

public class KeystoreMain extends JFrame {
	private static final long serialVersionUID = 6384155833940406345L;

	private static File selectedFile;

	private static KeystoreData data;

	private static final ObjectMapper OBJECTMAPPER = new ObjectMapper(new YAMLFactory());

	public static void main(String[] args) {
		new KeystoreMain().setVisible(true);
	}

	private JPasswordField passwordField;
	private JTextField tfFilePath;
	private JTextArea textArea;

	private BCECPublicKey pubKey;
	private BCECPrivateKey privKey;

	public KeystoreMain() {
		setSize(450, 300);

		JPanel panelPassAction = new JPanel();
		getContentPane().add(panelPassAction, BorderLayout.SOUTH);

		passwordField = new JPasswordField();
		passwordField.setHorizontalAlignment(SwingConstants.CENTER);
		passwordField.setColumns(15);
		panelPassAction.add(passwordField);

		JButton btnEncrypt = new JButton("Encrypt");
		btnEncrypt.addActionListener(ae -> encryptData());
		panelPassAction.add(btnEncrypt);

		JButton btnDecrypt = new JButton("Decrypt");
		btnDecrypt.addActionListener(ae -> decryptData());
		panelPassAction.add(btnDecrypt);

		JPanel panelFile = new JPanel();
		getContentPane().add(panelFile, BorderLayout.NORTH);

		tfFilePath = new JTextField();
		tfFilePath.setEditable(false);
		tfFilePath.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(tfFilePath);
		tfFilePath.setColumns(10);

		JButton btnSelectFile = new JButton("save file");
		btnSelectFile.addActionListener(ae -> {
			try {
				chooseFile();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		});
		panelFile.add(btnSelectFile);

		JPanel panelData = new JPanel();
		getContentPane().add(panelData, BorderLayout.CENTER);
		panelData.setLayout(new BorderLayout(0, 0));

		JScrollPane scrollPane = new JScrollPane();
		panelData.add(scrollPane, BorderLayout.CENTER);

		textArea = new JTextArea();
		scrollPane.setViewportView(textArea);

	}

	private void chooseFile() throws IOException {
		JFileChooser chooser = new JFileChooser();
		chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
		int option = chooser.showSaveDialog(null);
		File file;
		if (option == JFileChooser.APPROVE_OPTION) {
			file = chooser.getSelectedFile();
		} else {
			System.out.println("KeystoreMain.chooseFile(1)");
			return;
		}
		if (file == null) {
			return;
		}
		if (file.exists()) {
			if (file.isFile()) {
				selectedFile = file;
			} else if (file.isDirectory()) {
				Files.delete(file.toPath());
				selectedFile = file;
			} else {
				throw new IllegalArgumentException(file.getAbsolutePath());
			}
		} else {
			selectedFile = file;
		}
		tfFilePath.setText(selectedFile.getAbsolutePath());

	}

	private void decryptData() {
		try {
			char[] passwd = passwordField.getPassword();
			byte[] inputBase64 = Files.readAllBytes(selectedFile.toPath());
			byte[] inputYAML = Base64.getDecoder().decode(inputBase64);
			data = OBJECTMAPPER.readValue(inputYAML, KeystoreData.class);

			KeyPair keyPair = KeyUtils.restoreFromString(data.getKeystore(), passwd);
			privKey = (BCECPrivateKey) keyPair.getPrivate();
			pubKey = (BCECPublicKey) keyPair.getPublic();

			byte[] dataAr = KeyUtils.decrypt(data.getSecrets(), privKey);
			String dataDecr = new String(dataAr, StandardCharsets.UTF_8);

			textArea.setText(dataDecr);
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException | CertificateException
				| IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException
				| InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

	private void encryptData() {
		try {
			char[] passw = passwordField.getPassword();

			if (selectedFile == null) {
				throw new NullPointerException("select FILE");
			}
			if (selectedFile.exists()) {
				Files.delete(selectedFile.toPath());
			}
			KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(passw);

			if (data == null) {
				data = new KeystoreData();
			}

			if (data.getKeystore() == null) {
				KeyPair generatedKeyPair = KeyUtils.generateKeyPair();
				privKey = (BCECPrivateKey) generatedKeyPair.getPrivate();
				pubKey = (BCECPublicKey) generatedKeyPair.getPublic();
				byte[] storedKey = KeyUtils.storeToString(generatedKeyPair, param, passw);
				data.setKeystore(storedKey);
			}

			// gen

			// STORE

			String dataString = textArea.getText();
			byte[] dataE = KeyUtils.encrypt(dataString, pubKey);
			data.setSecrets(dataE);

			byte[] yamlBytes = OBJECTMAPPER.writeValueAsBytes(data);
			byte[] fullBase64 = Base64.getEncoder().encode(yamlBytes);
			Files.createFile(selectedFile.toPath());
			Files.write(selectedFile.toPath(), fullBase64, StandardOpenOption.TRUNCATE_EXISTING);
			System.out.println("KeystoreMain.encryptData(3)");
		} catch (IOException | OperatorCreationException | CertificateException | KeyStoreException
				| NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

}
