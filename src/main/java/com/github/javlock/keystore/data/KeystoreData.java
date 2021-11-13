package com.github.javlock.keystore.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.Getter;
import lombok.Setter;

@SuppressFBWarnings(value = { "EI_EXPOSE_REP", "EI_EXPOSE_REP2" })
public class KeystoreData {
	private @Getter @Setter byte[] keystore;
	private @Getter @Setter byte[] secrets;
}
