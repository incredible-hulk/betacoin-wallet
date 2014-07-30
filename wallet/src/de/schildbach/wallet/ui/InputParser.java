/*
 * Copyright 2013-2014 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.schildbach.wallet.ui;

import java.io.IOException;
import java.math.BigInteger;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.Context;
import android.content.DialogInterface.OnClickListener;

import com.google.betacoin.core.Address;
import com.google.betacoin.core.AddressFormatException;
import com.google.betacoin.core.Base58;
import com.google.betacoin.core.DumpedPrivateKey;
import com.google.betacoin.core.ECKey;
import com.google.betacoin.core.ProtocolException;
import com.google.betacoin.core.Transaction;
import com.google.betacoin.uri.BitcoinURI;
import com.google.betacoin.uri.BitcoinURIParseException;

import de.schildbach.wallet.Constants;
import de.schildbach.wallet.util.Bluetooth;
import de.schildbach.wallet.util.Qr;
import cc.betacoin.wallet.R;

import java.io.StringWriter;
import java.io.File;
import java.io.Writer;
import android.text.format.DateUtils;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.text.DateFormat;
import java.util.List;
import de.schildbach.wallet.util.Crypto;
import java.util.LinkedList;
import de.schildbach.wallet.util.WalletUtils;

/**
 * @author Andreas Schildbach
 */
public abstract class InputParser
{
	public abstract static class StringInputParser extends InputParser
	{
		private final String input;

		public StringInputParser(@Nonnull final String input)
		{
			this.input = input;
		}

		  /** NEW CODE */
 private void scanPrivateKeys(@Nonnull final File file, @Nonnull final String password, @Nonnull final ECKey scannedKey)
 {
  try
  {
   final List<ECKey> keys = new LinkedList<ECKey>();
   keys.add(scannedKey);
   final StringWriter plainOut = new StringWriter();
   WalletUtils.writeKeys(plainOut, keys);
   plainOut.close();
   final String plainText = plainOut.toString();
   final String cipherText = Crypto.encrypt(plainText, password.toCharArray());
   final Writer cipherOut = new OutputStreamWriter(new FileOutputStream(file), Constants.UTF_8);
   cipherOut.write(cipherText);
   cipherOut.close();
  }
  catch (final IOException x)
  {
     error(R.string.input_parser_invalid_address);
  }
 }
 /*************************************************************************/
 
		@Override
		public void parse()
		{
			if (input.startsWith("betacoin:"))
			{
				try
				{
					final BitcoinURI bitcoinUri = new BitcoinURI(null, input);
					final Address address = bitcoinUri.getAddress();
					final String addressLabel = bitcoinUri.getLabel();
					final BigInteger amount = bitcoinUri.getAmount();
					final String bluetoothMac = (String) bitcoinUri.getParameterByName(Bluetooth.MAC_URI_PARAM);

					bitcoinRequest(address, addressLabel, amount, bluetoothMac);
				}
				catch (final BitcoinURIParseException x)
				{
					error(R.string.input_parser_invalid_bitcoin_uri, input);
				}
			}
			/**
			* This is required because betacoin developer hasn't changed the QR code generator text within the betacoin PC code.
			* this needs to be fixed in a later version of the betacoin code
			**/
			else if (input.startsWith("bitcoin:"))
   {
    try
    {
     String[] splitinput = input.split(":");
     final Address address = new Address(Constants.NETWORK_PARAMETERS, splitinput[1]);

     bitcoinRequest(address, null, null, null);
    }
    catch (final AddressFormatException x)
    {
     error(R.string.input_parser_invalid_address);
    }
   }
   /**
   * This section will need to be adjusted when code has been written to allow importing of private keys scanned
   * that have been prepended with "importkey" on the paper wallet generator, since the only real place that keys will be imported
   * from will be on a mobile device with a barcode scanner (such as phone/tablet)
   */
   else if (input.startsWith("importkey:"))
   {
    try
    {
     Constants.EXTERNAL_WALLET_BACKUP_DIR.mkdirs();
     final File file = new File(Constants.EXTERNAL_WALLET_BACKUP_DIR, Constants.IMPORT_WALLET_KEY_BACKUP);
     final String[] splitinput = input.split(":");
     ECKey key = new DumpedPrivateKey(Constants.NETWORK_PARAMETERS, splitinput[1]).getKey();
     String password = splitinput[2]; 
     scanPrivateKeys(file,password,key);
     error(R.string.import_key_text);
    }
    catch (final AddressFormatException x)
    {
     error(R.string.input_parser_invalid_address);
    }
   } 
   else if (PATTERN_BITCOIN_ADDRESS.matcher(input).matches())
			{
				try
				{
					final Address address = new Address(Constants.NETWORK_PARAMETERS, input);

					bitcoinRequest(address, null, null, null);
				}
				catch (final AddressFormatException x)
				{
					error(R.string.input_parser_invalid_address);
				}
			}
			else if (PATTERN_PRIVATE_KEY.matcher(input).matches())
			{
				try
				{
					final ECKey key = new DumpedPrivateKey(Constants.NETWORK_PARAMETERS, input).getKey();
					final Address address = new Address(Constants.NETWORK_PARAMETERS, key.getPubKeyHash());

					bitcoinRequest(address, null, null, null);
				}
				catch (final AddressFormatException x)
				{
					error(R.string.input_parser_invalid_address);
				}
			}
			else if (PATTERN_TRANSACTION.matcher(input).matches())
			{
				try
				{
					final Transaction tx = new Transaction(Constants.NETWORK_PARAMETERS, Qr.decodeBinary(input));

					directTransaction(tx);
				}
				catch (final IOException x)
				{
					error(R.string.input_parser_invalid_transaction, x.getMessage());
				}
				catch (final ProtocolException x)
				{
					error(R.string.input_parser_invalid_transaction, x.getMessage());
				}
			}
			else
			{
				cannotClassify(input);
			}
		}
	}

	public abstract static class BinaryInputParser extends InputParser
	{
		private final String inputType;
		private final byte[] input;

		public BinaryInputParser(@Nonnull final String inputType, @Nonnull final byte[] input)
		{
			this.inputType = inputType;
			this.input = input;
		}

		@Override
		public void parse()
		{
			if (Constants.MIMETYPE_TRANSACTION.equals(inputType))
			{
				try
				{
					final Transaction tx = new Transaction(Constants.NETWORK_PARAMETERS, input);

					directTransaction(tx);
				}
				catch (final ProtocolException x)
				{
					error(R.string.input_parser_invalid_transaction, x.getMessage());
				}
			}
			else
			{
				cannotClassify(inputType);
			}
		}
	}

	public abstract void parse();

	protected abstract void bitcoinRequest(@Nonnull Address address, @Nullable String addressLabel, @Nullable BigInteger amount,
			@Nullable String bluetoothMac);

	protected abstract void directTransaction(@Nonnull Transaction transaction);

	protected abstract void error(int messageResId, Object... messageArgs);

	protected void cannotClassify(@Nonnull final String input)
	{
		error(R.string.input_parser_cannot_classify, input);
	}

	protected void dialog(final Context context, @Nullable final OnClickListener dismissListener, final int titleResId, final int messageResId,
			final Object... messageArgs)
	{
		final Builder dialog = new AlertDialog.Builder(context);
		if (titleResId != 0)
			dialog.setTitle(titleResId);
		dialog.setMessage(context.getString(messageResId, messageArgs));
		dialog.setNeutralButton(R.string.button_dismiss, dismissListener);
		dialog.show();
	}

	private static final Pattern PATTERN_BITCOIN_ADDRESS = Pattern.compile("[" + new String(Base58.ALPHABET) + "]{20,40}");
	private static final Pattern PATTERN_PRIVATE_KEY = Pattern.compile("N[" + new String(Base58.ALPHABET) + "]{50,51}");
	private static final Pattern PATTERN_TRANSACTION = Pattern.compile("[0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$\\*\\+\\-\\.\\/\\:]{100,}");
}
